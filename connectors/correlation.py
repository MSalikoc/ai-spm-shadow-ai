"""
Asset korelasyonu — farklı kaynaklardan gelen aynı varlığı tek asset altında birleştirir.

Öncelik (güçlü → zayıf), confidence ağırlığıyla:
  1. entra_app_id (98)
  2. agent_identity_id (96)
  3. agent_blueprint_id (90)
  4. agent365_package_id (85)
  5. agent365_asset_id (80)
  6. manifest_id (75)
  7. verified publisher + domain (65)
  8. normalize edilmiş ad → SADECE zayıf sinyal; TEK BAŞINA kesin korelasyon YAPMAZ.

İsim eşleşmesiyle asla merge edilmez (yanlış birleşmeyi önlemek için). İsim yalnızca
başka bir güçlü sinyal varken confidence'ı doğrulamak için kullanılabilir.
"""
PRIORITY = [
    ("entra_app_id", 98), ("agent_identity_id", 96),
    ("agent365_package_id", 85), ("agent365_asset_id", 80), ("manifest_id", 75),
]
PUB_DOMAIN_WEIGHT = 65
NAME_ONLY_WEIGHT = 40
# NOT: `agent_blueprint_id` bilinçli olarak MERGE token'ı DEĞİL (Adım 6 düzeltmesi).
# Aynı blueprint'ten türeyen birden fazla identity'yi tek asset'e collapse etmemek için
# blueprint "relate-not-merge" ile bağlanır (bkz. _relate_blueprints): identity ve blueprint
# ayrı asset kalır, `related` alanıyla çapraz referanslanır.
BLUEPRINT_RELATE_WEIGHT = 90

_SOURCE_NAME_PRIORITY = ["AGENT_365", "ENTRA_AGENT_ID", "ENTRA_APPS",
                         "DEFENDER_CLOUD_APPS", "PURVIEW_AUDIT", "PURVIEW_DSPM_EXPORT"]


def _tokens(a):
    """Bir asset'in merge token'ları: (token, weight). İsim token'ı YOK (merge etmez)."""
    toks = []
    ext = a.get("external_ids") or {}
    for key, w in PRIORITY:
        if ext.get(key):
            toks.append((f"{key}={ext[key]}", w))
    pub = (a.get("publisher") or a.get("verified_publisher_name") or "").strip().lower()
    dom = (a.get("domain") or "").strip().lower()
    if pub and dom and pub != "—":
        toks.append((f"pubdom={pub}|{dom}", PUB_DOMAIN_WEIGHT))
    return toks


def _pick_name(members):
    best = None
    best_rank = 99
    for m in members:
        for s in m.get("sources", []):
            rank = _SOURCE_NAME_PRIORITY.index(s) if s in _SOURCE_NAME_PRIORITY else 98
            if m.get("display_name") and rank < best_rank:
                best, best_rank = m["display_name"], rank
    return best or (members[0].get("display_name") if members else "—")


def _merge(members):
    from .model import EXTERNAL_ID_KEYS, _provisional_id
    ext = {k: None for k in EXTERNAL_ID_KEYS}
    sources, first, last = set(), [], []
    for m in members:
        for k, v in (m.get("external_ids") or {}).items():
            if v and not ext.get(k):
                ext[k] = v
        sources.update(m.get("sources", []))
        if m.get("first_seen"):
            first.append(m["first_seen"])
        if m.get("last_seen"):
            last.append(m["last_seen"])

    merged = dict(members[0])          # connector'a özel alanları koru (ilk üye baz)
    for m in members[1:]:              # eksik alanları diğer üyelerden tamamla
        for k, v in m.items():
            if k not in ("external_ids", "sources", "first_seen", "last_seen",
                         "correlation_confidence") and merged.get(k) in (None, "", "—", []):
                merged[k] = v
    merged["display_name"] = _pick_name(members)
    merged["external_ids"] = ext
    merged["sources"] = sorted(sources)
    merged["first_seen"] = min(first) if first else None
    merged["last_seen"] = max(last) if last else None
    merged["asset_id"] = _provisional_id(merged.get("asset_type"), ext, merged["display_name"])

    if len(members) == 1:
        merged["correlation_confidence"] = 100
    else:
        counts = {}
        for m in members:
            for tok, w in _tokens(m):
                counts.setdefault(tok, [0, w])
                counts[tok][0] += 1
        shared = [w for c, w in counts.values() if c >= 2]
        merged["correlation_confidence"] = max(shared) if shared else NAME_ONLY_WEIGHT
    merged["_correlated_from"] = [
        {"asset_id": m.get("asset_id"), "sources": m.get("sources"),
         "display_name": m.get("display_name")} for m in members]
    return merged


def correlate(assets):
    """assets (ham entity listesi) → korele edilmiş asset listesi (union-find)."""
    n = len(assets)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    token_owner = {}
    for i, a in enumerate(assets):
        for tok, _w in _tokens(a):
            if tok in token_owner:
                union(token_owner[tok], i)
            else:
                token_owner[tok] = i

    clusters = {}
    for i in range(n):
        clusters.setdefault(find(i), []).append(assets[i])
    return _relate_blueprints([_merge(members) for members in clusters.values()])


def _relate_blueprints(assets):
    """
    agent_blueprint_id paylaşan identity ve blueprint asset'lerini MERGE etmeden bağlar.
    Blueprint = 'parent' tanım; identity = ondan türeyen çalışma-zamanı örneği. Aynı
    blueprint'ten birden fazla identity olabilir → collapse etmeyip `related` ile çapraz
    referans veririz (identity ↔ blueprint, confidence BLUEPRINT_RELATE_WEIGHT).
    """
    from collections import defaultdict
    by_bp = defaultdict(list)
    for a in assets:
        bp = (a.get("external_ids") or {}).get("agent_blueprint_id")
        if bp:
            by_bp[bp].append(a)
    for bp, members in by_bp.items():
        blueprints = [m for m in members if m.get("asset_type") == "AGENT_BLUEPRINT"]
        identities = [m for m in members if m.get("asset_type") != "AGENT_BLUEPRINT"]
        bp_asset = blueprints[0] if blueprints else None
        for ident in identities:
            rel = ident.setdefault("related", {})
            rel["blueprint_id"] = bp
            if bp_asset:
                rel["blueprint_asset_id"] = bp_asset["asset_id"]
                rel["blueprint_confidence"] = BLUEPRINT_RELATE_WEIGHT
        for bpa in blueprints:
            bpa.setdefault("related", {})["identity_asset_ids"] = [
                i["asset_id"] for i in identities]
    return assets
