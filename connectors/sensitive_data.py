"""
Uygulama bazlı hassas veri korelasyonu (Adım 6).

Dört kaynağı (Agent 365 / Entra Agent ID / Defender-MDCA / Purview audit+DSPM) uygulama
(veya agent) bazında birleştirir ve ürünün ana sorusunu cevaplar:
  "Hangi AI uygulaması üzerinden HANGİ hassas veri, kaç kullanıcı, ne zaman, hangi yönde,
   ve uygulamanın kurumsal onay durumu nedir?"

Girdi: registry.run()'ın döndürdüğü korele asset listesi (app/agent asset'leri + event
entity'leri: SENSITIVE_INTERACTION, USAGE_OBSERVATION birlikte).

Çıktı: her uygulama için `AppProfile` — usage (MDCA) + hassaslık (Purview) birleşik;
7g/30g özet; yön dağılımı; etkilenen kullanıcı/agent; SIT/label/workload dağılımı; findings.

KRİTİK ayrım: **erişim ≠ paylaşım**. Yön taksonomisi ACCESSED/SHARED/UPLOADED/GENERATED/
BLOCKED/ALLOWED/UNKNOWN_DIRECTION ayrı tutulur; MDCA upload hacmi tek başına "hassas paylaşım"
sayılmaz (Purview korelasyonu olmadan `sensitivity=UNDETERMINED`).
"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from .base import EntityType

DIRECTIONS = ["ACCESSED", "SHARED", "UPLOADED", "GENERATED",
              "BLOCKED", "ALLOWED", "UNKNOWN_DIRECTION"]
_SHARING_DIRECTIONS = {"SHARED", "UPLOADED", "GENERATED", "ALLOWED"}   # veri dışarı/işlendi
_APP_ASSET_TYPES = {EntityType.AI_APPLICATION, EntityType.AI_AGENT, EntityType.AGENT_IDENTITY}


# ---------- yardımcılar ----------
def _parse_iso(s):
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _norm(s):
    return (s or "").strip().lower()


def _event_view(e):
    """Bir event entity'sini (interaction/observation) ortak görünüme indirger."""
    if e.get("interaction"):
        i = e["interaction"]
        return {
            "kind": "interaction",
            "ts": _parse_iso(i.get("timestamp") or e.get("last_seen")),
            "user": i.get("user"),
            "app_name": i.get("app_host"),
            "app_id": i.get("app_id"),
            "mdca_app_id": None,
            "direction": i.get("direction") or "UNKNOWN_DIRECTION",
            "sits": [s.get("name") for s in (i.get("sensitive_info_types") or []) if s.get("name")],
            "label": i.get("sensitivity_label_id"),
            "workload": i.get("workload"),
            "sources": e.get("sources", []),
        }
    if e.get("usage_observation"):
        u = e["usage_observation"]
        return {
            "kind": "observation",
            "ts": _parse_iso(e.get("last_seen") or u.get("period")),
            "user": None,
            "app_name": u.get("app_name"),
            "app_id": None,
            "mdca_app_id": u.get("mdca_app_id"),
            "direction": u.get("direction") or "UNKNOWN_DIRECTION",
            "sits": [],
            "label": None,
            "workload": None,
            "observed_users": u.get("users") or 0,
            "uploaded_bytes": u.get("uploaded_bytes") or 0,
            "transactions": u.get("transactions") or 0,
            "sources": e.get("sources", []),
        }
    return None


def _index_apps(app_assets):
    idx = {"app_id": {}, "mdca": {}, "name": {}, "domain": {}}
    for a in app_assets:
        ext = a.get("external_ids") or {}
        if ext.get("entra_app_id"):
            idx["app_id"][ext["entra_app_id"]] = a
        if ext.get("mdca_app_id"):
            idx["mdca"][ext["mdca_app_id"]] = a
        if a.get("display_name"):
            idx["name"].setdefault(_norm(a["display_name"]), a)
        if a.get("domain"):
            idx["domain"].setdefault(_norm(a["domain"]), a)
    return idx


def _resolve(view, idx):
    """Event → app asset eşleştir (güçlü→zayıf). Eşleşmezse None (sentetik app)."""
    if view.get("app_id") and view["app_id"] in idx["app_id"]:
        return idx["app_id"][view["app_id"]]
    if view.get("mdca_app_id") and view["mdca_app_id"] in idx["mdca"]:
        return idx["mdca"][view["mdca_app_id"]]
    if view.get("app_name") and _norm(view["app_name"]) in idx["name"]:
        return idx["name"][_norm(view["app_name"])]
    return None


def _blank_profile(key, name, asset=None):
    mdca = (asset or {}).get("mdca") or {}
    return {
        "app_key": key,
        "display_name": name or "—",
        "asset_id": (asset or {}).get("asset_id"),
        "asset_type": (asset or {}).get("asset_type"),
        "matched_to_inventory": asset is not None,
        "sanctioned_state": mdca.get("sanctioned_state"),
        "sources": set((asset or {}).get("sources", [])),
        "usage": {
            "observed_users": mdca.get("users", 0),
            "uploaded_bytes": mdca.get("uploaded_bytes", 0),
            "transactions": mdca.get("transactions", 0),
            "data_sensitivity": mdca.get("data_sensitivity"),
        },
        "affected_users": set(),
        "directions": {d: 0 for d in DIRECTIONS},
        "sit_distribution": defaultdict(int),
        "label_distribution": defaultdict(int),
        "workload_distribution": defaultdict(int),
        "interactions_7d": 0, "interactions_30d": 0,
        "sensitive_7d": 0, "sensitive_30d": 0,
        "blocked": 0, "allowed": 0,
        "_interaction_count": 0,
    }


# ---------- ana API ----------
def build_app_profiles(all_assets, now=None):
    """Korele asset+event listesinden uygulama-bazlı hassas veri profilleri üretir."""
    app_assets = [a for a in all_assets if a.get("asset_type") in _APP_ASSET_TYPES]
    events = [v for v in (_event_view(e) for e in all_assets) if v]
    if now is None:
        ts_all = [v["ts"] for v in events if v["ts"]]
        now = max(ts_all) if ts_all else datetime.now(timezone.utc)
    idx = _index_apps(app_assets)

    profiles = {}
    # 1) envanterdeki her app-benzeri asset için profil (event'siz de görünsün → dürüst coverage)
    for a in app_assets:
        profiles[a["asset_id"]] = _blank_profile(a["asset_id"], a.get("display_name"), a)

    # 2) event'leri app'lere bağla
    for v in events:
        asset = _resolve(v, idx)
        if asset is not None:
            key = asset["asset_id"]
        else:
            key = "name:" + _norm(v["app_name"] or "unknown")
            if key not in profiles:
                profiles[key] = _blank_profile(key, v["app_name"])
        p = profiles[key]
        p["sources"].update(v.get("sources", []))
        _apply_event(p, v, now)

    out = []
    for p in profiles.values():
        _finalize(p, now)
        p["findings"] = evaluate_findings(p)
        out.append(p)
    # en riskli/aktif önce
    out.sort(key=lambda x: (len(x["findings"]), x["sensitive_30d"], x["_interaction_count"]),
             reverse=True)
    for p in out:
        p.pop("_interaction_count", None)
    return out


def _apply_event(p, v, now):
    d = v["direction"] if v["direction"] in p["directions"] else "UNKNOWN_DIRECTION"
    p["directions"][d] += 1
    if v["kind"] == "observation":
        # gözlem: usage sinyali; hassaslık DEĞİL (Purview korele edecek)
        p["usage"]["observed_users"] = max(p["usage"]["observed_users"], v.get("observed_users", 0))
        p["usage"]["uploaded_bytes"] = max(p["usage"]["uploaded_bytes"], v.get("uploaded_bytes", 0))
        p["usage"]["transactions"] = max(p["usage"]["transactions"], v.get("transactions", 0))
        return
    # interaction (Purview audit/DSPM)
    p["_interaction_count"] += 1
    if v["user"]:
        p["affected_users"].add(v["user"])
    for s in v["sits"]:
        p["sit_distribution"][s] += 1
    if v["label"]:
        p["label_distribution"][v["label"]] += 1
    if v["workload"]:
        p["workload_distribution"][v["workload"]] += 1
    if d == "BLOCKED":
        p["blocked"] += 1
    if d == "ALLOWED":
        p["allowed"] += 1
    is_sensitive = bool(v["sits"]) or bool(v["label"])
    if v["ts"]:
        age = now - v["ts"]
        if age <= timedelta(days=30):
            p["interactions_30d"] += 1
            if is_sensitive:
                p["sensitive_30d"] += 1
        if age <= timedelta(days=7):
            p["interactions_7d"] += 1
            if is_sensitive:
                p["sensitive_7d"] += 1


def _finalize(p, now):
    p["sources"] = sorted(p["sources"])
    p["affected_user_count"] = len(p["affected_users"])
    p["affected_users"] = sorted(p["affected_users"])
    p["sit_distribution"] = dict(p["sit_distribution"])
    p["label_distribution"] = dict(p["label_distribution"])
    p["workload_distribution"] = dict(p["workload_distribution"])
    p["sensitive_data_summary"] = {
        "window_7d": {"interactions": p["interactions_7d"], "sensitive": p["sensitive_7d"]},
        "window_30d": {"interactions": p["interactions_30d"], "sensitive": p["sensitive_30d"]},
        "affected_users": p["affected_user_count"],
        "blocked": p["blocked"], "allowed": p["allowed"],
        "sit_types": sorted(p["sit_distribution"], key=p["sit_distribution"].get, reverse=True),
        "labels": sorted(p["label_distribution"]),
    }


def evaluate_findings(p):
    """Uygulama profilinden bulgular üretir (erişim≠paylaşım ayrımıyla)."""
    findings = []
    name = p["display_name"]
    sanctioned = p.get("sanctioned_state")
    shared_sensitive = sum(p["directions"][d] for d in _SHARING_DIRECTIONS)
    has_sensitive = bool(p["sit_distribution"]) or bool(p["label_distribution"])

    if sanctioned == "unsanctioned" and has_sensitive and shared_sensitive > 0:
        findings.append({
            "type": "SENSITIVE_DATA_SHARED_WITH_UNSANCTIONED_AI",
            "severity": "high",
            "app": name,
            "detail": f"{name} onaysız (unsanctioned) ve hassas veri paylaşım/işlem yönünde "
                      f"({shared_sensitive} etkileşim). SIT: {list(p['sit_distribution'])[:5]}.",
            "affected_users": p["affected_user_count"],
        })
    if p["blocked"] > 0:
        findings.append({
            "type": "SENSITIVE_DATA_BLOCKED_TO_AI",
            "severity": "info",
            "app": name,
            "detail": f"{name} için {p['blocked']} hassas etkileşim DLP ile engellendi (pozitif kontrol).",
        })
    if (p["usage"].get("uploaded_bytes", 0) > 0
            and p["usage"].get("data_sensitivity") == "UNDETERMINED_REQUIRES_PURVIEW"
            and not has_sensitive):
        findings.append({
            "type": "UNSANCTIONED_AI_UPLOAD_UNDETERMINED",
            "severity": "medium" if sanctioned == "unsanctioned" else "low",
            "app": name,
            "detail": f"{name} yüksek upload hacmi var ({p['usage']['uploaded_bytes']} bayt) "
                      f"ama Purview korelasyonu yok → hassaslık BELİRSİZ (hacim tek başına paylaşım değil).",
        })
    if p["label_distribution"] and p["directions"]["ACCESSED"] > 0:
        findings.append({
            "type": "AI_APP_ACCESSING_LABELED_DATA",
            "severity": "medium",
            "app": name,
            "detail": f"{name} etiketli (labeled) kurumsal veriye erişiyor: {list(p['label_distribution'])}.",
        })
    return findings


def portfolio_summary(profiles):
    """Adım 7 dashboard için üst-düzey özet."""
    apps_with_sensitive = [p for p in profiles
                           if p["sensitive_data_summary"]["window_30d"]["sensitive"] > 0]
    findings = [f for p in profiles for f in p["findings"]]
    return {
        "total_apps": len(profiles),
        "matched_to_inventory": sum(1 for p in profiles if p["matched_to_inventory"]),
        "apps_with_sensitive_data": len(apps_with_sensitive),
        "unsanctioned_with_sensitive": sum(
            1 for p in profiles if p.get("sanctioned_state") == "unsanctioned"
            and (p["sit_distribution"] or p["label_distribution"])),
        "total_affected_users": len({u for p in profiles for u in p["affected_users"]}),
        "total_blocked": sum(p["blocked"] for p in profiles),
        "total_allowed": sum(p["allowed"] for p in profiles),
        "findings_by_severity": {
            sev: sum(1 for f in findings if f["severity"] == sev)
            for sev in ("high", "medium", "low", "info")},
        "high_severity_findings": sum(1 for f in findings if f["severity"] == "high"),
    }
