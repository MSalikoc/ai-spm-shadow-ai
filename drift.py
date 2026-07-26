"""
Drift / değişiklik motoru — "önceki taramadan beri ne değişti?".

Her başarılı tarama normalize bir snapshot üretir (snapshot.json). Yeni tarama,
önceki snapshot ile diff'lenir → change event'leri (changes.json'a birikir).
İlk başarılı scan baseline olur ve DEĞİŞİKLİK ÜRETMEZ (kriter 1, 2).

Deterministic ID: app için app_id (yoksa sp_id), permission için
`resource|permission`. Change ID = (tip|asset|old|new|ts) hash'i.
"""
import hashlib
from datetime import datetime, timedelta, timezone

import storage
from scoring import _scope_weight

IMPORTANCE = {
    "NEW_APP_ONLY_ACCESS": "Critical", "ADMIN_CONSENT_ADDED": "High",
    "PERMISSION_ESCALATED": "High", "NEW_APPLICATION": "High",
    "NEW_PERMISSION": "Medium", "REMOVED_APPLICATION": "Medium",
    "OWNER_ADDED": "Medium", "OWNER_CHANGED": "Medium", "BUSINESS_OWNER_CHANGED": "Medium",
    "CLASSIFICATION_CHANGED": "Medium", "LIFECYCLE_CHANGED": "Medium", "APP_DISABLED": "Medium",
    "REMOVED_PERMISSION": "Low", "ADMIN_CONSENT_REMOVED": "Low", "OWNER_REMOVED": "Low",
    "APP_REENABLED": "Low", "FIRST_SIGNIN": "Info",
    "ACTIVITY_INCREASED": "Info", "ACTIVITY_DECREASED": "Info",
}


def _perm_key(p):
    return f"{p.get('resource', '')}|{p.get('permission', '')}"


def _max_weight(f):
    w = [_scope_weight(s) for s in f.get("scopes", [])]
    w += [_scope_weight((p.get("permission") or "").lower())
          for p in f.get("application_permissions", [])]
    return max(w, default=0)


def snapshot(findings) -> dict:
    """Diff için normalize edilmiş, JSON-serileştirilebilir snapshot (app_id anahtarlı)."""
    snap = {}
    for f in findings:
        aid = f.get("app_id") or f.get("sp_id")
        if not aid:
            continue
        ti = f.get("technical_inventory") or {}
        own = f.get("ownership") or {}
        usage = f.get("usage") or {}
        avail = bool(usage.get("available"))
        snap[aid] = {
            "name": f.get("display_name") or "—",
            "vendor": f.get("vendor") or "",
            "enabled": ti.get("enabled"),
            "delegated": sorted({_perm_key(p) for p in f.get("delegated_permissions", [])}),
            "application": sorted({_perm_key(p) for p in f.get("application_permissions", [])}),
            "has_app_only": bool(f.get("has_app_only_access")),
            "admin_consent": f.get("consent_type") == "AllPrincipals",
            "owners": sorted(o.get("id") or o.get("name") or ""
                             for o in own.get("service_principal_owners", [])),
            "business_owner": own.get("business_owner") or "",
            "classification": (f.get("classification") or {}).get("category") or "",
            "lifecycle": (f.get("lifecycle") or {}).get("status") or "",
            "business_unit": (f.get("business_context") or {}).get("business_unit") or "",
            "max_weight": _max_weight(f),
            "active_30d": usage.get("active_users_30d") if avail else None,
            "last_signin": usage.get("last_used_date") if avail else None,
        }
    return snap


def _ev(now, ctype, aid, name, old, new, desc):
    cid = hashlib.sha1(f"{ctype}|{aid}|{old}|{new}|{now.isoformat()}".encode()).hexdigest()[:12]
    return {"change_id": cid, "change_type": ctype, "asset_id": aid, "asset_name": name,
            "timestamp": now.isoformat(), "old_value": old, "new_value": new,
            "importance": IMPORTANCE.get(ctype, "Info"), "description": desc}


def diff(prev: dict, cur: dict, now=None) -> list:
    now = now or datetime.now(timezone.utc)
    events = []
    prev_ids, cur_ids = set(prev), set(cur)

    for aid in cur_ids - prev_ids:
        c = cur[aid]
        events.append(_ev(now, "NEW_APPLICATION", aid, c["name"], None, c["vendor"],
                          f"Yeni AI uygulaması keşfedildi: {c['name']}"))
    for aid in prev_ids - cur_ids:
        p = prev[aid]
        events.append(_ev(now, "REMOVED_APPLICATION", aid, p["name"], p["vendor"], None,
                          f"Uygulama kaldırıldı: {p['name']}"))

    for aid in cur_ids & prev_ids:
        p, c = prev[aid], cur[aid]
        nm = c["name"]
        for perm in sorted(set(c["delegated"]) - set(p["delegated"])):
            events.append(_ev(now, "NEW_PERMISSION", aid, nm, None, perm,
                              f"Yeni delegated izin: {perm}"))
        for perm in sorted(set(p["delegated"]) - set(c["delegated"])):
            events.append(_ev(now, "REMOVED_PERMISSION", aid, nm, perm, None,
                              f"Delegated izin kaldırıldı: {perm}"))
        for perm in sorted(set(c["application"]) - set(p["application"])):
            events.append(_ev(now, "NEW_PERMISSION", aid, nm, None, perm,
                              f"Yeni application izin: {perm}"))
        for perm in sorted(set(p["application"]) - set(c["application"])):
            events.append(_ev(now, "REMOVED_PERMISSION", aid, nm, perm, None,
                              f"Application izin kaldırıldı: {perm}"))
        if c["has_app_only"] and not p["has_app_only"]:
            events.append(_ev(now, "NEW_APP_ONLY_ACCESS", aid, nm, False, True,
                              f"App-only (kullanıcısız) erişim eklendi: {nm}"))
        if (c["max_weight"] or 0) > (p["max_weight"] or 0):
            events.append(_ev(now, "PERMISSION_ESCALATED", aid, nm, p["max_weight"], c["max_weight"],
                              f"İzin ayrıcalığı yükseldi ({p['max_weight']}→{c['max_weight']}/10)"))
        if c["admin_consent"] and not p["admin_consent"]:
            events.append(_ev(now, "ADMIN_CONSENT_ADDED", aid, nm, False, True,
                              "Admin (tüm org) consent eklendi"))
        if p["admin_consent"] and not c["admin_consent"]:
            events.append(_ev(now, "ADMIN_CONSENT_REMOVED", aid, nm, True, False,
                              "Admin consent kaldırıldı"))
        oadd = set(c["owners"]) - set(p["owners"])
        orem = set(p["owners"]) - set(c["owners"])
        if oadd and orem:
            events.append(_ev(now, "OWNER_CHANGED", aid, nm, p["owners"], c["owners"], "Owner değişti"))
        elif oadd:
            events.append(_ev(now, "OWNER_ADDED", aid, nm, None, sorted(oadd), "Owner eklendi"))
        elif orem:
            events.append(_ev(now, "OWNER_REMOVED", aid, nm, sorted(orem), None, "Owner kaldırıldı"))
        if c["business_owner"] != p["business_owner"]:
            events.append(_ev(now, "BUSINESS_OWNER_CHANGED", aid, nm,
                              p["business_owner"] or None, c["business_owner"] or None,
                              f"Business owner: {p['business_owner'] or '—'} → {c['business_owner'] or '—'}"))
        if c["classification"] != p["classification"]:
            events.append(_ev(now, "CLASSIFICATION_CHANGED", aid, nm, p["classification"], c["classification"],
                              f"Sınıflandırma: {p['classification']} → {c['classification']}"))
        if c["lifecycle"] != p["lifecycle"]:
            events.append(_ev(now, "LIFECYCLE_CHANGED", aid, nm, p["lifecycle"], c["lifecycle"],
                              f"Lifecycle: {p['lifecycle']} → {c['lifecycle']}"))
        if not p["last_signin"] and c["last_signin"]:
            events.append(_ev(now, "FIRST_SIGNIN", aid, nm, None, c["last_signin"],
                              f"İlk sign-in görüldü: {nm}"))
        pa, ca = p["active_30d"], c["active_30d"]
        if pa is not None and ca is not None and pa != ca:
            pct = round((ca - pa) / max(pa, 1) * 100)
            if ca > pa:
                events.append(_ev(now, "ACTIVITY_INCREASED", aid, nm, pa, ca,
                                  f"{nm} kullanımı %{pct} arttı ({pa}→{ca})"))
            else:
                events.append(_ev(now, "ACTIVITY_DECREASED", aid, nm, pa, ca,
                                  f"{nm} kullanımı %{abs(pct)} azaldı ({pa}→{ca})"))
        if p["enabled"] is True and c["enabled"] is False:
            events.append(_ev(now, "APP_DISABLED", aid, nm, True, False, f"Uygulama devre dışı: {nm}"))
        if p["enabled"] is False and c["enabled"] is True:
            events.append(_ev(now, "APP_REENABLED", aid, nm, False, True, f"Uygulama tekrar etkin: {nm}"))
    return events


def process(findings, now=None) -> list:
    """Diff hesaplar, snapshot ve changes.json'u günceller, bu taramanın event'lerini döner."""
    now = now or datetime.now(timezone.utc)
    prev = storage.read_json("snapshot.json")
    cur = snapshot(findings)
    events = [] if prev is None else diff(prev, cur, now)   # baseline: değişiklik yok
    storage.write_json("snapshot.json", cur)
    if events:
        log = storage.read_json("changes.json") or {"events": []}
        log["events"] = (events + log["events"])[:1000]
        storage.write_json("changes.json", log)
    return events


def recent(days=14, now=None) -> list:
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    log = storage.read_json("changes.json") or {"events": []}
    out = []
    for e in log["events"]:
        try:
            ts = datetime.fromisoformat(e["timestamp"])
        except (ValueError, KeyError):
            continue
        if ts >= cutoff:
            out.append(e)
    return out


def executive_summary(events) -> list:
    """Yönetici özeti satırları ('Bu hafta: ...' formatında)."""
    lines = []

    def cnt(t):
        return sum(1 for e in events if e["change_type"] == t)

    if cnt("NEW_APPLICATION"):
        lines.append(f"{cnt('NEW_APPLICATION')} yeni AI uygulaması keşfedildi.")
    if cnt("NEW_APP_ONLY_ACCESS"):
        lines.append(f"{cnt('NEW_APP_ONLY_ACCESS')} uygulamaya app-only permission eklendi.")
    if cnt("PERMISSION_ESCALATED"):
        lines.append(f"{cnt('PERMISSION_ESCALATED')} uygulamada izin ayrıcalığı yükseldi.")
    if cnt("ADMIN_CONSENT_ADDED"):
        lines.append(f"{cnt('ADMIN_CONSENT_ADDED')} uygulamaya admin (tüm org) consent verildi.")
    acts = [e for e in events if e["change_type"] == "ACTIVITY_INCREASED"]
    for e in sorted(acts, key=lambda x: (x["new_value"] or 0) - (x["old_value"] or 0), reverse=True)[:2]:
        pct = round(((e["new_value"] or 0) - (e["old_value"] or 0)) / max(e["old_value"] or 1, 1) * 100)
        lines.append(f"{e['asset_name']} kullanımı %{pct} arttı.")
    bo = sum(1 for e in events if e["change_type"] == "BUSINESS_OWNER_CHANGED" and e["new_value"])
    if bo:
        lines.append(f"{bo} uygulamaya business owner atandı.")
    for e in events:
        if e["change_type"] == "LIFECYCLE_CHANGED" and e["new_value"] == "Approved":
            lines.append(f"{e['asset_name']} {e['old_value']} durumundan Approved durumuna geçti.")
    return lines
