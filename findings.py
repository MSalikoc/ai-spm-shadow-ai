"""
Yönetilebilir finding kayıtları — açıklama/remediation metnini iş kuyruğuna çevirir.

Finding'ler kural motorundan üretilir (deterministic ID: finding-{asset_id}-{rule_key}),
kalıcı bir depoda (findings.json) tutulur. Her tarama:
  - yeni finding → kayıt oluştur (status Open, first_seen=now)
  - mevcut finding → last_seen güncelle, kural içeriğini tazele
  - Resolved iken tekrar görülürse → Reopened (kriter 4)
  - artık görülmeyen açık finding → otomatik Resolved
Manuel alanlar (owner, responsible_team, due_date, status, resolution_note,
ticket_reference) tarama tarafından EZİLMEZ.
"""
from datetime import datetime, timezone

import storage
from config import FINDING_STATUSES as STATUSES
from scoring import _scope_weight

OPEN_STATUSES = {"Open", "Assigned", "In Progress", "Pending Review", "Reopened"}
CLOSED_STATUSES = {"Resolved", "Accepted", "False Positive"}


def _maxw_delegated(app):
    return max((_scope_weight(s) for s in app.get("scopes", [])), default=0)


def _maxw_app(app):
    return max((_scope_weight((p.get("permission") or "").lower())
                for p in app.get("application_permissions", [])), default=0)


def _review_overdue(app, now):
    d = (app.get("lifecycle") or {}).get("next_review_date")
    if not d:
        return False
    try:
        dt = datetime.fromisoformat(d.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt < now


# Kural = (key, title, description, category, severity, priority, action, impact, applies)
RULES = [
    ("owner-missing", "Business owner atanmamış",
     "Uygulamaya business owner atanmamış — hesap verebilirlik yok.",
     "Governance", "Medium", "P2", "Bir business owner ata.",
     "Sahipsiz AI uygulaması; olay anında sorumlu belirsiz.",
     lambda a, now: not (a.get("ownership") or {}).get("business_owner")
     and not a.get("first_party_microsoft")),

    ("admin-consent-sensitive", "Admin onaylı uygulamada hassas izin",
     "Tüm organizasyon için admin consent verilmiş ve hassas veri izni mevcut.",
     "Permission", "High", "P1", "Admin consent'i gözden geçir/kaldır; least-privilege uygula.",
     "Org geneli hassas veri erişimi — geniş blast radius.",
     lambda a, now: a.get("consent_type") == "AllPrincipals" and _maxw_delegated(a) >= 8),

    ("app-only-highpriv", "Yüksek ayrıcalıklı app-only erişim",
     "Uygulama kullanıcı olmadan (app-only) yüksek ayrıcalıklı tenant erişimine sahip.",
     "Permission", "High", "P1", "App-only application permission'ları revoke et.",
     "Kullanıcısız, 7/24 tenant-geneli erişim.",
     lambda a, now: a.get("has_app_only_access") and _maxw_app(a) >= 8),

    ("unknown-classification", "Sınıflandırılmamış AI uygulaması",
     "Uygulama Unknown AI olarak sınıflandı — güvenli varsayılamaz.",
     "Classification", "Medium", "P2", "İncele ve doğru kategoriye sınıflandır.",
     "Yönetilmeyen, tanımsız AI riski.",
     lambda a, now: (a.get("classification") or {}).get("category") == "Unknown AI"),

    ("unused-high-risk", "Kullanılmayan yüksek riskli uygulama",
     "Yüksek riskli ama son 30 gündür kullanılmayan uygulama — saf saldırı yüzeyi.",
     "Usage", "Medium", "P2", "Gerekmiyorsa erişimi kaldır / uygulamayı sil.",
     "İş değeri yok ama izin riski sürüyor.",
     lambda a, now: (a.get("usage") or {}).get("inactive_30d") and a.get("risk_score", 0) >= 50),

    ("lifecycle-review-overdue", "Lifecycle review'ı gecikmiş",
     "Uygulamanın planlanmış review tarihi geçmiş.",
     "Governance", "Low", "P3", "Lifecycle review'ı tamamla ve tarihi güncelle.",
     "Governance SLA ihlali.",
     lambda a, now: _review_overdue(a, now)),

    ("blocked-still-active", "Bloklu uygulama hâlâ kullanımda",
     "Lifecycle Blocked olduğu hâlde uygulama son 30 günde aktif kullanılmış.",
     "Governance", "High", "P1", "Erişimi teknik olarak kes (consent kaldır / disable).",
     "Politika ihlali — bloklu app kullanılıyor.",
     lambda a, now: (a.get("lifecycle") or {}).get("status") == "Blocked"
     and (a.get("usage") or {}).get("active_users_30d", 0) > 0),
]


def generate(apps, now):
    """Kurallardan mevcut finding'leri üretir → {finding_id: generated_fields}."""
    out = {}
    for app in apps:
        aid = app.get("app_id") or app.get("sp_id")
        if not aid:
            continue
        for key, title, desc, cat, sev, prio, action, impact, applies in RULES:
            try:
                if not applies(app, now):
                    continue
            except Exception:
                continue
            fid = f"finding-{aid}-{key}"
            out[fid] = {
                "finding_id": fid, "rule_key": key, "title": title, "description": desc,
                "category": cat, "severity": sev, "priority": prio,
                "asset_id": aid, "asset_name": app.get("display_name") or "—",
                "business_impact": impact, "recommended_action": action,
            }
    return out


def _default(gen, now):
    d = now.date().isoformat()
    rec = dict(gen)
    rec.update({"status": "Open", "owner": "", "responsible_team": "", "due_date": None,
                "first_seen": d, "last_seen": d, "resolution_note": "",
                "ticket_reference": "", "closed_date": None, "history": []})
    return rec


def process(apps, now=None):
    """Finding'leri üretir, depo ile uzlaştırır, kalıcılaştırır; kayıt listesi döner."""
    now = now or datetime.now(timezone.utc)
    today = now.date().isoformat()
    gen = generate(apps, now)
    store = storage.read_json("findings.json") or {}

    for fid, g in gen.items():
        rec = store.get(fid)
        if rec is None:
            store[fid] = _default(g, now)
            continue
        # Tarama-türevi alanları tazele (manuel alanlara dokunma)
        for k in ("title", "description", "category", "severity", "priority",
                  "asset_name", "business_impact", "recommended_action", "rule_key"):
            rec[k] = g[k]
        rec["last_seen"] = today
        if rec["status"] == "Resolved":          # çözülmüş bulgu geri geldi → Reopened
            rec["history"].append({"timestamp": now.isoformat(), "field": "status",
                                   "from": "Resolved", "to": "Reopened"})
            rec["status"] = "Reopened"
            rec["closed_date"] = None

    # Artık görülmeyen açık finding'ler → otomatik Resolved
    for fid, rec in store.items():
        if fid not in gen and rec.get("status") in OPEN_STATUSES:
            rec["history"].append({"timestamp": now.isoformat(), "field": "status",
                                   "from": rec["status"], "to": "Resolved"})
            rec["status"] = "Resolved"
            rec["closed_date"] = today
            if not rec.get("resolution_note"):
                rec["resolution_note"] = "Otomatik: bulgu artık tespit edilmiyor."

    storage.write_json("findings.json", store)
    return list(store.values())


def set_finding(store, finding_id, patch, now=None):
    """Manuel güncelleme (dashboard/config): owner, team, due date, status, vb."""
    now = now or datetime.now(timezone.utc)
    rec = store.get(finding_id)
    if rec is None:
        return None
    new_status = patch.get("status")
    if new_status in STATUSES and new_status != rec["status"]:
        rec["history"].append({"timestamp": now.isoformat(), "field": "status",
                               "from": rec["status"], "to": new_status})
        rec["status"] = new_status
        rec["closed_date"] = now.date().isoformat() if new_status in CLOSED_STATUSES else None
    for k in ("owner", "responsible_team", "due_date", "resolution_note", "ticket_reference"):
        if k in patch and patch[k] is not None:
            rec[k] = patch[k]
    return rec


def _parse_date(s):
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def overdue(records, now=None):
    """Due date geçmiş ve kapanmamış finding'ler (kriter 10)."""
    now = now or datetime.now(timezone.utc)
    out = []
    for r in records:
        d = _parse_date(r.get("due_date"))
        if d and d < now and r.get("status") not in CLOSED_STATUSES:
            out.append(r)
    out.sort(key=lambda r: r.get("due_date") or "")
    return out


def by_status(records):
    counts = {s: 0 for s in STATUSES}
    for r in records:
        counts[r.get("status", "Open")] = counts.get(r.get("status", "Open"), 0) + 1
    return counts


def by_owner(records):
    counts = {}
    for r in records:
        if r.get("status") in CLOSED_STATUSES:
            continue
        o = r.get("owner") or "Atanmamış"
        counts[o] = counts.get(o, 0) + 1
    return counts
