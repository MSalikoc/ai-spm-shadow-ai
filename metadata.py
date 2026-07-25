"""
Business ownership + lifecycle metadata deposu.

Scan her seferinde Graph'tan yeniden kurulur; bu manuel metadata AYRI bir depoda
(metadata.json, app_id anahtarlı) tutulur ve her taramada bulgulara merge edilir —
böylece otomatik tarama manuel veriyi ezmez (kriter 5). Lifecycle status ve review
tarihi değişiklikleri history olarak saklanır (kriter 9).
"""
from datetime import datetime, timezone

import storage
from config import LIFECYCLE_STATUSES


def default_entry() -> dict:
    return {
        "ownership": {"business_owner": "", "technical_owner": "", "sponsor": ""},
        "business_context": {"business_unit": "", "subsidiary": "", "purpose": "",
                             "process": "", "criticality": "", "environment": ""},
        "lifecycle": {"status": "Discovered", "next_review_date": None},
        "notes": "",
        "history": [],
    }


def load() -> dict:
    return storage.read_metadata()


def save(store: dict) -> None:
    storage.write_metadata(store)


def merge(findings: list[dict], store: dict) -> None:
    """Depodaki business/lifecycle metadata'sını bulgulara işler (teknik owner'ı ezmeden)."""
    for f in findings:
        entry = store.get(f.get("app_id")) or default_entry()
        own = f.setdefault("ownership", {"application_owners": [], "service_principal_owners": []})
        own.update(entry["ownership"])  # business_owner / technical_owner / sponsor
        f["business_context"] = entry["business_context"]
        f["lifecycle"] = entry["lifecycle"]
        f["notes"] = entry.get("notes", "")
        f["history"] = entry.get("history", [])


def set_metadata(store: dict, app_id: str, patch: dict, now=None) -> dict:
    """Bir app'in business/lifecycle metadata'sını günceller; status/review değişimini history'e yazar."""
    now = now or datetime.now(timezone.utc)
    entry = store.setdefault(app_id, default_entry())

    lc = patch.get("lifecycle") or {}
    new_status = lc.get("status")
    if new_status in LIFECYCLE_STATUSES and new_status != entry["lifecycle"]["status"]:
        entry["history"].append({"timestamp": now.isoformat(), "field": "status",
                                 "from": entry["lifecycle"]["status"], "to": new_status})
        entry["lifecycle"]["status"] = new_status
    if "next_review_date" in lc and lc["next_review_date"] != entry["lifecycle"]["next_review_date"]:
        entry["history"].append({"timestamp": now.isoformat(), "field": "next_review_date",
                                 "from": entry["lifecycle"]["next_review_date"],
                                 "to": lc["next_review_date"]})
        entry["lifecycle"]["next_review_date"] = lc["next_review_date"]

    for key in ("ownership", "business_context"):
        for k, v in (patch.get(key) or {}).items():
            if k in entry[key] and v is not None:
                entry[key][k] = v
    if "notes" in patch and patch["notes"] is not None:
        entry["notes"] = patch["notes"]
    return entry


def _parse_date(s):
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def upcoming_reviews(findings: list[dict], within_days: int = 30, now=None) -> list[dict]:
    """Review tarihi geçmiş veya `within_days` içinde olan uygulamalar (kriter: yaklaşan review)."""
    now = now or datetime.now(timezone.utc)
    out = []
    for f in findings:
        d = _parse_date((f.get("lifecycle") or {}).get("next_review_date"))
        if d and (d - now).days <= within_days:
            out.append((d, f))
    out.sort(key=lambda x: x[0])
    return [f for _, f in out]
