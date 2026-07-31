"""
Business ownership + lifecycle metadata store.

Every scan is rebuilt from Graph; this manual metadata is kept in a SEPARATE store
(metadata.json, keyed by app_id) and merged into the findings on every scan — so an
automated scan never overwrites manual data (criterion 5). Lifecycle status and review
date changes are kept as history (criterion 9).
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
        "classification": {"category": None, "ownership": None},  # manual override
        "notes": "",
        "history": [],
    }


def load() -> dict:
    return storage.read_metadata()


def save(store: dict) -> None:
    storage.write_metadata(store)


def merge(findings: list[dict], store: dict) -> None:
    """Applies the store's business/lifecycle metadata onto the findings (without overwriting technical owner)."""
    for f in findings:
        entry = store.get(f.get("app_id")) or default_entry()
        own = f.setdefault("ownership", {"application_owners": [], "service_principal_owners": []})
        own.update(entry["ownership"])  # business_owner / technical_owner / sponsor
        f["business_context"] = entry["business_context"]
        f["lifecycle"] = entry["lifecycle"]
        f["classification_override"] = entry.get("classification") or {}
        f["notes"] = entry.get("notes", "")
        f["history"] = entry.get("history", [])


def set_metadata(store: dict, app_id: str, patch: dict, now=None) -> dict:
    """Updates an app's business/lifecycle metadata; writes status/review changes to history."""
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
    # Manual classification override — an empty value clears the override
    if "classification" in patch:
        entry.setdefault("classification", {"category": None, "ownership": None})
        for k, v in (patch["classification"] or {}).items():
            if k in entry["classification"]:
                entry["classification"][k] = v or None
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
    """Applications whose review date is past due or within `within_days` (criterion: upcoming review)."""
    now = now or datetime.now(timezone.utc)
    out = []
    for f in findings:
        d = _parse_date((f.get("lifecycle") or {}).get("next_review_date"))
        if d and (d - now).days <= within_days:
            out.append((d, f))
    out.sort(key=lambda x: x[0])
    return [f for _, f in out]
