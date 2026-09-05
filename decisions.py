"""Persistent governance state for the three executive decision programs."""
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
import hashlib
import json

import storage

KEYS = {"sensitive-access", "identity-exposure", "governance"}
STATUSES = {
    "Decision required", "Approved", "In progress", "Verified", "Risk accepted",
    "Compensating control", "False positive", "Deferred",
}
OWNER_REQUIRED = STATUSES - {"Decision required"}
STORE_NAME = "decisions.json"
EDITABLE_FIELDS = {"status", "owner", "due_date", "notes", "compensating_control", "acceptance"}


class StaleDecision(storage.StorageConflict):
    """The decision changed after this editor read it."""


def revision(key, stored=None):
    """Opaque content revision, not an identity signature or a store-wide lock."""
    baseline = default_state(key)
    record = stored if isinstance(stored, dict) else {}
    canonical = {field: record.get(field, value) for field, value in baseline.items()}
    canonical["persisted"] = stored is not None
    return hashlib.sha256(json.dumps(
        canonical, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


def _parse_date(value, field):
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO-8601 date or timestamp string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be an ISO-8601 date or timestamp")
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def _elapsed(value, field, now):
    parsed = _parse_date(value, field)
    if parsed is None:
        return False
    try:
        calendar_date = date.fromisoformat(value)
    except ValueError:
        return parsed <= now
    return calendar_date < now.astimezone(timezone.utc).date()


def _validate_fields(values):
    if "status" in values:
        status = values["status"]
        if not isinstance(status, str) or status not in STATUSES:
            raise ValueError("invalid decision status")
    for field in ("owner", "notes", "compensating_control"):
        if field in values and values[field] is not None and not isinstance(values[field], str):
            raise ValueError(f"{field} must be a string or null")
    for field in ("due_date", "updated_at"):
        if field in values:
            _parse_date(values[field], field)
    acceptance = values.get("acceptance")
    if acceptance is not None:
        if not isinstance(acceptance, dict):
            raise ValueError("acceptance must contain a JSON object or null")
        for field in ("rationale", "approved_by"):
            value = acceptance.get(field)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"acceptance.{field} must be a string or null")
        _parse_date(acceptance.get("expires_at"), "acceptance.expires_at")
    if "history" in values:
        history = values["history"]
        if not isinstance(history, list) or any(not isinstance(h, dict) for h in history):
            raise ValueError("history must contain a JSON array of objects")
        for item in history:
            if not isinstance(item.get("field"), str) or item["field"] not in EDITABLE_FIELDS:
                raise ValueError("invalid history field")
            if not _parse_date(item.get("timestamp"), "history.timestamp"):
                raise ValueError("history.timestamp is required")


def _validate_requirements(state):
    status = state["status"]
    if status in OWNER_REQUIRED and not (state.get("owner") or "").strip():
        raise ValueError(f"owner is required when status is {status}")
    if status == "Risk accepted":
        acceptance = state.get("acceptance") or {}
        for field in ("rationale", "approved_by", "expires_at"):
            if not (acceptance.get(field) or "").strip():
                raise ValueError(f"acceptance.{field} is required for Risk accepted")
    if status == "Compensating control" and not (state.get("compensating_control") or "").strip():
        raise ValueError("compensating_control is required for Compensating control")
    if status == "Deferred" and not state.get("due_date"):
        raise ValueError("a future due_date is required for Deferred")
    if status in {"Deferred", "False positive"} and not (state.get("notes") or "").strip():
        raise ValueError(f"notes are required for {status}")


def default_state(key):
    if not isinstance(key, str) or key not in KEYS:
        raise ValueError("unknown decision_key")
    return {
        "decision_key": key,
        "status": "Decision required",
        "owner": "",
        "due_date": None,
        "notes": "",
        "compensating_control": "",
        "acceptance": None,
        "updated_at": None,
        "history": [],
    }


def load():
    """Load for display, degrading corrupt records visibly instead of blanking a report."""
    try:
        raw, version = storage.read_json_versioned(STORE_NAME)
    except ValueError as exc:
        return {key: {**default_state(key), "_data_error": str(exc)} for key in KEYS}
    if raw is None and version is None:
        return {}
    if not isinstance(raw, dict):
        message = "decisions.json must contain a JSON object"
        return {key: {**default_state(key), "_data_error": message} for key in KEYS}
    store = {}
    for key in KEYS:
        if key not in raw:
            continue
        record = raw[key]
        if isinstance(record, dict):
            store[key] = record
        else:
            store[key] = {**default_state(key),
                          "_data_error": f"{key} must contain a JSON object"}
    unknown = sorted(set(raw) - KEYS)
    if unknown:
        message = "unknown decision key(s): " + ", ".join(unknown)
        for key in KEYS:
            store[key] = {**store.get(key, default_state(key)), "_data_error": message}
    return store


def save(store):
    storage.write_json(STORE_NAME, store)


def _load_versioned():
    raw, version = storage.read_json_versioned(STORE_NAME)
    if raw is None and version is None:
        return {}, version
    if not isinstance(raw, dict):
        raise ValueError("decisions.json must contain a JSON object")
    store = {}
    errors = []
    for key, record in raw.items():
        if not isinstance(key, str) or key not in KEYS:
            errors.append(f"unknown decision key: {key}")
        elif not isinstance(record, dict):
            errors.append(f"{key} must contain a JSON object")
        else:
            store[key] = record
            viewed = view_state(key, record)
            if viewed.get("data_error"):
                errors.append(f"{key}: {viewed['data_error']}")
    if errors:
        raise ValueError("; ".join(errors))
    return store, version


def read_current(now=None):
    """Strict API read: corrupt state must not look like a successful empty store."""
    store, _version = _load_versioned()
    return {key: view_state(key, store.get(key), now=now) for key in sorted(KEYS)}


def update_decision(key, patch, now=None, retries=3, expected_revision=None):
    """Optimistic-concurrency update; reload and merge when another writer wins."""
    if not isinstance(key, str) or key not in KEYS:
        raise ValueError("unknown decision_key")
    if expected_revision is not None and (
            not isinstance(expected_revision, str) or not expected_revision):
        raise ValueError("expected_revision must be a nonempty revision string")
    for attempt in range(retries):
        store, version = _load_versioned()
        if expected_revision is not None and revision(key, store.get(key)) != expected_revision:
            raise StaleDecision("decision changed since it was loaded; reload before saving")
        store = deepcopy(store)
        state = set_decision(store, key, patch, now=now)
        try:
            storage.write_json_conditional(STORE_NAME, store, version)
            return state
        except storage.StorageConflict:
            if attempt == retries - 1:
                raise
    raise storage.StorageConflict(STORE_NAME)


def set_decision(store, key, patch, now=None):
    """Validate and update one decision. Risk acceptance is never allowed without expiry."""
    if not isinstance(key, str) or key not in KEYS:
        raise ValueError("unknown decision_key")
    if not isinstance(patch, dict):
        raise ValueError("decision update must be a JSON object")
    unknown = set(patch) - EDITABLE_FIELDS
    if unknown:
        raise ValueError("unsupported field(s): " + ", ".join(sorted(unknown)))
    _validate_fields(patch)
    now = now or datetime.now(timezone.utc)
    current = view_state(key, store.get(key), now=now)
    if current["data_error"]:
        raise ValueError(current["data_error"])
    current = {field: deepcopy(current[field]) for field in default_state(key)}
    candidate = deepcopy(current)

    for field in ("owner", "notes", "compensating_control"):
        if field in patch:
            candidate[field] = (patch[field] or "").strip()
    if "due_date" in patch:
        candidate["due_date"] = patch["due_date"] or None
    if "status" in patch:
        candidate["status"] = patch["status"]
    if "acceptance" in patch:
        candidate["acceptance"] = deepcopy(patch["acceptance"]) if patch["acceptance"] else None

    status = candidate["status"]
    _validate_requirements(candidate)
    if status == "Risk accepted":
        acceptance = candidate["acceptance"]
        if _elapsed(acceptance["expires_at"], "acceptance.expires_at", now):
            raise ValueError("acceptance.expires_at must be in the future")
        candidate["acceptance"] = {
            "rationale": acceptance["rationale"].strip(),
            "approved_by": acceptance["approved_by"].strip(),
            "expires_at": acceptance["expires_at"],
        }
    else:
        candidate["acceptance"] = None
    if status != "Compensating control":
        candidate["compensating_control"] = ""
    if status == "Deferred":
        if _elapsed(candidate["due_date"], "due_date", now):
            raise ValueError("a future due_date is required for Deferred")

    changes = []
    for field in ("status", "owner", "due_date", "notes", "compensating_control", "acceptance"):
        if candidate.get(field) != current.get(field):
            changes.append({"timestamp": now.isoformat(), "field": field,
                            "from": current.get(field), "to": candidate.get(field)})
    candidate["history"] = list(current.get("history") or []) + changes
    candidate["updated_at"] = now.isoformat()
    store[key] = candidate
    return candidate


def view_state(key, stored=None, now=None, failed_controls=None):
    """Add derived due/acceptance state without mutating the persistent record."""
    now = now or datetime.now(timezone.utc)
    if stored is None:
        state = default_state(key)
    elif not isinstance(stored, dict):
        state = default_state(key)
        state["_data_error"] = f"{key} must contain a JSON object"
    else:
        state = deepcopy(stored)
    baseline = default_state(key)
    for field, value in baseline.items():
        state.setdefault(field, deepcopy(value))
    errors = []
    try:
        _validate_fields(state)
        _validate_requirements(state)
    except ValueError as exc:
        errors.append(str(exc))
    if state["decision_key"] != key:
        errors.append("stored decision_key does not match its program")
    if state.get("_data_error"):
        errors.append(str(state["_data_error"]))
    acceptance = state.get("acceptance")
    if not isinstance(acceptance, dict):
        acceptance = {}
        state["acceptance"] = None
    elapsed = {}
    for field, value in (("due_date", state["due_date"]),
                         ("acceptance.expires_at", acceptance.get("expires_at"))):
        try:
            elapsed[field] = _elapsed(value, field, now)
        except ValueError as exc:
            elapsed[field] = False
            if str(exc) not in errors:
                errors.append(str(exc))
    state["data_error"] = "; ".join(errors) or None
    status = state["status"] if isinstance(state["status"], str) else None
    state["overdue"] = bool(elapsed["due_date"] and status not in
                           {"Verified", "False positive", "Risk accepted"})
    state["acceptance_expired"] = bool(
        status == "Risk accepted" and elapsed["acceptance.expires_at"])
    state["acceptance_expiring"] = False
    if status == "Risk accepted" and not state["data_error"] and not state["acceptance_expired"]:
        expiry = _parse_date(acceptance.get("expires_at"), "acceptance.expires_at")
        if expiry:
            value = acceptance["expires_at"]
            if len(value) == 10:
                state["acceptance_expiring"] = (
                    expiry.date() <= (now.astimezone(timezone.utc) + timedelta(days=7)).date())
            else:
                state["acceptance_expiring"] = expiry <= now + timedelta(days=7)
    state["persisted"] = stored is not None
    state["revision"] = revision(key, stored)
    state["evidence_conflict"] = bool(status == "Verified" and failed_controls)
    state["failed_controls"] = failed_controls
    if state["data_error"]:
        state["display_status"] = "Workflow data invalid"
    elif state["evidence_conflict"]:
        state["display_status"] = "Verification needs review"
    elif state["acceptance_expired"]:
        state["display_status"] = "Risk acceptance expired"
    else:
        state["display_status"] = state["status"]
    return state


def attention(states):
    """Count only active programs supplied by the evidence-aware caller."""
    return {
        "overdue": sum(bool(s["overdue"]) for s in states),
        "expiring": sum(bool(s["acceptance_expiring"]) for s in states),
        "expired": sum(bool(s["acceptance_expired"]) for s in states),
        "unassigned": sum(not isinstance(s["owner"], str) or not s["owner"].strip()
                          for s in states),
        "conflicting": sum(bool(s["evidence_conflict"]) for s in states),
    }
