"""
Unified data model — the common asset/entity schema written by all connectors.

Deterministic asset_id: derived from the strongest external_id (same order as
correlation priority); if none, a hash of type+name. This means the same real-world
entity gets the same id (or correlatable ids) across different scans and different sources.
"""
import hashlib

# External id keys aligned with correlation priority (strong → weak).
# NOTE: `purview_record_id` is NOT in the correlation priority (correlation.PRIORITY) →
# it is not a merge token; it's listed last only to give high-cardinality event entities
# (SENSITIVE_INTERACTION) a unique/deterministic asset_id (it never merges assets).
EXTERNAL_ID_KEYS = [
    "entra_app_id", "agent_identity_id", "agent_blueprint_id",
    "agent365_package_id", "agent365_asset_id", "manifest_id",
    "entra_object_id", "mdca_app_id", "purview_record_id",
]

# Field-availability states (mainly for Purview — a field missing from the API is never hidden).
AVAILABLE = "AVAILABLE"
NOT_PRESENT = "NOT_PRESENT"
NOT_EXPOSED_BY_API = "NOT_EXPOSED_BY_API"
NOT_LICENSED = "NOT_LICENSED"
UNKNOWN = "UNKNOWN"


def new_external_ids(**kw) -> dict:
    """Returns a dict containing every external id key (filled with None)."""
    return {k: kw.get(k) for k in EXTERNAL_ID_KEYS}


def _provisional_id(asset_type: str, ext: dict, display_name: str) -> str:
    """Produces a deterministic internal id from the strongest external id; else a type+name hash."""
    for key in EXTERNAL_ID_KEYS:
        if ext.get(key):
            return f"{key}:{ext[key]}"
    seed = f"{asset_type}|{(display_name or '').strip().lower()}"
    return "name:" + hashlib.sha1(seed.encode()).hexdigest()[:16]


def make_asset(asset_type, display_name, source, external_ids=None,
               first_seen=None, last_seen=None, **extra) -> dict:
    """Produces a unified asset record (shared fields + connector-specific `extra`)."""
    ext = new_external_ids(**(external_ids or {}))
    asset = {
        "asset_id": _provisional_id(asset_type, ext, display_name),
        "asset_type": asset_type,
        "display_name": display_name or "—",
        "external_ids": ext,
        "sources": [source],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "correlation_confidence": 100,   # single source → no correlation risk
    }
    asset.update(extra)
    return asset


def field(status=UNKNOWN, values=None):
    """Wraps fields that are/aren't in the API with an availability marker."""
    return {"status": status, "values": values if values is not None else []}


def raw_reference(source, **kw) -> dict:
    """For keeping raw definitions that couldn't be parsed, without losing them."""
    return {"source": source, **kw}
