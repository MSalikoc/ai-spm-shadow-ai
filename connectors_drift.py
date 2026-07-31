"""
Connector-sourced change tracking (Step 8) — Agent 365 package, Entra Agent Identity,
Defender/MDCA Shadow AI, and Purview sensitive interaction events.

Runs PARALLEL to the existing `drift.py` engine (classic Entra/OAuth application drift)
— `drift.py` is NOT MODIFIED AT ALL. Uses separate snapshot/changes keys
(`connectors_snapshot.json` / `connectors_changes.json`) so the two different schemas
(classic `findings` list vs. the unified connector asset/profile model) don't mix, and
the existing Entra drift flow (criterion: first scan is baseline, no changes produced)
is never put at risk. The first run (no prev snapshot) follows the same rule: baseline,
NO events.

`process(result)`'s input is `pipeline.run_connectors()`'s output; if `result is None`
(no connector flag is on) it reads/writes nothing — no-op.
"""
import hashlib
from datetime import datetime, timedelta, timezone

import storage

IMPORTANCE = {
    "NEW_AGENT_365_PACKAGE": "Medium", "AGENT_365_PACKAGE_BLOCKED": "High",
    "AGENT_365_PACKAGE_UNBLOCKED": "Info",
    "NEW_AGENT_IDENTITY": "Medium",
    "AGENT_IDENTITY_DISABLED": "Low", "AGENT_IDENTITY_ENABLED": "Info",
    "AGENT_OWNER_CHANGED": "Medium", "AGENT_SPONSOR_CHANGED": "Medium",
    "NEW_UNSANCTIONED_AI_APP": "High", "AI_APP_SANCTIONED": "Info",
    "NEW_SENSITIVE_INTERACTION": "Info",
    "SENSITIVE_INTERACTION_BLOCKED": "Info", "SENSITIVE_INTERACTION_ALLOWED": "High",
    "PURVIEW_COVERAGE_CHANGED": "High",
    "DATA_SOURCE_CONNECTED": "Info", "DATA_SOURCE_DISCONNECTED": "High",
}

_CONNECTED_LIKE = {"CONNECTED", "PARTIALLY_CONNECTED", "NO_DATA"}
_MAX_INTERACTION_IDS = 5000       # upper bound so the snapshot doesn't grow unbounded (see process())


def _ev(now, ctype, aid, name, old, new, desc):
    cid = hashlib.sha1(f"{ctype}|{aid}|{old}|{new}|{now.isoformat()}".encode()).hexdigest()[:12]
    return {"change_id": cid, "change_type": ctype, "asset_id": aid, "asset_name": name,
            "timestamp": now.isoformat(), "old_value": old, "new_value": new,
            "importance": IMPORTANCE.get(ctype, "Info"), "description": desc}


# ---------- snapshot ----------
def snapshot(result: dict) -> dict:
    """Produces a JSON-serializable snapshot from `pipeline.run_connectors()` output."""
    assets = result.get("assets", [])
    packages, identities, apps = {}, {}, {}
    interaction_ids = []

    for a in assets:
        aid = a.get("asset_id")
        if a.get("agent365"):
            p = a["agent365"]
            packages[aid] = {"name": a.get("display_name"), "blocked": bool(p.get("blocked")),
                             "build_type": p.get("build_type")}
        if a.get("agent_identity"):
            ai = a["agent_identity"]
            identities[aid] = {
                "name": a.get("display_name"), "enabled": ai.get("account_enabled"),
                "owners": sorted({o.get("id") or o.get("upn") or "" for o in ai.get("owners", [])}),
                "sponsors": sorted({s.get("id") or s.get("upn") or "" for s in ai.get("sponsors", [])}),
            }
        if a.get("mdca"):
            apps[aid] = {"name": a.get("display_name"),
                        "sanctioned_state": a["mdca"].get("sanctioned_state")}
        if a.get("interaction"):
            rid = a["interaction"].get("interaction_id")
            if rid:
                interaction_ids.append(rid)

    return {
        "packages": packages, "identities": identities, "apps": apps,
        "interaction_ids": sorted(set(interaction_ids))[-_MAX_INTERACTION_IDS:],
        "connector_status": {name: h.get("status") for name, h in result.get("health", {}).items()},
        # Keep only the minimal fields needed to produce new interaction events.
        # NOTE: `raw_content` (prompt/response when STORE_RAW_AI_CONTENT=true) is
        # DELIBERATELY not copied — this snapshot is written to persistent storage
        # (Blob), raw content is never retained.
        "_interactions": {
            a["interaction"]["interaction_id"]: {
                "app_host": a["interaction"].get("app_host"),
                "user": a["interaction"].get("user"),
                "direction": a["interaction"].get("direction"),
                "sensitive_info_types": a["interaction"].get("sensitive_info_types") or [],
                "sensitivity_label_id": a["interaction"].get("sensitivity_label_id"),
            }
            for a in assets if a.get("interaction") and a["interaction"].get("interaction_id")
        },
    }


def diff(prev: dict, cur: dict, now=None) -> list:
    now = now or datetime.now(timezone.utc)
    events = []

    # --- Agent 365 packages ---
    p_prev, p_cur = prev.get("packages", {}), cur.get("packages", {})
    for aid in set(p_cur) - set(p_prev):
        c = p_cur[aid]
        events.append(_ev(now, "NEW_AGENT_365_PACKAGE", aid, c["name"], None, c["name"],
                          f"New Agent 365 package discovered: {c['name']}"))
    for aid in set(p_cur) & set(p_prev):
        p, c = p_prev[aid], p_cur[aid]
        if c["blocked"] and not p["blocked"]:
            events.append(_ev(now, "AGENT_365_PACKAGE_BLOCKED", aid, c["name"], False, True,
                              f"Agent 365 package blocked: {c['name']}"))
        elif p["blocked"] and not c["blocked"]:
            events.append(_ev(now, "AGENT_365_PACKAGE_UNBLOCKED", aid, c["name"], True, False,
                              f"Agent 365 package unblocked: {c['name']}"))

    # --- Entra Agent Identity ---
    i_prev, i_cur = prev.get("identities", {}), cur.get("identities", {})
    for aid in set(i_cur) - set(i_prev):
        c = i_cur[aid]
        events.append(_ev(now, "NEW_AGENT_IDENTITY", aid, c["name"], None, c["name"],
                          f"New Entra Agent Identity discovered: {c['name']}"))
    for aid in set(i_cur) & set(i_prev):
        p, c = i_prev[aid], i_cur[aid]
        if p["enabled"] is True and c["enabled"] is False:
            events.append(_ev(now, "AGENT_IDENTITY_DISABLED", aid, c["name"], True, False,
                              f"Agent identity disabled: {c['name']}"))
        elif p["enabled"] is False and c["enabled"] is True:
            events.append(_ev(now, "AGENT_IDENTITY_ENABLED", aid, c["name"], False, True,
                              f"Agent identity re-enabled: {c['name']}"))
        if set(c["owners"]) != set(p["owners"]):
            events.append(_ev(now, "AGENT_OWNER_CHANGED", aid, c["name"], p["owners"], c["owners"],
                              f"{c['name']} owner list changed"))
        if set(c["sponsors"]) != set(p["sponsors"]):
            events.append(_ev(now, "AGENT_SPONSOR_CHANGED", aid, c["name"], p["sponsors"], c["sponsors"],
                              f"{c['name']} sponsor list changed"))

    # --- Defender/MDCA Shadow AI apps (sanctioned/unsanctioned status) ---
    a_prev, a_cur = prev.get("apps", {}), cur.get("apps", {})
    for aid, c in a_cur.items():
        p = a_prev.get(aid)
        if p is None:
            if c["sanctioned_state"] == "unsanctioned":
                events.append(_ev(now, "NEW_UNSANCTIONED_AI_APP", aid, c["name"], None, "unsanctioned",
                                  f"New unsanctioned AI application: {c['name']}"))
            continue
        if c["sanctioned_state"] != p["sanctioned_state"]:
            if c["sanctioned_state"] == "unsanctioned":
                events.append(_ev(now, "NEW_UNSANCTIONED_AI_APP", aid, c["name"],
                                  p["sanctioned_state"], "unsanctioned",
                                  f"{c['name']} became unsanctioned"))
            elif c["sanctioned_state"] == "sanctioned":
                events.append(_ev(now, "AI_APP_SANCTIONED", aid, c["name"],
                                  p["sanctioned_state"], "sanctioned",
                                  f"{c['name']} became organizationally sanctioned"))

    # --- Purview sensitive interactions (only NEW + sensitive-content records) ---
    new_ids = set(cur.get("interaction_ids", [])) - set(prev.get("interaction_ids", []))
    interactions = cur.get("_interactions", {})
    for rid in sorted(new_ids):
        it = interactions.get(rid)
        if not it or not (it.get("sensitive_info_types") or it.get("sensitivity_label_id")):
            continue           # not drift-worthy without sensitive content
        direction = it.get("direction")
        name = f"{it.get('app_host') or '—'} — {it.get('user') or 'unknown'}"
        if direction == "BLOCKED":
            events.append(_ev(now, "SENSITIVE_INTERACTION_BLOCKED", rid, name, None, direction,
                              f"Sensitive data blocked by DLP: {name}"))
        elif direction == "ALLOWED":
            events.append(_ev(now, "SENSITIVE_INTERACTION_ALLOWED", rid, name, None, direction,
                              f"Sensitive data matched DLP but was allowed: {name}"))
        else:
            events.append(_ev(now, "NEW_SENSITIVE_INTERACTION", rid, name, None, direction,
                              f"New AI interaction containing sensitive data: {name}"))

    # --- Data source connection status (coverage) ---
    s_prev, s_cur = prev.get("connector_status", {}), cur.get("connector_status", {})
    for name in set(s_cur):
        p_status, c_status = s_prev.get(name), s_cur.get(name)
        if p_status is None or p_status == c_status:
            continue
        p_ok, c_ok = p_status in _CONNECTED_LIKE, c_status in _CONNECTED_LIKE
        if p_ok == c_ok:
            continue
        ctype = "PURVIEW_COVERAGE_CHANGED" if name in ("purview_audit", "purview_dspm_import") else (
            "DATA_SOURCE_CONNECTED" if c_ok else "DATA_SOURCE_DISCONNECTED")
        events.append(_ev(now, ctype, name, name, p_status, c_status,
                          f"{name}: {p_status} → {c_status}"))
    return events


# ---------- persistence (same pattern as drift.py, separate file names) ----------
def process(result, now=None) -> list:
    """
    Computes the diff, updates connectors_snapshot.json/connectors_changes.json.
    If `result is None` (connectors disabled), reads/writes NOTHING — no-op.
    """
    if result is None:
        return []
    now = now or datetime.now(timezone.utc)
    prev = storage.read_json("connectors_snapshot.json")
    cur = snapshot(result)
    events = [] if prev is None else diff(prev, cur, now)   # baseline: no changes
    storage.write_json("connectors_snapshot.json", cur)
    if events:
        log = storage.read_json("connectors_changes.json") or {"events": []}
        log["events"] = (events + log["events"])[:1000]
        storage.write_json("connectors_changes.json", log)
    return events


def recent(days=14, now=None) -> list:
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    log = storage.read_json("connectors_changes.json") or {"events": []}
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
    """Executive summary lines (for the weekly digest — same style as drift.executive_summary)."""
    lines = []

    def cnt(t):
        return sum(1 for e in events if e["change_type"] == t)

    if cnt("NEW_UNSANCTIONED_AI_APP"):
        lines.append(f"{cnt('NEW_UNSANCTIONED_AI_APP')} new unsanctioned AI applications detected.")
    if cnt("SENSITIVE_INTERACTION_ALLOWED"):
        lines.append(f"{cnt('SENSITIVE_INTERACTION_ALLOWED')} sensitive data interactions matched DLP "
                     "but were not blocked.")
    if cnt("SENSITIVE_INTERACTION_BLOCKED"):
        lines.append(f"{cnt('SENSITIVE_INTERACTION_BLOCKED')} sensitive data interactions were blocked by DLP.")
    if cnt("NEW_AGENT_365_PACKAGE"):
        lines.append(f"{cnt('NEW_AGENT_365_PACKAGE')} new Agent 365 packages registered.")
    if cnt("NEW_AGENT_IDENTITY"):
        lines.append(f"{cnt('NEW_AGENT_IDENTITY')} new Entra Agent Identities discovered.")
    if cnt("AGENT_OWNER_CHANGED") or cnt("AGENT_SPONSOR_CHANGED"):
        lines.append(f"{cnt('AGENT_OWNER_CHANGED') + cnt('AGENT_SPONSOR_CHANGED')} agent identities had "
                     "an owner/sponsor change.")
    disc = [e for e in events if e["change_type"] in ("DATA_SOURCE_DISCONNECTED", "PURVIEW_COVERAGE_CHANGED")
            and e.get("new_value") not in _CONNECTED_LIKE]
    if disc:
        lines.append(f"{len(disc)} data source connections were lost — coverage was affected.")
    return lines
