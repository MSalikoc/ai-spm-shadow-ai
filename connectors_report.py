"""
Microsoft AI Data Sources — unified assessment/report (Step 7).

`report.py` (the existing Entra/OAuth dashboard) is NOT MODIFIED AT ALL; this module
produces a completely separate, standalone page (in the same CSS/theme language —
`report.CSS` is imported, not copied; the tab-switching JS pattern is also rebuilt here
— inspired by report.py, copied not imported). Input is the result dict returned by
`pipeline.run_connectors()` (assets/coverage/health/counts/profiles/portfolio) — if the
connectors are disabled via env flag, this module is never called.

15 sections (assessment(result) dict keys):
 1. executive            — portfolio summary (apps_with_sensitive_data, affected_users, findings…)
 2. data_source_coverage — health/permission/license status of the 5 connectors (honest, no fabrication)
 3. sensitive_exposure   — "Applications with Sensitive Data Exposure" table (Step 7 acceptance criterion)
 4. agent_identities      — Entra Agent ID inventory (owner/sponsor/permission breakdown)
 5. agent365_packages     — Agent 365 package inventory (build_type/blocked/scope)
 6. shadow_ai_usage       — AI apps discovered by Defender/MDCA (sanctioned/upload/risk)
 7. sensitive_interactions— Purview audit summary (blocked/allowed/SIT)
 8. findings              — evaluate_findings output, ordered by importance
 9. direction_analysis    — ACCESSED/SHARED/UPLOADED/GENERATED/BLOCKED/ALLOWED/UNKNOWN breakdown
10. correlation_quality   — confidence distribution + per-source uncorrelated counters
11. application_detail    — "Sensitive Data" tab content per app (Step 7 acceptance criterion)
12. agent_detail          — "Data Access" tab content per identity (owners/sponsors/perms)
13. sit_distribution      — estate-wide SIT/label distribution
14. users_and_groups      — most-affected users + group memberships without owner/sponsor
15. known_gaps            — fields not in the API + known correlation gaps (honest coverage)

The HTML view (html_string) builds a multi-page dashboard in the pattern of Microsoft's
Zero Trust Assessment tool:
  - Overview   : hero (tenant/KPI/finding donut) + flow diagrams (for Shadow AI and Agent
                 Identity) + the top 5 highest-scored items estate-wide.
  - Agents     : Agent 365 packages + Entra Agent Identities (assessment table).
  - Shadow AI  : apps discovered by Defender/MDCA (with user/device/IP COUNTS —
                 individual identity lists are not in the API, see known_gaps).
  - Sensitive Data: sensitive data exposure table + Purview interaction log.
  - Findings   : findings.
  - Gaps       : known gaps / API limitations.
Every item (agent/app/finding) gets a 0-100 TRANSPARENT RISK SCORE — same philosophy as
`scoring.py`'s "additive score + reason chain": every score component is shown as
"+N — reason", the score is never fabricated. Clicking a row opens a detail panel:
facts → Risk Score + reason list → Result → What was checked → Remediation action.
"""
import html
import json
from datetime import datetime, timezone

import charts
from connectors.agent365 import metrics as agent365_metrics
from connectors.base import ConnectorStatus
from connectors.defender_cloud_apps import metrics as mdca_metrics
from connectors.entra_agent_id import metrics as entra_agent_metrics
from connectors.purview_audit import metrics as purview_metrics
from report import CSS

_CONNECTOR_INFO = {
    "agent365": ("Microsoft Agent 365", "CopilotPackages.Read.All"),
    "entra_agent_id": ("Microsoft Entra Agent ID", "Application.Read.All + Directory.Read.All"),
    "defender_cloud_apps": ("Defender for Cloud Apps (Shadow AI)", "CloudApp-Discovery.Read.All"),
    "purview_audit": ("Microsoft Purview Audit", "AuditLogsQuery.Read.All"),
    # NOTE: "purview_dspm_import" is deliberately NOT here — it isn't shown in the
    # dashboard's coverage list. It isn't a real connector, it's a file-path-based
    # manual import adapter (see connectors/purview_dspm_import.py): on its own it
    # always shows NOT_CONFIGURED and can't be enabled by itself (requires a Kudu file
    # upload), so it's hidden here to avoid confusion. The `PURVIEW_DSPM_IMPORT_PATH`
    # env var still works — it remains usable silently for advanced users, it just
    # doesn't appear as a row in the coverage/gaps list.
}

_SOURCE_LABEL = {
    "AGENT_365": "Agent 365", "ENTRA_AGENT_ID": "Entra Agent ID",
    "DEFENDER_CLOUD_APPS": "Defender for Cloud Apps", "PURVIEW_AUDIT": "Purview Audit",
    "PURVIEW_DSPM_EXPORT": "Purview DSPM", "ENTRA_APPS": "Entra OAuth (classic)",
}


def _sources_label(sources) -> str:
    return ", ".join(_SOURCE_LABEL.get(s, s) for s in (sources or [])) or "—"


def _fmt_names(names, limit=6) -> str:
    names = [n for n in (names or []) if n]
    if not names:
        return "—"
    shown = names[:limit]
    rest = len(names) - len(shown)
    return ", ".join(shown) + (f" (+{rest} more)" if rest > 0 else "")


def assessment(result: dict, now=None) -> dict:
    """
    Produces the 15-section assessment dict from `pipeline.run_connectors()` output.

    NOTE: when correlation merges assets from different sources, the merged asset's
    `asset_type` is inherited from the first member (by index order) — e.g. an Entra
    Agent Identity correlated via the same entra_app_id as an Agent365 package may show
    `asset_type=AI_AGENT` on the merged asset, but the `agent_identity` sub-dict is still
    carried along. That's why filtering here (and in the connector `metrics()` functions)
    is done by the PRESENCE of the connector-specific sub-dict key, NOT by `asset_type`
    equality.
    """
    now = now or datetime.now(timezone.utc)
    assets = result.get("assets", [])
    coverage = result.get("coverage", {})
    health = result.get("health", {})
    profiles = result.get("profiles", [])
    portfolio = result.get("portfolio", {})

    agent365 = [a for a in assets if a.get("agent365")]
    identities = [a for a in assets if a.get("agent_identity")]
    blueprints = [a for a in assets if a.get("agent_blueprint")]
    ai_apps = [a for a in assets if a.get("mdca")]
    interactions = [a for a in assets if a.get("interaction")]

    return {
        "executive": _executive(portfolio, health),
        "data_source_coverage": _coverage_section(coverage, health),
        "sensitive_exposure": _sensitive_exposure(profiles),
        "agent_identities": _agent_identities(identities, entra_agent_metrics(assets)),
        "agent365_packages": _agent365_section(agent365, agent365_metrics(assets)),
        "shadow_ai_usage": _shadow_ai(ai_apps, mdca_metrics(assets)),
        "sensitive_interactions": _sensitive_interactions(interactions, purview_metrics(assets)),
        "findings": _findings(profiles),
        "direction_analysis": _direction_analysis(profiles),
        "correlation_quality": _correlation_quality(assets),
        "application_detail": _application_detail(profiles),
        "agent_detail": _agent_detail(identities, blueprints),
        "sit_distribution": _sit_distribution(profiles),
        "users_and_groups": _users_and_groups(profiles, identities),
        "known_gaps": _known_gaps(coverage),
        "_generated_at": now.isoformat(),
    }


# ---------- section builders ----------
def _executive(portfolio, health):
    connected = sum(1 for h in health.values() if h.get("status") == ConnectorStatus.CONNECTED)
    return {**portfolio, "connectors_connected": connected, "connectors_total": len(health)}


def _coverage_section(coverage, health):
    rows = []
    for name, (label, perm) in _CONNECTOR_INFO.items():
        h = health.get(name, {})
        rows.append({
            "name": name, "label": label, "permission": perm,
            "status": h.get("status", ConnectorStatus.NOT_CONFIGURED),
            "count": h.get("count", 0), "error": h.get("error"),
            "coverage": coverage.get(name, {}),
        })
    return rows


def _sensitive_exposure(profiles):
    rows = [p for p in profiles if p["sensitive_data_summary"]["window_30d"]["sensitive"] > 0]
    return sorted(rows, key=lambda p: p["sensitive_data_summary"]["window_30d"]["sensitive"],
                 reverse=True)


def _agent_identities(identities, m):
    rows = [{
        "display_name": a.get("display_name"),
        "enabled": (a.get("agent_identity") or {}).get("account_enabled"),
        "owners": [o.get("upn") or o.get("display_name")
                   for o in (a.get("agent_identity") or {}).get("owners", [])],
        "sponsors": [s.get("upn") or s.get("display_name")
                     for s in (a.get("agent_identity") or {}).get("sponsors", [])],
        "app_only_perms": len((a.get("agent_identity") or {}).get("application_permissions", [])),
        "delegated_perms": len((a.get("agent_identity") or {}).get("delegated_permissions", [])),
        "app_only_perm_names": [p.get("resource_display_name") or p.get("resource_id") or "—"
                                for p in (a.get("agent_identity") or {}).get("application_permissions", [])],
        "delegated_perm_names": [s for g in (a.get("agent_identity") or {}).get("delegated_permissions", [])
                                 for s in (g.get("scopes") or [])],
        "blueprint_id": (a.get("related") or {}).get("blueprint_id")
                        or (a.get("agent_identity") or {}).get("blueprint_id"),
        "entra_app_id": (a.get("external_ids") or {}).get("entra_app_id"),
        "sources": a.get("sources") or [],
        "correlation_confidence": a.get("correlation_confidence"),
    } for a in identities]
    return {"metrics": m, "identities": rows}


def _agent365_section(agents, m):
    rows = [{
        "display_name": a.get("display_name"),
        "build_type": (a.get("agent365") or {}).get("build_type"),
        "blocked": (a.get("agent365") or {}).get("blocked"),
        "available_to": (a.get("agent365") or {}).get("available_to"),
        "deployed_to": (a.get("agent365") or {}).get("deployed_to"),
        "entra_app_id": (a.get("external_ids") or {}).get("entra_app_id"),
        "sources": a.get("sources") or [],
        "correlation_confidence": a.get("correlation_confidence"),
    } for a in agents]
    return {"metrics": m, "packages": rows}


def _shadow_ai(apps, m):
    rows = sorted([{
        "display_name": a.get("display_name"),
        "vendor": (a.get("mdca") or {}).get("vendor") or a.get("publisher") or "",
        "category": (a.get("mdca") or {}).get("category") or "",
        "sanctioned_state": (a.get("mdca") or {}).get("sanctioned_state"),
        "users": (a.get("mdca") or {}).get("users", 0),
        "devices": (a.get("mdca") or {}).get("devices", 0),
        "ip_addresses": (a.get("mdca") or {}).get("ip_addresses", 0),
        "transactions": (a.get("mdca") or {}).get("transactions", 0),
        "uploaded_bytes": (a.get("mdca") or {}).get("uploaded_bytes", 0),
        "downloaded_bytes": (a.get("mdca") or {}).get("downloaded_bytes", 0),
        "risk_score": (a.get("mdca") or {}).get("risk_score"),
        "data_sensitivity": (a.get("mdca") or {}).get("data_sensitivity"),
        "last_seen": a.get("last_seen"),
    } for a in apps], key=lambda r: r["uploaded_bytes"] + r["downloaded_bytes"], reverse=True)
    return {"metrics": m, "applications": rows}


def _sensitive_interactions(interactions, m):
    return {"metrics": m, "sample": [{
        "user": (i.get("interaction") or {}).get("user"),
        "app_host": (i.get("interaction") or {}).get("app_host"),
        "direction": (i.get("interaction") or {}).get("direction"),
        "sits": [s.get("name") for s in (i.get("interaction") or {}).get("sensitive_info_types", [])],
        "timestamp": (i.get("interaction") or {}).get("timestamp"),
    } for i in interactions[:25]]}


def _findings(profiles):
    findings = [dict(f, app_key=p["app_key"]) for p in profiles for f in p["findings"]]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(findings, key=lambda f: order.get(f["severity"], 9))


def _direction_analysis(profiles):
    totals = {}
    for p in profiles:
        for d, n in p["directions"].items():
            totals[d] = totals.get(d, 0) + n
    return totals


def _correlation_quality(assets):
    buckets = {"high_98_100": 0, "medium_65_97": 0, "name_only_or_single": 0}
    uncorrelated_by_source = {}
    for a in assets:
        conf = a.get("correlation_confidence")
        if conf is None:
            continue
        if conf >= 98:
            buckets["high_98_100"] += 1
        elif conf >= 65:
            buckets["medium_65_97"] += 1
        else:
            buckets["name_only_or_single"] += 1
        if len(a.get("sources", [])) == 1 and conf == 100:
            for s in a["sources"]:
                uncorrelated_by_source[s] = uncorrelated_by_source.get(s, 0) + 1
    return {"confidence_buckets": buckets, "single_source_by_connector": uncorrelated_by_source}


def _application_detail(profiles):
    """Content of the Application Detail 'Sensitive Data' tab (Step 7 acceptance criterion)."""
    return [{
        "app_key": p["app_key"], "display_name": p["display_name"],
        "matched_to_inventory": p["matched_to_inventory"],
        "sanctioned_state": p.get("sanctioned_state"),
        "sensitive_data_summary": p["sensitive_data_summary"],
        "sit_distribution": p["sit_distribution"],
        "directions": p["directions"],
        "findings": p["findings"],
    } for p in profiles]


def _agent_detail(identities, blueprints):
    """Content of the Agent Detail 'Data Access' tab (owners/sponsors/perms/groups)."""
    bp_by_id = {b["asset_id"]: b for b in blueprints}
    rows = []
    for a in identities:
        ai = a.get("agent_identity") or {}
        rel = a.get("related") or {}
        bp = bp_by_id.get(rel.get("blueprint_asset_id"))
        rows.append({
            "display_name": a.get("display_name"),
            "account_enabled": ai.get("account_enabled"),
            "owners": ai.get("owners", []),
            "sponsors": ai.get("sponsors", []),
            "application_permissions": ai.get("application_permissions", []),
            "delegated_permissions": ai.get("delegated_permissions", []),
            "group_memberships": ai.get("group_memberships", []),
            "blueprint": {"display_name": bp.get("display_name")} if bp else None,
        })
    return rows


def _sit_distribution(profiles):
    agg = {}
    for p in profiles:
        for sit, n in p["sit_distribution"].items():
            agg[sit] = agg.get(sit, 0) + n
    return dict(sorted(agg.items(), key=lambda kv: kv[1], reverse=True))


def _users_and_groups(profiles, identities):
    user_counts = {}
    for p in profiles:
        for u in p["affected_users"]:
            user_counts[u] = user_counts.get(u, 0) + 1
    top_users = sorted(user_counts.items(), key=lambda kv: kv[1], reverse=True)[:15]
    groups_without_owner = [
        {"display_name": a.get("display_name"),
         "groups": [g.get("display_name") for g in (a.get("agent_identity") or {}).get("group_memberships", [])]}
        for a in identities if not (a.get("agent_identity") or {}).get("owners")
        and (a.get("agent_identity") or {}).get("group_memberships")
    ]
    return {"top_affected_users": top_users, "identities_without_owner_but_in_groups": groups_without_owner}


def _known_gaps(coverage):
    gaps = []
    for name, (label, _) in _CONNECTOR_INFO.items():
        if not coverage.get(name):
            gaps.append(f"{label}: no coverage data (connector never ran).")
        elif coverage[name].get("status") in (ConnectorStatus.NOT_CONFIGURED,):
            gaps.append(f"{label}: not connected — there is NO inventory/sensitivity data for this "
                        f"source (no fabricated inventory was generated; honestly empty).")
    gaps.append("Purview audit's sensitivity_label_name is not exposed by the API "
               "(field=NOT_EXPOSED_BY_API); only label_id is available.")
    gaps.append("MDCA upload volume alone does not count as 'sensitive sharing'; without Purview "
               "correlation, data_sensitivity stays UNDETERMINED_REQUIRES_PURVIEW.")
    gaps.append("agent_blueprint_id is NOT a merge token (relate-not-merge); multiple identities "
               "derived from the same blueprint remain separate assets.")
    gaps.append("Defender for Cloud Apps (aggregatedAppsDetails) only returns user/device/IP "
               "COUNTS — individual user/device/IP identity is NOT in this API; so the "
               "'which user/device' question can only be answered via Purview interactions "
               "(which carry real user identity).")
    return gaps


# ---------- JSON output ----------
def json_string(result: dict, now=None) -> str:
    return json.dumps(assessment(result, now), ensure_ascii=False, indent=2, default=str)


# ---------- shared HTML helpers ----------
# Risk tiers here are the same status scale as report.py's severity levels, one step
# coarser: high/medium/low map onto Critical/Medium/Low, and info stays neutral ink.
_SEV = {"high": charts.SEVERITY["Critical"], "medium": charts.SEVERITY["Medium"],
        "low": charts.SEVERITY["Low"], "info": "#6b7280"}
_RISK_LABEL = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
_RISK_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}  # for table sorting


def _risk_tier(score):
    """Score → risk tier. Single source of truth: risk_label is ALWAYS derived from score."""
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def _esc(s):
    return html.escape(str(s)) if s is not None else "—"


def _status_color(status):
    return {ConnectorStatus.CONNECTED: "#2e8b57", ConnectorStatus.PARTIALLY_CONNECTED: "#b8860b",
           ConnectorStatus.NOT_CONFIGURED: "#6b7280", ConnectorStatus.PERMISSION_MISSING: "#c0392b",
           ConnectorStatus.LICENSE_MISSING: "#c0392b", ConnectorStatus.NO_DATA: "#6b7280",
           ConnectorStatus.API_UNAVAILABLE: "#d35400", ConnectorStatus.ERROR: "#c0392b"}.get(status, "#6b7280")


def _coverage_html(rows):
    items = "".join(
        f'<li><span class="dot" style="background:{_status_color(r["status"])}"></span>'
        f'<b>{_esc(r["label"])}</b> — {_esc(r["status"])} · {_esc(r["count"])} assets '
        f'· <span style="color:var(--muted)">{_esc(r["permission"])}</span></li>'
        for r in rows)
    return f'<ul class="conn">{items}</ul>'


def _table(headers, rows_html, empty_msg):
    if not rows_html:
        return f'<div class="empty">{_esc(empty_msg)}</div>'
    ths = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    return (f'<div class="c-tbl-wrap"><table class="c-tbl"><thead><tr>{ths}</tr></thead>'
           f'<tbody>{"".join(rows_html)}</tbody></table></div>')


def _tags(values):
    spans = [f'<span class="c-tag">{_esc(v)}</span>' for v in values]
    return "".join(spans) or "—"


def _interactions_table(sample):
    trs = [
        f'<tr><td class="c-num">{_esc(i.get("timestamp"))}</td><td class="c-name">{_esc(i.get("app_host"))}</td>'
        f'<td>{_esc(i.get("user"))}</td><td><span class="c-tag">{_esc(i.get("direction"))}</span></td>'
        f'<td>{_tags(i.get("sits") or [])}</td></tr>'
        for i in sample]
    return _table(["Time", "Application", "User", "Direction", "Data type"], trs,
                 "No sensitive interactions in Purview (or the source is not connected).")


# ---------- helpers reusing the classic dashboard's (report.py) visual language ----------
def _donut(segments, size=170, stroke=26, center_label="Finding"):
    return charts.donut(segments, center_label=center_label, size=size, stroke=stroke)


def _bars(rows, maxv=None):
    """rows: [(label, sublabel, value, color)] → ranked horizontal bars."""
    return charts.hbar(rows)


# ---------- analytical charts over the correlated estate ----------
# Kept short enough to survive the bar chart's label column without being clipped.
_DIRECTION_LABEL = {
    "BLOCKED": "Blocked by DLP", "ALLOWED": "Allowed despite DLP",
    "ACCESSED": "Accessed org data", "SHARED": "Shared to AI app",
    "UPLOADED": "Uploaded", "GENERATED": "Generated", "OBSERVED": "Observed",
    "UNKNOWN_DIRECTION": "Direction unknown",
}
# Direction is an outcome scale, not a set of peer categories: DLP blocking sensitive
# content is the good end, DLP matching it and allowing it through is the bad end, and
# data leaving the tenant sits between. So it takes the status palette rather than
# categorical slots — which also avoids putting a categorical green ("Uploaded") right
# beside the status green ("Blocked"), where the two read as the same outcome.
_DIRECTION_COLOR = {
    "BLOCKED": charts.SEVERITY["Low"],
    "OBSERVED": "#6b7280",
    "GENERATED": "#6b7280",
    "ACCESSED": charts.SEVERITY["Medium"],
    "UPLOADED": charts.SEVERITY["High"],
    "SHARED": charts.SEVERITY["High"],
    "ALLOWED": charts.SEVERITY["Critical"],
    "UNKNOWN_DIRECTION": "#6b7280",
}


def _direction_chart(directions: dict) -> str:
    """
    What actually happened to sensitive data, worst outcome first — so the row that
    needs attention is the one at the top, rather than whichever happens to be largest.
    """
    order = ["ALLOWED", "SHARED", "UPLOADED", "ACCESSED", "GENERATED", "OBSERVED",
             "UNKNOWN_DIRECTION", "BLOCKED"]
    rank = {d: i for i, d in enumerate(order)}
    rows = [(_DIRECTION_LABEL.get(d, d), "", n, _DIRECTION_COLOR.get(d, "#6b7280"))
            for d, n in sorted(directions.items(), key=lambda kv: (rank.get(kv[0], 99), -kv[1]))
            if n]
    if not rows:
        return '<div class="empty">No interaction directions recorded yet.</div>'
    return charts.hbar(rows, unit=" interactions")


def _sit_chart(sit_distribution: dict, top: int = 8) -> str:
    """Which sensitive information types are actually reaching AI apps."""
    # Sorted here rather than trusting the caller: the fold only means "the small ones"
    # if the list is actually in descending order.
    ranked = sorted(((k, v) for k, v in sit_distribution.items() if v and v > 0),
                    key=lambda kv: -kv[1])
    if not ranked:
        return '<div class="empty">No sensitive information types detected.</div>'
    items = [(name, n, charts.cat(i)) for i, (name, n) in enumerate(ranked[:top])]
    tail = sum(n for _, n in ranked[top:])
    if tail:
        items.append((f"Other ({len(ranked) - top} types)", tail, charts.cat(top)))
    return charts.treemap(items, height=200)


def _shadow_traffic_chart(apps, top: int = 8) -> str:
    """Upload volume by discovered app — where data is actually leaving."""
    ranked = sorted((a for a in apps if a.get("uploaded_bytes")),
                    key=lambda a: -a["uploaded_bytes"])[:top]
    if not ranked:
        return '<div class="empty">No upload volume reported by Defender for Cloud Apps.</div>'
    rows = [(a.get("display_name") or "—", _fmt_bytes(a["uploaded_bytes"]),
             round(a["uploaded_bytes"] / 1_048_576, 1),
             charts.severity_color(_mdca_risk_level(a.get("risk_score"))))
            for a in ranked]
    return charts.hbar(rows, unit=" MB")


def _mdca_risk_level(score) -> str:
    """
    MDCA scores run 0-10 where LOW means risky — the inverse of every other score on
    these pages. Converting here keeps the inversion in one place.
    """
    if not isinstance(score, int):
        return "Low"
    return ("Critical" if score <= 3 else "High" if score <= 5
            else "Medium" if score <= 7 else "Low")


def _shadow_risk_scatter(apps) -> str:
    """
    Discovered Shadow AI by reach against risk, the same triage read as the core
    dashboard so both pages are looked at the same way. Dot size is upload volume,
    because a widely-used app that also uploads is the one to look at first.
    """
    pts = []
    for a in apps:
        score = a.get("risk_score")
        risk_0_100 = (10 - score) * 10 if isinstance(score, int) else 50
        pts.append((a.get("display_name") or "—", risk_0_100, a.get("users", 0) or 0,
                    _mdca_risk_level(score),
                    max(1, round((a.get("uploaded_bytes") or 0) / 1_048_576))))
    return charts.risk_scatter(pts)


def _analysis_cards(a: dict, shadow_apps) -> str:
    """
    The four charts that summarise the correlated estate. Each one is dropped rather
    than drawn empty when its source connector has no data, so a tenant without Purview
    does not get a page of blank frames.
    """
    cards = []
    directions = a.get("direction_analysis") or {}
    if any(directions.values()):
        cards.append(
            '<div class="card"><h3>What happened to sensitive data</h3>'
            f'{_direction_chart(directions)}'
            '<p class="c-note">Blocked is the good outcome. Allowed means DLP matched '
            'sensitive content and let it through.</p></div>')

    sits = a.get("sit_distribution") or {}
    if any(sits.values()):
        cards.append('<div class="card"><h3>Sensitive information types reaching AI</h3>'
                     f'{_sit_chart(sits)}</div>')

    if any(x.get("uploaded_bytes") for x in shadow_apps):
        cards.append('<div class="card"><h3>Upload volume by application</h3>'
                     f'{_shadow_traffic_chart(shadow_apps)}</div>')

    if shadow_apps:
        cards.append(
            '<div class="card"><h3>Shadow AI: reach against risk</h3>'
            f'{_shadow_risk_scatter(shadow_apps)}'
            f'{charts.legend([(lv, charts.severity_color(lv), None) for lv in charts.SEVERITY_ORDER], show_values=False)}'
            '<p class="c-note">Defender scores 0–10 with low meaning risky; shown here '
            'inverted so higher is worse, matching every other score in AI-SPM. '
            'Dot size is upload volume.</p></div>')

    if not cards:
        return ""
    rows = "".join(f'<div class="grid cols-2" style="margin-top:16px">{"".join(pair)}</div>'
                   for pair in (cards[i:i + 2] for i in range(0, len(cards), 2)))
    return rows


def _flow_diagram(columns, flows, width=520, height=210, node_w=10):
    """
    Dependency-free (no D3), hand-built "flow" (Sankey-style) diagram — same idea as the
    pipe-themed charts in Microsoft's Zero Trust Assessment tool.
    columns: [[(node_id, label, color, value), ...], ...] — flow occurs between adjacent columns.
    flows: [(from_id, to_id, value), ...] — only adjacent columns are supported.
    """
    n_cols = len(columns)
    if n_cols < 2 or not any(columns):
        return '<div class="empty">No data</div>'
    col_gap = (width - node_w * n_cols) / max(1, n_cols - 1)
    pad_y, gap_between = 10, 6
    usable_h = height - 2 * pad_y

    positions = {}
    for ci, col in enumerate(columns):
        total = sum(v for _, _, _, v in col) or 1
        avail = usable_h - gap_between * max(0, len(col) - 1)
        y = pad_y
        for nid, label, color, value in col:
            h = max(2.0, avail * value / total)
            positions[nid] = {"col": ci, "y0": y, "y1": y + h, "color": color,
                              "label": label, "value": value}
            y += h + gap_between

    svg = [f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
          f'role="img" class="flow" preserveAspectRatio="xMidYMid meet">']
    out_used, in_used = {}, {}
    for fid, tid, value in flows:
        if fid not in positions or tid not in positions:
            continue
        f_pos, t_pos = positions[fid], positions[tid]
        fx = f_pos["col"] * (node_w + col_gap) + node_w
        tx = t_pos["col"] * (node_w + col_gap)
        f_span = (f_pos["y1"] - f_pos["y0"])
        t_span = (t_pos["y1"] - t_pos["y0"])
        f_h = f_span * (value / f_pos["value"]) if f_pos["value"] else 0
        t_h = t_span * (value / t_pos["value"]) if t_pos["value"] else 0
        fy = f_pos["y0"] + out_used.get(fid, 0)
        ty = t_pos["y0"] + in_used.get(tid, 0)
        out_used[fid] = out_used.get(fid, 0) + f_h
        in_used[tid] = in_used.get(tid, 0) + t_h
        midx = (fx + tx) / 2
        path = (f"M{fx:.1f},{fy:.1f} C{midx:.1f},{fy:.1f} {midx:.1f},{ty:.1f} {tx:.1f},{ty:.1f} "
               f"L{tx:.1f},{ty + t_h:.1f} C{midx:.1f},{ty + t_h:.1f} {midx:.1f},{fy + f_h:.1f} "
               f"{fx:.1f},{fy + f_h:.1f} Z")
        svg.append(f'<path d="{path}" fill="{f_pos["color"]}" opacity="0.42"/>')

    for nid, pos in positions.items():
        x = pos["col"] * (node_w + col_gap)
        h = max(1.0, pos["y1"] - pos["y0"])
        svg.append(f'<rect x="{x:.1f}" y="{pos["y0"]:.1f}" width="{node_w}" height="{h:.1f}" '
                  f'fill="{pos["color"]}" rx="2"/>')
        ly = (pos["y0"] + pos["y1"]) / 2
        if pos["col"] == 0:
            anchor, tx_label = "start", x + node_w + 6
        elif pos["col"] == n_cols - 1:
            anchor, tx_label = "end", x - 6
        else:
            anchor, tx_label = "middle", x + node_w / 2
        svg.append(f'<text x="{tx_label:.1f}" y="{ly:.1f}" dy="4" text-anchor="{anchor}" '
                  f'class="flow-label">{_esc(pos["label"])} ({pos["value"]})</text>')
    svg.append("</svg>")
    return "".join(svg)


# Real Microsoft logo (4-color square) — inline SVG, no external dependency.
_MS_LOGO_SVG = """<svg width="21" height="21" viewBox="0 0 21 21" xmlns="http://www.w3.org/2000/svg">
<rect x="1" y="1" width="9" height="9" fill="#F25022"/>
<rect x="11" y="1" width="9" height="9" fill="#7FBA00"/>
<rect x="1" y="11" width="9" height="9" fill="#00A4EF"/>
<rect x="11" y="11" width="9" height="9" fill="#FFB900"/>
</svg>"""


# ==================================================================================
# "Assessment results" component — the pattern from Microsoft's Zero Trust Assessment
# tool: a filterable/searchable table (Name | Risk | Status) + a side panel that opens
# on row click (facts → Risk Score+reasons → Result → What was checked → Remediation).
# Score 0-100, following `scoring.py`'s "additive score + reason chain" philosophy: each
# score component comes with its own reason sentence, risk_label is ALWAYS derived from
# score (see _risk_tier) — the answer to "it says 45, based on what?" is spelled out line
# by line in the panel.
# ==================================================================================
def _item(item_id, name, score, reasons, status_label, status_color,
         facts, result_line, what_checked, remediation, bucket=None):
    score = max(0, min(100, score))
    risk = _risk_tier(score)
    return {
        "id": item_id, "name": name, "bucket": bucket,
        "score": score, "risk_key": risk,
        "risk_label": _RISK_LABEL[risk], "risk_color": _SEV[risk],
        "reasons": [f"+{p} — {r}" if p > 0 else r for p, r in reasons],
        "status_label": status_label, "status_color": status_color,
        "facts": facts, "result_line": result_line, "what_checked": what_checked,
        "remediation": remediation if isinstance(remediation, list) else [remediation],
    }


def _agent365_items(packages):
    items = []
    for idx, p in enumerate(packages):
        name = p["display_name"]
        build_type = p["build_type"] or "unknown"
        deployed_to, available_to = p["deployed_to"] or "unclear", p["available_to"] or "unclear"
        available_all = available_to.strip().lower() in ("everyone", "all", "alltenant", "organization")
        correlated = bool(p.get("entra_app_id"))

        reasons = []
        if p["blocked"]:
            score = 5
            reasons.append((5, "Package is currently blocked — cannot be used actively"))
            status_label, status_c, result_line = "Blocked", _SEV["high"], "Package is blocked."
        else:
            score = 0
            if available_all:
                score += 35
                reasons.append((35, "Deployment scope is 'everyone' — open to the entire organization"))
            if not correlated:
                score += 30
                reasons.append((30, "Not correlated with Entra Agent ID — no identity/permission visibility"))
            if build_type == "custom":
                score += 20
                reasons.append((20, "Custom (in-house built) build — may have had less review"))
            if not reasons:
                reasons.append((0, "No notable risk signal"))
            if available_all and not correlated:
                status_label, status_c = "Investigate", _SEV["medium"]
                result_line = "Open to everyone and not correlated with an Entra identity."
            elif available_all:
                status_label, status_c = "Investigate", _SEV["medium"]
                result_line = "Open deployment."
            else:
                status_label, status_c = "Passed", _SEV["low"]
                result_line = "Scope is limited, no additional risk signal."

        what_checked = (
            f"{name} is a {build_type} package registered in the Agent 365 catalog. "
            f"It is deployed to {deployed_to} scope and available to {available_to} users. "
            + ("The package is currently blocked. " if p["blocked"] else "The package is active and not blocked. ")
            + (f"Correlated with Entra application: {p['entra_app_id']}."
               if correlated else "Not correlated with any Entra application.")
        )
        remediation = []
        if not p["blocked"] and available_all and not correlated:
            remediation += ["Narrow the deployment scope (who the package is available to).",
                          "Verify the relevant appId for correlation with Entra Agent ID."]
        elif not p["blocked"] and available_all:
            remediation.append("Verify the deployment scope matches an actual business need.")
        elif p["blocked"]:
            remediation.append("Verify the reason for blocking with the publisher/responsible team; don't remove it unless necessary.")
        else:
            remediation.append("No further action needed; review periodically.")

        facts = [("Build Type", build_type), ("Deployment", deployed_to),
                ("Entra Correlation", "Yes" if correlated else "No"),
                ("Sources", _sources_label(p.get("sources"))),
                ("Correlation Confidence",
                 f"{p['correlation_confidence']}/100" if p.get("correlation_confidence") is not None else "—")]
        items.append(_item(f"agent365-{idx}", name, score, reasons, status_label, status_c,
                          facts, result_line, what_checked, remediation,
                          bucket="Blocked" if p["blocked"] else ("Everyone" if available_all else "Limited")))
    return items


def _identity_items(identities):
    items = []
    for idx, i in enumerate(identities):
        name = i["display_name"]
        has_owner, has_sponsor = bool(i["owners"]), bool(i["sponsors"])
        perm_type = ("app-only + delegated" if i["app_only_perms"] and i["delegated_perms"]
                    else "app-only only" if i["app_only_perms"]
                    else "delegated only" if i["delegated_perms"] else "no permissions")

        reasons = []
        if not i["enabled"]:
            score = 5
            reasons.append((5, "Disabled — no active access risk"))
            status_label, status_c, result_line = "Disabled", _SEV["info"], "Disabled — no active risk."
            bucket = "Disabled"
        else:
            score = 0
            if not has_owner:
                score += 35
                reasons.append((35, "No owner assigned"))
            if not has_sponsor:
                score += 20
                reasons.append((20, "No sponsor assigned"))
            if i["app_only_perms"] > 0:
                score += 15
                reasons.append((15, f"{i['app_only_perms']} app-only (unattended) permissions"))
            if not i.get("blueprint_id"):
                score += 10
                reasons.append((10, "Not linked to any blueprint"))
            if not reasons:
                reasons.append((0, "Owner/sponsor/blueprint assignment complete"))
            if has_owner and has_sponsor:
                status_label, status_c, result_line = "Passed", _SEV["low"], "Owner and sponsor assigned."
            elif has_owner or has_sponsor:
                status_label, status_c, result_line = "Investigate", _SEV["medium"], "Owner or sponsor missing."
            else:
                status_label, status_c, result_line = "Failed", _SEV["high"], "Owner and sponsor not assigned."
            bucket = "Full" if (has_owner and has_sponsor) else ("Partial" if (has_owner or has_sponsor) else "None")

        app_only_names = _fmt_names(i.get("app_only_perm_names"))
        delegated_names = _fmt_names(i.get("delegated_perm_names"))
        what_checked = (
            f"{name} is " + ("enabled. " if i["enabled"] else "disabled. ")
            + f"Owner: {', '.join(i['owners']) if has_owner else 'none assigned'}. "
            + f"Sponsor: {', '.join(i['sponsors']) if has_sponsor else 'none assigned'}. "
            + f"Has {i['app_only_perms']} app-only ({app_only_names}) and {i['delegated_perms']} delegated "
              f"({delegated_names}) permissions ({perm_type}). "
            + (f"Blueprint: {i['blueprint_id']}." if i.get("blueprint_id") else "Not linked to any blueprint.")
            + f" Sources: {_sources_label(i.get('sources'))}."
        )
        remediation = []
        if i["enabled"] and not has_owner:
            remediation.append("Assign an owner to this agent identity — required for accountability.")
        if i["enabled"] and not has_sponsor:
            remediation.append("Assign a sponsor (especially if it has app-only permissions).")
        if not remediation:
            remediation.append("No further action needed.")

        facts = [("Owner", ", ".join(i["owners"]) or "—"), ("Sponsor", ", ".join(i["sponsors"]) or "—"),
                ("App-only Permissions", app_only_names), ("Delegated Permissions", delegated_names),
                ("Sources", _sources_label(i.get("sources"))),
                ("Correlation Confidence",
                 f"{i['correlation_confidence']}/100" if i.get("correlation_confidence") is not None else "—")]
        items.append(_item(f"identity-{idx}", name, score, reasons, status_label, status_c,
                          facts, result_line, what_checked, remediation, bucket=bucket))
    return items


def _shadow_items(apps, tenant_id=""):
    defender_url = (f"https://security.microsoft.com/cloudapps/discovery?tid={tenant_id}"
                    if tenant_id else None)
    items = []
    for idx, a in enumerate(apps):
        name, state = a["display_name"], a.get("sanctioned_state")
        reasons = []
        score = 0
        if state == "unsanctioned":
            score += 45
            reasons.append((45, "Unsanctioned application"))
        elif state == "unreviewed":
            score += 25
            reasons.append((25, "Not yet reviewed (unreviewed)"))
        elif state == "sanctioned":
            reasons.append((0, "Organizationally sanctioned"))
        else:
            score += 10
            reasons.append((10, "Sanction status unknown"))
        if isinstance(a.get("risk_score"), int):
            mdca_pts = round((10 - a["risk_score"]) / 10 * 25)
            if mdca_pts:
                score += mdca_pts
                reasons.append((mdca_pts, f"MDCA risk score {a['risk_score']}/10 (lower score = higher risk)"))
        if a["users"] >= 20:
            score += 15
            reasons.append((15, f"{a['users']} users are using this application (wide spread)"))
        elif a["users"] >= 5:
            score += 8
            reasons.append((8, f"{a['users']} users are using this application"))
        if a["uploaded_bytes"] >= 1_000_000:
            score += 10
            reasons.append((10, f"{a['uploaded_bytes']:,} bytes uploaded (30d)"))

        result_line = {"unsanctioned": "Unsanctioned application.", "sanctioned": "Organizationally sanctioned.",
                      "unreviewed": "Not yet reviewed."}.get(state, "Sanction status unclear.")
        status_label, status_c = {
            "unsanctioned": ("Unsanctioned", _SEV["high"]), "unreviewed": ("Unreviewed", _SEV["medium"]),
            "sanctioned": ("Sanctioned", _SEV["low"]),
        }.get(state, ("Unreviewed", _SEV["info"]))

        what_checked = (
            f"{name} was discovered by Defender for Cloud Apps over the last 30 days with traffic "
            f"from {a['users']} users, {a['devices']} devices, and {a['ip_addresses']} distinct IP "
            f"addresses: {a.get('transactions', 0):,} transactions, {a['uploaded_bytes']:,} bytes "
            f"uploaded, {a.get('downloaded_bytes', 0):,} bytes downloaded. Sanction status: {state or 'unknown'}. "
            + (f"MDCA risk score: {a['risk_score']}/10. " if a.get("risk_score") is not None else "")
            + f"Sensitivity status: {a.get('data_sensitivity') or 'unknown'} "
              "— not conclusive without Purview correlation. Note: these numbers are TOTALS; the MDCA "
              "aggregatedAppsDetails API does not provide individual user/device/IP identity."
        )
        remediation = []
        if state == "unsanctioned":
            remediation += ["Mark the application as sanctioned or blocked in Defender for Cloud Apps.",
                          "Redirect users to an approved alternative."]
        elif state == "unreviewed":
            remediation.append("Review the application and classify it as sanctioned/unsanctioned.")
        else:
            remediation.append("No further action needed; continue monitoring traffic periodically.")

        facts = [("Users (30d)", a["users"]), ("Devices (30d)", a["devices"]),
                ("IP Addresses (30d)", a["ip_addresses"])]
        it = _item(f"shadow-{idx}", name, score, reasons, status_label, status_c,
                  facts, result_line, what_checked, remediation, bucket=state or "Unknown")
        # Raw data for the same columns as Defender for Cloud Apps' "Discovered apps" grid
        # (Risk score/Tag/Traffic/Upload/Transactions/Users/IP addresses/Devices/Last seen).
        it["traffic"] = {
            "vendor": a.get("vendor") or "", "category": a.get("category") or "",
            "sanctioned_state": state, "risk_score": a.get("risk_score"),
            "users": a["users"], "devices": a["devices"], "ip_addresses": a["ip_addresses"],
            "transactions": a.get("transactions", 0),
            "uploaded_bytes": a["uploaded_bytes"], "downloaded_bytes": a.get("downloaded_bytes", 0),
            "last_seen": a.get("last_seen"),
            "defender_url": defender_url,
        }
        items.append(it)
    return items


def _exposure_items(rows):
    items = []
    for idx, p in enumerate(rows):
        s = p["sensitive_data_summary"]
        name = p["display_name"]
        dirs = ", ".join(f"{k}:{v}" for k, v in p["directions"].items() if v) or "none"

        reasons = []
        score = 0
        if s["allowed"] > 0:
            score += 50
            reasons.append((50, f"{s['allowed']} sensitive interactions were allowed despite DLP"))
        if s["blocked"] > 0:
            score += 10
            reasons.append((10, f"{s['blocked']} sensitive interactions were blocked (positive control)"))
        sit_pts = min(len(s["sit_types"]) * 8, 24)
        if sit_pts:
            score += sit_pts
            reasons.append((sit_pts, f"{len(s['sit_types'])} distinct sensitive data types: {', '.join(s['sit_types'])}"))
        user_pts = min(p["affected_user_count"] * 3, 15)
        if user_pts:
            score += user_pts
            reasons.append((user_pts, f"{p['affected_user_count']} users affected"))
        if p.get("sanctioned_state") == "unsanctioned":
            score += 15
            reasons.append((15, "Unsanctioned application"))
        if not reasons:
            reasons.append((0, "No notable risk signal"))

        if s["allowed"] > 0:
            status_label, status_c, result_line = "Failed", _SEV["high"], "DLP matched but access was allowed — needs review."
        elif s["blocked"] > 0:
            status_label, status_c, result_line = "Passed", _SEV["low"], "All sensitive interactions were blocked."
        else:
            status_label, status_c, result_line = "Investigate", _SEV["medium"], "Access exists but no DLP match/block occurred."

        what_checked = (
            f"{name} had {s['window_30d']['sensitive']}/{s['window_30d']['interactions']} "
            f"sensitive interactions in the last 30 days, affecting {p['affected_user_count']} users. "
            f"Data types: {', '.join(s['sit_types']) or 'none'}. Direction breakdown: {dirs}. "
            f"{s['blocked']} blocked, {s['allowed']} allowed."
        )
        remediation = [f["detail"] for f in p["findings"]] or ["No further action needed."]
        facts = [("Affected Users", p["affected_user_count"]),
                ("Sensitive Interactions (30d)", s["window_30d"]["sensitive"]),
                ("Data Type Count", len(s["sit_types"]))]
        items.append(_item(f"exposure-{idx}", name, score, reasons, status_label, status_c,
                          facts, result_line, what_checked, remediation))
    return items


_FINDING_REMEDIATION = {
    "SENSITIVE_DATA_SHARED_WITH_UNSANCTIONED_AI":
        "Mark this application as sanctioned or blocked in Defender for Cloud Apps; expand the "
        "DLP policy to also cover this application; redirect users to an approved alternative.",
    "SENSITIVE_DATA_BLOCKED_TO_AI":
        "Positive control — the DLP policy is working. No further action needed; review policy "
        "coverage periodically.",
    "AI_APP_ACCESSING_LABELED_DATA":
        "Verify whether this application's access to labeled data reflects an actual business "
        "need; define an additional DLP policy if necessary.",
    "UNSANCTIONED_AI_UPLOAD_UNDETERMINED":
        "Enable the Purview Audit/DSPM connection to determine this application's real data "
        "sensitivity; keep monitoring upload volume until it's connected.",
}
_DEFAULT_REMEDIATION = "Review the finding detail and build an action plan with the relevant team."
_FINDING_SCORE = {"high": 80, "medium": 50, "low": 25, "info": 10}


def _finding_items(findings):
    items = []
    for idx, f in enumerate(findings):
        sev = f["severity"] if f["severity"] in _SEV else "info"
        score = _FINDING_SCORE[sev]
        reasons = [(score, f["detail"])]
        status_label, status_c = ("Passed", _SEV["low"]) if sev == "info" else ("Failed", _SEV[sev])
        facts = [("Application", f.get("app") or "—"), ("Affected Users", f.get("affected_users", "—")),
                ("Source", "MDCA / Purview")]
        items.append(_item(
            f"finding-{idx}", f["type"].replace("_", " ").title(), score, reasons,
            status_label, status_c, facts, f["detail"], f["detail"],
            [_FINDING_REMEDIATION.get(f["type"], _DEFAULT_REMEDIATION)]))
    return items


def _fmt_bytes(n):
    n = n or 0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _mdca_risk_bar(score):
    """Same as the risk score bar in Defender for Cloud Apps — 0-10, 10=safe (green)."""
    if score is None:
        return '<span style="color:var(--muted)">—</span>'
    color = "#2e8b57" if score >= 7 else ("#b8860b" if score >= 4 else "#c0392b")
    pct = max(5, score * 10)
    return (f'<div style="display:flex;align-items:center;gap:6px">'
           f'<div style="width:46px;height:7px;border-radius:4px;background:var(--track);overflow:hidden">'
           f'<div style="width:{pct}%;height:100%;background:{color}"></div></div>'
           f'<span class="c-num">{score}</span></div>')


def _sanction_pill(state):
    color = {"sanctioned": "#2e8b57", "unsanctioned": "#c0392b", "unreviewed": "#b8860b"}.get(state, "#6b7280")
    label = {"sanctioned": "Sanctioned", "unsanctioned": "Unsanctioned",
            "unreviewed": "Unreviewed"}.get(state, "—")
    return f'<span class="zt-pill" style="--pc:{color}">{_esc(label)}</span>'


def _zt_toolbar(section_id, items):
    risk_order = list(_RISK_LABEL.values())
    risks = sorted({it["risk_label"] for it in items}, key=lambda r: risk_order.index(r))
    statuses = sorted({it["status_label"] for it in items})
    risk_chips = "".join(
        f'<button class="zt-chip" data-scope="{section_id}" data-key="risk" data-val="{_esc(r)}" '
        f'onclick="ztChip(this)">{_esc(r)}</button>' for r in risks)
    status_chips = "".join(
        f'<button class="zt-chip" data-scope="{section_id}" data-key="status" data-val="{_esc(s)}" '
        f'onclick="ztChip(this)">{_esc(s)}</button>' for s in statuses)
    return (f'<div class="zt-toolbar">'
           f'<input class="zt-search" data-scope="{section_id}" placeholder="Search..." oninput="ztSearch(this)">'
           f'<div class="zt-chips"><span class="zt-chip-label">Risk</span>{risk_chips}</div>'
           f'<div class="zt-chips"><span class="zt-chip-label">Status</span>{status_chips}</div>'
           f'</div>')


def _shadow_traffic_section(section_id, title, subtitle, items, empty_msg):
    """Same columns as Defender for Cloud Apps' 'Discovered apps' grid: Risk score/Tag/
    Traffic/Upload/Transactions/Users/IP addresses/Devices/Last seen. Clicking a row still
    opens the same assessment detail panel (score+reasons+remediation)."""
    if not items:
        return (f'<div class="card" id="{section_id}"><h3>{_esc(title)}</h3>'
               f'<div class="empty">{_esc(empty_msg)}</div></div>')

    rows = []
    for it in sorted(items, key=lambda x: x["traffic"]["uploaded_bytes"] + x["traffic"]["downloaded_bytes"],
                     reverse=True):
        t = it["traffic"]
        total = t["uploaded_bytes"] + t["downloaded_bytes"]
        detail_json = html.escape(json.dumps(it), quote=True)
        last_seen = (t["last_seen"] or "")[:10] or "—"
        rows.append(
            f'<tr class="zt-row" data-scope="{section_id}" data-risk="{_esc(it["risk_label"])}" '
            f'data-status="{_esc(it["status_label"])}" data-name="{_esc(it["name"]).lower()}" '
            f"data-detail='{detail_json}' onclick=\"ztOpen(this)\">"
            f'<td data-sort="{_esc(it["name"]).lower()}"><div class="c-name">{_esc(it["name"])}</div>'
            f'<div style="font-size:11px;color:var(--muted)">{_esc(t["category"] or t["vendor"] or "—")}'
            + (f' &middot; <a href="{_esc(t["defender_url"])}" target="_blank" rel="noopener" '
               f'onclick="event.stopPropagation()" style="color:var(--accent)">Open in Defender ↗</a>'
               if t.get("defender_url") else "")
            + '</div></td>'
            f'<td data-sort="{t["risk_score"] if t["risk_score"] is not None else -1}">'
            f'{_mdca_risk_bar(t["risk_score"])}</td>'
            f'<td data-sort="{_esc(t["sanctioned_state"] or "").lower()}">'
            f'{_sanction_pill(t["sanctioned_state"])}</td>'
            f'<td class="c-num" data-sort="{total}">{_fmt_bytes(total)}</td>'
            f'<td class="c-num" data-sort="{t["uploaded_bytes"]}">{_fmt_bytes(t["uploaded_bytes"])}</td>'
            f'<td class="c-num" data-sort="{t["transactions"]}">{t["transactions"]:,}</td>'
            f'<td class="c-num" data-sort="{t["users"]}">{t["users"]}</td>'
            f'<td class="c-num" data-sort="{t["ip_addresses"]}">{t["ip_addresses"]}</td>'
            f'<td class="c-num" data-sort="{t["devices"]}">{t["devices"]}</td>'
            f'<td class="c-num" data-sort="{_esc(t["last_seen"] or "")}" style="white-space:nowrap">'
            f'{_esc(last_seen)}</td>'
            f"</tr>")

    headers = ["Application", "Risk Score", "Tag", "Traffic", "Upload", "Transactions",
              "Users", "IP Addresses", "Devices", "Last Seen"]
    ths = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    return f"""
<div class="card" id="{section_id}"><h3>{_esc(title)}</h3>
<div class="c-subtitle">{_esc(subtitle)}</div>
{_zt_toolbar(section_id, items)}
<div class="c-tbl-wrap"><table class="c-tbl zt-table"><thead><tr>{ths}</tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
</div>"""


def _zt_section(section_id, title, subtitle, items, empty_msg):
    if not items:
        return (f'<div class="card" id="{section_id}"><h3>{_esc(title)}</h3>'
               f'<div class="empty">{_esc(empty_msg)}</div></div>')

    rows = []
    for it in sorted(items, key=lambda x: x["score"], reverse=True):
        detail_json = html.escape(json.dumps(it), quote=True)
        rows.append(
            f'<tr class="zt-row" data-scope="{section_id}" data-risk="{_esc(it["risk_label"])}" '
            f'data-status="{_esc(it["status_label"])}" data-name="{_esc(it["name"]).lower()}" '
            f"data-detail='{detail_json}' onclick=\"ztOpen(this)\">"
            f'<td class="c-name" data-sort="{_esc(it["name"]).lower()}">{_esc(it["name"])}</td>'
            f'<td class="c-num" data-sort="{it["score"]}"><b>{it["score"]}</b>/100</td>'
            f'<td data-sort="{_RISK_RANK[it["risk_key"]]}">'
            f'<span class="zt-pill" style="--pc:{it["risk_color"]}">{_esc(it["risk_label"])}</span></td>'
            f'<td data-sort="{_esc(it["status_label"]).lower()}">'
            f'<span class="zt-pill" style="--pc:{it["status_color"]}">{_esc(it["status_label"])}</span></td>'
            f'</tr>')

    return f"""
<div class="card" id="{section_id}"><h3>{_esc(title)}</h3>
<div class="c-subtitle">{_esc(subtitle)}</div>
{_zt_toolbar(section_id, items)}
<div class="zt-tbl-wrap"><table class="zt-table">
<thead><tr><th>Name</th><th>Score</th><th>Risk</th><th>Status</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
</div>"""


def _top_risks_html(all_items, n=5):
    top = sorted(all_items, key=lambda x: x["score"], reverse=True)[:n]
    if not top:
        return '<div class="empty">No items.</div>'
    rows = "".join(
        f'<div class="zt-toprow" data-detail-ref="{it["id"]}">'
        f'<span class="zt-pill" style="--pc:{it["risk_color"]}">{it["score"]}</span>'
        f'<span class="c-name">{_esc(it["name"])}</span>'
        f'<span style="color:var(--muted);font-size:12px">{_esc(it["result_line"])}</span>'
        f'</div>' for it in top)
    return rows


_ZT_CSS = """
.c-subtitle{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;
 letter-spacing:.03em;margin:4px 0 10px}
.c-tbl-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
table.c-tbl{width:100%;border-collapse:collapse;font-size:13px;min-width:520px}
table.c-tbl thead th{text-align:left;font-size:11px;text-transform:uppercase;color:var(--muted);
 letter-spacing:.03em;padding:9px 12px;border-bottom:1px solid var(--line);white-space:nowrap}
table.c-tbl tbody td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
table.c-tbl tbody tr:last-child td{border-bottom:none}
.c-name{font-weight:600}
.c-note{font-size:12px;color:var(--muted);margin:12px 0 0;line-height:1.5}
.c-num{font-variant-numeric:tabular-nums}
.c-tag{display:inline-block;font-size:11px;background:var(--track);color:var(--ink);
 padding:1px 7px;border-radius:5px;margin:1px 3px 1px 0}
header .navlink{cursor:pointer}
.flow-label{font-size:11px;fill:var(--ink)}
.flow-wrap{overflow-x:auto}
.zt-toolbar{display:flex;gap:16px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.zt-search{border:1px solid var(--line);background:var(--bg);color:var(--ink);border-radius:8px;
 padding:7px 12px;font-size:13px;min-width:160px}
.zt-chips{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.zt-chip-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;margin-right:2px}
.zt-chip{cursor:pointer;border:1px solid var(--line);background:transparent;color:var(--ink);
 border-radius:999px;padding:4px 12px;font-size:12px}
.zt-chip.active{background:var(--accent);color:#fff;border-color:var(--accent)}
table.zt-table{width:100%;border-collapse:collapse;font-size:13px;min-width:420px}
table.zt-table thead th{text-align:left;font-size:11px;text-transform:uppercase;color:var(--muted);
 letter-spacing:.03em;padding:9px 12px;border-bottom:1px solid var(--line)}
table.c-tbl thead th.zt-sortable,table.zt-table thead th.zt-sortable{cursor:pointer;user-select:none;
 white-space:nowrap}
table.c-tbl thead th.zt-sortable:hover,table.zt-table thead th.zt-sortable:hover{color:var(--ink)}
th.zt-sortable::after{content:"";margin-left:4px;opacity:.35}
th.sorted-asc::after{content:"▲";opacity:1}
th.sorted-desc::after{content:"▼";opacity:1}
table.zt-table tbody td{padding:10px 12px;border-bottom:1px solid var(--line)}
table.zt-table tbody tr:last-child td{border-bottom:none}
table.zt-table tbody tr{cursor:pointer;transition:background .12s}
table.zt-table tbody tr:hover{background:var(--track)}
.zt-pill{display:inline-block;background:var(--pc,#6b7280);color:#fff;font-size:11px;font-weight:700;
 padding:3px 10px;border-radius:999px}
.zt-toprow{display:flex;align-items:center;gap:12px;padding:9px 4px;border-bottom:1px solid var(--line);
 font-size:13px}
.zt-toprow:last-child{border-bottom:none}
.zt-overlay{position:fixed;inset:0;background:rgba(0,0,0,.4);opacity:0;pointer-events:none;
 transition:opacity .18s;z-index:20}
.zt-overlay.open{opacity:1;pointer-events:auto}
.zt-panel{position:fixed;top:0;right:0;bottom:0;width:min(500px,92vw);background:var(--panel);
 box-shadow:-8px 0 30px rgba(0,0,0,.18);transform:translateX(100%);transition:transform .22s ease;
 z-index:21;overflow-y:auto;padding:26px}
.zt-panel.open{transform:translateX(0)}
.zt-panel-close{position:absolute;top:18px;right:18px;cursor:pointer;border:1px solid var(--line);
 background:transparent;color:var(--ink);border-radius:8px;width:30px;height:30px;font-size:16px;
 line-height:1}
.zt-panel h2{font-size:19px;margin:0 34px 20px 0;text-wrap:balance}
.zt-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:14px;
 border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:18px}
.zt-fact{display:flex;flex-direction:column;gap:3px}
.zt-fact-l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
.zt-fact-v{font-size:14px;font-weight:600}
.zt-score{display:flex;align-items:center;gap:14px;margin-bottom:8px}
.zt-score-num{font-size:30px;font-weight:700;font-family:"Cascadia Code",Consolas,ui-monospace,monospace;
 min-width:60px}
.zt-score-bar{flex:1;height:10px;border-radius:6px;background:var(--track);overflow:hidden}
.zt-score-fill{height:100%;border-radius:6px;transition:width .2s}
.zt-result{display:flex;align-items:center;gap:10px;margin:18px 0;padding-bottom:18px;
 border-bottom:1px solid var(--line)}
.zt-result b{font-size:15px}
.zt-panel h4{font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);
 margin:0 0 8px}
.zt-panel section{margin-bottom:20px}
.zt-panel p{font-size:13.5px;line-height:1.65;margin:0;color:var(--ink)}
.zt-panel ul{margin:0;padding-left:18px;font-size:13.5px;line-height:1.65}
.zt-panel ul li{margin:5px 0}
"""

_ZT_SCRIPT = """
(function(){
function showTab(n){
  document.querySelectorAll('.tab').forEach(function(t){t.classList.toggle('active',t.getAttribute('data-tab')===n);});
  document.querySelectorAll('.navlink').forEach(function(x){x.classList.toggle('active',x.getAttribute('data-tab')===n);});
  window.scrollTo(0,0);
}
document.querySelectorAll('.navlink').forEach(function(l){l.onclick=function(){showTab(l.getAttribute('data-tab'));};});
document.querySelectorAll('[data-goto]').forEach(function(c){c.onclick=function(e){e.preventDefault();showTab(c.getAttribute('data-goto'));};});
window.ztGoto = showTab;
var coreLink=document.getElementById('coreDashboardLink');
if(coreLink){
  if(location.pathname.indexOf('/api/')===0){
    var coreCode=new URLSearchParams(location.search).get('code');
    coreLink.href='/api/report'+(coreCode?('?code='+encodeURIComponent(coreCode)):'');
  }else{
    coreLink.remove();
  }
}
})();
function ztRows(scope){return document.querySelectorAll('tr.zt-row[data-scope="'+scope+'"]');}
function ztActiveChips(scope,key){
  var sel='.zt-chip.active[data-scope="'+scope+'"][data-key="'+key+'"]';
  return Array.prototype.map.call(document.querySelectorAll(sel), function(c){return c.dataset.val;});
}
function ztApply(scope){
  var risks=ztActiveChips(scope,'risk'), statuses=ztActiveChips(scope,'status');
  var searchEl=document.querySelector('.zt-search[data-scope="'+scope+'"]');
  var q=searchEl?searchEl.value.trim().toLowerCase():'';
  ztRows(scope).forEach(function(row){
    var okRisk=risks.length===0||risks.indexOf(row.dataset.risk)>-1;
    var okStatus=statuses.length===0||statuses.indexOf(row.dataset.status)>-1;
    var okSearch=!q||row.dataset.name.indexOf(q)>-1;
    row.style.display=(okRisk&&okStatus&&okSearch)?'':'none';
  });
}
function ztChip(btn){btn.classList.toggle('active');ztApply(btn.dataset.scope);}
function ztSearch(input){ztApply(input.dataset.scope);}
function ztOpen(row){
  var d=JSON.parse(row.getAttribute('data-detail'));
  document.getElementById('zt-title').textContent=d.name;
  var factsEl=document.getElementById('zt-facts');factsEl.innerHTML='';
  d.facts.forEach(function(f){
    var wrap=document.createElement('div');wrap.className='zt-fact';
    var l=document.createElement('span');l.className='zt-fact-l';l.textContent=f[0];
    var v=document.createElement('span');v.className='zt-fact-v';v.textContent=f[1];
    wrap.appendChild(l);wrap.appendChild(v);factsEl.appendChild(wrap);
  });
  document.getElementById('zt-score-num').textContent=d.score+'/100';
  var fill=document.getElementById('zt-score-fill');
  fill.style.width=d.score+'%';fill.style.background=d.risk_color;
  var reasonsEl=document.getElementById('zt-reasons');reasonsEl.innerHTML='';
  d.reasons.forEach(function(r){var li=document.createElement('li');li.textContent=r;reasonsEl.appendChild(li);});
  var pill=document.getElementById('zt-result-pill');
  pill.textContent=d.status_label;pill.style.setProperty('--pc',d.status_color);
  document.getElementById('zt-result-line').textContent=d.result_line;
  document.getElementById('zt-checked').textContent=d.what_checked;
  var remEl=document.getElementById('zt-remediation');remEl.innerHTML='';
  d.remediation.forEach(function(r){var li=document.createElement('li');li.textContent=r;remEl.appendChild(li);});
  document.getElementById('zt-overlay').classList.add('open');
  document.getElementById('zt-panel').classList.add('open');
}
function ztClose(){
  document.getElementById('zt-overlay').classList.remove('open');
  document.getElementById('zt-panel').classList.remove('open');
}
document.addEventListener('keydown',function(e){if(e.key==='Escape')ztClose();});
function ztSortTable(th){
  var table=th.closest('table');
  if(!table)return;
  var tbody=table.querySelector('tbody');
  if(!tbody)return;
  var ths=Array.prototype.slice.call(th.parentNode.children);
  var idx=ths.indexOf(th);
  var dir=th.classList.contains('sorted-asc')?'desc':'asc';
  ths.forEach(function(h){h.classList.remove('sorted-asc','sorted-desc');});
  th.classList.add(dir==='asc'?'sorted-asc':'sorted-desc');
  var rows=Array.prototype.slice.call(tbody.rows);
  rows.sort(function(a,b){
    var ac=a.cells[idx],bc=b.cells[idx];
    var av=ac?(ac.dataset.sort!==undefined?ac.dataset.sort:ac.textContent.trim().toLowerCase()):'';
    var bv=bc?(bc.dataset.sort!==undefined?bc.dataset.sort:bc.textContent.trim().toLowerCase()):'';
    var an=parseFloat(av),bn=parseFloat(bv);
    var cmp=(!isNaN(an)&&!isNaN(bn)&&av!==''&&bv!=='')?(an-bn):String(av).localeCompare(String(bv));
    return dir==='asc'?cmp:-cmp;
  });
  rows.forEach(function(r){tbody.appendChild(r);});
}
document.querySelectorAll('table.zt-table thead th, table.c-tbl thead th').forEach(function(th){
  th.classList.add('zt-sortable');
  th.onclick=function(){ztSortTable(th);};
});
"""


def _shadow_flow(shadow_items):
    if not shadow_items:
        return None
    bucket_color = {"unsanctioned": "#c0392b", "sanctioned": "#2e8b57", "unreviewed": "#b8860b"}
    buckets, risk_by_bucket = {}, {}
    for it in shadow_items:
        b = it["bucket"]
        buckets[b] = buckets.get(b, 0) + 1
        risk_by_bucket.setdefault(b, {})
        risk_by_bucket[b][it["risk_key"]] = risk_by_bucket[b].get(it["risk_key"], 0) + 1

    col1 = [("src", "Discovered Applications", "#5f6b7a", len(shadow_items))]
    col2 = [(f"b:{b}", b, bucket_color.get(b, "#5f6b7a"), c) for b, c in buckets.items()]
    risk_totals = {}
    for rc in risk_by_bucket.values():
        for rk, c in rc.items():
            risk_totals[rk] = risk_totals.get(rk, 0) + c
    col3 = [(f"r:{rk}", _RISK_LABEL[rk], _SEV[rk], c) for rk, c in risk_totals.items()]

    flows = [("src", f"b:{b}", c) for b, c in buckets.items()]
    for b, rc in risk_by_bucket.items():
        for rk, c in rc.items():
            flows.append((f"b:{b}", f"r:{rk}", c))
    return _flow_diagram([col1, col2, col3], flows)


def _identity_flow(identity_items):
    if not identity_items:
        return None
    bucket_color = {"Full": "#2e8b57", "Partial": "#b8860b", "None": "#c0392b", "Disabled": "#6b7280"}
    buckets, risk_by_bucket = {}, {}
    for it in identity_items:
        b = it["bucket"]
        buckets[b] = buckets.get(b, 0) + 1
        risk_by_bucket.setdefault(b, {})
        risk_by_bucket[b][it["risk_key"]] = risk_by_bucket[b].get(it["risk_key"], 0) + 1

    col1 = [("src", "Agent Identities", "#5f6b7a", len(identity_items))]
    col2 = [(f"b:{b}", f"Owner/Sponsor: {b}", bucket_color.get(b, "#5f6b7a"), c) for b, c in buckets.items()]
    risk_totals = {}
    for rc in risk_by_bucket.values():
        for rk, c in rc.items():
            risk_totals[rk] = risk_totals.get(rk, 0) + c
    col3 = [(f"r:{rk}", _RISK_LABEL[rk], _SEV[rk], c) for rk, c in risk_totals.items()]

    flows = [("src", f"b:{b}", c) for b, c in buckets.items()]
    for b, rc in risk_by_bucket.items():
        for rk, c in rc.items():
            flows.append((f"b:{b}", f"r:{rk}", c))
    return _flow_diagram([col1, col2, col3], flows)


def html_string(result: dict, tenant_id: str = "", now=None) -> str:
    a = assessment(result, now)
    exec_ = a["executive"]
    sev = exec_.get("findings_by_severity", {})
    donut = _donut([
        ("High", sev.get("high", 0), _SEV["high"]),
        ("Medium", sev.get("medium", 0), _SEV["medium"]),
        ("Low", sev.get("low", 0), _SEV["low"]),
        ("Info", sev.get("info", 0), _SEV["info"]),
    ], center_label="Finding")
    legend = "".join(
        f'<div><span class="dot" style="background:{_SEV[k]}"></span>{lbl} '
        f'<b style="margin-left:auto">{sev.get(k, 0)}</b></div>'
        for k, lbl in (("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Info")))

    tiles = "".join([
        f'<div class="card tile{" high" if exec_.get("apps_with_sensitive_data") else ""}">'
        f'<span class="n">{_esc(exec_.get("apps_with_sensitive_data", 0))}</span>'
        f'<span class="l">Apps sharing sensitive data</span></div>',
        f'<div class="card tile"><span class="n">{_esc(exec_.get("total_affected_users", 0))}</span>'
        f'<span class="l">Affected users</span></div>',
        f'<div class="card tile"><span class="n">{_esc(exec_.get("total_blocked", 0))}</span>'
        f'<span class="l">Blocked (DLP)</span></div>',
        f'<div class="card tile{" high" if exec_.get("high_severity_findings") else ""}">'
        f'<span class="n">{_esc(exec_.get("high_severity_findings", 0))}</span>'
        f'<span class="l">High severity findings</span></div>',
    ])

    nav = "".join(
        f'<a class="navlink{" active" if t == "overview" else ""}" data-tab="{t}">{label}</a>'
        for t, label in (("overview", "Overview"), ("agents", "Agents"), ("shadow", "Shadow AI"),
                        ("sensitive", "Sensitive Data"), ("findings", "Findings"), ("gaps", "Gaps")))

    agent365_items = _agent365_items(a["agent365_packages"]["packages"])
    identity_items = _identity_items(a["agent_identities"]["identities"])
    shadow_items = _shadow_items(a["shadow_ai_usage"]["applications"], tenant_id)
    exposure_items = _exposure_items(a["sensitive_exposure"])
    finding_items = _finding_items(a["findings"])
    all_items = agent365_items + identity_items + shadow_items + exposure_items + finding_items

    quick = "".join([
        f'<a class="card kpi" data-goto="agents"><span class="n">{exec_["connectors_connected"]}/{exec_["connectors_total"]}</span>'
        f'<span class="l">Connected data sources</span></a>',
        f'<a class="card kpi" data-goto="agents"><span class="n">{len(agent365_items) + len(identity_items)}</span>'
        f'<span class="l">Agent (365 + Identity)</span></a>',
        f'<a class="card kpi" data-goto="shadow"><span class="n">{len(shadow_items)}</span>'
        f'<span class="l">Shadow AI applications</span></a>',
        f'<a class="card kpi high" data-goto="sensitive"><span class="n">{len(exposure_items)}</span>'
        f'<span class="l">Sensitive data exposure</span></a>',
    ])

    shadow_apps = a["shadow_ai_usage"]["applications"]
    analysis_cards = _analysis_cards(a, shadow_apps)

    shadow_flow = _shadow_flow(shadow_items)
    identity_flow = _identity_flow(identity_items)
    flow_cards = ""
    if shadow_flow or identity_flow:
        cells = []
        if shadow_flow:
            cells.append(f'<div class="card"><h3>Shadow AI: Sanction Status → Risk Flow</h3>'
                        f'<div class="flow-wrap">{shadow_flow}</div></div>')
        if identity_flow:
            cells.append(f'<div class="card"><h3>Agent Identity: Owner/Sponsor → Risk Flow</h3>'
                        f'<div class="flow-wrap">{identity_flow}</div></div>')
        flow_cards = f'<div class="grid cols-2" style="margin-top:16px">{"".join(cells)}</div>'

    top_risks = _top_risks_html(all_items)

    overview = f"""
<div class="hero">
  <div class="card">
    <h3>Source Status</h3>
    <div class="tenant-facts">
      <b>Tenant</b><span>{_esc(tenant_id) or "—"}</span>
      <b>Connected sources</b><span>{exec_["connectors_connected"]}/{exec_["connectors_total"]}</span>
      <b>Matched assets</b><span>{_esc(exec_.get("matched_to_inventory", 0))}/{_esc(exec_.get("total_apps", 0))}</span>
      <b>Generated</b><span>{_esc(a["_generated_at"])[:19].replace("T", " ")} UTC</span>
    </div>
  </div>
  <div class="tiles">{tiles}</div>
  <div class="card">
    <h3>Finding Distribution</h3>
    <div class="summary">{donut}<div class="legend">{legend}</div></div>
  </div>
</div>
<div class="kpi-grid" style="margin-top:16px">{quick}</div>
{analysis_cards}
{flow_cards}
<div class="card" style="margin-top:16px"><h3>Top 5 Highest-Risk Items (all sources)</h3>
{top_risks}</div>
<div class="card" style="margin-top:16px"><h3>Data Source Coverage</h3>
{_coverage_html(a["data_source_coverage"])}</div>"""

    agents_tab = (
        _zt_section("identities", "Entra Agent Identities",
                   "Owner/sponsor/permission assignment — score rises as assignments are missing",
                   identity_items, "No Entra Agent Identity discovered.")
        + _zt_section("agent365", "Agent 365 Packages",
                     "Deployment scope and Entra correlation — score: wide scope + lack of correlation",
                     agent365_items, "No Agent 365 package discovered."))

    shadow_tab = _shadow_traffic_section(
        "shadow", "Shadow AI — Discovered Apps",
        "Same columns as Defender for Cloud Apps' 'Discovered apps' view — user/device/IP "
        "COUNTS (individual identity lists are not in the API — see Gaps). "
        "Click a row to open the risk score + reasons + remediation panel.",
        shadow_items, "No Shadow AI application discovered (or the source is not connected).")

    sensitive_tab = (
        _zt_section("exposure", "Applications with Sensitive Data Exposure",
                   "DLP outcome (blocked/allowed) and data-type diversity determine the score",
                   exposure_items, "No sensitive data sharing detected (or the sources are not connected).")
        + f'<div class="card" style="margin-top:16px"><h3>Purview — Recent Sensitive Interactions</h3>'
          f'{_interactions_table(a["sensitive_interactions"]["sample"])}</div>')

    findings_tab = _zt_section("findings", "Findings",
                              "Each finding is listed as a failed assessment check",
                              finding_items, "No findings.")

    gaps_tab = (f'<div class="card"><h3>Known Gaps / API Limitations</h3>'
              f'<ul class="na">{"".join(f"<li>{_esc(g)}</li>" for g in a["known_gaps"])}</ul></div>')

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>AI-SPM — Microsoft AI Data Sources Assessment</title>
<style>{CSS}{charts.CSS}{_ZT_CSS}</style></head><body>
<header>{_MS_LOGO_SVG}<h1>AI-SPM</h1>
<nav class="tabs">{nav}</nav>
<div class="spacer"></div><div class="tenant">{_esc(tenant_id)}</div>
<a id="coreDashboardLink" class="themebtn" href="#" style="display:inline-block;text-decoration:none;margin-left:10px" title="Go to the Core (OAuth-consent) dashboard">&#8592; Core Dashboard</a>
</header>
<main>
<section class="tab active" data-tab="overview">{overview}</section>
<section class="tab" data-tab="agents">{agents_tab}</section>
<section class="tab" data-tab="shadow">{shadow_tab}</section>
<section class="tab" data-tab="sensitive">{sensitive_tab}</section>
<section class="tab" data-tab="findings">{findings_tab}</section>
<section class="tab" data-tab="gaps">{gaps_tab}</section>
<div class="foot">AI-SPM — Microsoft AI Data Sources · connectors_report.assessment()</div>
</main>

<div class="zt-overlay" id="zt-overlay" onclick="ztClose()"></div>
<aside class="zt-panel" id="zt-panel" role="dialog" aria-label="Detail">
  <button class="zt-panel-close" onclick="ztClose()" aria-label="Close">&times;</button>
  <h2 id="zt-title"></h2>
  <div class="zt-facts" id="zt-facts"></div>
  <h4>Risk Score</h4>
  <div class="zt-score"><span class="zt-score-num" id="zt-score-num"></span>
  <div class="zt-score-bar"><div class="zt-score-fill" id="zt-score-fill"></div></div></div>
  <h4>Why this score?</h4>
  <ul id="zt-reasons"></ul>
  <div class="zt-result">
    <span>Test result →</span>
    <span class="zt-pill" id="zt-result-pill"></span>
    <span id="zt-result-line" style="color:var(--muted);font-size:13px"></span>
  </div>
  <section><h4>What was checked</h4><p id="zt-checked"></p></section>
  <section><h4>Remediation action</h4><ul id="zt-remediation"></ul></section>
</aside>
<script>{_ZT_SCRIPT}</script>
</body></html>"""


def write_html(result: dict, path: str, tenant_id: str = "") -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_string(result, tenant_id))
