"""JSON + single-file HTML dashboard (no dependencies, light/dark)."""
import html
import re
import json
import math
from datetime import datetime, timezone

import charts
from config import (SENSITIVE_SCOPES, SCOPE_HEURISTICS,
                    LIFECYCLE_STATUSES, CRITICALITY, ENVIRONMENTS,
                    AI_CATEGORIES, OWNERSHIP_CLASSES, FINDING_STATUSES)

# Severity is a status scale, so it uses the one validated status palette everywhere —
# chips, rows, and charts alike. See charts.SEVERITY.
_SEV_COLOR = dict(charts.SEVERITY)
_FSTATUS_COLOR = {"Open": charts.SEVERITY["Critical"], "Assigned": charts.SEVERITY["High"],
                  "In Progress": charts.CATEGORICAL_LIGHT[0],
                  "Pending Review": charts.SEVERITY["Medium"],
                  "Resolved": charts.SEVERITY["Low"], "Accepted": "#4b5563",
                  "False Positive": "#6b7280", "Reopened": charts.SEVERITY["Critical"]}

_LIFECYCLE_COLOR = {"Discovered": "#6b7280", "Under Review": charts.SEVERITY["Medium"],
                    "Pilot": charts.CATEGORICAL_LIGHT[0], "Approved": charts.SEVERITY["Low"],
                    "Restricted": charts.SEVERITY["High"], "Blocked": charts.SEVERITY["Critical"],
                    "Retired": "#4b5563", "Unknown": "#6b7280"}

# Classification is identity, not severity — categorical slots, in fixed order so a
# category keeps its color as counts change.
_CAT_COLOR = {c: charts.cat(i) for i, c in enumerate(AI_CATEGORIES)}

_IMP_COLOR = {**charts.SEVERITY, "Info": "#6b7280"}


def _finding_editor(rec):
    fid = html.escape(rec.get("finding_id", ""))
    opts = "".join(f'<option{" selected" if s == rec.get("status") else ""}>{html.escape(s)}</option>'
                   for s in FINDING_STATUSES)

    def fld(label, name, val=""):
        return f'<label>{label}<input name="{name}" value="{html.escape(val or "")}"></label>'

    return (
        '<details class="editor"><summary>Edit finding</summary>'
        f'<div class="fform" data-finding="{fid}">'
        f'<label>Status<select name="status">{opts}</select></label>'
        f'{fld("Owner", "owner", rec.get("owner"))}'
        f'{fld("Responsible team", "responsible_team", rec.get("responsible_team"))}'
        f'<label>Due date<input name="due_date" type="date" value="{html.escape((rec.get("due_date") or "")[:10])}"></label>'
        f'{fld("Ticket ref", "ticket_reference", rec.get("ticket_reference"))}'
        f'<label>Resolution note<textarea name="resolution_note">{html.escape(rec.get("resolution_note", "") or "")}</textarea></label>'
        '<button type="button" class="fsave">Save</button><span class="mstatus"></span>'
        '</div></details>')


def _finding_record_row(rec, now):
    sev = rec.get("severity", "Medium")
    sc = _SEV_COLOR.get(sev, "#b8860b")
    status = rec.get("status", "Open")
    stc = _FSTATUS_COLOR.get(status, "#c0392b")
    due = rec.get("due_date") or ""
    od = ""
    if due and status not in ("Resolved", "Accepted", "False Positive"):
        try:
            dd = datetime.fromisoformat(due.replace("Z", "+00:00"))
            if dd.tzinfo is None:
                dd = dd.replace(tzinfo=timezone.utc)
            if dd < now:
                od = ' <span style="color:#c0392b;font-weight:600">(overdue)</span>'
        except (ValueError, AttributeError):
            pass
    owner = html.escape(rec.get("owner") or "—")
    return (
        f'<details class="finding" data-fstatus="{html.escape(status)}">'
        f'<summary>'
        f'<span class="pill" style="background:{sc}">{html.escape(rec.get("priority","P?"))}</span>'
        f'<span class="f-name">{html.escape(rec.get("title","—"))}'
        f'<span class="f-vendor">{html.escape(rec.get("asset_name",""))} · {html.escape(sev)}</span></span>'
        f'<span class="ptype" style="background:{stc}">{html.escape(status)}</span>'
        f'<span class="f-meta">owner: {owner} · due: {html.escape(due) or "—"}{od}</span>'
        f'</summary>'
        f'<div class="f-body">'
        f'<div class="f-col"><h4>Description</h4><p>{html.escape(rec.get("description",""))}</p>'
        f'<h4 style="margin-top:8px">Business impact</h4><p>{html.escape(rec.get("business_impact",""))}</p></div>'
        f'<div class="f-col"><h4>Recommended action</h4><p>{html.escape(rec.get("recommended_action",""))}</p>'
        f'<h4 style="margin-top:8px">Record</h4><ul>'
        f'<li>Finding ID: <code>{html.escape(rec.get("finding_id",""))}</code></li>'
        f'<li>First seen: {html.escape(rec.get("first_seen",""))} · Last: {html.escape(rec.get("last_seen",""))}</li>'
        f'<li>Ticket: {html.escape(rec.get("ticket_reference") or "—")}</li></ul></div>'
        f'<div class="f-col">{_finding_editor(rec)}</div>'
        f'</div></details>')


def _findings_section(findings):
    if findings is None:
        return ""
    now = datetime.now(timezone.utc)
    active = [f for f in findings if f.get("status") not in ("Resolved", "Accepted", "False Positive")]
    active.sort(key=lambda f: (["P1", "P2", "P3", "P4"].index(f.get("priority", "P4"))
                               if f.get("priority") in ("P1", "P2", "P3", "P4") else 9))
    counts = {}
    for f in findings:
        counts[f.get("status", "Open")] = counts.get(f.get("status", "Open"), 0) + 1
    open_n = sum(counts.get(s, 0) for s in ("Open", "Assigned", "Reopened"))
    prog_n = sum(counts.get(s, 0) for s in ("In Progress", "Pending Review"))
    resolved_n = counts.get("Resolved", 0)
    overdue = []
    for f in active:
        d = f.get("due_date")
        if not d:
            continue
        try:
            dd = datetime.fromisoformat(d.replace("Z", "+00:00"))
            if dd.tzinfo is None:
                dd = dd.replace(tzinfo=timezone.utc)
            if dd < now:
                overdue.append(f)
        except (ValueError, AttributeError):
            pass
    overdue_list = "".join(
        f'<li><b>{html.escape(f.get("title",""))}</b> — {html.escape(f.get("asset_name",""))} · '
        f'due {html.escape(f.get("due_date") or "")} · owner {html.escape(f.get("owner") or "—")}</li>'
        for f in overdue) or '<li class="governed">No overdue findings.</li>'

    # owner-based (open)
    owners = {}
    for f in active:
        owners[f.get("owner") or "Unassigned"] = owners.get(f.get("owner") or "Unassigned", 0) + 1
    owner_bars = _bars([(o, "", n, "#0f6cbd") for o, n in
                        sorted(owners.items(), key=lambda kv: -kv[1])[:8]],
                       max(owners.values(), default=1))

    rows = "".join(_finding_record_row(f, now) for f in active) or \
        '<div class="empty">No open findings. 👍</div>'
    return f"""
  <h3 style="margin:22px 4px 10px;font-size:13px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)">Findings — manageable records</h3>
  <div class="grid cols-4">
    <div class="card kpi crit"><span class="n">{open_n}</span><span class="l">Open / reopened</span></div>
    <div class="card kpi med"><span class="n">{prog_n}</span><span class="l">In progress / review</span></div>
    <div class="card kpi high"><span class="n">{len(overdue)}</span><span class="l">Overdue</span></div>
    <div class="card kpi low"><span class="n">{resolved_n}</span><span class="l">Resolved</span></div>
  </div>
  <div class="grid cols-2" style="margin-top:16px">
    <div class="card"><h3>Overdue findings</h3><ul>{overdue_list}</ul></div>
    <div class="card"><h3>Open findings by owner</h3>{owner_bars}</div>
  </div>
  <div class="card" style="margin-top:16px"><h3>Open findings ({len(active)})</h3>
    <div class="findings">{rows}</div></div>
"""


def _executive_section(apps, changes, findings):
    import executive
    m = executive.estate_metrics(apps, changes, findings)
    cov = executive.coverage(apps)
    surface = executive.usage_surface(apps)
    na = executive.needs_attention(apps, changes, findings)
    tc = executive.top_changes(changes, 5)

    cards = [
        (m["total_applications"], "AI Applications", "apps", ""),
        (m["total_agents"], "AI Agents", "apps", ""),
        (m["active_users"], "Active AI Users", "usage", ""),
        (m["unapproved"], "Unapproved AI", "apps", "high"),
        (m["local_agents"], "Local AI Agents", "governance", "muted"),
        (m["mcp_servers"], "MCP Servers", "governance", "muted"),
        (m["ai_models"], "AI Models", "governance", "muted"),
        (m["new_this_week"], "New Assets (7d)", "changes", ""),
        (m["unknown_assets"], "Unknown Assets", "apps", "crit"),
        (m["apps_without_owner"], "Apps w/o Owner", "governance", "high"),
        (m["agents_without_purpose"], "Agents w/o Purpose", "governance", "high"),
        (m["open_findings"], "Open Findings", "findings", "crit"),
        (m["overdue_findings"], "Overdue Findings", "findings", "high"),
        (f'{m["assessment_coverage"]}%', "Assessment Coverage", "governance", "low"),
    ]
    kpi = "".join(
        f'<a class="card kpi {cls}" data-goto="{goto}"><span class="n">{v}</span>'
        f'<span class="l">{html.escape(lbl)}</span></a>' for v, lbl, goto, cls in cards)

    na_html = "".join(f"<li>{html.escape(x)}</li>" for x in na) or \
        "<li>Nothing significant needs attention.</li>"
    tc_html = "".join(
        f'<li><b>{html.escape(e.get("change_type",""))}</b> {html.escape(e.get("asset_name",""))} '
        f'— {html.escape(e.get("description",""))}</li>' for e in tc) or \
        '<li class="governed">No significant changes this period.</li>'

    aa_bars = _bars([("Application", "", m["total_applications"], "#0f6cbd"),
                     ("Agent", "", m["total_agents"], "#7c3aed")],
                    max(m["total_applications"], m["total_agents"], 1))
    surf_bars = _bars([("Enterprise (admin-sanctioned)", "", surface["enterprise"], "#2e8b57"),
                       ("Web (user-consent)", "", surface["web"], "#b8860b"),
                       ("Local (connector required)", "", surface["local"], "#6b7280")],
                      max(surface["enterprise"], surface["web"], 1))
    return f"""
  <div class="kpi-grid">{kpi}</div>
  <div class="grid cols-2" style="margin-top:16px">
    <div class="card"><h3>Needs Attention</h3><ul class="na">{na_html}</ul></div>
    <div class="card"><h3>Top 5 changes</h3><ul>{tc_html}</ul></div>
  </div>
  <div class="card" style="margin-top:16px"><h3>Application vs Agent · usage surface</h3>
    <div class="grid cols-2"><div>{aa_bars}</div><div>{surf_bars}</div></div></div>
"""


_CONN_DOT = {True: charts.SEVERITY["Low"], False: charts.SEVERITY["Critical"], None: "#6b7280"}


_VIEWS = [("assessment", "Assessment", "Every control tested, with a pass or a fail"),
          ("portal", "AI estate", "One row per vendor, whichever route it came in by"),
          ("report", "OAuth assessment", "Per-application permissions, usage, governance"),
          ("connectors", "AI data sources", "Agents, Shadow AI traffic, sensitive data")]


def view_switcher(current, portal_href=None, report_href=None, connectors_href=None,
                  assessment_href=None):
    """
    The three-way nav carried by every page.

    Each view keeps a fixed colour so the control reads the same everywhere; the page
    you are on is filled rather than outlined. A destination with no href is dropped —
    nothing worse than a nav button that goes nowhere.
    """
    hrefs = {"portal": portal_href, "report": report_href, "connectors": connectors_href,
             "assessment": assessment_href}
    colors = {"assessment": charts.CATEGORICAL_LIGHT[2],
              "portal": charts.CATEGORICAL_LIGHT[6],
              "report": charts.CATEGORICAL_LIGHT[0],
              "connectors": charts.CATEGORICAL_LIGHT[1]}
    out = []
    for key, label, why in _VIEWS:
        href = hrefs.get(key)
        if key != current and not href:
            continue
        here = " here" if key == current else ""
        target = html.escape(href or "#", quote=True)
        out.append(f'<a class="{key}{here}" style="--vc:{colors[key]}" '
                   f'href="{target}" title="{html.escape(why)}">'
                   f'<i class="vd"></i><span class="vl">{html.escape(label)}</span></a>')
    return f'<nav class="vswitch">{"".join(out)}</nav>' if len(out) > 1 else ""


def _coverage_section(apps, connector_health=None):
    """
    Ownership coverage only — how much of the estate a human has claimed.

    Which data source answered is a different question with a different answer, and it is
    rendered beside this one on the detail page's Coverage tab rather than repeated here.
    Keeping two copies of that list is exactly how they drifted apart once before.
    """
    import executive
    cov = executive.coverage(apps)
    own_bar = _bars([("Owner coverage", f"{cov['owner_coverage']}%", cov["owner_coverage"],
                      charts.cat(0)),
                     ("Agent purpose coverage", f"{cov['purpose_coverage']}%",
                      cov["purpose_coverage"], charts.cat(6))], 100)
    return (f'<div class="card" style="margin-top:16px"><h3>Coverage Overview</h3>{own_bar}'
            f'<p class="governed">This is what people have recorded. What the tool itself '
            f'can see is the next section.</p></div>')


def _timeline_section(changes):
    if changes is None:
        return ""
    if not changes:
        return ('<div class="card" style="margin-top:16px"><h3>Changes</h3>'
                '<p class="governed">No changes since the previous scan '
                '(or this is the first scan — baseline).</p></div>')
    rows = ""
    for e in changes[:60]:
        imp = e.get("importance", "Info")
        c = _IMP_COLOR.get(imp, "#6b7280")
        ts = html.escape((e.get("timestamp") or "")[:16].replace("T", " "))
        rows += (
            f'<div class="tl-row" data-imp="{html.escape(imp)}">'
            f'<span class="ptype" style="background:{c}">{html.escape(e.get("change_type",""))}</span>'
            f'<span class="tl-name">{html.escape(e.get("asset_name",""))}</span>'
            f'<span class="tl-desc">{html.escape(e.get("description",""))}</span>'
            f'<span class="tl-ts">{ts}</span></div>')
    return (f'<div class="card" style="margin-top:16px"><h3>Changes — timeline '
            f'({len(changes)})</h3><div class="timeline">{rows}</div></div>')

LEVELS = charts.SEVERITY_ORDER
LEVEL_COLORS = _SEV_COLOR


# ---------------------------------------------------------------- JSON
def json_string(apps: list[dict]) -> str:
    return json.dumps(
        {"generated": datetime.now(timezone.utc).isoformat(), "findings": apps},
        ensure_ascii=False, indent=2)


def write_json(apps: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(json_string(apps))


# ---------------------------------------------------------------- helpers
def _scope_weight(scope: str) -> int:
    if scope in SENSITIVE_SCOPES:
        return SENSITIVE_SCOPES[scope]
    for frag, w in SCOPE_HEURISTICS:
        if frag in scope:
            return w
    return 1


def _donut(segments, size=180, stroke=28):
    """segments: [(label, value, color)] → SVG donut string."""
    return charts.donut(segments, center_label="Shadow AI", size=size, stroke=stroke)


def _bars(rows, maxv=None):
    """rows: [(label, sublabel, value, color)] → ranked horizontal bars."""
    return charts.hbar(rows)


_POSTURE_WEIGHTS = {"Critical": 14, "High": 7, "Medium": 2, "Low": 0.5,
                    "admin_consent": 3, "app_only": 4}
_POSTURE_SCALE = 120.0


def _posture_points(shadow, counts) -> list[tuple[str, int, float]]:
    """The (label, count, weight) rows the posture score is built from."""
    admin = sum(1 for a in shadow if a.get("consent_type") == "AllPrincipals")
    apponly = sum(1 for a in shadow
                  if any(_scope_weight((p.get("permission") or "").lower()) >= 8
                         for p in a.get("application_permissions", [])))
    w = _POSTURE_WEIGHTS
    return [("Critical findings", counts["Critical"], w["Critical"]),
            ("High findings", counts["High"], w["High"]),
            ("Medium findings", counts["Medium"], w["Medium"]),
            ("Low findings", counts["Low"], w["Low"]),
            ("Org-wide admin consent", admin, w["admin_consent"]),
            ("High-privilege app-only", apponly, w["app_only"])]


def _posture_score(shadow, counts) -> int:
    """
    One number for the tenant's AI exposure, 0 (clean) to 100 (severe).

    Deliberately not an average of risk scores: twenty Low-risk apps should not dilute
    two Criticals into a comfortable-looking number. Each severity band contributes a
    fixed weight, and the total is put through a saturating curve rather than simply
    clipped — a straight sum pins a mid-sized estate at exactly 100 and then stops
    moving, so getting worse and getting better both look identical.
    """
    if not shadow:
        return 0
    raw = sum(n * w for _label, n, w in _posture_points(shadow, counts))
    return round(100 * (1 - math.exp(-raw / _POSTURE_SCALE)))


def _posture_breakdown(shadow, counts) -> str:
    """Shows what the posture number is actually made of, so it isn't a black box."""
    rows = _posture_points(shadow, counts)
    items = "".join(
        f'<li><span>{html.escape(label)}</span>'
        f'<b>{n} &times; {w:g} = {n * w:g}</b></li>' for label, n, w in rows if n)
    if not items:
        return '<p class="governed">Nothing contributing to the score.</p>'
    total = sum(n * w for _label, n, w in rows)
    return (f'<ul class="posture-parts">{items}'
            f'<li><span>Exposure points</span><b>{total:g}</b></li></ul>')


def _triage_chart(shadow) -> str:
    """Risk against blast radius — which finding to work on first."""
    pts = [(a.get("display_name") or "—", a.get("risk_score", 0),
            a.get("user_count", 0), a.get("risk_level", "Low"),
            len(a.get("scopes", [])) + len(a.get("application_permissions", [])))
           for a in shadow]
    return charts.risk_scatter(pts)


def _permission_heatmap(shadow, top_apps=8, top_perms=7) -> str:
    """
    Where sensitive access piles up: the riskiest apps against the permissions most
    often granted to them, shaded by how sensitive each permission is.
    """
    counted = {}
    for a in shadow:
        for s in a.get("scopes", []):
            if _scope_weight(s) >= 5:
                counted[s] = counted.get(s, 0) + 1
    perms = [p for p, _ in sorted(counted.items(),
                                  key=lambda kv: (-kv[1], -_scope_weight(kv[0])))][:top_perms]
    apps = [a for a in shadow if any(s in perms for s in a.get("scopes", []))][:top_apps]
    if not apps or not perms:
        return charts._empty("No overlapping sensitive permissions to chart")
    values = [[_scope_weight(p) if p in set(a.get("scopes", [])) else 0 for p in perms]
              for a in apps]
    return charts.heatmap([a.get("display_name") or "—" for a in apps], perms, values,
                          legend_title="Permission sensitivity")


def _vendor_treemap(shadow, top=7) -> str:
    """
    Share of the estate by vendor.

    A treemap only says something when a few vendors dominate. Estates where every
    vendor has one or two apps are common, and there the folded "Other" tile becomes the
    biggest thing on screen — which tells the reader nothing except that the form was
    wrong. In that case this falls back to ranked bars, which read fine flat. Either
    way the tail folds rather than generating a ninth hue.
    """
    by_vendor = {}
    for a in shadow:
        vendor = a.get("vendor") or "Unknown"
        by_vendor[vendor] = by_vendor.get(vendor, 0) + 1
    ranked = sorted(by_vendor.items(), key=lambda kv: -kv[1])
    if not ranked:
        return charts._empty("No applications to chart")

    tail = sum(n for _, n in ranked[top:])
    if tail > ranked[0][1]:
        rows = [(v, f"{n} app{'s' if n != 1 else ''}", n, charts.cat(i))
                for i, (v, n) in enumerate(ranked[:charts.CATEGORICAL_SLOTS])]
        return charts.hbar(rows) + (
            f'<p class="governed">{len(ranked)} vendors, none dominant — shown ranked '
            f'rather than as shares.</p>' if len(ranked) > charts.CATEGORICAL_SLOTS else "")

    items = [(v, n, charts.cat(i)) for i, (v, n) in enumerate(ranked[:top])]
    if tail:
        items.append((f"Other ({len(ranked) - top} vendors)", tail, charts.cat(top)))
    return charts.treemap(items)


def _perm_type(app):
    delegated = bool(app.get("delegated_permissions") or app.get("scopes"))
    apponly = bool(app.get("has_app_only_access"))
    if delegated and apponly:
        return "both"
    if apponly:
        return "apponly"
    if delegated:
        return "delegated"
    return "none"


_PERM_CHIP = {"both": ("delegated + app-only", "#7c3aed"),
              "apponly": ("app-only", "#b45309"),
              "delegated": ("delegated", "#0f6cbd"),
              "none": ("no permissions", "#6b7280")}

_USAGE_CHIP = {"active": ("active", "#2e8b57"), "inactive": ("inactive 30d+", "#b45309"),
               "unused": ("never used", "#c0392b"), "unknown": ("no activity", "#6b7280")}


def _usage_type(app):
    u = app.get("usage")
    if not u or not u.get("available"):
        return "unknown"
    if u.get("never_used"):
        return "unused"
    if u.get("inactive_30d"):
        return "inactive"
    return "active"


def _days_ago(iso):
    dt = None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00")) if iso else None
    except (ValueError, AttributeError):
        dt = None
    if not dt:
        return None
    return (datetime.now(timezone.utc) - dt).days


def _trend_svg(values, width=680, height=150):
    if not values or max(values) == 0:
        return '<div class="empty">No activity data (requires Entra ID P1)</div>'
    n = len(values)
    labels = [f"{n - i} days ago" if i < n - 1 else "today" for i in range(n)]
    return charts.timeseries(values, labels=labels, width=width, height=height,
                             unit=" users")


def _usage_block(app):
    u = app.get("usage")
    if not u or not u.get("available"):
        return '<h4>Usage</h4><p class="f-pub">No activity data (Entra ID P1)</p>'
    if u.get("never_used"):
        last = "never used"
    else:
        d = _days_ago(u.get("last_used_date"))
        last = f"{d} days ago" if d is not None else "—"
    sp = ""
    if app.get("has_app_only_access") and u.get("last_service_principal_signin"):
        dsp = _days_ago(u["last_service_principal_signin"])
        sp = f'<li>Last SP (app-only) sign-in: {dsp} days ago</li>' if dsp is not None else ""
    return (
        '<h4>Usage</h4><ul>'
        f'<li>Last used: <b>{html.escape(last)}</b></li>'
        f'<li>Active users: {u.get("active_users_7d",0)} (7d) · '
        f'{u.get("active_users_30d",0)} (30d) · {u.get("active_users_90d",0)} (90d)</li>'
        f'<li>Consent: {u.get("consent_user_count",0)} users</li>'
        f'<li>Sign-ins (30d): {u.get("successful_signins_30d",0)} successful / '
        f'{u.get("failed_signins_30d",0)} failed</li>'
        f'<li>{u.get("unique_ip_count",0)} IP · {u.get("country_count",0)} countries</li>'
        f'{sp}</ul>')


def _lifecycle_status(app):
    return (app.get("lifecycle") or {}).get("status") or "Discovered"


def _review_due_days(app, now=None):
    now = now or datetime.now(timezone.utc)
    d = (app.get("lifecycle") or {}).get("next_review_date")
    if not d:
        return None
    try:
        dt = datetime.fromisoformat(d.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - now).days


def _governance_block(app):
    own = app.get("ownership") or {}
    bc = app.get("business_context") or {}
    lc = app.get("lifecycle") or {}
    ti = app.get("technical_inventory") or {}
    sp_owners = ", ".join(html.escape(o.get("name", "")) for o in
                          own.get("service_principal_owners", [])) or "—"

    def val(x):
        return html.escape(x) if x else "—"

    cred_exp = ti.get("credential_next_expiry")
    cred = f'{ti.get("credential_count", 0)} credential'
    if cred_exp:
        cred += f' · nearest expiry {html.escape(cred_exp[:10])}'
    review = lc.get("next_review_date")
    return (
        '<h4>Ownership & Lifecycle</h4><ul>'
        f'<li>Technical owner (SP): {sp_owners}</li>'
        f'<li>Business owner: {val(own.get("business_owner"))}'
        f' · Technical: {val(own.get("technical_owner"))}</li>'
        f'<li>Sponsor: {val(own.get("sponsor"))}</li>'
        f'<li>Business unit: {val(bc.get("business_unit"))} · {val(bc.get("subsidiary"))}</li>'
        f'<li>Purpose: {val(bc.get("purpose"))}</li>'
        f'<li>Criticality: {val(bc.get("criticality"))} · Environment: {val(bc.get("environment"))}</li>'
        f'<li>Next review: {val(review)}</li>'
        f'<li>{cred}</li></ul>')


def _classification(app):
    return app.get("classification") or {"category": "Unknown AI", "ownership": "Unknown",
                                         "confidence": 0, "reasons": [], "manual_override": False}


def _classification_block(app):
    c = _classification(app)
    reasons = "".join(f"<li>{html.escape(r)}</li>" for r in c.get("reasons", []))
    ov = ' · <b>manual override</b>' if c.get("manual_override") else ""
    return (
        '<h4>Classification</h4><ul>'
        f'<li>Category: <b>{html.escape(c.get("category", "Unknown AI"))}</b>{ov}</li>'
        f'<li>Ownership: {html.escape(c.get("ownership", "Unknown"))} · Confidence: {c.get("confidence", 0)}%</li>'
        f'</ul><h4 style="margin-top:6px">Classification reason</h4><ul>{reasons}</ul>')


def _editor_form(app):
    lc = app.get("lifecycle") or {}
    bc = app.get("business_context") or {}
    own = app.get("ownership") or {}

    def opts(values, current):
        return "".join(f'<option{" selected" if v == current else ""}>{html.escape(v)}</option>'
                       for v in values)

    def field(label, name, value=""):
        return (f'<label>{label}<input name="{name}" value="{html.escape(value or "")}"></label>')

    review = (lc.get("next_review_date") or "")[:10]
    return (
        '<details class="editor"><summary>Edit metadata</summary>'
        f'<div class="mform" data-app="{html.escape(app.get("app_id", ""))}">'
        f'<label>Class (override)<select name="class_category">{opts([""] + AI_CATEGORIES, (app.get("classification_override") or {}).get("category") or "")}</select></label>'
        f'<label>Ownership (override)<select name="class_ownership">{opts([""] + OWNERSHIP_CLASSES, (app.get("classification_override") or {}).get("ownership") or "")}</select></label>'
        f'<label>Lifecycle<select name="status">{opts(LIFECYCLE_STATUSES, _lifecycle_status(app))}</select></label>'
        f'{field("Business owner", "business_owner", own.get("business_owner"))}'
        f'{field("Technical owner", "technical_owner", own.get("technical_owner"))}'
        f'{field("Sponsor", "sponsor", own.get("sponsor"))}'
        f'{field("Business unit", "business_unit", bc.get("business_unit"))}'
        f'{field("Subsidiary", "subsidiary", bc.get("subsidiary"))}'
        f'{field("Purpose", "purpose", bc.get("purpose"))}'
        f'<label>Criticality<select name="criticality">{opts(CRITICALITY, bc.get("criticality") or "")}</select></label>'
        f'<label>Environment<select name="environment">{opts(ENVIRONMENTS, bc.get("environment") or "")}</select></label>'
        f'<label>Next review<input name="next_review_date" type="date" value="{html.escape(review)}"></label>'
        f'<label>Notes<textarea name="notes">{html.escape(app.get("notes", "") or "")}</textarea></label>'
        '<button type="button" class="msave">Save</button><span class="mstatus"></span>'
        '</div></details>')


def _finding_row(app):
    color = LEVEL_COLORS.get(app["risk_level"], "#555")
    scopes = ", ".join(html.escape(s) for s in app.get("scopes", [])) or "—"
    reasons = "".join(f"<li>{html.escape(r)}</li>" for r in app.get("reasons", []))
    remed = "".join(f"<li>{html.escape(r)}</li>" for r in app.get("remediation", []))
    consent = app.get("consent_type") or "no consent"
    tag = "3rd-party" if app.get("third_party") else "internal/first-party"
    ver = "✓ verified" if app.get("verified_publisher") else "⚠ unverified"
    ptype = _perm_type(app)
    chip_label, chip_color = _PERM_CHIP[ptype]
    utype = _usage_type(app)
    u_label, u_color = _USAGE_CHIP[utype]
    status = _lifecycle_status(app)
    lc_color = _LIFECYCLE_COLOR.get(status, "#6b7280")
    cls = _classification(app)
    cat = cls.get("category", "Unknown AI")
    cat_color = _CAT_COLOR.get(cat, "#6b7280")
    bc = app.get("business_context") or {}
    bu = bc.get("business_unit") or ""
    sub = bc.get("subsidiary") or ""

    app_perms = app.get("application_permissions", [])
    if app_perms:
        rows = "".join(
            f'<li><b>{html.escape(p.get("permission",""))}</b> '
            f'<span class="res">({html.escape(p.get("resource",""))})</span></li>'
            for p in app_perms)
        app_block = (f'<h4>App-only permissions (unattended)</h4><ul class="apperms">{rows}</ul>')
    else:
        app_block = ""

    return (
        f'<details class="finding" data-perm="{ptype}" data-usage="{utype}" '
        f'data-bu="{html.escape(bu)}" data-sub="{html.escape(sub)}" data-cat="{html.escape(cat)}">'
        f'<summary>'
        f'<span class="pill" style="background:{color}">{app["risk_score"]}</span>'
        f'<span class="f-name">{html.escape(app.get("display_name") or "—")}'
        f'<span class="f-vendor">{html.escape(app.get("vendor",""))}</span></span>'
        f'<span class="ptype" style="background:{cat_color}">{html.escape(cat)} · {cls.get("confidence",0)}%</span>'
        f'<span class="ptype" style="background:{chip_color}">{chip_label}</span>'
        f'<span class="ptype" style="background:{u_color}">{u_label}</span>'
        f'<span class="ptype" style="background:{lc_color}">{html.escape(status)}</span>'
        f'<span class="f-meta">{tag} · {html.escape(consent)} · {app.get("user_count",0)} users</span>'
        f'<span class="f-level" style="color:{color}">{html.escape(app["risk_level"])}</span>'
        f'</summary>'
        f'<div class="f-body">'
        f'<div class="f-col">{_classification_block(app)}</div>'
        f'<div class="f-col"><h4>Delegated permissions</h4><code>{scopes}</code>'
        f'{app_block}<p class="f-pub">{ver}</p></div>'
        f'<div class="f-col">{_usage_block(app)}</div>'
        f'<div class="f-col">{_governance_block(app)}</div>'
        f'<div class="f-col"><h4>Why risky</h4><ul>{reasons}</ul></div>'
        f'<div class="f-col"><h4>Remediation</h4><ul>{remed}</ul></div>'
        f'</div>{_editor_form(app)}</details>')


CSS = """
:root{
 --bg:#f3f4f6; --panel:#ffffff; --ink:#1a1a1a; --muted:#5f6b7a; --line:#e3e6ea;
 --track:#e9edf1; --accent:#0f6cbd; --shadow:0 1px 3px rgba(0,0,0,.08);
}
@media (prefers-color-scheme:dark){
 :root{--bg:#0f1419;--panel:#171e26;--ink:#e6edf3;--muted:#8b98a6;--line:#232c37;
 --track:#232c37;--accent:#4aa3f0;--shadow:0 1px 3px rgba(0,0,0,.4);}
}
:root[data-theme=light]{--bg:#f3f4f6;--panel:#fff;--ink:#1a1a1a;--muted:#5f6b7a;--line:#e3e6ea;--track:#e9edf1;--accent:#0f6cbd;--shadow:0 1px 3px rgba(0,0,0,.08);}
:root[data-theme=dark]{--bg:#0f1419;--panel:#171e26;--ink:#e6edf3;--muted:#8b98a6;--line:#232c37;--track:#232c37;--accent:#4aa3f0;--shadow:0 1px 3px rgba(0,0,0,.4);}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
 font:14px/1.5 'Segoe UI',-apple-system,Roboto,sans-serif}
header{display:flex;align-items:center;gap:14px;padding:12px 22px;background:var(--panel);
 border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.logo{flex-shrink:0}
header h1{font-size:15px;margin:0;font-weight:600}
header .spacer{flex:1}
header .tenant{font-size:12px;color:var(--muted)}
.themebtn{cursor:pointer;border:1px solid var(--line);background:transparent;color:var(--ink);
 border-radius:6px;padding:4px 9px;font-size:13px}
.tabs{display:flex;gap:2px;margin-left:10px;flex-wrap:wrap}
.navlink{cursor:pointer;padding:8px 13px;font-size:13px;color:var(--muted);font-weight:600;
 border-bottom:2px solid transparent;user-select:none}
.navlink:hover{color:var(--ink)}
.navlink.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab{display:none;animation:fade .18s ease}
.tab.active{display:block}
@keyframes fade{from{opacity:.4}to{opacity:1}}
.hero{display:grid;grid-template-columns:1.1fr 1.2fr 1fr;gap:16px;align-items:stretch}
.hero .card{margin:0}
.tiles{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.tile{display:flex;flex-direction:column;justify-content:center;gap:3px}
.tile .n{font-size:32px;font-weight:700;line-height:1}
.tile .l{font-size:12px;color:var(--muted)}
.tile.high .n{color:#d35400}
@media(max-width:900px){.hero{grid-template-columns:1fr}}
main{max-width:1180px;margin:0 auto;padding:22px}
.grid{display:grid;gap:16px}
.cols-4{grid-template-columns:repeat(4,1fr)}
.cols-2{grid-template-columns:1fr 1fr}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
 padding:18px;box-shadow:var(--shadow)}
.card h3{margin:0 0 14px;font-size:13px;font-weight:600;letter-spacing:.02em;
 text-transform:uppercase;color:var(--muted)}
.kpi{display:flex;flex-direction:column;gap:2px}
.kpi .n{font-size:30px;font-weight:700;line-height:1}
.kpi .l{font-size:12px;color:var(--muted)}
.kpi.crit .n{color:#c0392b}.kpi.high .n{color:#d35400}
.kpi.med .n{color:#b8860b}.kpi.low .n{color:#2e8b57}.kpi.muted .n{color:var(--muted)}
a.card{text-decoration:none;color:inherit;cursor:pointer;transition:border-color .15s}
a.card:hover{border-color:var(--accent)}
a.card .n{font-size:24px}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px}
.na li{margin:5px 0}
/* The three-view switcher, shared by all three pages so the same control sits in the
   same place wherever you are. Colour marks the destination, not the state. */
/* A tab row, a tenant GUID and the three-view switcher will not share one line unless
   the header gives ground: tighter tabs, a truncating tenant, a logo that never wraps. */
header{gap:10px}
header h1{white-space:nowrap}
header .tabs{gap:0;flex-wrap:nowrap;overflow-x:auto;scrollbar-width:none}
header .tabs::-webkit-scrollbar{display:none}
header .navlink{padding:8px 9px;white-space:nowrap}
header .tenant{max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
 flex:0 1 auto}
@media(max-width:1150px){header .tenant{display:none}}
.vswitch{display:flex;gap:6px;align-items:center;flex:0 0 auto}
.vswitch a{display:inline-flex;align-items:center;gap:7px;text-decoration:none;
 font-size:12.5px;font-weight:600;padding:6px 13px;border-radius:7px;white-space:nowrap;
 border:1px solid var(--vc);color:var(--vc);transition:background .12s}
.vswitch a:hover{background:color-mix(in srgb,var(--vc) 12%,transparent)}
.vswitch a.here{background:var(--vc);color:#fff;cursor:default}
.vswitch a .vd{width:7px;height:7px;border-radius:50%;background:currentColor;flex:0 0 auto}
@media(max-width:820px){.vswitch a span.vl{display:none}.vswitch a{padding:6px 9px}}
.gov-cmd{background:var(--track);border-radius:8px;padding:11px 13px;font-size:11.5px;
 line-height:1.5;overflow-x:auto;margin:10px 0;color:var(--ink)}
details.explain{border:1px solid var(--line);border-radius:9px;padding:10px 14px;
 margin:0 0 16px;background:var(--panel);font-size:13px;color:var(--muted);line-height:1.55}
details.explain summary{cursor:pointer;font-weight:600;color:var(--ink);font-size:13px}
details.explain[open] summary{margin-bottom:8px}
details.explain b{color:var(--ink)}
details.explain code{background:var(--track);padding:1px 5px;border-radius:4px}
.scoretab{width:100%;border-collapse:collapse;font-size:12px;margin:10px 0}
.scoretab th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.03em;
 color:var(--muted);padding:6px 10px 6px 0;border-bottom:1px solid var(--line)}
.scoretab td{padding:6px 10px 6px 0;border-bottom:1px solid var(--line);vertical-align:top}
.scoretab td:nth-child(2){white-space:nowrap;font-variant-numeric:tabular-nums;color:var(--ink)}
.posture-parts{list-style:none;margin:14px 0 0;padding:0;font-size:12px}
.posture-parts li{display:flex;justify-content:space-between;gap:12px;padding:5px 0;
 border-top:1px solid var(--line);color:var(--muted)}
.posture-parts b{color:var(--ink);font-variant-numeric:tabular-nums}
.conn{margin:8px 0 0;padding:0}
.conn li{list-style:none;display:flex;align-items:center;gap:8px;font-size:13px;margin:5px 0}
.summary{display:flex;gap:26px;align-items:center;flex-wrap:wrap}
.tenant-facts{display:grid;grid-template-columns:auto auto;gap:6px 26px;font-size:13px}
.tenant-facts b{color:var(--muted);font-weight:500}
.donut-num{font-size:34px;font-weight:700;fill:var(--ink)}
.donut-cap{font-size:11px;fill:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.legend{display:flex;flex-direction:column;gap:7px}
.legend div{display:flex;align-items:center;gap:8px;font-size:13px}
.dot{width:11px;height:11px;border-radius:3px;display:inline-block}
.bar-row{display:flex;align-items:center;gap:10px;margin:9px 0}
.bar-label{width:190px;font-size:13px;flex-shrink:0}
.bar-sub{display:block;font-size:11px;color:var(--muted)}
.bar-track{flex:1;height:9px;background:var(--track);border-radius:6px;overflow:hidden}
.bar-fill{height:100%;border-radius:6px}
.bar-val{width:34px;text-align:right;font-size:13px;font-variant-numeric:tabular-nums}
.empty{color:var(--muted);font-size:13px;padding:8px 0}
.findings{margin-top:4px}
.finding{border:1px solid var(--line);border-radius:10px;margin-bottom:8px;background:var(--panel);
 overflow:hidden}
.finding summary{display:flex;align-items:center;gap:14px;padding:12px 16px;cursor:pointer;
 list-style:none}
.finding summary::-webkit-details-marker{display:none}
.pill{color:#fff;min-width:34px;text-align:center;padding:3px 8px;border-radius:7px;
 font-weight:700;font-size:13px}
.f-name{font-weight:600;flex:1}
.f-vendor{display:block;font-size:12px;color:var(--muted);font-weight:400}
.f-meta{font-size:12px;color:var(--muted);text-align:right}
.f-level{font-weight:600;min-width:56px;text-align:right}
.f-body{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:18px;
 padding:4px 16px 16px;border-top:1px solid var(--line)}
.trend{display:block}
.f-body h4{margin:12px 0 6px;font-size:12px;color:var(--muted);text-transform:uppercase}
.f-body ul{margin:0;padding-left:16px}.f-body li{margin:3px 0}
.f-body code{font-size:12px;word-break:break-word;color:var(--ink)}
.f-pub{font-size:12px;color:var(--muted);margin:8px 0 0}
.governed{font-size:13px;color:var(--muted)}
.governed summary{cursor:pointer;font-weight:600;color:var(--ink)}
.governed ul{columns:2;margin:10px 0 0;padding-left:18px}
.ptype{color:#fff;font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;white-space:nowrap}
.apperms{margin:4px 0 0}.apperms b{font-weight:600}.apperms .res{color:var(--muted);font-size:12px}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 14px}
.filters button{cursor:pointer;border:1px solid var(--line);background:transparent;color:var(--ink);
 border-radius:999px;padding:5px 14px;font-size:13px}
.filters button.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.filters label{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted)}
.filters select{border:1px solid var(--line);background:transparent;color:var(--ink);
 border-radius:999px;padding:5px 12px;font-size:13px}
.editor{margin:0 16px 14px;border-top:1px dashed var(--line)}
.editor summary{cursor:pointer;padding:8px 0;font-size:13px;color:var(--accent);font-weight:600}
.mform,.fform{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;padding:8px 0}
.mform label,.fform label{display:flex;flex-direction:column;font-size:12px;color:var(--muted);gap:4px}
.mform input,.mform select,.mform textarea,.fform input,.fform select,.fform textarea{
 background:var(--bg);color:var(--ink);border:1px solid var(--line);border-radius:6px;
 padding:6px 8px;font:13px inherit}
.mform textarea,.fform textarea{min-height:46px;grid-column:1/-1}
.mform .msave,.fform .fsave{background:var(--accent);color:#fff;border:none;border-radius:6px;
 padding:8px 16px;cursor:pointer;font-weight:600;align-self:end}
.mstatus{font-size:12px;color:var(--muted);align-self:center}
.timeline{display:flex;flex-direction:column}
.tl-row{display:flex;align-items:center;gap:12px;padding:8px 4px;border-bottom:1px solid var(--line);font-size:13px}
.tl-name{font-weight:600;min-width:130px}
.tl-desc{flex:1}
.tl-ts{color:var(--muted);font-size:12px;white-space:nowrap}
@media(max-width:820px){.tl-desc{display:none}}
.foot{color:var(--muted);font-size:12px;text-align:center;padding:18px}
@media(max-width:820px){.cols-4,.cols-2{grid-template-columns:1fr}
 .f-body{grid-template-columns:1fr}.bar-label{width:130px}
 .f-meta,.ptype{display:none}}
"""

THEME_JS = """
(function(){
var aiLink=document.getElementById('aiDataSourcesLink');
if(aiLink){
  var localHref=aiLink.getAttribute('data-local-href');
  if(location.pathname.indexOf('/api/')===0){
    var aiCode=new URLSearchParams(location.search).get('code');
    aiLink.href='/api/connectors?format=html'+(aiCode?'&code='+encodeURIComponent(aiCode):'');
  }else if(localHref){
    aiLink.href=localHref;
  }else{
    aiLink.remove();
  }
}
})();
(function(){var b=document.getElementById('tg');
b.onclick=function(){var r=document.documentElement;
var d=(r.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light'))==='dark';
r.setAttribute('data-theme',d?'light':'dark');b.textContent=d?'\\u263C':'\\u263E';};
function showTab(n){document.querySelectorAll('.tab').forEach(function(t){t.classList.toggle('active',t.getAttribute('data-tab')===n);});document.querySelectorAll('.navlink').forEach(function(x){x.classList.toggle('active',x.getAttribute('data-tab')===n);});window.scrollTo(0,0);}
document.querySelectorAll('.navlink').forEach(function(l){l.onclick=function(){showTab(l.getAttribute('data-tab'));};});
document.querySelectorAll('[data-goto]').forEach(function(c){c.onclick=function(e){e.preventDefault();showTab(c.getAttribute('data-goto'));};});
var state={perm:'all',usage:'all',bu:'all',sub:'all',cat:'all'};
function apply(){document.querySelectorAll('.finding').forEach(function(el){
 var show=true;
 for(var d in state){var s=state[d];if(s==='all')continue;
  var val=el.getAttribute('data-'+d)||'';
  if(d==='perm'){if(!(val===s||(s==='apponly'&&val==='both')))show=false;}
  else if(val!==s)show=false;}
 el.style.display=show?'':'none';});}
document.querySelectorAll('.filters button').forEach(function(b){b.onclick=function(){
 state[b.getAttribute('data-group')]=b.getAttribute('data-value');
 b.parentNode.querySelectorAll('button').forEach(function(x){x.classList.remove('active')});
 b.classList.add('active');apply();};});
document.querySelectorAll('.filters select').forEach(function(s){s.onchange=function(){
 state[s.getAttribute('data-group')]=s.value;apply();};});
var code=new URLSearchParams(location.search).get('code')||'';
document.querySelectorAll('.msave').forEach(function(btn){btn.onclick=function(){
 var box=btn.closest('.mform'),app=box.getAttribute('data-app');
 function v(n){var e=box.querySelector('[name="'+n+'"]');return e?e.value:'';}
 var body={app_id:app,ownership:{business_owner:v('business_owner'),technical_owner:v('technical_owner'),sponsor:v('sponsor')},business_context:{business_unit:v('business_unit'),subsidiary:v('subsidiary'),purpose:v('purpose'),criticality:v('criticality'),environment:v('environment')},lifecycle:{status:v('status'),next_review_date:v('next_review_date')||null},classification:{category:v('class_category')||null,ownership:v('class_ownership')||null},notes:v('notes')};
 var st=box.querySelector('.mstatus');st.textContent='Saving...';
 fetch('/api/metadata?code='+encodeURIComponent(code),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.ok?r.json():Promise.reject(r.status);}).then(function(){st.textContent='\\u2713 Saved (applied on next scan)';}).catch(function(e){st.textContent='Error: '+e;});};});
document.querySelectorAll('.fsave').forEach(function(btn){btn.onclick=function(){
 var box=btn.closest('.fform'),fid=box.getAttribute('data-finding');
 function v(n){var e=box.querySelector('[name="'+n+'"]');return e?e.value:'';}
 var body={finding_id:fid,status:v('status'),owner:v('owner'),responsible_team:v('responsible_team'),due_date:v('due_date')||null,ticket_reference:v('ticket_reference'),resolution_note:v('resolution_note')};
 var st=box.querySelector('.mstatus');st.textContent='Saving...';
 fetch('/api/finding?code='+encodeURIComponent(code),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.ok?r.json():Promise.reject(r.status);}).then(function(){st.textContent='\\u2713 Saved';}).catch(function(e){st.textContent='Error: '+e;});};});
})();
"""


def build_tabs(apps: list[dict], tenant_id: str, changes=None, findings=None,
               connector_health=None) -> dict:
    """
    The six tab bodies of the core dashboard.

    Split out of html_string so the unified portal can place these sections beside the
    connector ones instead of reimplementing them. html_string wraps this.
    """
    return _build(apps, tenant_id, changes, findings, connector_health)["tabs"]


def html_string(apps: list[dict], tenant_id: str, changes=None, findings=None,
                connector_health=None, connectors_href=None, portal_href=None,
                assessment_href=None) -> str:
    return _build(apps, tenant_id, changes, findings, connector_health,
                  connectors_href, portal_href, assessment_href)["page"]


def _build(apps: list[dict], tenant_id: str, changes=None, findings=None,
           connector_health=None, connectors_href=None, portal_href=None,
           assessment_href=None) -> dict:
    microsoft = [a for a in apps if a.get("first_party_microsoft")]
    shadow = [a for a in apps if not a.get("first_party_microsoft")]
    shadow.sort(key=lambda a: a["risk_score"], reverse=True)

    counts = {lv: sum(1 for a in shadow if a["risk_level"] == lv) for lv in LEVELS}
    third = sum(1 for a in shadow if a.get("third_party"))

    donut_segments = [(lv, counts[lv], LEVEL_COLORS[lv]) for lv in LEVELS]
    donut = _donut(donut_segments)
    legend = "".join(
        f'<div><span class="dot" style="background:{LEVEL_COLORS[lv]}"></span>'
        f'{lv} <b style="margin-left:auto">{counts[lv]}</b></div>' for lv in LEVELS)

    top_rows = [(a.get("display_name") or "—", a.get("vendor", ""), a["risk_score"],
                 LEVEL_COLORS.get(a["risk_level"], "#555")) for a in shadow[:8]]
    top_bars = _bars(top_rows, max((a["risk_score"] for a in shadow), default=1))

    posture = _posture_score(shadow, counts)
    triage_chart = _triage_chart(shadow)
    permission_heatmap = _permission_heatmap(shadow)
    vendor_treemap = _vendor_treemap(shadow)
    severity_legend = charts.legend(
        [(lv, LEVEL_COLORS[lv], counts[lv]) for lv in LEVELS])

    scope_count = {}
    for a in shadow:
        for s in a.get("scopes", []):
            if _scope_weight(s) >= 5:
                scope_count[s] = scope_count.get(s, 0) + 1
    scope_rows = sorted(scope_count.items(), key=lambda kv: (-kv[1], -_scope_weight(kv[0])))[:8]
    scope_bars = _bars(
        [(s, f"sensitivity {_scope_weight(s)}/10", c, "#0f6cbd") for s, c in scope_rows],
        max((c for _, c in scope_rows), default=1))

    admin = sum(1 for a in shadow if a.get("consent_type") == "AllPrincipals")
    persist = sum(1 for a in shadow if "offline_access" in a.get("scopes", []))
    unverified = sum(1 for a in shadow if not a.get("verified_publisher"))

    # Permission-type distribution (delegated / app-only / both)
    delegated_n = sum(1 for a in shadow if a.get("delegated_permissions") or a.get("scopes"))
    apponly_n = sum(1 for a in shadow if a.get("has_app_only_access"))
    both_n = sum(1 for a in shadow
                 if (a.get("delegated_permissions") or a.get("scopes")) and a.get("has_app_only_access"))
    highpriv_apponly = sum(
        1 for a in shadow
        if any(_scope_weight(p["permission"].lower()) >= 8
               for p in a.get("application_permissions", [])))

    # Usage / activity (Entra ID P1 — graceful if unavailable)
    activity_available = any((a.get("usage") or {}).get("available") for a in shadow)
    active_users_30d = sum((a.get("usage") or {}).get("active_users_30d", 0) for a in shadow)
    inactive_apps = sum(1 for a in shadow if (a.get("usage") or {}).get("inactive_30d"))
    apponly_active = sum(
        1 for a in shadow if a.get("has_app_only_access")
        and (a.get("usage") or {}).get("last_service_principal_signin")
        and not (a.get("usage") or {}).get("inactive_30d"))
    # aggregate daily active-user trend (30d)
    trend = [0] * 30
    for a in shadow:
        d = (a.get("usage") or {}).get("daily_active_30d") or []
        for i, v in enumerate(d[:30]):
            trend[i] += v
    most_used = sorted(shadow, key=lambda a: (a.get("usage") or {}).get("active_users_30d", 0),
                       reverse=True)
    most_used = [a for a in most_used if (a.get("usage") or {}).get("active_users_30d", 0) > 0][:6]
    growing = sorted(shadow, key=lambda a: (a.get("usage") or {}).get("growth_7d", 0),
                     reverse=True)
    growing = [a for a in growing if (a.get("usage") or {}).get("growth_7d", 0) > 0][:6]
    most_used_bars = _bars([(a.get("display_name") or "—", a.get("vendor", ""),
                             (a.get("usage") or {}).get("active_users_30d", 0), "#2e8b57")
                            for a in most_used], max(((a.get("usage") or {}).get("active_users_30d", 0)
                                                      for a in most_used), default=1))
    growing_bars = _bars([(a.get("display_name") or "—", "7d growth",
                           (a.get("usage") or {}).get("growth_7d", 0), "#7c3aed")
                          for a in growing], max(((a.get("usage") or {}).get("growth_7d", 0)
                                                  for a in growing), default=1))

    # New AI applications — by business unit (criterion 8)
    new_ids = {e["asset_id"] for e in (changes or []) if e.get("change_type") == "NEW_APPLICATION"}
    new_bu_section = ""
    if new_ids:
        id_map = {a.get("app_id"): a for a in apps}
        by_bu = {}
        for aid in new_ids:
            a = id_map.get(aid) or {}
            bu = (a.get("business_context") or {}).get("business_unit") or "Unassigned"
            by_bu.setdefault(bu, []).append(a.get("display_name") or aid)
        rows = "".join(f'<li><b>{html.escape(bu)}</b>: {html.escape(", ".join(sorted(n)))}</li>'
                       for bu, n in sorted(by_bu.items()))
        new_bu_section = (f'<div class="card" style="margin-top:16px">'
                          f'<h3>New AI applications — by business unit ({len(new_ids)})</h3>'
                          f'<ul>{rows}</ul></div>')

    if activity_available:
        usage_section = f"""
  <h3 style="margin:22px 4px 10px;font-size:13px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)">Usage & Activity (real sign-in)</h3>
  <div class="grid cols-4">
    <div class="card kpi"><span class="n">{active_users_30d}</span><span class="l">Active AI usage (30d)</span></div>
    <div class="card kpi crit"><span class="n">{inactive_apps}</span><span class="l">Unused apps (30d+)</span></div>
    <div class="card kpi"><span class="n">{apponly_active}</span><span class="l">App-only active apps</span></div>
    <div class="card kpi"><span class="n">{len(growing)}</span><span class="l">Growing apps</span></div>
  </div>
  <div class="grid cols-2" style="margin-top:16px">
    <div class="card"><h3>Active user trend (last 30 days)</h3>{_trend_svg(trend)}</div>
    <div class="card"><h3>Most used applications</h3>{most_used_bars}</div>
  </div>
  <div class="card" style="margin-top:16px"><h3>Fastest-growing applications (7d)</h3>{growing_bars}</div>
"""
    else:
        usage_section = ('<div class="card" style="margin-top:16px">'
                         '<h3>Usage & Activity</h3>'
                         '<p class="governed">Sign-in activity unavailable — real usage '
                         'metrics require an <b>Entra ID P1/P2</b> license. '
                         'The assessment continues uninterrupted; consent/permission findings remain valid.</p></div>')

    # Governance (ownership + lifecycle)
    lc_counts = {s: sum(1 for a in shadow if _lifecycle_status(a) == s) for s in LIFECYCLE_STATUSES}
    approved = lc_counts.get("Approved", 0)
    under_review = lc_counts.get("Under Review", 0)
    blocked = lc_counts.get("Blocked", 0) + lc_counts.get("Restricted", 0)
    review_due = [(_review_due_days(a), a) for a in shadow]
    review_due = sorted([(d, a) for d, a in review_due if d is not None and d <= 30],
                        key=lambda x: x[0])
    reviews_list = "".join(
        f'<li><b>{html.escape(a.get("display_name") or "—")}</b> — '
        f'{html.escape((a.get("lifecycle") or {}).get("next_review_date") or "")}'
        f' ({"overdue" if d < 0 else str(d) + " days"}) · {html.escape(_lifecycle_status(a))}</li>'
        for d, a in review_due) or '<li class="governed">No upcoming reviews.</li>'

    bus = sorted({(a.get("business_context") or {}).get("business_unit") for a in shadow
                  if (a.get("business_context") or {}).get("business_unit")})
    subs = sorted({(a.get("business_context") or {}).get("subsidiary") for a in shadow
                   if (a.get("business_context") or {}).get("subsidiary")})
    bu_opts = "".join(f'<option value="{html.escape(b)}">{html.escape(b)}</option>' for b in bus)
    sub_opts = "".join(f'<option value="{html.escape(s)}">{html.escape(s)}</option>' for s in subs)

    # Governance is the only tab fed by data a human enters rather than the scan. Four
    # zeros and an empty list is technically accurate and tells the reader nothing, so
    # when nothing has been assigned yet the tab explains what it is and how to fill it.
    governed_any = any(_lifecycle_status(a) not in ("Discovered", "Unknown", "", None)
                       or (a.get("ownership") or {}).get("business_owner")
                       for a in shadow)
    governance_intro = "" if governed_any else """
  <div class="card" style="margin-top:16px">
    <h3>Nothing assigned yet</h3>
    <p class="governed">Everything else in AI-SPM is discovered. This tab is the part
    <b>you</b> decide: who owns each AI tool, whether it is approved, and when it is next
    reviewed. Until someone records that, the counters below are all zero — which is an
    honest reading of an ungoverned estate, not a bug.</p>
    <p class="governed">Assign an owner and a lifecycle state per application, and it
    persists across every future scan:</p>
    <pre class="gov-cmd">curl -X POST "$REPORT_URL/../metadata?code=$KEY" -H "Content-Type: application/json" \\
  -d '{"app_id":"&lt;APP_ID&gt;","ownership":{"business_owner":"finance-ops@contoso.com"},
       "lifecycle":{"status":"Approved","next_review_date":"2027-01-31"}}'</pre>
    <p class="governed">Then this tab tracks approvals, review dates that have fallen due,
    and anything still unowned — and the Changes tab records each transition.</p>
  </div>"""

    governance_section = f"""
  <h3 style="margin:22px 4px 10px;font-size:13px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)">Governance (ownership & lifecycle)</h3>
  {governance_intro}
  <div class="grid cols-4">
    <div class="card kpi low"><span class="n">{approved}</span><span class="l">Approved</span></div>
    <div class="card kpi med"><span class="n">{under_review}</span><span class="l">Under Review</span></div>
    <div class="card kpi crit"><span class="n">{blocked}</span><span class="l">Blocked / Restricted</span></div>
    <div class="card kpi high"><span class="n">{len(review_due)}</span><span class="l">Reviews due/overdue</span></div>
  </div>
  <div class="card" style="margin-top:16px"><h3>Upcoming / overdue reviews</h3><ul>{reviews_list}</ul></div>
"""

    # --- Classification (across ALL apps — including Microsoft, criterion 9) ----
    all_apps = sorted(apps, key=lambda a: a["risk_score"], reverse=True)
    cat_counts = {c: sum(1 for a in all_apps if _classification(a).get("category") == c)
                  for c in AI_CATEGORIES}
    unknown_n = cat_counts.get("Unknown AI", 0)
    approved_n = cat_counts.get("Approved Enterprise AI", 0)
    unapproved_n = cat_counts.get("Unapproved Enterprise AI", 0)
    internal_n = sum(1 for a in all_apps if _classification(a).get("ownership") == "Internal")
    external_n = sum(1 for a in all_apps if _classification(a).get("ownership") == "External")
    confs = [_classification(a).get("confidence", 0) for a in all_apps]
    avg_conf = round(sum(confs) / len(confs)) if confs else 0

    cat_bars = _bars([(c, "", cat_counts[c], _CAT_COLOR.get(c, "#6b7280"))
                      for c in AI_CATEGORIES if cat_counts[c]],
                     max(cat_counts.values(), default=1))
    unknown_apps = [a for a in all_apps if _classification(a).get("category") == "Unknown AI"]
    unknown_list = "".join(
        f'<li><b>{html.escape(a.get("display_name") or "—")}</b> — '
        f'{html.escape(a.get("vendor", ""))} · confidence {_classification(a).get("confidence", 0)}%</li>'
        for a in unknown_apps) or '<li class="governed">No Unknown AI.</li>'

    cats_present = [c for c in AI_CATEGORIES if cat_counts[c]]
    cat_opts = "".join(f'<option value="{html.escape(c)}">{html.escape(c)} ({cat_counts[c]})</option>'
                       for c in cats_present)

    classification_section = f"""
  <h3 style="margin:22px 4px 10px;font-size:13px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)">Classification</h3>
  <div class="grid cols-4">
    <div class="card kpi crit"><span class="n">{unknown_n}</span><span class="l">Unknown AI (needs review)</span></div>
    <div class="card kpi low"><span class="n">{approved_n}</span><span class="l">Approved Enterprise</span></div>
    <div class="card kpi high"><span class="n">{unapproved_n}</span><span class="l">Unapproved Enterprise</span></div>
    <div class="card kpi"><span class="n">{avg_conf}%</span><span class="l">Average confidence</span></div>
  </div>
  <div class="grid cols-2" style="margin-top:16px">
    <div class="card"><h3>Applications by category</h3>{cat_bars}</div>
    <div class="card"><h3>Internal vs External</h3>
      <div class="bar-row"><div class="bar-label">Internal</div><div class="bar-track"><div class="bar-fill" style="width:{round(100*internal_n/max(internal_n+external_n,1))}%;background:#7c3aed"></div></div><div class="bar-val">{internal_n}</div></div>
      <div class="bar-row"><div class="bar-label">External</div><div class="bar-track"><div class="bar-fill" style="width:{round(100*external_n/max(internal_n+external_n,1))}%;background:#c0392b"></div></div><div class="bar-val">{external_n}</div></div>
    </div>
  </div>
  <div class="card" style="margin-top:16px"><h3>Unknown AI — review queue</h3><ul>{unknown_list}</ul></div>
"""

    findings_html = "".join(_finding_row(a) for a in all_apps) or \
        '<div class="empty">No AI applications found.</div>'

    import executive
    estate = executive.estate_metrics(apps, changes, findings)
    ts = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
    local_link_attr = (f' data-local-href="{html.escape(connectors_href, quote=True)}"'
                       if connectors_href else "")
    switcher = view_switcher("report", portal_href=portal_href,
                             report_href="#", connectors_href=connectors_href,
                             assessment_href=assessment_href)

    body = f"""
<header>
  <svg class="logo" width="22" height="22" viewBox="0 0 21 21" xmlns="http://www.w3.org/2000/svg">
    <rect x="1" y="1" width="9" height="9" fill="#F25022"/>
    <rect x="11" y="1" width="9" height="9" fill="#7FBA00"/>
    <rect x="1" y="11" width="9" height="9" fill="#00A4EF"/>
    <rect x="11" y="11" width="9" height="9" fill="#FFB900"/>
  </svg>
  <h1>AI-SPM</h1>
  <nav class="tabs">
    <a class="navlink active" data-tab="overview">Overview</a>
    <a class="navlink" data-tab="apps">Applications</a>
    <a class="navlink" data-tab="usage">Usage</a>
    <a class="navlink" data-tab="governance">Governance</a>
    <a class="navlink" data-tab="findings">Findings</a>
    <a class="navlink" data-tab="changes">Changes</a>
    <a class="navlink" data-tab="coverage">Coverage</a>
  </nav>
  <span class="spacer"></span>
  <span class="tenant">{html.escape(tenant_id)}</span>
  {switcher}
  <button id="tg" class="themebtn" title="Theme">&#9790;</button>
</header>
<main>
  <section class="tab active" data-tab="overview">
    <div class="hero">
      <div class="card hero-tenant">
        <h3>Tenant</h3>
        <div class="tenant-facts">
          <b>Tenant ID</b><span>{html.escape(tenant_id)}</span>
          <b>Total AI</b><span>{len(apps)}</span>
          <b>Shadow AI</b><span>{len(shadow)}</span>
          <b>Microsoft 1st-party</b><span>{len(microsoft)}</span>
          <b>Scan</b><span>{ts}</span>
        </div>
      </div>
      <div class="tiles">
        <div class="card tile"><span class="n">{estate['total_applications']}</span><span class="l">AI Applications</span></div>
        <div class="card tile"><span class="n">{estate['total_agents']}</span><span class="l">AI Agents</span></div>
        <div class="card tile"><span class="n">{estate['active_users']}</span><span class="l">Active AI Users</span></div>
        <div class="card tile high"><span class="n">{estate['unapproved']}</span><span class="l">Unapproved AI</span></div>
      </div>
      <div class="card hero-donut">
        <h3>Assessment · risk distribution</h3>
        <div class="summary">{donut}<div class="legend">{legend}</div></div>
      </div>
    </div>
    <div class="grid cols-4" style="margin-top:16px">
      <div class="card kpi"><span class="n">{len(shadow)}</span><span class="l">Shadow AI</span></div>
      <div class="card kpi crit"><span class="n">{counts['Critical']}</span><span class="l">Critical</span></div>
      <div class="card kpi high"><span class="n">{counts['High']}</span><span class="l">High</span></div>
      <div class="card kpi med"><span class="n">{counts['Medium']}</span><span class="l">Medium</span></div>
    </div>
    <div class="grid cols-2" style="margin-top:16px">
      <div class="card">
        <h3>Where to start</h3>
        {triage_chart}{severity_legend}
        <p class="governed">Up and to the right is urgent: a high score reaching many
        users. Dot size is the number of permissions the app holds.</p>
      </div>
      <div class="card">
        <h3>Tenant AI posture</h3>
        <div style="display:flex;justify-content:center">{charts.gauge(posture, "Tenant AI posture")}</div>
        <p class="governed">Weighted by severity rather than averaged, so a handful of
        Critical findings is not diluted by a long tail of Low ones.</p>
        {_posture_breakdown(shadow, counts)}
      </div>
    </div>
    {_executive_section(apps, changes, findings)}
  </section>

  <section class="tab" data-tab="apps">
    <details class="explain">
      <summary>What an application's 0–100 score means, and where the number comes from</summary>
      <p>Per <b>application</b> here, not per vendor — the Estate tab rolls these up.
      Every score is a sum of named signals; open any row below to see the ones that
      produced it. Nothing is weighted secretly and nothing is a model output.</p>
      <table class="scoretab">
        <tr><th>Signal</th><th>Points</th><th>Why it counts</th></tr>
        <tr><td>Sensitive permissions</td><td>up to +55</td>
            <td>The four riskiest scopes it holds, weighted 0–10 each</td></tr>
        <tr><td>App-only permissions</td><td>up to +45</td>
            <td>Runs with no user present, tenant-wide, around the clock</td></tr>
        <tr><td>Admin consent for everyone</td><td>+20</td>
            <td>Granted across the whole organisation, not app by app</td></tr>
        <tr><td>10 or more users consented</td><td>+10</td><td>Blast radius</td></tr>
        <tr><td>Publisher not verified</td><td>+10</td><td>Nobody vouches for who wrote it</td></tr>
        <tr><td>offline_access</td><td>+6</td>
            <td>A refresh token keeps working until someone revokes it</td></tr>
      </table>
      <p><b>Bands:</b> 75+ Critical · 50–74 High · 25–49 Medium · under 25 Low.
      Permission sensitivity itself is tunable in <code>config.py</code>.</p>
    </details>
    <div class="grid cols-2">
      <div class="card"><h3>Riskiest applications</h3>{top_bars}</div>
      <div class="card"><h3>Most granted sensitive permissions</h3>{scope_bars}</div>
    </div>
    <div class="grid cols-2" style="margin-top:16px">
      <div class="card">
        <h3>Sensitive permission concentration</h3>
        {permission_heatmap}
      </div>
      <div class="card">
        <h3>Estate share by vendor</h3>
        {vendor_treemap}
      </div>
    </div>
    <div class="grid cols-4" style="margin-top:16px">
      <div class="card kpi"><span class="n">{admin}</span><span class="l">Admin (org-wide) consent</span></div>
      <div class="card kpi"><span class="n">{third}</span><span class="l">External 3rd-party</span></div>
      <div class="card kpi"><span class="n">{persist}</span><span class="l">Persistent access (offline)</span></div>
      <div class="card kpi"><span class="n">{unverified}</span><span class="l">Unverified publisher</span></div>
    </div>
    <h3 style="margin:20px 4px 10px;font-size:13px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)">Access type</h3>
    <div class="grid cols-4">
      <div class="card kpi"><span class="n">{delegated_n}</span><span class="l">Delegated access</span></div>
      <div class="card kpi high"><span class="n">{apponly_n}</span><span class="l">App-only (unattended)</span></div>
      <div class="card kpi"><span class="n">{both_n}</span><span class="l">Both access types</span></div>
      <div class="card kpi crit"><span class="n">{highpriv_apponly}</span><span class="l">High-privilege app-only</span></div>
    </div>
    {classification_section}
    <div class="card" style="margin-top:16px">
      <h3>Inventory ({len(all_apps)} apps · {len(shadow)} shadow · {len(microsoft)} Microsoft first-party)</h3>
      <div class="filters">
        <button data-group="perm" data-value="all" class="active">Permission: All</button>
        <button data-group="perm" data-value="delegated">Delegated</button>
        <button data-group="perm" data-value="apponly">App-only</button>
        <button data-group="perm" data-value="both">Both</button>
      </div>
      <div class="filters">
        <button data-group="usage" data-value="all" class="active">Usage: All</button>
        <button data-group="usage" data-value="active">Active</button>
        <button data-group="usage" data-value="inactive">Inactive (30d+)</button>
        <button data-group="usage" data-value="unused">Never used</button>
      </div>
      <div class="filters">
        <label>Category <select data-group="cat"><option value="all">All</option>{cat_opts}</select></label>
        <label>Business unit <select data-group="bu"><option value="all">All</option>{bu_opts}</select></label>
        <label>Subsidiary <select data-group="sub"><option value="all">All</option>{sub_opts}</select></label>
      </div>
      <div class="findings">{findings_html}</div>
    </div>
  </section>

  <section class="tab" data-tab="usage">{usage_section}</section>
  <section class="tab" data-tab="governance">{governance_section}</section>
  <section class="tab" data-tab="coverage">{_coverage_section(apps, connector_health)}</section>
  <section class="tab" data-tab="findings">{_findings_section(findings)}</section>
  <section class="tab" data-tab="changes">{_timeline_section(changes)}{new_bu_section}</section>

  <div class="foot">AI-SPM · read-only Entra/Graph scan · {ts}</div>
</main>
<script>{THEME_JS}{charts.JS}</script>
"""
    # The tab bodies are lifted back out of the assembled page rather than built twice.
    # `<section>` appears nowhere else in this document, so the split is unambiguous, and
    # a tab added to the markup is exported here automatically instead of being forgotten.
    _TABS = dict(re.findall(
        r'<section class="tab(?: active)?" data-tab="([^"]+)">(.*?)</section>', body, re.S))

    page = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>AI-SPM · Shadow AI Assessment</title>"
            f"<style>{CSS}{charts.CSS}</style></head>"
            f"<body>{body}</body></html>")
    return {"page": page, "tabs": _TABS}


def write_html(apps: list[dict], path: str, tenant_id: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_string(apps, tenant_id))
