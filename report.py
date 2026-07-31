"""JSON + tek-dosya HTML dashboard (bağımlılıksız, light/dark)."""
import html
import json
import math
from datetime import datetime, timezone

from config import (SENSITIVE_SCOPES, SCOPE_HEURISTICS,
                    LIFECYCLE_STATUSES, CRITICALITY, ENVIRONMENTS,
                    AI_CATEGORIES, OWNERSHIP_CLASSES, FINDING_STATUSES)

_SEV_COLOR = {"Critical": "#c0392b", "High": "#d35400", "Medium": "#b8860b", "Low": "#2e8b57"}
_FSTATUS_COLOR = {"Open": "#c0392b", "Assigned": "#d35400", "In Progress": "#0f6cbd",
                  "Pending Review": "#b8860b", "Resolved": "#2e8b57", "Accepted": "#4b5563",
                  "False Positive": "#6b7280", "Reopened": "#c0392b"}

_LIFECYCLE_COLOR = {"Discovered": "#6b7280", "Under Review": "#b8860b", "Pilot": "#0f6cbd",
                    "Approved": "#2e8b57", "Restricted": "#d35400", "Blocked": "#c0392b",
                    "Retired": "#4b5563", "Unknown": "#6b7280"}

_CAT_COLOR = {"Microsoft First-Party AI": "#0f6cbd", "Approved Enterprise AI": "#2e8b57",
              "Unapproved Enterprise AI": "#d35400", "Third-Party Shadow AI": "#c0392b",
              "Internal Custom AI": "#7c3aed", "Personal AI Usage": "#b8860b",
              "Unknown AI": "#6b7280", "Retired AI": "#4b5563"}

_IMP_COLOR = {"Critical": "#c0392b", "High": "#d35400", "Medium": "#b8860b",
              "Low": "#2e8b57", "Info": "#6b7280"}


def _finding_editor(rec):
    fid = html.escape(rec.get("finding_id", ""))
    opts = "".join(f'<option{" selected" if s == rec.get("status") else ""}>{html.escape(s)}</option>'
                   for s in FINDING_STATUSES)

    def fld(label, name, val=""):
        return f'<label>{label}<input name="{name}" value="{html.escape(val or "")}"></label>'

    return (
        '<details class="editor"><summary>Finding düzenle</summary>'
        f'<div class="fform" data-finding="{fid}">'
        f'<label>Status<select name="status">{opts}</select></label>'
        f'{fld("Owner", "owner", rec.get("owner"))}'
        f'{fld("Responsible team", "responsible_team", rec.get("responsible_team"))}'
        f'<label>Due date<input name="due_date" type="date" value="{html.escape((rec.get("due_date") or "")[:10])}"></label>'
        f'{fld("Ticket ref", "ticket_reference", rec.get("ticket_reference"))}'
        f'<label>Resolution note<textarea name="resolution_note">{html.escape(rec.get("resolution_note", "") or "")}</textarea></label>'
        '<button type="button" class="fsave">Kaydet</button><span class="mstatus"></span>'
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
                od = ' <span style="color:#c0392b;font-weight:600">(gecikmiş)</span>'
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
        f'<div class="f-col"><h4>Açıklama</h4><p>{html.escape(rec.get("description",""))}</p>'
        f'<h4 style="margin-top:8px">İş etkisi</h4><p>{html.escape(rec.get("business_impact",""))}</p></div>'
        f'<div class="f-col"><h4>Önerilen aksiyon</h4><p>{html.escape(rec.get("recommended_action",""))}</p>'
        f'<h4 style="margin-top:8px">Kayıt</h4><ul>'
        f'<li>Finding ID: <code>{html.escape(rec.get("finding_id",""))}</code></li>'
        f'<li>İlk görülme: {html.escape(rec.get("first_seen",""))} · Son: {html.escape(rec.get("last_seen",""))}</li>'
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
        for f in overdue) or '<li class="governed">Gecikmiş finding yok.</li>'

    # owner bazında (açık)
    owners = {}
    for f in active:
        owners[f.get("owner") or "Atanmamış"] = owners.get(f.get("owner") or "Atanmamış", 0) + 1
    owner_bars = _bars([(o, "", n, "#0f6cbd") for o, n in
                        sorted(owners.items(), key=lambda kv: -kv[1])[:8]],
                       max(owners.values(), default=1))

    rows = "".join(_finding_record_row(f, now) for f in active) or \
        '<div class="empty">Açık finding yok. 👍</div>'
    return f"""
  <h3 style="margin:22px 4px 10px;font-size:13px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)">Findings — yönetilebilir kayıtlar</h3>
  <div class="grid cols-4">
    <div class="card kpi crit"><span class="n">{open_n}</span><span class="l">Açık / yeniden açık</span></div>
    <div class="card kpi med"><span class="n">{prog_n}</span><span class="l">İşlemde / review</span></div>
    <div class="card kpi high"><span class="n">{len(overdue)}</span><span class="l">Gecikmiş (overdue)</span></div>
    <div class="card kpi low"><span class="n">{resolved_n}</span><span class="l">Çözülmüş</span></div>
  </div>
  <div class="grid cols-2" style="margin-top:16px">
    <div class="card"><h3>Gecikmiş finding'ler</h3><ul>{overdue_list}</ul></div>
    <div class="card"><h3>Owner bazında açık finding</h3>{owner_bars}</div>
  </div>
  <div class="card" style="margin-top:16px"><h3>Açık finding'ler ({len(active)})</h3>
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
        (m["new_this_week"], "New Assets (7g)", "changes", ""),
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
        "<li>Dikkat gerektiren belirgin bir durum yok.</li>"
    tc_html = "".join(
        f'<li><b>{html.escape(e.get("change_type",""))}</b> {html.escape(e.get("asset_name",""))} '
        f'— {html.escape(e.get("description",""))}</li>' for e in tc) or \
        '<li class="governed">Bu dönem önemli değişiklik yok.</li>'

    aa_bars = _bars([("Application", "", m["total_applications"], "#0f6cbd"),
                     ("Agent", "", m["total_agents"], "#7c3aed")],
                    max(m["total_applications"], m["total_agents"], 1))
    surf_bars = _bars([("Enterprise (admin-sanctioned)", "", surface["enterprise"], "#2e8b57"),
                       ("Web (user-consent)", "", surface["web"], "#b8860b"),
                       ("Local (connector gerekli)", "", surface["local"], "#6b7280")],
                      max(surface["enterprise"], surface["web"], 1))
    return f"""
  <div class="kpi-grid">{kpi}</div>
  <div class="grid cols-2" style="margin-top:16px">
    <div class="card"><h3>Needs Attention</h3><ul class="na">{na_html}</ul></div>
    <div class="card"><h3>En önemli 5 değişiklik</h3><ul>{tc_html}</ul></div>
  </div>
  <div class="card" style="margin-top:16px"><h3>Application vs Agent · kullanım yüzeyi</h3>
    <div class="grid cols-2"><div>{aa_bars}</div><div>{surf_bars}</div></div></div>
"""


def _coverage_section(apps):
    import executive
    cov = executive.coverage(apps)
    conn_html = "".join(
        f'<li><span class="dot" style="background:{"#2e8b57" if ok else "#c0392b"}"></span>'
        f'{html.escape(name)} — {"bağlı" if ok else "<b>bağlı değil</b>"} '
        f'<span class="governed">({html.escape(purpose)})</span></li>'
        for name, ok, purpose in cov["connectors"])
    own_bar = _bars([("Owner coverage", f"{cov['owner_coverage']}%", cov["owner_coverage"], "#0f6cbd"),
                     ("Agent purpose coverage", f"{cov['purpose_coverage']}%", cov["purpose_coverage"], "#7c3aed")],
                    100)
    return (f'<div class="card" style="margin-top:16px"><h3>Coverage Overview</h3>{own_bar}'
            f'<h3 style="margin-top:14px">Veri kaynağı / connector durumu</h3>'
            f'<ul class="conn">{conn_html}</ul></div>')


def _timeline_section(changes):
    if changes is None:
        return ""
    if not changes:
        return ('<div class="card" style="margin-top:16px"><h3>Değişiklikler</h3>'
                '<p class="governed">Önceki taramaya göre değişiklik yok '
                '(ya da bu ilk taramadır — baseline).</p></div>')
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
    return (f'<div class="card" style="margin-top:16px"><h3>Değişiklikler — zaman çizelgesi '
            f'({len(changes)})</h3><div class="timeline">{rows}</div></div>')

LEVELS = ["Kritik", "Yüksek", "Orta", "Düşük"]
LEVEL_COLORS = {"Kritik": "#c0392b", "Yüksek": "#d35400", "Orta": "#b8860b", "Düşük": "#2e8b57"}


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
    total = sum(v for _, v, _ in segments) or 1
    r = (size - stroke) / 2
    cx = cy = size / 2
    circ = 2 * math.pi * r
    offset = 0.0
    arcs = []
    for _, value, color in segments:
        if value <= 0:
            continue
        dash = circ * (value / total)
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r:.2f}" fill="none" stroke="{color}" '
            f'stroke-width="{stroke}" stroke-dasharray="{dash:.2f} {circ - dash:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>')
        offset += dash
    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" '
        f'role="img" class="donut">'
        f'<circle cx="{cx}" cy="{cy}" r="{r:.2f}" fill="none" stroke="var(--track)" '
        f'stroke-width="{stroke}"/>{"".join(arcs)}'
        f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" class="donut-num">{total}</text>'
        f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" class="donut-cap">Shadow AI</text>'
        f'</svg>')


def _bars(rows, maxv):
    """rows: [(label, sublabel, value, color)] → HTML bar list."""
    maxv = maxv or 1
    out = []
    for label, sub, value, color in rows:
        pct = max(3, round(100 * value / maxv))
        out.append(
            f'<div class="bar-row"><div class="bar-label">{html.escape(label)}'
            f'<span class="bar-sub">{html.escape(sub)}</span></div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;'
            f'background:{color}"></div></div>'
            f'<div class="bar-val">{value}</div></div>')
    return "".join(out) or '<div class="empty">Veri yok</div>'


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
              "none": ("izin yok", "#6b7280")}

_USAGE_CHIP = {"active": ("aktif", "#2e8b57"), "inactive": ("30g+ pasif", "#b45309"),
               "unused": ("hiç kullanılmamış", "#c0392b"), "unknown": ("aktivite yok", "#6b7280")}


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


def _trend_svg(values, width=680, height=84):
    if not values or max(values) == 0:
        return '<div class="empty">Aktivite verisi yok (Entra ID P1 gerekir)</div>'
    n = len(values)
    maxv = max(values) or 1
    dx = width / (n - 1) if n > 1 else width
    pts = [(i * dx, height - (v / maxv) * (height - 16) - 8) for i, v in enumerate(values)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = f"0,{height} {line} {width},{height}"
    lx, ly = pts[-1]
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'preserveAspectRatio="none" class="trend" role="img">'
            f'<polygon points="{area}" fill="var(--accent)" opacity="0.12"/>'
            f'<polyline points="{line}" fill="none" stroke="var(--accent)" stroke-width="2"/>'
            f'<circle cx="{lx:.1f}" cy="{ly:.1f}" r="3.5" fill="var(--accent)"/></svg>')


def _usage_block(app):
    u = app.get("usage")
    if not u or not u.get("available"):
        return '<h4>Kullanım</h4><p class="f-pub">Aktivite verisi yok (Entra ID P1)</p>'
    if u.get("never_used"):
        last = "hiç kullanılmamış"
    else:
        d = _days_ago(u.get("last_used_date"))
        last = f"{d} gün önce" if d is not None else "—"
    sp = ""
    if app.get("has_app_only_access") and u.get("last_service_principal_signin"):
        dsp = _days_ago(u["last_service_principal_signin"])
        sp = f'<li>Son SP (app-only) sign-in: {dsp} gün önce</li>' if dsp is not None else ""
    return (
        '<h4>Kullanım</h4><ul>'
        f'<li>Son kullanım: <b>{html.escape(last)}</b></li>'
        f'<li>Aktif kullanıcı: {u.get("active_users_7d",0)} (7g) · '
        f'{u.get("active_users_30d",0)} (30g) · {u.get("active_users_90d",0)} (90g)</li>'
        f'<li>Consent: {u.get("consent_user_count",0)} kullanıcı</li>'
        f'<li>Sign-in (30g): {u.get("successful_signins_30d",0)} başarılı / '
        f'{u.get("failed_signins_30d",0)} başarısız</li>'
        f'<li>{u.get("unique_ip_count",0)} IP · {u.get("country_count",0)} ülke</li>'
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
        cred += f' · en yakın bitiş {html.escape(cred_exp[:10])}'
    review = lc.get("next_review_date")
    return (
        '<h4>Sahiplik & Lifecycle</h4><ul>'
        f'<li>Teknik owner (SP): {sp_owners}</li>'
        f'<li>Business owner: {val(own.get("business_owner"))}'
        f' · Technical: {val(own.get("technical_owner"))}</li>'
        f'<li>Sponsor: {val(own.get("sponsor"))}</li>'
        f'<li>Birim: {val(bc.get("business_unit"))} · {val(bc.get("subsidiary"))}</li>'
        f'<li>Amaç: {val(bc.get("purpose"))}</li>'
        f'<li>Kritiklik: {val(bc.get("criticality"))} · Ortam: {val(bc.get("environment"))}</li>'
        f'<li>Sonraki review: {val(review)}</li>'
        f'<li>{cred}</li></ul>')


def _classification(app):
    return app.get("classification") or {"category": "Unknown AI", "ownership": "Unknown",
                                         "confidence": 0, "reasons": [], "manual_override": False}


def _classification_block(app):
    c = _classification(app)
    reasons = "".join(f"<li>{html.escape(r)}</li>" for r in c.get("reasons", []))
    ov = ' · <b>manuel override</b>' if c.get("manual_override") else ""
    return (
        '<h4>Sınıflandırma</h4><ul>'
        f'<li>Kategori: <b>{html.escape(c.get("category", "Unknown AI"))}</b>{ov}</li>'
        f'<li>Sahiplik: {html.escape(c.get("ownership", "Unknown"))} · Güven: {c.get("confidence", 0)}%</li>'
        f'</ul><h4 style="margin-top:6px">Sınıflandırma nedeni</h4><ul>{reasons}</ul>')


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
        '<details class="editor"><summary>Metadata düzenle</summary>'
        f'<div class="mform" data-app="{html.escape(app.get("app_id", ""))}">'
        f'<label>Sınıf (override)<select name="class_category">{opts([""] + AI_CATEGORIES, (app.get("classification_override") or {}).get("category") or "")}</select></label>'
        f'<label>Sahiplik (override)<select name="class_ownership">{opts([""] + OWNERSHIP_CLASSES, (app.get("classification_override") or {}).get("ownership") or "")}</select></label>'
        f'<label>Lifecycle<select name="status">{opts(LIFECYCLE_STATUSES, _lifecycle_status(app))}</select></label>'
        f'{field("Business owner", "business_owner", own.get("business_owner"))}'
        f'{field("Technical owner", "technical_owner", own.get("technical_owner"))}'
        f'{field("Sponsor", "sponsor", own.get("sponsor"))}'
        f'{field("Business unit", "business_unit", bc.get("business_unit"))}'
        f'{field("Subsidiary", "subsidiary", bc.get("subsidiary"))}'
        f'{field("Amaç", "purpose", bc.get("purpose"))}'
        f'<label>Kritiklik<select name="criticality">{opts(CRITICALITY, bc.get("criticality") or "")}</select></label>'
        f'<label>Ortam<select name="environment">{opts(ENVIRONMENTS, bc.get("environment") or "")}</select></label>'
        f'<label>Sonraki review<input name="next_review_date" type="date" value="{html.escape(review)}"></label>'
        f'<label>Notlar<textarea name="notes">{html.escape(app.get("notes", "") or "")}</textarea></label>'
        '<button type="button" class="msave">Kaydet</button><span class="mstatus"></span>'
        '</div></details>')


def _finding_row(app):
    color = LEVEL_COLORS.get(app["risk_level"], "#555")
    scopes = ", ".join(html.escape(s) for s in app.get("scopes", [])) or "—"
    reasons = "".join(f"<li>{html.escape(r)}</li>" for r in app.get("reasons", []))
    remed = "".join(f"<li>{html.escape(r)}</li>" for r in app.get("remediation", []))
    consent = app.get("consent_type") or "consent yok"
    tag = "3. parti" if app.get("third_party") else "iç/first-party"
    ver = "✓ doğrulanmış" if app.get("verified_publisher") else "⚠ doğrulanmamış"
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
        app_block = (f'<h4>App-only izinler (kullanıcısız)</h4><ul class="apperms">{rows}</ul>')
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
        f'<span class="f-meta">{tag} · {html.escape(consent)} · {app.get("user_count",0)} kullanıcı</span>'
        f'<span class="f-level" style="color:{color}">{html.escape(app["risk_level"])}</span>'
        f'</summary>'
        f'<div class="f-body">'
        f'<div class="f-col">{_classification_block(app)}</div>'
        f'<div class="f-col"><h4>Delegated izinler</h4><code>{scopes}</code>'
        f'{app_block}<p class="f-pub">{ver}</p></div>'
        f'<div class="f-col">{_usage_block(app)}</div>'
        f'<div class="f-col">{_governance_block(app)}</div>'
        f'<div class="f-col"><h4>Neden riskli</h4><ul>{reasons}</ul></div>'
        f'<div class="f-col"><h4>Öneri</h4><ul>{remed}</ul></div>'
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
.logo{width:22px;height:22px;border-radius:5px;
 background:linear-gradient(135deg,#0f6cbd,#2e8b57 55%,#c0392b)}
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
  if(location.pathname.indexOf('/api/')===0){
    var aiCode=new URLSearchParams(location.search).get('code');
    aiLink.href='/api/connectors?format=html'+(aiCode?'&code='+encodeURIComponent(aiCode):'');
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
 var st=box.querySelector('.mstatus');st.textContent='Kaydediliyor...';
 fetch('/api/metadata?code='+encodeURIComponent(code),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.ok?r.json():Promise.reject(r.status);}).then(function(){st.textContent='\\u2713 Kaydedildi (sonraki taramada islenir)';}).catch(function(e){st.textContent='Hata: '+e;});};});
document.querySelectorAll('.fsave').forEach(function(btn){btn.onclick=function(){
 var box=btn.closest('.fform'),fid=box.getAttribute('data-finding');
 function v(n){var e=box.querySelector('[name="'+n+'"]');return e?e.value:'';}
 var body={finding_id:fid,status:v('status'),owner:v('owner'),responsible_team:v('responsible_team'),due_date:v('due_date')||null,ticket_reference:v('ticket_reference'),resolution_note:v('resolution_note')};
 var st=box.querySelector('.mstatus');st.textContent='Kaydediliyor...';
 fetch('/api/finding?code='+encodeURIComponent(code),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.ok?r.json():Promise.reject(r.status);}).then(function(){st.textContent='\\u2713 Kaydedildi';}).catch(function(e){st.textContent='Hata: '+e;});};});
})();
"""


def html_string(apps: list[dict], tenant_id: str, changes=None, findings=None) -> str:
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

    scope_count = {}
    for a in shadow:
        for s in a.get("scopes", []):
            if _scope_weight(s) >= 5:
                scope_count[s] = scope_count.get(s, 0) + 1
    scope_rows = sorted(scope_count.items(), key=lambda kv: (-kv[1], -_scope_weight(kv[0])))[:8]
    scope_bars = _bars(
        [(s, f"hassasiyet {_scope_weight(s)}/10", c, "#0f6cbd") for s, c in scope_rows],
        max((c for _, c in scope_rows), default=1))

    admin = sum(1 for a in shadow if a.get("consent_type") == "AllPrincipals")
    persist = sum(1 for a in shadow if "offline_access" in a.get("scopes", []))
    unverified = sum(1 for a in shadow if not a.get("verified_publisher"))

    # Permission-type dağılımı (delegated / app-only / both)
    delegated_n = sum(1 for a in shadow if a.get("delegated_permissions") or a.get("scopes"))
    apponly_n = sum(1 for a in shadow if a.get("has_app_only_access"))
    both_n = sum(1 for a in shadow
                 if (a.get("delegated_permissions") or a.get("scopes")) and a.get("has_app_only_access"))
    highpriv_apponly = sum(
        1 for a in shadow
        if any(_scope_weight(p["permission"].lower()) >= 8
               for p in a.get("application_permissions", [])))

    # Kullanım / aktivite (Entra ID P1 — yoksa graceful)
    activity_available = any((a.get("usage") or {}).get("available") for a in shadow)
    active_users_30d = sum((a.get("usage") or {}).get("active_users_30d", 0) for a in shadow)
    inactive_apps = sum(1 for a in shadow if (a.get("usage") or {}).get("inactive_30d"))
    apponly_active = sum(
        1 for a in shadow if a.get("has_app_only_access")
        and (a.get("usage") or {}).get("last_service_principal_signin")
        and not (a.get("usage") or {}).get("inactive_30d"))
    # aggregate günlük aktif kullanıcı trendi (30g)
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
    growing_bars = _bars([(a.get("display_name") or "—", "son 7g artış",
                           (a.get("usage") or {}).get("growth_7d", 0), "#7c3aed")
                          for a in growing], max(((a.get("usage") or {}).get("growth_7d", 0)
                                                  for a in growing), default=1))

    # Yeni AI uygulamaları — business unit bazında (kriter 8)
    new_ids = {e["asset_id"] for e in (changes or []) if e.get("change_type") == "NEW_APPLICATION"}
    new_bu_section = ""
    if new_ids:
        id_map = {a.get("app_id"): a for a in apps}
        by_bu = {}
        for aid in new_ids:
            a = id_map.get(aid) or {}
            bu = (a.get("business_context") or {}).get("business_unit") or "Atanmamış"
            by_bu.setdefault(bu, []).append(a.get("display_name") or aid)
        rows = "".join(f'<li><b>{html.escape(bu)}</b>: {html.escape(", ".join(sorted(n)))}</li>'
                       for bu, n in sorted(by_bu.items()))
        new_bu_section = (f'<div class="card" style="margin-top:16px">'
                          f'<h3>Yeni AI uygulamaları — business unit bazında ({len(new_ids)})</h3>'
                          f'<ul>{rows}</ul></div>')

    if activity_available:
        usage_section = f"""
  <h3 style="margin:22px 4px 10px;font-size:13px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)">Kullanım & Aktivite (gerçek sign-in)</h3>
  <div class="grid cols-4">
    <div class="card kpi"><span class="n">{active_users_30d}</span><span class="l">Aktif AI kullanımı (30g)</span></div>
    <div class="card kpi crit"><span class="n">{inactive_apps}</span><span class="l">Kullanılmayan uygulama (30g+)</span></div>
    <div class="card kpi"><span class="n">{apponly_active}</span><span class="l">App-only aktif uygulama</span></div>
    <div class="card kpi"><span class="n">{len(growing)}</span><span class="l">Yükselen uygulama</span></div>
  </div>
  <div class="grid cols-2" style="margin-top:16px">
    <div class="card"><h3>Aktif kullanıcı trendi (son 30 gün)</h3>{_trend_svg(trend)}</div>
    <div class="card"><h3>En çok kullanılan uygulamalar</h3>{most_used_bars}</div>
  </div>
  <div class="card" style="margin-top:16px"><h3>En hızlı büyüyen uygulamalar (7g)</h3>{growing_bars}</div>
"""
    else:
        usage_section = ('<div class="card" style="margin-top:16px">'
                         '<h3>Kullanım & Aktivite</h3>'
                         '<p class="governed">Sign-in aktivitesi alınamadı — gerçek kullanım '
                         'metrikleri için <b>Entra ID P1/P2</b> lisansı gerekir. '
                         'Assessment kesintisiz devam ediyor; consent/permission bulguları geçerli.</p></div>')

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
        f' ({"gecikmiş" if d < 0 else str(d) + " gün"}) · {html.escape(_lifecycle_status(a))}</li>'
        for d, a in review_due) or '<li class="governed">Yaklaşan review yok.</li>'

    bus = sorted({(a.get("business_context") or {}).get("business_unit") for a in shadow
                  if (a.get("business_context") or {}).get("business_unit")})
    subs = sorted({(a.get("business_context") or {}).get("subsidiary") for a in shadow
                   if (a.get("business_context") or {}).get("subsidiary")})
    bu_opts = "".join(f'<option value="{html.escape(b)}">{html.escape(b)}</option>' for b in bus)
    sub_opts = "".join(f'<option value="{html.escape(s)}">{html.escape(s)}</option>' for s in subs)

    governance_section = f"""
  <h3 style="margin:22px 4px 10px;font-size:13px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)">Yönetişim (ownership & lifecycle)</h3>
  <div class="grid cols-4">
    <div class="card kpi low"><span class="n">{approved}</span><span class="l">Approved</span></div>
    <div class="card kpi med"><span class="n">{under_review}</span><span class="l">Under Review</span></div>
    <div class="card kpi crit"><span class="n">{blocked}</span><span class="l">Blocked / Restricted</span></div>
    <div class="card kpi high"><span class="n">{len(review_due)}</span><span class="l">Review yaklaşan/geçmiş</span></div>
  </div>
  <div class="card" style="margin-top:16px"><h3>Yaklaşan / geçmiş review'lar</h3><ul>{reviews_list}</ul></div>
"""

    # --- Sınıflandırma (TÜM app'ler üzerinde — Microsoft dahil, kriter 9) ----
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
        f'{html.escape(a.get("vendor", ""))} · güven {_classification(a).get("confidence", 0)}%</li>'
        for a in unknown_apps) or '<li class="governed">Unknown AI yok.</li>'

    cats_present = [c for c in AI_CATEGORIES if cat_counts[c]]
    cat_opts = "".join(f'<option value="{html.escape(c)}">{html.escape(c)} ({cat_counts[c]})</option>'
                       for c in cats_present)

    classification_section = f"""
  <h3 style="margin:22px 4px 10px;font-size:13px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)">Sınıflandırma</h3>
  <div class="grid cols-4">
    <div class="card kpi crit"><span class="n">{unknown_n}</span><span class="l">Unknown AI (inceleme)</span></div>
    <div class="card kpi low"><span class="n">{approved_n}</span><span class="l">Approved Enterprise</span></div>
    <div class="card kpi high"><span class="n">{unapproved_n}</span><span class="l">Unapproved Enterprise</span></div>
    <div class="card kpi"><span class="n">{avg_conf}%</span><span class="l">Ortalama güven</span></div>
  </div>
  <div class="grid cols-2" style="margin-top:16px">
    <div class="card"><h3>Kategoriye göre uygulamalar</h3>{cat_bars}</div>
    <div class="card"><h3>Internal vs External</h3>
      <div class="bar-row"><div class="bar-label">Internal</div><div class="bar-track"><div class="bar-fill" style="width:{round(100*internal_n/max(internal_n+external_n,1))}%;background:#7c3aed"></div></div><div class="bar-val">{internal_n}</div></div>
      <div class="bar-row"><div class="bar-label">External</div><div class="bar-track"><div class="bar-fill" style="width:{round(100*external_n/max(internal_n+external_n,1))}%;background:#c0392b"></div></div><div class="bar-val">{external_n}</div></div>
    </div>
  </div>
  <div class="card" style="margin-top:16px"><h3>Unknown AI — inceleme kuyruğu</h3><ul>{unknown_list}</ul></div>
"""

    findings_html = "".join(_finding_row(a) for a in all_apps) or \
        '<div class="empty">AI uygulaması bulunamadı.</div>'

    import executive
    estate = executive.estate_metrics(apps, changes, findings)
    ts = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")

    body = f"""
<header>
  <span class="logo"></span>
  <h1>AI-SPM</h1>
  <nav class="tabs">
    <a class="navlink active" data-tab="overview">Overview</a>
    <a class="navlink" data-tab="apps">Applications</a>
    <a class="navlink" data-tab="usage">Usage</a>
    <a class="navlink" data-tab="governance">Governance</a>
    <a class="navlink" data-tab="findings">Findings</a>
    <a class="navlink" data-tab="changes">Changes</a>
  </nav>
  <span class="spacer"></span>
  <span class="tenant">{html.escape(tenant_id)}</span>
  <a id="aiDataSourcesLink" class="themebtn" href="#" style="display:inline-block;text-decoration:none" title="Microsoft AI Data Sources dashboard'una git">AI Data Sources &#8594;</a>
  <button id="tg" class="themebtn" title="Tema">&#9790;</button>
</header>
<main>
  <section class="tab active" data-tab="overview">
    <div class="hero">
      <div class="card hero-tenant">
        <h3>Tenant</h3>
        <div class="tenant-facts">
          <b>Tenant ID</b><span>{html.escape(tenant_id)}</span>
          <b>Toplam AI</b><span>{len(apps)}</span>
          <b>Shadow AI</b><span>{len(shadow)}</span>
          <b>Microsoft 1st-party</b><span>{len(microsoft)}</span>
          <b>Tarama</b><span>{ts}</span>
        </div>
      </div>
      <div class="tiles">
        <div class="card tile"><span class="n">{estate['total_applications']}</span><span class="l">AI Applications</span></div>
        <div class="card tile"><span class="n">{estate['total_agents']}</span><span class="l">AI Agents</span></div>
        <div class="card tile"><span class="n">{estate['active_users']}</span><span class="l">Active AI Users</span></div>
        <div class="card tile high"><span class="n">{estate['unapproved']}</span><span class="l">Unapproved AI</span></div>
      </div>
      <div class="card hero-donut">
        <h3>Assessment · risk dağılımı</h3>
        <div class="summary">{donut}<div class="legend">{legend}</div></div>
      </div>
    </div>
    <div class="grid cols-4" style="margin-top:16px">
      <div class="card kpi"><span class="n">{len(shadow)}</span><span class="l">Shadow AI</span></div>
      <div class="card kpi crit"><span class="n">{counts['Kritik']}</span><span class="l">Kritik</span></div>
      <div class="card kpi high"><span class="n">{counts['Yüksek']}</span><span class="l">Yüksek</span></div>
      <div class="card kpi med"><span class="n">{counts['Orta']}</span><span class="l">Orta</span></div>
    </div>
    {_executive_section(apps, changes, findings)}
  </section>

  <section class="tab" data-tab="apps">
    <div class="grid cols-2">
      <div class="card"><h3>En riskli uygulamalar</h3>{top_bars}</div>
      <div class="card"><h3>En çok verilen hassas izinler</h3>{scope_bars}</div>
    </div>
    <div class="grid cols-4" style="margin-top:16px">
      <div class="card kpi"><span class="n">{admin}</span><span class="l">Admin (tüm org) onayı</span></div>
      <div class="card kpi"><span class="n">{third}</span><span class="l">Dış 3. parti</span></div>
      <div class="card kpi"><span class="n">{persist}</span><span class="l">Kalıcı erişim (offline)</span></div>
      <div class="card kpi"><span class="n">{unverified}</span><span class="l">Doğrulanmamış publisher</span></div>
    </div>
    <h3 style="margin:20px 4px 10px;font-size:13px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)">Erişim tipi</h3>
    <div class="grid cols-4">
      <div class="card kpi"><span class="n">{delegated_n}</span><span class="l">Delegated erişim</span></div>
      <div class="card kpi high"><span class="n">{apponly_n}</span><span class="l">App-only (kullanıcısız)</span></div>
      <div class="card kpi"><span class="n">{both_n}</span><span class="l">Her iki erişim tipi</span></div>
      <div class="card kpi crit"><span class="n">{highpriv_apponly}</span><span class="l">Yüksek ayrıcalıklı app-only</span></div>
    </div>
    {classification_section}
    <div class="card" style="margin-top:16px">
      <h3>Envanter ({len(all_apps)} uygulama · {len(shadow)} shadow · {len(microsoft)} Microsoft first-party)</h3>
      <div class="filters">
        <button data-group="perm" data-value="all" class="active">İzin: Tümü</button>
        <button data-group="perm" data-value="delegated">Delegated</button>
        <button data-group="perm" data-value="apponly">App-only</button>
        <button data-group="perm" data-value="both">Her ikisi</button>
      </div>
      <div class="filters">
        <button data-group="usage" data-value="all" class="active">Kullanım: Tümü</button>
        <button data-group="usage" data-value="active">Aktif</button>
        <button data-group="usage" data-value="inactive">Pasif (30g+)</button>
        <button data-group="usage" data-value="unused">Hiç kullanılmamış</button>
      </div>
      <div class="filters">
        <label>Kategori <select data-group="cat"><option value="all">Tümü</option>{cat_opts}</select></label>
        <label>Birim <select data-group="bu"><option value="all">Tümü</option>{bu_opts}</select></label>
        <label>Subsidiary <select data-group="sub"><option value="all">Tümü</option>{sub_opts}</select></label>
      </div>
      <div class="findings">{findings_html}</div>
    </div>
  </section>

  <section class="tab" data-tab="usage">{usage_section}</section>
  <section class="tab" data-tab="governance">{governance_section}{_coverage_section(apps)}</section>
  <section class="tab" data-tab="findings">{_findings_section(findings)}</section>
  <section class="tab" data-tab="changes">{_timeline_section(changes)}{new_bu_section}</section>

  <div class="foot">AI-SPM · read-only Entra/Graph taraması · {ts}</div>
</main>
<script>{THEME_JS}</script>
"""
    return ("<!doctype html><html lang=\"tr\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>AI-SPM · Shadow AI Assessment</title><style>{CSS}</style></head>"
            f"<body>{body}</body></html>")


def write_html(apps: list[dict], path: str, tenant_id: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_string(apps, tenant_id))
