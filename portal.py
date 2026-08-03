"""
The unified portal — one estate view over both scans.

An administrator asks "which AI is in my tenant and what should I do first?". Answering
that used to mean opening two dashboards and joining them by eye, because the same
vendor arrives twice under different identities: Entra reports a consented service
principal, Defender reports browser traffic, and the two share no ID at all — Defender's
records carry neither an appId nor, in practice, a domain.

So this does NOT merge them by ID. Forcing that would fabricate a correlation the data
does not support, which is the one outcome worse than showing two lists. It groups by
**vendor**, matching both sides through the same catalog, and shows the evidence behind
every row: consented OAuth app, web traffic, registered agent, sensitive interaction. A
vendor is counted once; how it was seen is never hidden.

Everything here is a read of what the two scans already produced — no new Graph calls.
"""
import html
import json
from datetime import datetime, timezone

import charts
import collectors
import executive
import report
from report import CSS, LEVEL_COLORS, LEVELS, THEME_JS, _scope_weight

# Where a vendor was observed. Order is the order badges appear in.
EVIDENCE = [
    ("oauth", "OAuth consent", "A user or admin granted this app access to tenant data"),
    ("web", "Web traffic", "Seen in Defender for Cloud Apps network discovery"),
    ("agent", "Registered agent", "Present in Agent 365 or Entra Agent ID"),
    ("sensitive", "Sensitive interaction", "Purview recorded sensitive data reaching it"),
]
_EVIDENCE_COLOR = {"oauth": charts.cat(0), "web": charts.cat(1),
                   "agent": charts.cat(2), "sensitive": charts.cat(4)}


def _esc(s):
    return html.escape(str(s if s is not None else ""))


def _canonical(*texts) -> tuple[str, bool]:
    """(vendor name, matched the catalog). Falls back to the first non-empty text."""
    hit = collectors.match_vendor_name(*texts)
    if hit:
        return hit, True
    for t in texts:
        if t:
            return str(t), False
    return "Unknown", False


def _blank(vendor, matched):
    return {"vendor": vendor, "catalog_match": matched, "evidence": set(),
            "oauth_apps": [], "agents": [], "web": None,
            "interactions": 0, "blocked": 0, "sensitive_types": set(),
            "users": 0, "risk_score": 0, "risk_level": "Low", "reasons": []}


def build_estate(scored, connectors_result=None) -> dict:
    """
    The AI estate, plus everything deliberately kept out of it.

    Two rules decide what becomes a row, and both exist because breaking them produced
    a useless page on a real tenant:

    * Only AI creates a vendor. A `--scope consented` scan sweeps in every app holding
      a grant; those belong on the OAuth dashboard, not at the top of an AI estate
      ranked above ChatGPT. They are counted here and linked, not ranked.
    * Agents attach, they never create. Agent 365's catalogue is the tenant's Teams app
      list — 292 entries like "Jira Cloud" and "Viva Goals" on the tenant this was
      built against. Letting each become a vendor turned 20 real vendors into 307 rows.
      An agent joins a vendor when it matches one, and is counted separately when not.

    Returns {vendors, non_ai_apps, unattached_agents, unattached_interactions}.
    """
    rollup: dict[str, dict] = {}
    non_ai_apps: list[dict] = []
    unattached_agents: list[str] = []
    unattached_interactions = 0

    def bucket(*texts):
        """Creates or returns a vendor row."""
        vendor, matched = _canonical(*texts)
        rec = rollup.get(vendor)
        if rec is None:
            rec = rollup[vendor] = _blank(vendor, matched)
        return rec

    def attach(*texts):
        """Returns an EXISTING vendor row, or None — never creates one."""
        hit = collectors.match_vendor_name(*texts)
        if hit and hit in rollup:
            return rollup[hit]
        if hit:
            return bucket(hit)          # a known AI vendor is allowed to appear
        for t in texts:
            if t and t in rollup:
                return rollup[t]
        return None

    # --- Entra OAuth consent -------------------------------------------------
    for app in scored or []:
        if app.get("first_party_microsoft"):
            continue
        if not app.get("ai_match", True):
            non_ai_apps.append(app)     # part of the consent surface, not the AI estate
            continue
        rec = bucket(app.get("vendor"), app.get("display_name"), app.get("publisher"))
        rec["evidence"].add("oauth")
        rec["oauth_apps"].append(app)
        rec["users"] = max(rec["users"], app.get("user_count", 0) or 0)

    if connectors_result:
        a = _assessment(connectors_result)

        # --- Defender for Cloud Apps: browser-observed usage ------------------
        # These already passed the connector's own AI filter, so each one is a vendor.
        for app in (a.get("shadow_ai_usage") or {}).get("applications", []):
            rec = bucket(app.get("display_name"), app.get("vendor"))
            rec["evidence"].add("web")
            web = rec["web"] or {"users": 0, "uploaded_bytes": 0, "traffic_bytes": 0,
                                 "risk_score": None, "sanctioned": None, "apps": []}
            web["users"] = max(web["users"], app.get("users", 0) or 0)
            web["uploaded_bytes"] += app.get("uploaded_bytes", 0) or 0
            web["traffic_bytes"] += app.get("traffic_bytes", 0) or 0
            if isinstance(app.get("risk_score"), int):
                web["risk_score"] = app["risk_score"]
            web["sanctioned"] = app.get("sanctioned_state") or web["sanctioned"]
            web["apps"].append(app.get("display_name"))
            rec["web"] = web
            rec["users"] = max(rec["users"], web["users"])

        # --- Registered agents: attach only ------------------------------------
        for pkg in (a.get("agent365_packages") or {}).get("packages", []):
            rec = attach(pkg.get("publisher"), pkg.get("display_name"))
            if rec is None:
                unattached_agents.append(pkg.get("display_name"))
                continue
            rec["evidence"].add("agent")
            rec["agents"].append(pkg.get("display_name"))
        for ident in (a.get("agent_identities") or {}).get("identities", []):
            rec = attach(ident.get("display_name"))
            if rec is None:
                unattached_agents.append(ident.get("display_name"))
                continue
            rec["evidence"].add("agent")
            rec["agents"].append(ident.get("display_name"))

        # --- Purview sensitive interactions -----------------------------------
        for ix in (a.get("sensitive_interactions") or {}).get("sample", []):
            rec = attach(ix.get("app_host"))
            if rec is None:
                unattached_interactions += 1
                continue
            rec["evidence"].add("sensitive")
            rec["interactions"] += 1
            if str(ix.get("direction")) == "BLOCKED":
                rec["blocked"] += 1
            for sit in ix.get("sits") or []:
                rec["sensitive_types"].add(sit)

    for rec in rollup.values():
        _score_vendor(rec)
    return {
        "vendors": sorted(rollup.values(),
                          key=lambda r: (-r["risk_score"], r["vendor"].lower())),
        "non_ai_apps": non_ai_apps,
        "unattached_agents": unattached_agents,
        "unattached_interactions": unattached_interactions,
    }


def vendor_rollup(scored, connectors_result=None) -> list[dict]:
    """Just the vendor rows — see build_estate for what is deliberately excluded."""
    return build_estate(scored, connectors_result)["vendors"]


def _assessment(connectors_result):
    """connectors_result may be the raw run or an already-built assessment."""
    import connectors_report
    return connectors_report.assessment(connectors_result)


def _score_vendor(rec) -> None:
    """
    One score per vendor, and the reason chain that produced it.

    The highest-scoring consented app sets the floor — a vendor is at least as risky as
    its worst OAuth grant. Reach and sensitive data then add to it, because the same
    permission is worse when more people use it and worse again when Purview has
    already seen sensitive content go that way.
    """
    parts: list[tuple[int, str]] = []          # (points, why) — the visible arithmetic
    score = 0

    worst = max((app.get("risk_score", 0) or 0 for app in rec["oauth_apps"]), default=0)
    if worst:
        score = worst
        top = max(rec["oauth_apps"], key=lambda x: x.get("risk_score", 0) or 0)
        parts.append((worst, f"Starting point: its riskiest consented app, "
                             f"{top.get('display_name')} at {worst}/100"))
    if len(rec["oauth_apps"]) > 1:
        n = min(len(rec["oauth_apps"]), 5)
        score += n
        parts.append((n, f"{len(rec['oauth_apps'])} separate consented applications"))

    web = rec["web"]
    if web:
        users = web["users"]
        pts = 18 if users >= 100 else 10 if users >= 10 else 4 if users else 0
        if pts:
            score += pts
            parts.append((pts, f"{users} people reached it through the browser"))
        gb = web["uploaded_bytes"] / 1_073_741_824
        pts = (26 if gb >= 50 else 20 if gb >= 10 else 13 if gb >= 1
               else 7 if web["uploaded_bytes"] >= 100 * 1_048_576
               else 3 if web["uploaded_bytes"] else 0)
        if pts:
            score += pts
            parts.append((pts, f"{charts._fmt(web['uploaded_bytes'] / 1_048_576)} MB "
                               f"uploaded to it"))
        # Reach and volume together are the egress signal: a hundred people each moving
        # a little is a different problem from one person moving a lot, and scoring the
        # two factors independently flattens both into the same middling band.
        if users >= 100 and gb >= 1:
            score += 15
            parts.append((15, "Large volume leaving the tenant, spread across many people"))
        if web["sanctioned"] == "unsanctioned":
            score += 12
            parts.append((12, "Marked unsanctioned in Defender for Cloud Apps"))
        elif web["sanctioned"] in (None, "unreviewed"):
            score += 5
            parts.append((5, "Never reviewed in Defender for Cloud Apps"))

    if rec["interactions"]:
        allowed = rec["interactions"] - rec["blocked"]
        if allowed > 0:
            score += 15
            parts.append((15, f"{allowed} sensitive interaction(s) were allowed through"))
        if rec["blocked"]:
            parts.append((0, f"{rec['blocked']} blocked by DLP — no points, this is the "
                             f"control working"))
        if rec["sensitive_types"]:
            parts.append((0, "Data types seen: "
                             + ", ".join(sorted(rec["sensitive_types"])[:4])))

    if not rec["catalog_match"]:
        parts.append((0, "Not in the AI catalog — verify what this is before acting"))

    raw = round(score)
    rec["raw_score"] = raw
    rec["risk_score"] = max(0, min(100, raw))
    rec["risk_level"] = ("Critical" if rec["risk_score"] >= 75 else
                         "High" if rec["risk_score"] >= 50 else
                         "Medium" if rec["risk_score"] >= 25 else "Low")
    rec["breakdown"] = parts
    rec["reasons"] = [f"+{p} — {why}" if p else why for p, why in parts] or ["No notable signal"]


# --- rendering ---------------------------------------------------------------
def _evidence_badges(rec) -> str:
    out = []
    for key, label, why in EVIDENCE:
        if key in rec["evidence"]:
            out.append(f'<span class="ev" style="--ec:{_EVIDENCE_COLOR[key]}" '
                       f'title="{_esc(why)}">{_esc(label)}</span>')
    return "".join(out) or '<span class="ev muted">No evidence recorded</span>'


def _vendor_row(rec, idx) -> str:
    web = rec["web"] or {}
    facts = []
    if rec["oauth_apps"]:
        facts.append(f"{len(rec['oauth_apps'])} consented app"
                     f"{'s' if len(rec['oauth_apps']) > 1 else ''}")
    if web.get("users"):
        facts.append(f"{web['users']} web users")
    if web.get("uploaded_bytes"):
        facts.append(f"{charts._fmt(web['uploaded_bytes'] / 1_048_576)} MB up")
    if rec["agents"]:
        facts.append(f"{len(rec['agents'])} agent{'s' if len(rec['agents']) > 1 else ''}")
    if rec["interactions"]:
        facts.append(f"{rec['interactions']} sensitive interaction"
                     f"{'s' if rec['interactions'] > 1 else ''}")

    perms = sorted({p for app in rec["oauth_apps"] for p in app.get("scopes", [])
                    if _scope_weight(p) >= 6})
    perm_html = "".join(f'<span class="chip">{_esc(p)}</span>' for p in perms[:6])
    app_html = "".join(
        f'<li><b>{_esc(app.get("display_name"))}</b> — {app.get("risk_score", 0)}/100 · '
        f'{_esc(app.get("consent_type") or "no consent recorded")}</li>'
        for app in sorted(rec["oauth_apps"], key=lambda x: -(x.get("risk_score") or 0))[:8])
    sums = "".join(
        f'<li><span class="pt{"" if pts else " zero"}">{"+" + str(pts) if pts else "·"}</span>'
        f'<span>{_esc(why)}</span></li>' for pts, why in rec.get("breakdown", []))
    total = sum(p for p, _ in rec.get("breakdown", []))
    capped = ('<li class="cap"><span class="pt">=</span><span>capped at 100</span></li>'
              if total > 100 else "")
    reasons = (f'<ul class="calc">{sums}'
               f'<li class="tot"><span class="pt">{rec["risk_score"]}</span>'
               f'<span>Risk score out of 100</span></li>{capped}</ul>'
               if sums else '<p class="governed">No notable signal.</p>')

    return f"""
<div class="vrow" data-level="{_esc(rec['risk_level'])}"
     data-evidence="{_esc(' '.join(sorted(rec['evidence'])))}">
  <button class="vhead" aria-expanded="false">
    <span class="vscore" style="--sc:{LEVEL_COLORS[rec['risk_level']]}">{rec['risk_score']}</span>
    <span class="vname">{_esc(rec['vendor'])}
      <span class="vfacts">{_esc(' · '.join(facts)) or 'no activity recorded'}</span>
      <span class="vwhy">{_esc(_top_reason(rec))}</span>
    </span>
    <span class="vbadges">{_evidence_badges(rec)}</span>
    <span class="vchev">&#9662;</span>
  </button>
  <div class="vbody">
    <div class="vgrid">
      <div><h4>How this score is built</h4>{reasons}</div>
      <div><h4>Consented applications</h4>
        <ul>{app_html or '<li class="muted">None — seen only through other sources.</li>'}</ul>
        {f'<h4>Sensitive permissions</h4><div>{perm_html}</div>' if perm_html else ''}
      </div>
    </div>
  </div>
</div>"""


PORTAL_CSS = """
.vrow{border:1px solid var(--line);border-radius:10px;margin-bottom:8px;background:var(--panel);
 overflow:hidden}
.vhead{display:flex;align-items:center;gap:14px;width:100%;padding:13px 16px;cursor:pointer;
 background:none;border:0;color:var(--ink);text-align:left;font:inherit}
.vhead:hover{background:var(--track)}
.vscore{flex:0 0 auto;min-width:38px;height:26px;display:inline-flex;align-items:center;
 justify-content:center;border-radius:6px;background:var(--sc);color:#fff;font-weight:700;
 font-size:13px;font-variant-numeric:tabular-nums}
.vname{flex:1;font-weight:600;display:flex;flex-direction:column;gap:2px;min-width:0}
.vfacts{font-weight:400;font-size:12px;color:var(--muted)}
.vbadges{display:flex;gap:6px;flex-wrap:wrap;flex:0 0 auto}
.ev{font-size:11px;padding:2px 8px;border-radius:20px;border:1px solid var(--ec);
 color:var(--ink);white-space:nowrap}
.ev.muted{border-color:var(--line);color:var(--muted)}
.vchev{color:var(--muted);transition:transform .15s}
.vrow.open .vchev{transform:rotate(180deg)}
.vbody{display:none;padding:0 16px 16px;border-top:1px solid var(--line)}
.vrow.open .vbody{display:block}
.vgrid{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin-top:14px}
.vgrid h4{margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.03em;
 color:var(--muted)}
.vgrid ul{margin:0;padding-left:18px;font-size:13px}
.vgrid li{margin:4px 0}
.chip{display:inline-block;font-size:11px;background:var(--track);padding:2px 8px;
 border-radius:5px;margin:2px 4px 2px 0;font-family:ui-monospace,monospace}
.muted{color:var(--muted)}
.hero{grid-template-columns:1.35fr 1fr 1.05fr;align-items:start}
/* The context card is fifteen rows now; without this the four tiles beside it stretch
   to match its height and become mostly whitespace. */
.hero .tiles{grid-auto-rows:min-content}
.hero .tile{padding:15px 18px}
.hero .tile .n{font-size:27px}
.tenant-facts{grid-template-columns:auto 1fr;gap:7px 18px;align-items:baseline}
.tenant-facts b{color:var(--muted);font-weight:600;font-size:11.5px;white-space:nowrap}
.tenant-facts span{font-size:12.5px;word-break:break-word}
header .vswitch{margin-left:14px}
@media(max-width:960px){.hero{grid-template-columns:1fr}}
.changes-list{list-style:none;margin:0;padding:0;font-size:13px}
.changes-list li{display:flex;gap:10px;align-items:baseline;padding:7px 0;
 border-top:1px solid var(--line);line-height:1.45}
.changes-list li:first-child{border-top:0}
.cdot{width:8px;height:8px;border-radius:50%;flex:0 0 auto;margin-top:5px}
ul.na{margin:0;padding-left:18px;font-size:13px}
ul.na li{margin:6px 0;line-height:1.45}
.calc{list-style:none;margin:10px 0 0;padding:0;font-size:13px}
.calc li{display:flex;gap:12px;align-items:baseline;padding:5px 0;
 border-top:1px solid var(--line)}
.calc li:first-child{border-top:0}
.calc .pt{flex:0 0 46px;text-align:right;font-weight:700;font-variant-numeric:tabular-nums;
 color:var(--ink)}
.calc .pt.zero{color:var(--muted);font-weight:400}
.calc li.tot{border-top:2px solid var(--line);margin-top:4px;padding-top:8px;font-weight:600}
.calc li.cap span{color:var(--muted);font-weight:400;font-size:12px}
.explain{font-size:13px;color:var(--muted);line-height:1.55;margin-top:12px}
.explain p{margin:8px 0}
.explain b{color:var(--ink)}
details.explain{border:1px solid var(--line);border-radius:9px;padding:10px 14px;
 margin:12px 0 16px}
details.explain summary{cursor:pointer;font-weight:600;color:var(--ink);font-size:13px}
details.explain[open] summary{margin-bottom:8px}
.scoretab{width:100%;border-collapse:collapse;font-size:12px;margin:10px 0}
.scoretab th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.03em;
 color:var(--muted);padding:6px 10px 6px 0;border-bottom:1px solid var(--line)}
.scoretab td{padding:6px 10px 6px 0;border-bottom:1px solid var(--line);vertical-align:top}
.scoretab td:nth-child(2){white-space:nowrap;font-variant-numeric:tabular-nums;color:var(--ink)}
.vwhy{font-size:11px;color:var(--muted);font-weight:400}
@media(max-width:820px){.vgrid{grid-template-columns:1fr}.vbadges{display:none}}
.pfilters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.pfilters button{cursor:pointer;border:1px solid var(--line);background:transparent;
 color:var(--muted);border-radius:20px;padding:5px 13px;font-size:12px}
.pfilters button.active{border-color:var(--accent);color:var(--accent);font-weight:600}
.srcnav{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px}
.srcnav a{flex:1;min-width:220px;text-decoration:none;color:inherit;border:1px solid var(--line);
 border-radius:10px;padding:14px 16px;background:var(--panel);transition:border-color .15s}
.srcnav a:hover{border-color:var(--accent)}
.srcnav b{display:block;font-size:14px;margin-bottom:3px}
.srcnav span{font-size:12px;color:var(--muted)}
"""

PORTAL_JS = """
document.querySelectorAll('.vhead').forEach(function(h){
  h.onclick=function(){var r=h.closest('.vrow');var open=r.classList.toggle('open');
    h.setAttribute('aria-expanded',open?'true':'false');};
});
var pstate={level:'all',evidence:'all'};
function papply(){
  document.querySelectorAll('.vrow').forEach(function(r){
    var okL=pstate.level==='all'||r.getAttribute('data-level')===pstate.level;
    var okE=pstate.evidence==='all'||
      (r.getAttribute('data-evidence')||'').split(' ').indexOf(pstate.evidence)>=0;
    r.style.display=(okL&&okE)?'':'none';});
}
document.querySelectorAll('.pfilters button').forEach(function(b){
  b.onclick=function(){
    var g=b.getAttribute('data-group');
    b.parentNode.querySelectorAll('button').forEach(function(x){x.classList.remove('active');});
    b.classList.add('active');pstate[g]=b.getAttribute('data-value');papply();};
});
/* Served from /api/, the detail views need the function key carried across, and the
   connectors route needs format=html. Opened off disk, the plain hrefs already work. */
(function(){
  if(location.pathname.indexOf('/api/')!==0){return;}
  var code=new URLSearchParams(location.search).get('code');
  document.querySelectorAll('.srcnav a').forEach(function(a){
    var base=a.getAttribute('href'), q=[];
    if(code){q.push('code='+encodeURIComponent(code));}
    if(base.indexOf('connectors')>=0){q.push('format=html');}
    a.href=base+(q.length?'?'+q.join('&'):'');});
})();
"""


def html_string(scored, tenant_id="", connectors_result=None, changes=None,
                findings=None, report_href="report.html",
                connectors_href="connectors.html", now=None,
                standalone_links=True, context=None) -> str:
    """
    `standalone_links` links out to the two dashboards as separate files. Turn it off
    when the portal travels alone — as an email attachment, say — because those hrefs
    point at sibling files that will not be there, and a dead link is worse than none.
    The portal carries all of their content in its own tabs regardless.
    """
    now = now or datetime.now(timezone.utc)
    estate = build_estate(scored, connectors_result)
    vendors = estate["vendors"]
    ts = now.strftime("%d.%m.%Y %H:%M UTC")

    counts = {lv: sum(1 for v in vendors if v["risk_level"] == lv) for lv in LEVELS}
    health = _health_of(connectors_result)

    with_web = [v for v in vendors if "web" in v["evidence"]]
    with_oauth = [v for v in vendors if "oauth" in v["evidence"]]
    both = [v for v in vendors if {"oauth", "web"} <= v["evidence"]]
    sensitive = [v for v in vendors if "sensitive" in v["evidence"]]
    web_users = sum((v["web"] or {}).get("users", 0) for v in vendors)
    uploaded = sum((v["web"] or {}).get("uploaded_bytes", 0) for v in vendors)

    posture, posture_parts = _posture(vendors, counts)
    posture_calc = (
        '<ul class="calc">'
        + "".join(f'<li><span class="pt">+{p}</span><span>{_esc(w)}</span></li>'
                  for p, w in posture_parts)
        + f'<li class="tot"><span class="pt">{posture}</span>'
          f'<span>Posture score out of 100</span></li></ul>'
    ) if posture_parts else '<p class="governed">Nothing contributing yet.</p>' 
    donut = charts.donut([(lv, counts[lv], LEVEL_COLORS[lv]) for lv in LEVELS],
                         center_value=len(vendors), center_label="AI vendors")
    legend = charts.legend([(lv, LEVEL_COLORS[lv], counts[lv]) for lv in LEVELS])
    scatter = charts.risk_scatter(
        [(v["vendor"], v["risk_score"], v["users"], v["risk_level"],
          sum(len(a.get("scopes", [])) for a in v["oauth_apps"]) or 1) for v in vendors])
    top_bars = charts.hbar(
        [(v["vendor"], " · ".join(sorted(v["evidence"])) or "—", v["risk_score"],
          LEVEL_COLORS[v["risk_level"]]) for v in vendors[:8]])

    rows = "".join(_vendor_row(v, i) for i, v in enumerate(vendors)) or \
        '<div class="empty">No AI vendors found in this scan.</div>'

    switcher = report.view_switcher(
        "portal",
        report_href=report_href if standalone_links else None,
        connectors_href=connectors_href if standalone_links else None)
    standalone_block = ""

    # With no sibling files to point at, these read as plain references to the tab that
    # holds the detail — a dead link is worse than no link.
    def _ref(href, label, tab):
        return f'<a href="{_esc(href)}">{label}</a>' if standalone_links \
            else f"the <b>{tab}</b> tab above"

    ctx = context or {}
    prof = ctx.get("tenant_profile") or {}
    org_label = prof.get("display_name") or tenant_id or "—"
    context_facts = _context_card(ctx, tenant_id, vendors, ts)

    attention = _attention_card(scored, changes, findings, health)
    change_card = _changes_card(changes)

    excluded_rows = []
    if estate["non_ai_apps"]:
        worst = max(a.get("risk_score", 0) or 0 for a in estate["non_ai_apps"])
        excluded_rows.append(
            f'<b>{len(estate["non_ai_apps"])} consented applications</b> that did not match '
            f'the AI catalog (highest risk score {worst}/100). They hold real OAuth grants '
            f'and are fully assessed on '
            f'{_ref(report_href, "the Entra OAuth assessment", "Applications")}.')
    if estate["unattached_agents"]:
        sample = ", ".join(_esc(n) for n in estate["unattached_agents"][:4] if n)
        excluded_rows.append(
            f'<b>{len(estate["unattached_agents"])} registered agents and Teams packages</b> '
            f'with no AI vendor match ({sample}…). Listed in full on '
            f'{_ref(connectors_href, "the AI data sources view", "Agents")}.')
    if estate["unattached_interactions"]:
        excluded_rows.append(
            f'<b>{estate["unattached_interactions"]} sensitive interactions</b> whose host '
            f'application could not be matched to a vendor.')
    excluded = "".join(f"<li>{row}</li>" for row in excluded_rows) or \
        '<li class="governed">Nothing excluded — every discovered asset is in the estate above.</li>'

    coverage = "".join(
        f'<li><span class="dot" style="background:'
        f'{charts.SEVERITY["Low"] if ok else (charts.SEVERITY["Critical"] if ok is False else "#6b7280")}'
        f'"></span><b>{_esc(name)}</b> <span class="governed">{_esc(detail)}</span></li>'
        for name, ok, detail in executive.connector_status(health))

    estate_body = f"""
  <div class="hero">
    <div class="card">
      <h3>Scan context</h3>
      {context_facts}
    </div>
    <div class="tiles">
      <div class="card tile"><span class="n">{len(with_oauth)}</span><span class="l">With OAuth consent</span></div>
      <div class="card tile"><span class="n">{len(with_web)}</span><span class="l">Seen in web traffic</span></div>
      <div class="card tile high"><span class="n">{len(both)}</span><span class="l">Both routes</span></div>
      <div class="card tile"><span class="n">{charts._fmt(web_users)}</span><span class="l">Users reached</span></div>
    </div>
    <div class="card">
      <h3>Risk distribution</h3>
      <div class="summary">{donut}</div>{legend}
    </div>
  </div>

  <div class="grid cols-2" style="margin-top:16px">
    <div class="card">
      <h3>Where to start</h3>
      {scatter}{legend}
      <div class="explain">
        <p><b>How to read this.</b> One dot per vendor. Left to right is how many people
        it reaches; bottom to top is its risk score. Bigger dots hold more permissions.</p>
        <p><b>Work the top-right corner first</b> — high risk reaching many people. A dot
        high on the left is serious but contained; one low on the right is widespread but
        currently harmless. The user axis is logarithmic, so each gridline is ten times
        the last: 5 users and 500 users are not a short distance apart.</p>
      </div>
    </div>
    <div class="card">
      <h3>Tenant AI posture</h3>
      <div style="display:flex;justify-content:center">{charts.gauge(posture, "Tenant AI posture")}</div>
      <p class="governed">One number for the whole estate. Each vendor contributes points
      by severity; the total is put through a curve so it keeps moving instead of pinning
      at 100. It is not an average — two Critical vendors must not be diluted by twenty
      quiet ones.</p>
      {posture_calc}
    </div>
  </div>

  <div class="grid cols-2" style="margin-top:16px">
    <div class="card"><h3>Needs attention</h3>{attention}</div>
    <div class="card"><h3>What changed since the last scan</h3>{change_card}</div>
  </div>

  <div class="card" style="margin-top:16px">
    <h3>AI estate — {len(vendors)} vendors</h3>
    <p class="governed" style="margin-top:-6px">One row per vendor. Badges show how it was
    seen; a vendor found through several routes is one row, not several.</p>
    <details class="explain">
      <summary>What the score means, and where the number comes from</summary>
      <p>Every score is a sum of named signals — open any row to see the arithmetic that
      produced it. Nothing is weighted secretly and nothing is a model output.</p>
      <table class="scoretab">
        <tr><th>Signal</th><th>Points</th><th>Why it counts</th></tr>
        <tr><td>Riskiest consented app</td><td>its own 0–100 score</td>
            <td>A vendor is at least as risky as the worst grant it holds</td></tr>
        <tr><td>People reached (browser)</td><td>+4 / +10 / +18</td>
            <td>1+, 10+, 100+ users — the blast radius</td></tr>
        <tr><td>Uploaded volume</td><td>+3 … +26</td>
            <td>100 MB through 50 GB+ — how much actually left</td></tr>
        <tr><td>Volume across many people</td><td>+15</td>
            <td>Wide and heavy together, which neither factor shows alone</td></tr>
        <tr><td>Unsanctioned / never reviewed</td><td>+12 / +5</td>
            <td>Nobody has made a decision about this tool</td></tr>
        <tr><td>Sensitive data allowed through</td><td>+15</td>
            <td>Purview saw it and DLP did not stop it</td></tr>
      </table>
      <p><b>Bands:</b> 75+ Critical · 50–74 High · 25–49 Medium · under 25 Low.
      A DLP <i>block</i> adds nothing — that is the control working, not a failure.</p>
    </details>
    <div class="pfilters">
      <button data-group="level" data-value="all" class="active">All risk</button>
      <button data-group="level" data-value="Critical">Critical</button>
      <button data-group="level" data-value="High">High</button>
      <button data-group="level" data-value="Medium">Medium</button>
      <button data-group="level" data-value="Low">Low</button>
    </div>
    <div class="pfilters">
      <button data-group="evidence" data-value="all" class="active">All sources</button>
      <button data-group="evidence" data-value="oauth">OAuth consent</button>
      <button data-group="evidence" data-value="web">Web traffic</button>
      <button data-group="evidence" data-value="agent">Agents</button>
      <button data-group="evidence" data-value="sensitive">Sensitive data</button>
    </div>
    {rows}
  </div>

  <div class="card" style="margin-top:16px"><h3>Highest-risk vendors</h3>{top_bars}</div>

  <div class="card" style="margin-top:16px">
    <h3>Deliberately not ranked above</h3>
    <p class="governed" style="margin-top:-6px">Counted, not hidden — none of it is
    identified as AI, so ranking it alongside the estate would bury the real findings.</p>
    <ul class="conn">{excluded}</ul>
  </div>

  <div class="card" style="margin-top:16px">
    <h3>Data sources</h3>
    <p class="governed" style="margin-top:-6px">Where everything above came from, and what
    is not covered. A grey entry has no collector yet — that is a limit of this tool, not
    of your tenant.</p>
    <ul class="conn">{coverage}</ul>
  </div>
{standalone_block}
"""

    # One page. The two dashboards keep their own tabs and are one click away; putting
    # ten tabs here as well made the portal a second copy of them rather than the place
    # you start. What the removed tabs carried that belongs in an overview — the
    # narratives and the change summary — is folded into the page below.
    page_body = f"""
<header>
  {_LOGO}
  <h1>AI-SPM</h1>
  {switcher}
  <span class="spacer"></span>
  <span class="tenant">{_esc(org_label)}</span>
  <button id="tg" class="themebtn" title="Theme">&#9790;</button>
</header>
<main>
  {estate_body}
  <div class="foot">AI-SPM · read-only · {ts}</div>
</main>
<script>{THEME_JS}{PORTAL_JS}{charts.JS}</script>
"""
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>AI-SPM · AI Estate</title>'
            f'<style>{CSS}{charts.CSS}{PORTAL_CSS}</style>'
            f'</head><body>{page_body}</body></html>')


_LOGO = """<svg class="logo" width="22" height="22" viewBox="0 0 21 21" xmlns="http://www.w3.org/2000/svg">
<rect x="1" y="1" width="9" height="9" fill="#F25022"/><rect x="11" y="1" width="9" height="9" fill="#7FBA00"/>
<rect x="1" y="11" width="9" height="9" fill="#00A4EF"/><rect x="11" y="11" width="9" height="9" fill="#FFB900"/>
</svg>"""


_POSTURE_WEIGHTS = {"Critical": 14, "High": 7, "Medium": 2, "Low": 0.5,
                    "both_routes": 4, "sensitive": 5}
_POSTURE_SCALE = 120.0


def _posture(vendors, counts):
    """
    (score, contributions). Same saturating curve as the core dashboard, over vendors.

    Returns the parts as well as the number so the page can show its arithmetic —
    a posture score nobody can decompose is a number nobody can act on.
    """
    import math
    if not vendors:
        return 0, []
    w = _POSTURE_WEIGHTS
    both = sum(1 for v in vendors if {"oauth", "web"} <= v["evidence"])
    sens = sum(1 for v in vendors if "sensitive" in v["evidence"])
    rows = [
        (counts["Critical"], w["Critical"], "Critical vendors"),
        (counts["High"], w["High"], "High vendors"),
        (counts["Medium"], w["Medium"], "Medium vendors"),
        (counts["Low"], w["Low"], "Low vendors"),
        (both, w["both_routes"], "reachable through both consent and the browser"),
        (sens, w["sensitive"], "with sensitive data recorded by Purview"),
    ]
    parts = [(round(n * weight), f"{n} {label} x {weight:g}")
             for n, weight, label in rows if n]
    raw = sum(n * weight for n, weight, _ in rows)
    return round(100 * (1 - math.exp(-raw / _POSTURE_SCALE))), parts


def json_string(scored, connectors_result=None, tenant_id="") -> str:
    vendors = vendor_rollup(scored, connectors_result)
    return json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "tenant": tenant_id,
        "vendors": [{**v, "evidence": sorted(v["evidence"]),
                     "sensitive_types": sorted(v["sensitive_types"]),
                     "oauth_apps": [a.get("display_name") for a in v["oauth_apps"]]}
                    for v in vendors],
    }, ensure_ascii=False, indent=2, default=str)


def write_html(scored, path, tenant_id="", connectors_result=None, **kw) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_string(scored, tenant_id, connectors_result, **kw))


def _top_reason(rec) -> str:
    """The single largest contributor — so a collapsed row never shows a bare number."""
    scoring = [(p, why) for p, why in rec.get("breakdown", []) if p]
    if not scoring:
        return "no scoring signal"
    pts, why = max(scoring, key=lambda x: x[0])
    return f"mostly: {why} (+{pts})"


def _health_of(connectors_result):
    """
    Connector health, from either shape of input.

    A raw run carries it under "health"; an assessment (the JSON cache, or anything that
    has already been through connectors_report) carries the same facts under
    "data_source_coverage". Reading only the first made every source read "not run in
    this scan" whenever the cached form was passed.
    """
    if not connectors_result:
        return None
    health = connectors_result.get("health")
    if health:
        return health
    rows = connectors_result.get("data_source_coverage")
    if not rows:
        return None
    return {r.get("name"): {"status": r.get("status"), "count": r.get("count")}
            for r in rows if r.get("name")}


_CHANGE_COLOR = {"Critical": charts.SEVERITY["Critical"], "High": charts.SEVERITY["High"],
                 "Medium": charts.SEVERITY["Medium"], "Low": charts.SEVERITY["Low"],
                 "Info": "#6b7280"}


def _attention_card(scored, changes, findings, health) -> str:
    """
    The executive narratives, which used to sit behind the Overview tab of the core
    dashboard. On a single-page portal they belong on the page, not one click away.
    """
    try:
        lines = executive.needs_attention(scored or [], changes or [], findings or [], health)
    except Exception:
        lines = []
    # Connector coverage is stated in full, per source and with its real status, in the
    # Data sources card at the foot of this page. Restating it as "needs attention"
    # would put seven duplicate lines above the estate narratives that are the point.
    lines = [l for l in lines if "not connected" not in l]
    if not lines:
        return ('<p class="governed">Nothing flagged. Every discovered application has an '
                'owner, a classification and a lifecycle state, and no findings are '
                'overdue.</p>')
    return ('<ul class="na">'
            + "".join(f"<li>{_esc(l)}</li>" for l in lines[:8]) + "</ul>")


def _changes_card(changes, top=7) -> str:
    """
    What a follow-up scan found, most important first.

    The first question anyone asks of a second scan is what moved, so it is answered on
    the page rather than behind a tab. Full history stays on the OAuth assessment.
    """
    if not changes:
        return ('<p class="governed">This is the baseline scan. From the next one on, '
                'everything that appears, escalates or disappears is listed here — new '
                'applications, permission escalations, admin consent granted, usage '
                'jumps.</p>')
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    ranked = sorted(changes, key=lambda e: order.get(e.get("importance"), 5))
    rows = "".join(
        f'<li><span class="cdot" style="background:'
        f'{_CHANGE_COLOR.get(e.get("importance"), "#6b7280")}"></span>'
        f'<span><b>{_esc(e.get("asset_name"))}</b> — {_esc(e.get("description"))}</span></li>'
        for e in ranked[:top])
    more = (f'<p class="governed">{len(changes) - top} more on the OAuth assessment.</p>'
            if len(changes) > top else "")
    return f'<ul class="changes-list">{rows}</ul>{more}'


def _context_card(ctx, tenant_id, vendors, ts) -> str:
    """
    Who ran this, against what, with which permissions and how wide.

    A dashboard read weeks later, or forwarded to someone who did not run it, needs to
    say whose view it is: a delegated scan by a Security Reader and an application scan
    with all six permissions produce very different pages from the same tenant. Every
    row is omitted when unknown rather than filled with a placeholder.
    """
    prof = ctx.get("tenant_profile") or {}
    ident = ctx.get("identity") or {}
    graph = ctx.get("graph") or {}

    who = ident.get("user") or ident.get("app_name") or ident.get("client_id")
    kind = {"delegated": "delegated — the signed-in user's permissions",
            "application": "application — the app registration's own permissions",
            }.get(ident.get("kind"), ident.get("kind"))

    rows = [
        ("Organisation", prof.get("display_name")),
        ("Primary domain", prof.get("primary_domain")),
        ("Tenant ID", tenant_id),
        ("Subscription", ctx.get("subscription_name")),
        ("Subscription ID", ctx.get("subscription_id")),
        ("Scanned by", who),
        ("Token type", kind),
        ("Graph permissions", ident.get("scope_count") or None),
        ("Scan scope", _SCOPE_LABEL.get(ctx.get("scan_scope"), ctx.get("scan_scope"))),
        ("Activity window", f"{ctx['activity_days']} days" if ctx.get("activity_days") else None),
        ("AI vendors", len(vendors)),
        ("Consented apps", sum(len(v["oauth_apps"]) for v in vendors)),
        ("Scan finished", ts),
        ("Duration", f"{ctx['duration_s']}s" if ctx.get("duration_s") is not None else None),
        ("Graph calls", _graph_summary(graph)),
    ]
    facts = "".join(f"<b>{_esc(k)}</b><span>{_esc(v)}</span>"
                    for k, v in rows if v not in (None, "", 0))
    return f'<div class="tenant-facts">{facts}</div>'


_SCOPE_LABEL = {
    "ai": "AI catalog matches only",
    "consented": "every app holding an OAuth grant",
    "all": "every third-party app",
}


def _graph_summary(graph) -> str:
    if not graph or not graph.get("requests"):
        return ""
    parts = [f"{graph['requests']} requests"]
    if graph.get("batch_calls"):
        parts.append(f"{graph['batched_requests']} batched")
    if graph.get("throttled"):
        parts.append(f"{graph['throttled']} throttled")
    return " · ".join(parts)
