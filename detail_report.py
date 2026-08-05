"""
The detail page: everything behind the assessment, on one page instead of two.

There used to be four pages. Two of them — the OAuth assessment and the AI data sources
dashboard — each opened with their own overview, each carried their own Findings tab, and
between them the same coverage story was told twice. Four overviews of one tenant is not
four points of view, it is three copies to keep in agreement, and they had already drifted
apart once.

So the sections are composed here from the two existing builders rather than reimplemented,
and the duplicates are dropped rather than repeated:

    dropped   the OAuth overview and the data-sources overview   (the assessment page
              already opens with one)
    merged    the two Findings tabs into one
    merged    coverage and connector gaps into one Coverage tab

Everything else keeps its own tab and its own home: permissions and usage belong to the
OAuth side, agents and observed traffic to the data-sources side, and neither is repeated
in the other's territory.
"""
import html

import charts
import connectors_report
import report

# (key, label, group) — the group is only a visual separator in the nav; every tab is
# a peer. Order follows the question being asked, not which module produced it.
_TABS = [
    ("apps", "Applications", "oauth"),
    ("usage", "Usage", "oauth"),
    ("governance", "Governance", "oauth"),
    ("agents", "Agents", "sources"),
    ("shadow", "Shadow AI", "sources"),
    ("sensitive", "Sensitive data", "sources"),
    ("findings", "Findings", "shared"),
    ("changes", "Changes", "shared"),
    ("coverage", "Coverage", "shared"),
]

LOGO = """<svg class="logo" width="22" height="22" viewBox="0 0 21 21"
 xmlns="http://www.w3.org/2000/svg">
<rect x="1" y="1" width="9" height="9" fill="#F25022"/>
<rect x="11" y="1" width="9" height="9" fill="#7FBA00"/>
<rect x="1" y="11" width="9" height="9" fill="#00A4EF"/>
<rect x="11" y="11" width="9" height="9" fill="#FFB900"/></svg>"""

CSS = """
.grp-sep{width:1px;align-self:stretch;background:var(--line);margin:8px 6px}
.merged-h{margin:26px 4px 12px;font-size:13px;text-transform:uppercase;letter-spacing:.03em;
 color:var(--muted);font-weight:600}
.merged-h:first-child{margin-top:0}
.src-note{color:var(--muted);font-size:12.5px;margin:0 4px 14px}
"""


def _section(title, note, body):
    """A composed tab says which side of the product each half came from."""
    return (f'<h3 class="merged-h">{html.escape(title)}</h3>'
            f'<p class="src-note">{html.escape(note)}</p>{body}')


def build(apps, tenant_id, changes=None, findings=None, connectors_result=None,
          now=None) -> dict:
    """The nine tab bodies, plus whatever assets the two builders need with them."""
    health = (connectors_result or {}).get("health")
    core = report.build_tabs(apps, tenant_id, changes, findings, health)

    if connectors_result:
        built = connectors_report.build_tabs(connectors_result, tenant_id, now)
        src = built["tabs"]
        extra_css = built["css"]
        extra_js = built["script"]
        panel = built["detail_panel"]
    else:
        # No connectors ran: the data-source tabs would each be an empty shell. Say so
        # once, in the tab, rather than rendering three empty tables.
        note = ('<div class="card"><h3>No AI data sources are connected</h3>'
                '<p class="governed">Agents, browser-observed Shadow AI and sensitive-data '
                'interactions come from Agent 365, Entra Agent ID, Defender for Cloud Apps '
                'and Purview. None of them answered on this run, so there is nothing to '
                'show here — which is a gap in visibility, not an all-clear. The Coverage '
                'tab names each source and what it needs.</p></div>')
        src = {"agents": note, "shadow": note, "sensitive": note, "findings": "",
               "gaps": "", "coverage": ""}
        extra_css = extra_js = panel = ""

    tabs = {
        "apps": core.get("apps", ""),
        "usage": core.get("usage", ""),
        "governance": core.get("governance", ""),
        "agents": src.get("agents", ""),
        "shadow": src.get("shadow", ""),
        "sensitive": src.get("sensitive", ""),
        # No drift history at all is the first scan, which is a real state with a real
        # answer — not an empty tab. (An empty *list* already renders its own baseline
        # note; this is the None case, where no store exists yet.)
        "changes": core.get("changes", "") or (
            '<div class="card"><h3>Nothing to compare against yet</h3>'
            '<p class="governed">The first scan is the baseline and deliberately reports '
            'no changes — inventing them on a first run would make every new deployment '
            'look like a breach. Run a second scan and this fills with what moved: a new '
            'application, a consent escalated from one user to the whole organisation, an '
            'application that has just gained unattended access.</p></div>'),
    }

    # The two halves each produced a Findings list. One tab, both lists, each labelled
    # with where it came from — the alternative was the same problem under two names.
    # `findings` is the managed record store, which only exists once a scan has written
    # one. Empty is a legitimate state; a nav button that opens nothing is not.
    core_findings = core.get("findings", "") or (
        '<div class="card"><h3>No managed finding records yet</h3>'
        '<p class="governed">Findings become tracked records — with an owner, a due date '
        'and a status — once a scan has written the store. Until then the failing tests '
        'on the assessment are the live list, and each one names the applications it '
        'applies to.</p></div>')
    src_findings = src.get("findings", "")
    if src_findings:
        tabs["findings"] = (
            _section("From the OAuth assessment",
                     "Findings raised against consented applications and their permissions.",
                     core_findings)
            + _section("From the AI data sources",
                       "Findings raised from agents, observed traffic and Purview records.",
                       src_findings))
    else:
        tabs["findings"] = core_findings

    core_coverage = core.get("coverage", "")
    src_coverage = src.get("coverage", "")
    src_gaps = src.get("gaps", "")
    if src_coverage or src_gaps:
        tabs["coverage"] = (
            _section("What is owned and reviewed",
                     "How much of the estate has a business owner and a purpose recorded.",
                     core_coverage)
            + _section("What each source can see",
                       "Every connector, whether it answered, and what it needs if it did not.",
                       src_coverage)
            + _section("What no source can see",
                       "Limits of the APIs themselves — true however well the tenant is "
                       "configured.", src_gaps))
    else:
        tabs["coverage"] = core_coverage

    return {"tabs": tabs, "css": extra_css, "script": extra_js, "panel": panel}


def html_string(apps, tenant_id, changes=None, findings=None, connectors_result=None,
                now=None, assessment_href=None) -> str:
    built = build(apps, tenant_id, changes, findings, connectors_result, now)
    tabs = built["tabs"]

    nav, last_group = [], None
    for key, label, group in _TABS:
        if group != last_group and last_group is not None:
            nav.append('<span class="grp-sep"></span>')
        last_group = group
        active = " active" if key == _TABS[0][0] else ""
        nav.append(f'<a class="navlink{active}" data-tab="{key}">{html.escape(label)}</a>')

    sections = "".join(
        f'<section class="tab{" active" if key == _TABS[0][0] else ""}" data-tab="{key}">'
        f'{tabs.get(key, "")}</section>' for key, _l, _g in _TABS)

    back = ""
    if assessment_href:
        back = (f'<a class="backlink" href="{html.escape(assessment_href, quote=True)}">'
                f'&#8592; Assessment</a>')

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI-SPM &middot; Detail</title>
<style>{report.CSS}{charts.CSS}{built["css"]}{CSS}
.backlink{{color:var(--accent);text-decoration:none;font-size:13px;font-weight:600;
 white-space:nowrap;margin-left:10px}}</style></head>
<body>
<header>
  {LOGO}
  <h1>AI-SPM</h1>
  <nav class="tabs">{"".join(nav)}</nav>
  <span class="spacer"></span>
  <span class="tenant">{html.escape(tenant_id)}</span>
  {back}
  <button id="tg" class="themebtn" title="Theme">&#9790;</button>
</header>
<main>{sections}</main>
<div class="foot">AI-SPM &middot; read-only. Everything here is behind the assessment;
nothing is repeated from it.</div>
{built["panel"]}
<script>{report.THEME_JS}{charts.JS}{built["script"]}</script>
</body></html>
"""
