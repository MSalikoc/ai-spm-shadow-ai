"""
The assessment page — AI-SPM's landing view.

Modelled on Microsoft's Zero Trust Assessment, deliberately: it is the visual language a
Microsoft customer already trusts for exactly this kind of answer, and copying a proven
pattern is cheaper than teaching a new one. The shape it borrows is a poor table and a
rich panel — three columns (Name / Risk / Status) and every piece of depth behind a
click, because a table that tries to carry the depth ends up carrying neither.

What it adds beyond that pattern: a failing test names the assets that failed it, and a
test whose source is missing says so instead of passing quietly.

Above that table sits a decision cockpit: one number for exposure (reusing the same
`report._posture_score` a scan already computes), how much of the catalogue could
actually be answered this scan (never letting "not assessed" read as "safe"), which
findings concentrate the blast radius, and a triage of what to fix now / next / when
there is time — all folded straight out of `results`, `apps` and `estate` the page
already has. Nothing here is a second opinion; it is the same verdicts, ordered for
someone who has thirty seconds before the next meeting.

Self-contained HTML — no external CSS, fonts or scripts. These pages are served from Blob
storage and opened off disk, where a CDN reference is a blank page.
"""
import html
import math
from datetime import datetime, timezone

import assessment
import charts
import dashboard_theme
import dashboard_workflow
import decisions as decisionstate
import executive
import report

STATUS_COLOR = {assessment.FAILED: "var(--cp-danger)", assessment.PASSED: "var(--cp-success-readable)",
                assessment.NOT_ASSESSED: "var(--cp-text-muted)", assessment.SKIPPED: "var(--cp-text-soft)"}
RISK_COLOR = {"High": "var(--cp-danger)", "Medium": "var(--cp-text)", "Low": "var(--cp-text-muted)"}
PILLAR_COLOR = {assessment.P_ID: "var(--cp-accent)", assessment.P_DATA: "var(--cp-danger)",
                assessment.P_GOV: "var(--cp-success)", assessment.P_SURF: "var(--cp-warning)",
                assessment.P_MON: "var(--cp-link)"}
STATUS_MARK = {assessment.FAILED: "&#10060;", assessment.PASSED: "&#9989;",
               assessment.NOT_ASSESSED: "&#128683;", assessment.SKIPPED: "&#9899;"}
DECISION_PROGRAMS = (
    {
        "key": "sensitive-access",
        "title": "Control privileged AI access and sensitive-data exposure",
        "owner": "IAM + Data Protection",
        "sla": "7 days",
        "choice": ("Reduce delegated and application permissions to least privilege, narrow "
                   "consent where applicable, and enforce DLP for sensitive AI interactions. "
                   "Retain broad access only as a time-bound, documented exception."),
        "why": ("Broad consent, privileged application permissions and missing data controls "
                "create paths from an AI service to organisation-wide information."),
        "ids": {"AISPM-1001", "AISPM-1003", "AISPM-1005", "AISPM-2001", "AISPM-2002"},
    },
    {
        "key": "identity-exposure",
        "title": "Contain unattended and high-reach AI identities",
        "owner": "Identity Security / SecOps",
        "sla": "72 hours for High; 14 days otherwise",
        "choice": ("Disable unused identities, reduce app-only permissions and rotate or "
                   "replace long-lived credentials. Enforce existing blocked decisions and "
                   "approve only the justified remainder."),
        "why": ("Unattended identities operate without a user and high-reach applications "
                "multiply the impact of one credential or permission failure."),
        "ids": {"AISPM-1002", "AISPM-1004", "AISPM-1008", "AISPM-3005", "AISPM-4001",
                "AISPM-4003", "AISPM-5001"},
    },
    {
        "key": "governance",
        "title": "Establish ownership and govern Shadow AI adoption",
        "owner": "AI Governance Council",
        "sla": "30 days",
        "choice": ("Assign an accountable business owner, decide lifecycle and sanctioning "
                   "status, and record a business purpose for every application and agent."),
        "why": ("Unowned or unreviewed AI cannot be accepted, remediated or retired by an "
                "accountable decision-maker."),
        "ids": {"AISPM-1006", "AISPM-1007", "AISPM-2003", "AISPM-2004", "AISPM-3001",
                "AISPM-3002", "AISPM-3003", "AISPM-3004", "AISPM-3006",
                "AISPM-4002", "AISPM-4004", "AISPM-4005", "AISPM-5002", "AISPM-5003"},
    },
)

CSS = """
*{box-sizing:border-box}
:root{
 --bg:#faf9f8; --card:#fff; --ink:#1b1a19; --muted:#605e5c; --line:#e1dfdd;
 --track:#f3f2f1; --link:#0f6cbd;
}
:root[data-theme=dark]{
 --bg:#1b1a19; --card:#252423; --ink:#f3f2f1; --muted:#a19f9d; --line:#3b3a39;
 --track:#323130; --link:#6cb8f6;
}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font:15px/1.5 "Segoe UI",-apple-system,
 BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--link)}
.topbar{position:sticky;top:0;z-index:40;background:var(--card);border-bottom:1px solid var(--line);
 display:flex;align-items:center;gap:26px;padding:0 28px;height:56px}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:15px;white-space:nowrap}
.logo{display:grid;grid-template-columns:8px 8px;grid-gap:2px}
.logo i{width:8px;height:8px;display:block}
.logo i:nth-child(1){background:#f25022}.logo i:nth-child(2){background:#7fba00}
.logo i:nth-child(3){background:#00a4ef}.logo i:nth-child(4){background:#ffb900}
nav{display:flex;gap:4px;flex:1;overflow:auto}
nav a{color:var(--muted);text-decoration:none;font-size:14px;padding:8px 12px;border-radius:4px;
 white-space:nowrap;cursor:pointer}
nav a:hover{background:var(--track);color:var(--ink)}
nav a.on{color:var(--ink);font-weight:600}
nav a.out i{font-style:normal;font-size:11px;margin-left:4px;opacity:.7}
.navsep{width:1px;background:var(--line);margin:12px 8px;flex:0 0 auto}
.mono{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.tbl-wrap{overflow-x:auto}
.gap{display:flex;gap:10px;padding:9px 0;border-bottom:1px solid var(--line);font-size:14px}
.gap:last-of-type{border-bottom:none}
.gap span{color:#8a8886;flex:0 0 auto}
.gapwhy{color:var(--muted);font-size:13px;margin-top:3px;line-height:1.5}
.topright{display:flex;align-items:center;gap:16px;color:var(--muted);font-size:14px}
.iconbtn{background:none;border:none;color:var(--muted);cursor:pointer;font-size:16px;padding:6px}
.wrap{max-width:1180px;margin:0 auto;padding:28px 24px 60px}
h1{font-size:30px;font-weight:600;margin:6px 0 22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:22px 24px}
.card h2{font-size:20px;font-weight:600;margin:0 0 4px;display:flex;align-items:center;gap:9px}
.card h3{font-size:16px;font-weight:600;margin:0 0 14px}
.sub{color:var(--muted);font-size:13.5px;margin:0 0 18px}
.grid{display:grid;gap:16px}
.top3{grid-template-columns:1.05fr 1.25fr 1fr}
.two{grid-template-columns:1fr 1fr}
.tiles{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 18px;
 display:flex;align-items:center;gap:14px}
.tile .tn{font-size:22px;font-weight:600;line-height:1.1}
.tile .tl{color:var(--muted);font-size:13px}
.tile .dot{width:26px;height:26px;border-radius:6px;flex:0 0 auto}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 18px;font-size:13.5px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;font-weight:600;word-break:break-word}
.pillrow{display:flex;justify-content:space-between;align-items:baseline;padding:5px 0;
 font-size:13.5px;gap:14px}
.pillrow b{font-size:17px}
.pillrow .u{color:var(--muted);font-size:12px;margin-left:3px}
.cap{color:var(--muted);font-size:13.5px;margin:16px 0 0;line-height:1.55}
.foots{display:flex;border-top:1px solid var(--line);margin-top:18px;padding-top:14px}
.foots div{flex:1;border-left:1px solid var(--line);padding-left:14px}
.foots div:first-child{border-left:none;padding-left:0}
.foots .fl{color:var(--muted);font-size:12px}
.foots .fn{font-size:19px;font-weight:600}
.filters{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 12px}
.filters .lbl{color:var(--muted);font-size:13px;margin-left:8px}
.chip{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:999px;
 padding:5px 14px;font-size:13px;cursor:pointer;white-space:nowrap}
.chip:hover{background:var(--track)}
.chip.on{background:var(--ink);color:var(--card);border-color:var(--ink)}
.search{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:4px;
 padding:7px 11px;font:14px inherit;min-width:210px}
.count{color:var(--muted);font-size:13px;text-align:right;margin:2px 0 8px}
table{width:100%;border-collapse:collapse}
thead th{text-align:left;font-size:13px;color:var(--muted);font-weight:600;padding:10px 12px;
 border-bottom:1px solid var(--line);cursor:pointer;user-select:none;white-space:nowrap}
tbody td{padding:13px 12px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:middle}
tbody tr{cursor:pointer}
tbody tr:hover{background:var(--track)}
.badge{display:inline-block;border-radius:999px;padding:3px 11px;font-size:12px;font-weight:600;
 color:#fff;white-space:nowrap}
.badge.hollow{background:none;border:1px solid var(--line);color:var(--muted)}
.risk{white-space:nowrap;font-size:14px}
.risk i{font-style:normal;margin-right:6px}
.tname{font-weight:400}
.tid{color:var(--muted);font-size:12px;display:block;margin-top:3px}
.scrim{position:fixed;inset:0;background:rgba(0,0,0,.4);opacity:0;pointer-events:none;
 transition:opacity .15s;z-index:50}
.scrim.on{opacity:1;pointer-events:auto}
.panel{position:fixed;top:0;right:0;bottom:0;width:min(760px,58vw);background:var(--bg);
 border-left:1px solid var(--line);transform:translateX(100%);transition:transform .18s ease;
 z-index:60;overflow-y:auto;padding:26px 30px 60px}
.panel.on{transform:none}
.panel h2{font-size:24px;font-weight:600;margin:0 40px 20px 0;line-height:1.3}
.panel .card{margin-bottom:16px}
.pclose{position:absolute;top:20px;right:24px;background:none;border:none;font-size:20px;
 color:var(--muted);cursor:pointer;line-height:1}
.meta{display:grid;grid-template-columns:1fr 1fr;gap:10px 24px;font-size:13.5px}
.meta span{color:var(--muted)}
.meta b{font-weight:600}
.lic{background:#f0e6f7;color:#5c2e91;border-radius:4px;padding:2px 8px;font-size:12px;
 font-weight:600;font-family:ui-monospace,Menlo,monospace}
:root[data-theme=dark] .lic{background:#3b2d4a;color:#d9c2f0}
.verdict{display:flex;gap:10px;align-items:flex-start;font-size:15px;margin:14px 0 0}
.verdict .m{font-size:16px;line-height:1.4}
.panel p{margin:0 0 13px;line-height:1.62;font-size:14.5px}
.panel h4{font-size:15px;font-weight:600;margin:18px 0 8px}
.alist{width:100%;border-collapse:collapse;margin-top:6px}
.alist td{padding:8px 10px;border-bottom:1px solid var(--line);font-size:13.5px}
.alist td:first-child{font-weight:600;width:44%}
.alist td:last-child{color:var(--muted)}
.acts{margin:0;padding-left:18px}
.acts li{margin:6px 0;font-size:14px}
.empty{color:var(--muted);font-size:14px;padding:26px 0;text-align:center}
footer{border-top:1px solid var(--line);margin-top:44px;padding:26px 0;color:var(--muted);
 font-size:12.5px;display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap}
.view{display:none}.view.on{display:block}
@media(max-width:1000px){.top3,.two{grid-template-columns:1fr}.panel{width:100%}}

/* -- decision cockpit ------------------------------------------------------ */
.skiplink{position:absolute;left:-999px;top:0;background:var(--ink);color:var(--bg);
 padding:10px 16px;border-radius:0 0 6px 0;z-index:100;font-size:14px}
.skiplink:focus{left:0}
.cockpit{display:grid;gap:16px;margin-bottom:16px}
.narrative{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--link);
 border-radius:8px;padding:20px 24px}
.narrative h2{margin:0 0 8px}
.narrative p{margin:0 0 8px;font-size:15px;line-height:1.6}
.narrative p:last-child{margin-bottom:0}
.cockpit-grid{grid-template-columns:1fr 1fr 1.2fr}
.postrow{display:flex;align-items:center;gap:16px}
.postrow .pn{font-size:13.5px;color:var(--muted);margin:0 0 2px}
.trend{font-size:13px;margin-top:6px;padding:4px 0}
.trend.up{color:#c4314b}.trend.down{color:#0f7b0f}.trend.flat{color:var(--muted)}
.confbar{height:8px;border-radius:5px;background:var(--track);overflow:hidden;margin:4px 0 2px}
.confbar i{display:block;height:100%;background:var(--link)}
.confbar.telemetry i{background:#8764b8}
.confbadge{float:right;font-size:12px;padding:3px 8px;border-radius:12px;
 background:var(--track);color:var(--ink)}
.fresh{font-size:12px;color:var(--muted);margin:9px 0 0}
.conflist{list-style:none;margin:12px 0 0;padding:0;font-size:13px}
.conflist li{display:flex;justify-content:space-between;gap:10px;padding:5px 0;
 border-top:1px solid var(--line)}
.conflist li:first-child{border-top:none}
.conflist .ok{color:#0f7b0f}.conflist .bad{color:#c4314b}
.conflist .warn{color:#c07000}.conflist .roadmap{color:#8a8886}
.decisiongrid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.decision{border:1px solid var(--line);border-top:4px solid var(--link);border-radius:8px;
 padding:16px;background:var(--card);display:flex;flex-direction:column;gap:11px}
.decision h4{font-size:16px;line-height:1.35;margin:0}
.decision .dmeta{display:grid;grid-template-columns:auto 1fr;gap:5px 10px;font-size:12.5px}
.decision .dmeta span{color:var(--muted)}.decision .dmeta b{font-weight:600}
.decision .scope{font-size:14px;font-weight:600;color:var(--ink)}
.decision .why,.decision .choice{font-size:13px;line-height:1.5;margin:0}
.decision .choice{padding-top:10px;border-top:1px solid var(--line)}
.decision .effect{font-size:12.5px;color:var(--muted);margin-top:auto}
.dstatus{display:inline-block;width:max-content;font-size:12px;font-weight:600;
 padding:4px 9px;border-radius:12px;background:var(--track)}
.dstatus.overdue,.dstatus.expired{background:#fde7eb;color:#a4262c}
.acceptance{font-size:12.5px;padding:9px 10px;border-radius:5px;background:var(--track)}
.campaigns{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:12px}
.campaign{border:1px solid var(--line);border-radius:6px;padding:11px 12px}
.campaign b{display:block;font-size:13.5px}.campaign span{font-size:12px;color:var(--muted)}
.concrow{display:flex;align-items:center;gap:10px;padding:7px 0;font-size:13.5px;
 border-top:1px solid var(--line)}
.concrow:first-child{border-top:none}
.concrow .cn{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.concrow .cc{font-weight:600;color:var(--muted);white-space:nowrap}
[data-view]:not(a[href]){cursor:pointer}
a[role=button]:focus-visible,button:focus-visible,tr[tabindex]:focus-visible,
th[tabindex]:focus-visible,.chip:focus-visible{outline:2px solid var(--link);outline-offset:2px}
tbody tr[tabindex]:focus-visible{outline-offset:-2px}
@media(max-width:1000px){.cockpit-grid{grid-template-columns:1fr}
 .decisiongrid,.campaigns{grid-template-columns:1fr}}
@media print{
 .topbar,.scrim,.panel,.filters,.iconbtn,.skiplink{display:none!important}
 .view{display:block!important}
 body{background:#fff;color:#000}
 .card{border:1px solid #999;break-inside:avoid}
 .wrap{max-width:none;padding:0}
}
"""




# ---------------------------------------------------------------- charts

def radial(pairs, size=190):
    """One arc per pillar, filled by pass ratio — the Assessment card's chart."""
    cx = cy = size / 2
    out = [f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">']
    r = size / 2 - 10
    for label, done, total, color in pairs:
        ratio = (done / total) if total else 0
        circ = 2 * math.pi * r
        out.append(f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="var(--track)" '
                   f'stroke-width="9"/>')
        if ratio > 0:                    # a zero-length round cap draws a dot; draw nothing
            out.append(f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="{color}" '
                       f'stroke-width="9" stroke-linecap="round" '
                       f'stroke-dasharray="{circ * ratio * .78:.1f} {circ:.1f}" '
                       f'transform="rotate(-90 {cx} {cy})">'
                       f'<title>{html.escape(label)}: {done}/{total}</title></circle>')
        r -= 13
    out.append("</svg>")
    return "".join(out)


def sankey(stages, links, width=540, height=210):
    """
    A flow drawn from explicit links, so every ribbon is a number somebody can check.

    stages: [[(name, color), ...], ...]   links: [(stage, left_name, right_name, value)]
    Node sizes are derived from the links, never assumed — the first version distributed
    each node proportionally across the next column, which drew crossing ribbons that
    corresponded to nothing.
    """
    gap, barw = 16, 12
    cols = len(stages)
    colx = [int(i * (width - barw) / (cols - 1)) for i in range(cols)]

    value = {}
    for si, col in enumerate(stages):
        for name, _c in col:
            out_v = sum(v for s, a, _b, v in links if s == si and a == name)
            in_v = sum(v for s, _a, b, v in links if s == si - 1 and b == name)
            value[(si, name)] = max(out_v, in_v)

    # An empty node is not a thin bar with a label on top of the ribbon next to it —
    # it is a node that does not exist on this tenant. Drop it and its links.
    stages = [[(n, c) for n, c in col if value[(si, n)] > 0] for si, col in enumerate(stages)]
    links = [(s, a, b, v) for s, a, b, v in links if v > 0]

    pos = {}
    for si, col in enumerate(stages):
        total = sum(value[(si, n)] for n, _c in col) or 1
        avail = height - gap * (len(col) - 1)
        y = 0.0
        for name, color in col:
            h = max(4.0, avail * value[(si, name)] / total)
            pos[(si, name)] = {"y": y, "h": h, "color": color, "val": value[(si, name)]}
            y += h + gap

    cursor = {k: v["y"] for k, v in pos.items()}
    out = [f'<svg viewBox="0 0 {width} {height + 14}" width="100%" height="{height + 14}">']
    for si, a, b, v in links:
        if v <= 0:
            continue
        ln, rn = pos[(si, a)], pos[(si + 1, b)]
        h1 = ln["h"] * v / max(ln["val"], 1)
        h2 = rn["h"] * v / max(rn["val"], 1)
        x1, x2 = colx[si] + barw, colx[si + 1]
        y1, y2 = cursor[(si, a)], cursor[(si + 1, b)]
        mid = (x1 + x2) / 2
        out.append(
            f'<path d="M{x1},{y1:.1f} C{mid},{y1:.1f} {mid},{y2:.1f} {x2},{y2:.1f} '
            f'L{x2},{y2 + h2:.1f} C{mid},{y2 + h2:.1f} {mid},{y1 + h1:.1f} {x1},{y1 + h1:.1f} Z" '
            f'fill="{rn["color"]}" opacity=".26"><title>{html.escape(a)} &#8594; {html.escape(b)}: {v}</title></path>')
        cursor[(si, a)] += h1
        cursor[(si + 1, b)] += h2

    for si, col in enumerate(stages):
        for name, _c in col:
            n = pos[(si, name)]
            out.append(f'<rect x="{colx[si]}" y="{n["y"]:.1f}" width="{barw}" '
                       f'height="{n["h"]:.1f}" rx="2" fill="{n["color"]}"/>')
            anchor = "start" if si == 0 else ("end" if si == cols - 1 else "start")
            tx = colx[si] + (barw + 8 if si != cols - 1 else -8)
            # Labels sit over the ribbons; the halo is what keeps them readable there.
            out.append(f'<text x="{tx:.0f}" y="{n["y"] + n["h"] / 2 + 4:.0f}" text-anchor="{anchor}" '
                       f'font-size="12" fill="var(--muted)" stroke="var(--card)" stroke-width="3" '
                       f'paint-order="stroke" stroke-linejoin="round">{html.escape(name)} '
                       f'<tspan fill="var(--ink)" font-weight="600">{n["val"]}</tspan></text>')
    out.append("</svg>")
    return "".join(out)


def hbars(rows, color="#0f6cbd"):
    mx = max((v for _, v in rows), default=1) or 1
    out = []
    for label, v in rows:
        out.append(
            f'<div style="display:flex;align-items:center;gap:10px;margin:7px 0;font-size:13px">'
            f'<div style="width:190px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;'
            f'white-space:nowrap">{html.escape(label)}</div>'
            f'<div style="flex:1;height:9px;background:var(--track);border-radius:5px;overflow:hidden">'
            f'<div style="width:{100 * v / mx:.0f}%;height:100%;background:{color}"></div></div>'
            f'<div style="width:44px;text-align:right;font-weight:600">{v}</div></div>')
    return "".join(out)



# ---------------------------------------------------------------- page

def esc(s):
    return html.escape(str(s if s is not None else ""))


def _panel(t):
    """
    The slide-over body for one test.

    Order is fixed and deliberate: what kind of finding this is, then the verdict, then
    who it applies to, then what to do, then why it matters. A reader who stops early
    still has something they can act on.
    """
    sc = STATUS_COLOR.get(t["status"], "#8a8886")
    assets = ""
    if t["assets"]:
        trs = "".join("<tr><td>%s</td><td>%s</td></tr>" % (esc(n), esc(d))
                      for n, d in t["assets"])
        assets = ('<h4>Affected (%d)</h4><table class="alist">%s</table>'
                  % (len(t["assets"]), trs))
    acts = ""
    if t["actions"]:
        lis = "".join('<li><a href="%s" target="_blank" rel="noopener">%s</a></li>'
                      % (esc(u), esc(l)) for l, u in t["actions"])
        acts = '<h4>Remediation action</h4><ul class="acts">%s</ul>' % lis

    # A test that could not run needs a different next step from one that failed: the
    # reader's job there is to make it answerable, not to fix an unknown finding.
    gap = ""
    if t["status"] == assessment.NOT_ASSESSED:
        gap = ('<div class="card"><h3>How to make this test answerable</h3>'
               "<p>This test is answered from <b>%s</b>. Until that source is reachable "
               "AI-SPM reports the gap rather than assuming a pass — a control nobody "
               "can measure is not a control that is working.</p></div>"
               % esc(t["requirement"]))

    return (
        "<h2>%s</h2>" % esc(t["name"])
        + '<div class="card"><div class="meta">'
        + '<div><span>Risk:</span> <b style="color:%s">%s</b></div>'
          % (RISK_COLOR.get(t["risk"], "#5f6b7a"), esc(t["risk"]))
        + "<div><span>User impact:</span> <b>%s</b></div>" % esc(t["impact"])
        + "<div><span>Implementation effort:</span> <b>%s</b></div>" % esc(t["effort"])
        + "<div><span>Test ID:</span> <b>%s</b></div>" % esc(t["id"])
        + "<div><span>Pillar:</span> <b>%s</b></div>" % esc(t["pillar"])
        + '<div><span>Requires:</span> <span class="lic">%s</span></div>' % esc(t["requirement"])
        + "</div></div>"
        + '<div class="card"><h3 style="margin-bottom:0">Test result &nbsp;'
        + '<span class="badge" style="background:%s">%s</span></h3>' % (sc, esc(t["status"]))
        + '<div class="verdict"><span class="m">%s</span><span>%s</span></div>'
          % (STATUS_MARK.get(t["status"], ""), esc(t["verdict"]))
        + assets + "</div>"
        + gap
        + '<div class="card"><h3>Recommendation</h3><p>%s</p></div>' % esc(t["recommendation"])
        + '<div class="card"><h3>What was checked</h3>%s%s</div>'
          % ("".join("<p>%s</p>" % esc(p) for p in t["checked"]), acts))


def _rows(results):
    out = []
    for t in results:
        sc = STATUS_COLOR.get(t["status"], "#8a8886")
        hollow = t["status"] in (assessment.NOT_ASSESSED, assessment.SKIPPED)
        badge = ('<span class="badge hollow">%s</span>' % esc(t["status"]) if hollow
                 else '<span class="badge" style="background:%s">%s</span>'
                      % (sc, esc(t["status"])))
        out.append(
            '<tr id="control-%s" data-status="%s" data-risk="%s" data-pillar="%s" data-name="%s" data-panel="%s" '
            'tabindex="0" role="button" aria-haspopup="dialog">'
            '<td class="tname">%s<span class="tid">%s</span></td>'
            '<td class="risk" style="color:%s"><i>&#8593;</i>%s</td><td>%s</td></tr>'
            % (esc(t["id"]), esc(t["status"]), esc(t["risk"]), esc(t["pillar"]), esc(t["name"].lower()),
               html.escape(_panel(t), quote=True), esc(t["name"]), esc(t["id"]),
               RISK_COLOR.get(t["risk"], "#5f6b7a"), esc(t["risk"]), badge))
    return "".join(out)


def _tiles(ctx, estate, apps):
    """
    Estate counters.

    A tile fed by a source that is not attached shows an em dash and says so, never a
    zero. Zero means "looked, found none"; the dash means "could not look", and on this
    product the difference between those two is the whole argument.
    """
    vendors = estate.get("vendors", [])
    web = [v for v in vendors if "web" in v.get("evidence", set())]
    both = [v for v in vendors if {"oauth", "web"} <= set(v.get("evidence", set()))]
    users = sum(a.get("user_count", 0) for a in apps)
    agents = sum(1 for a in apps if a.get("asset_type") == "agent")
    seen_web = assessment.connected(ctx, "defender_cloud_apps")

    tiles = [("AI vendors", len(vendors), "#0f6cbd", True),
             ("With OAuth consent",
              len([v for v in vendors if "oauth" in v.get("evidence", set())]), "#8764b8", True),
             ("Seen in web traffic", len(web), "#c07000", seen_web),
             ("Reached both ways", len(both), "#c4314b", seen_web),
             # Agents visible in the OAuth estate need no connector; what Agent 365 would
             # add — agents built inside the tenant — is a test, not a tile.
             ("Agents", agents, "#0f7b0f", True),
             ("Consent-user counts (not unique)", ("%.1fk" % (users / 1000.0)) if users >= 1000 else users,
              "#038387", True)]
    return "".join(
        '<div class="tile"><div class="dot" style="background:%s;opacity:.16"></div>'
        '<div><div class="tn"%s>%s</div><div class="tl">%s%s</div></div></div>'
        % (c, "" if ok else ' style="color:var(--muted)"', v if ok else "&#8212;",
           esc(l), "" if ok else " &middot; not connected")
        for l, v, c, ok in tiles)


def _flow(ctx, estate):
    """How AI gets into the tenant, as counts of vendors rather than proportions."""
    vendors = estate.get("vendors", [])

    def route(v):
        ev = set(v.get("evidence", set()))
        if {"oauth", "web"} <= ev:
            return "Both routes"
        return "Browser only" if "web" in ev else "OAuth consent"

    routes = ["OAuth consent", "Both routes", "Browser only"]
    ends = ["Sensitive data seen", "No sensitive data recorded"]
    links = [(0, "AI vendors", r, len([v for v in vendors if route(v) == r])) for r in routes]
    stages = [[("AI vendors", "#0f6cbd")],
              [("OAuth consent", "#8764b8"), ("Both routes", "#c4314b"),
               ("Browser only", "#c07000")]]

    if assessment.connected(ctx, "purview_audit"):
        # Without Purview the last column would read "no sensitive data" for every
        # vendor, which is not a finding — it is the absence of one. Drop the stage.
        for r in routes:
            for e in ends:
                links.append((1, r, e, len(
                    [v for v in vendors if route(v) == r
                     and bool(v.get("sensitive_types")) == (e == ends[0])])))
        stages.append([("Sensitive data seen", "#c4314b"),
                       ("No sensitive data recorded", "#0f7b0f")])

    both = [v for v in vendors if {"oauth", "web"} <= set(v.get("evidence", set()))]
    if not assessment.connected(ctx, "defender_cloud_apps"):
        cap = ("Every one of these %d vendors arrived by OAuth consent, because that is "
               "the only route this scan can see. AI used through the browser needs "
               "Defender for Cloud Apps, which is not connected — so the browser column "
               "is absent rather than empty." % len(vendors))
    elif both:
        cap = ("Of %d AI vendors, %d are reached both by a consented application and "
               "through the browser — for those, revoking consent alone would not cut "
               "off the data path." % (len(vendors), len(both)))
    else:
        cap = ("Each of %d AI vendors has one observed route in this scan. Unobserved "
               "routes may exist; one action is not proof that access is contained." % len(vendors))
    return sankey(stages, links), cap


VENDOR_LEVEL_COLOR = {"Critical": "#8b0f2b", "High": "#c4314b",
                      "Medium": "#c07000", "Low": "#0f7b0f"}


def _estate_view(estate):
    """
    One row per AI vendor, the arithmetic behind its score in the panel.

    This is the estate table that used to be its own page. It moved here rather than
    being rebuilt: grouping is still portal.build_estate's, which follows two rules
    learned by breaking them on a real tenant — only AI creates a vendor row, and agents
    attach to a vendor but never create one.
    """
    vendors = sorted(estate.get("vendors", []),
                     key=lambda v: v.get("risk_score", 0), reverse=True)
    if not vendors:
        return ('<h1>AI estate</h1><div class="card">'
                '<div class="empty">No AI vendors were found in this scan.</div></div>')

    rows = []
    for v in vendors:
        level = v.get("risk_level", "Low")
        color = VENDOR_LEVEL_COLOR.get(level, "#5f6b7a")
        evidence = " + ".join(sorted(v.get("evidence", set()))) or "no evidence recorded"

        calc = "".join(
            "<tr><td>+%s</td><td>%s</td></tr>" % (pts, esc(why))
            for pts, why in v.get("breakdown", []) if pts)
        calc = ('<h4>How this score is built</h4><table class="alist">%s'
                '<tr><td><b>%s</b></td><td><b>Risk score out of 100</b></td></tr>'
                "</table>" % (calc, v.get("risk_score", 0))
                if calc else "<h4>How this score is built</h4><p>No notable signal.</p>")

        apps = "".join(
            "<tr><td>%s</td><td>%s &middot; %s</td></tr>"
            % (esc(a.get("display_name")), a.get("risk_score", 0),
               esc(a.get("consent_type") or "no consent recorded"))
            for a in sorted(v.get("oauth_apps", []),
                            key=lambda x: -(x.get("risk_score") or 0)))
        apps = ('<h4>Consented applications</h4><table class="alist">%s</table>' % apps
                if apps else "")

        web = v.get("web") or {}
        seen = []
        if web.get("users"):
            seen.append("%s people reached through the browser" % web["users"])
        if web.get("uploaded_bytes"):
            seen.append("%.0f MB uploaded" % (web["uploaded_bytes"] / 1048576.0))
        if v.get("agents"):
            seen.append("%d agent(s)" % len(v["agents"]))
        if v.get("interactions"):
            seen.append("%d sensitive interaction(s)" % v["interactions"])
        if v.get("blocked"):
            seen.append("%d blocked by DLP" % v["blocked"])
        seen_html = ("<h4>Also seen as</h4><ul class=\"acts\">%s</ul>"
                     % "".join("<li>%s</li>" % esc(s) for s in seen) if seen else "")

        sens = sorted(v.get("sensitive_types") or [])
        sens_html = ('<h4>Sensitive information types recorded</h4><p>%s</p>'
                     % esc(", ".join(sens)) if sens else "")

        panel = (
            "<h2>%s</h2>" % esc(v["vendor"])
            + '<div class="card"><div class="meta">'
            + '<div><span>Risk score:</span> <b style="color:%s">%s &middot; %s</b></div>'
              % (color, v.get("risk_score", 0), esc(level))
            + "<div><span>Seen through:</span> <b>%s</b></div>" % esc(evidence)
            + "<div><span>Reported user counts (not a unique reach measure):</span> <b>%s</b></div>" % v.get("users", 0)
            + "<div><span>Consented applications:</span> <b>%d</b></div>"
              % len(v.get("oauth_apps", []))
            + "</div></div>"
            + '<div class="card">%s</div>' % calc
            + ('<div class="card">%s%s%s</div>' % (apps, seen_html, sens_html)
               if (apps or seen_html or sens_html) else ""))

        rows.append(
            '<tr data-name="%s" data-panel="%s" tabindex="0" role="button" '
            'aria-haspopup="dialog">'
            '<td class="tname">%s<span class="tid">%s</span></td>'
            '<td class="risk" style="color:%s"><i>&#8593;</i>%s</td>'
            '<td><span class="badge" style="background:%s">%s</span></td></tr>'
            % (esc(v["vendor"].lower()), html.escape(panel, quote=True),
               esc(v["vendor"]), esc(evidence), color, esc(level), color,
               v.get("risk_score", 0)))

    held = estate.get("unattached_agents") or []
    held_note = ""
    if held:
        held_note = ('<p class="cap">%d agent(s) were discovered but could not be '
                     "attributed to a known AI vendor, so they are counted rather than "
                     "ranked here — an agent joins a vendor, it never invents one. They "
                     "are listed on the detail page.</p>" % len(held))

    return """
<h1>AI estate</h1>
<div class="card">
  <h2>%d vendors</h2>
  <p class="sub">One row per vendor, whichever route it came in by. A vendor consented as
  an application <i>and</i> used in the browser is one row, not two. Open a row for the
  arithmetic behind its score — every point is a named signal.</p>
  <div class="tbl-wrap"><table id="t-estate"><thead><tr>
    <th data-sort="0" tabindex="0" role="button" aria-sort="none">Vendor &#8645;</th>
    <th data-sort="1" tabindex="0" role="button" aria-sort="none">Risk &#8645;</th>
    <th data-sort="2" tabindex="0" role="button" aria-sort="none">Score &#8645;</th></tr></thead>
  <tbody>%s</tbody></table></div>
  %s
</div>
""" % (len(vendors), "".join(rows), held_note)


def _nav(current, detail_href=None):
    """
    Three views on one page, and one link out.

    There is exactly one outbound destination now. The estate table lives here rather
    than on a page of its own, and the two dashboards behind it were folded into a single
    detail page — four entry points for one tenant was three copies of the same overview
    to keep in agreement.
    """
    out = []
    for key, label in (("overview", "Overview"), ("assessment", "Assessment results"),
                       ("estate", "AI estate")):
        on = key == current
        out.append('<a data-view="%s" role="button" tabindex="0"%s%s>%s</a>'
                  % (key, ' class="on"' if on else "",
                     ' aria-current="page"' if on else "", label))
    if detail_href:
        out.append('<span class="navsep"></span>')
        out.append('<a href="%s" class="out">Detail<i>&#8599;</i></a>' % esc(detail_href))
    return "".join(out)


# ---------------------------------------------------------------- decision cockpit

# Change types that add exposure vs. remove it — read straight off drift.IMPORTANCE's
# own vocabulary, not a second severity scale invented for this page.
_MATERIAL_UP = {"NEW_APP_ONLY_ACCESS", "ADMIN_CONSENT_ADDED", "PERMISSION_ESCALATED"}
_MATERIAL_DOWN = {"ADMIN_CONSENT_REMOVED", "REMOVED_APPLICATION", "APP_DISABLED"}
_HEALTH_BY_LABEL = {
    "Microsoft Agent 365": "agent365",
    "Microsoft Entra Agent ID": "entra_agent_id",
    "Defender for Cloud Apps": "defender_cloud_apps",
    "Microsoft Purview Audit": "purview_audit",
}


def _posture(shadow_apps):
    """
    One exposure number, 0 (clean) to 100 (severe) — reused verbatim from
    `report._posture_score` rather than a second scoring formula that could quietly
    drift from the one the detail page already shows.
    """
    counts = {lv: sum(1 for a in shadow_apps if a.get("risk_level") == lv)
             for lv in report.LEVELS}
    score = report._posture_score(shadow_apps, counts)
    band = ("Critical" if score >= 75 else "High" if score >= 50
           else "Medium" if score >= 25 else "Low")
    return score, band


def _trend(changes):
    """
    Direction since the previous scan, from the same drift events AISPM-5003 already
    reads — never a fabricated sparkline. `changes=None` (a caller that has not wired
    scan history in) is kept distinct from `changes=[]` (a history exists and nothing
    moved): the first is a missing measurement, the second is a real one.
    """
    if changes is None:
        return ("flat", "No comparison available this run — trend needs a previous "
               "scan's changes, which a scheduled scan keeps building (see AISPM-5003).")
    if not changes:
        return ("flat", "No changes recorded against the previous scan — the estate "
               "held steady.")
    up = sum(1 for e in changes if e.get("change_type") in _MATERIAL_UP)
    down = sum(1 for e in changes if e.get("change_type") in _MATERIAL_DOWN)
    other = len(changes) - up - down
    cls = "up" if up > down else ("down" if down > up else "flat")
    material = up + down
    if not material:
        return ("flat", "%d inventory or usage event(s), but no material risk change "
                "was detected in the last 14 days." % other)
    return (cls, "%d material change(s) in the last 14 days &mdash; %d deterioration, "
            "%d improvement. %d other inventory or usage event(s) are kept in Detail."
            % (material, up, down, other))


def _source_freshness(health):
    timestamps = []
    event_times = []
    invalid = 0
    for entry in (health or {}).values():
        for key in ("collected_at", "checked_at", "last_success", "timestamp"):
            value = entry.get(key)
            if value:
                try:
                    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        raise ValueError("offset missing")
                    timestamps.append(parsed.astimezone(timezone.utc))
                except ValueError:
                    invalid += 1
                break
        value = entry.get("source_event_at")
        if value:
            try:
                parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError("offset missing")
                event_times.append(parsed.astimezone(timezone.utc))
            except ValueError:
                invalid += 1
    text = ("Source event freshness is not reported; collection/check times are not event freshness."
            if not event_times else
            "Source event time reported by %d connector(s); oldest reported event: %s. "
            "Other source freshness remains unknown." %
            (len(event_times), min(event_times).isoformat()))
    if timestamps:
        text += (" Collection/check time reported by %d connector(s); oldest: %s."
                 % (len(timestamps), min(timestamps).isoformat()))
    if invalid:
        text += " %d invalid or offset-free timestamp(s) excluded." % invalid
    return text


def _coverage_confidence(results, health, apps=None):
    """
    What share of the catalogue could actually be answered this scan, and which source
    each remaining gap needs — so a page full of green never quietly includes a
    `Not assessed` row read as a pass.
    """
    summary = assessment.summary(results)
    total = summary["total"]
    answerable = summary["assessable"]
    assessment_pct = round(100 * answerable / total) if total else 0
    sources = executive.connector_status(health)
    operational = [(name, ok, detail) for name, ok, detail in sources if ok is not None]
    core_complete = not any(a.get("collection_errors") or not (a.get("usage") or {}).get("available")
                            for a in (apps or []))
    connected = int(core_complete)
    connected += sum(1 for key in _HEALTH_BY_LABEL.values()
                     if (health or {}).get(key, {}).get("status") == "CONNECTED")
    telemetry_pct = round(100 * connected / len(operational)) if operational else 0
    degraded = not core_complete or any((entry or {}).get("status") in
                   ("PARTIALLY_CONNECTED", "NO_DATA", "TIMEOUT", "ERROR")
                   for entry in (health or {}).values())
    if total and assessment_pct >= 90 and telemetry_pct == 100 and not degraded:
        confidence = "High"
    elif assessment_pct >= 70 and telemetry_pct >= 40:
        confidence = "Medium"
    else:
        confidence = "Low"
    rows_html = []
    for name, ok, _detail in sources:
        status = (health or {}).get(_HEALTH_BY_LABEL.get(name, ""), {}).get("status")
        if name == "Entra ID / Microsoft Graph" and not core_complete:
            status = "PARTIALLY_CONNECTED"
        if ok is None:
            css, label = "roadmap", "Roadmap"
        elif status == "PARTIALLY_CONNECTED":
            css, label = "warn", "Partial"
        elif status == "NO_DATA":
            css, label = "warn", "Reachable · no detected data"
        elif ok:
            css, label = "ok", "Connected"
        else:
            css, label = "bad", "Gap"
        rows_html.append('<li><span>%s</span><span class="%s">%s</span></li>'
                         % (esc(name), css, label))
    return {"assessment_pct": assessment_pct, "assessable": answerable,
            "total": total, "telemetry_pct": telemetry_pct, "connected": connected,
            "operational": len(operational), "confidence": confidence,
            "rows": "".join(rows_html),
            "freshness": _source_freshness(health)}


def _concentration(results, apps):
    """
    Which assets carry the assessment's failures — blast radius, not just a fail count.
    An asset named in more failing controls, reaching more people, is where a single
    compromise (or a single fix) moves the needle furthest; ranking by fail-count alone
    would put a rarely-used app ahead of one every failing control keeps naming.
    """
    identities = {}
    for app in apps:
        name = app.get("display_name")
        if not name:
            continue
        identities[name] = identities.get(name, 0) + 1
    tally = {}
    for t in results:
        if t["status"] != assessment.FAILED:
            continue
        # A display name may identify multiple Entra service principals. Count a
        # control once per visible name and disclose the grouped identity count.
        for name in {name for name, _detail in t["assets"]}:
            e = tally.setdefault(name, {"tests": 0, "risk": "Low"})
            e["tests"] += 1
            if assessment.RISK_ORDER.get(t["risk"], 9) < assessment.RISK_ORDER.get(e["risk"], 9):
                e["risk"] = t["risk"]
    ranked = sorted(tally.items(),
                    key=lambda kv: (-kv[1]["tests"], -identities.get(kv[0], 0)))[:5]
    if not ranked:
        return ('<p class="cap" style="margin-top:0">No single asset is named by more '
               "than one failing test — risk is spread rather than concentrated.</p>")
    return "".join(
        '<div class="concrow"><span class="cn" style="color:%s">%s</span>'
        '<span class="cc">%d control(s) &middot; %s</span></div>'
        % (RISK_COLOR.get(v["risk"], "#5f6b7a"),
           esc(name + (f" ({identities.get(name, 0)} identities)"
                       if identities.get(name, 0) > 1 else "")),
           v["tests"],
           ("%d matching inventory record(s)" % identities[name]
            if identities.get(name) else "control evidence only"))
        for name, v in ranked)


def _decision_programs(results, apps, decision_states=None, now=None):
    """Keep failures and unfinished governance visible in at most three decision programs."""
    failed = {t["id"]: t for t in results if t["status"] == assessment.FAILED}
    decision_states = decision_states or {}
    decisions = []
    for definition in DECISION_PROGRAMS:
        controls = sorted(
            (failed[tid] for tid in definition["ids"] if tid in failed),
            key=lambda t: (assessment.RISK_ORDER[t["risk"]], t["id"]))
        key = definition["key"]
        workflow = decisionstate.view_state(
            key, decision_states.get(key), now=now, failed_controls=len(controls))
        actionable = key in decision_states and (
            workflow["data_error"] or workflow["overdue"] or workflow["acceptance_expired"]
            or workflow["status"] not in {"Verified", "False positive"})
        if not controls and not actionable:
            continue
        names = {name for control in controls for name, _detail in control["assets"]}
        decisions.append({
            **definition,
            "controls": controls,
            # Assessment evidence currently carries display labels, not stable IDs or a
            # cross-application user union. Call these evidence items rather than
            # pretending they are unique identities or people.
            "evidence_items": len(names),
            "evidence": [t["verdict"] for t in controls[:2]],
            "workflow": workflow,
        })
    return decisions


def _decisions_html(results, apps, decision_states=None, now=None):
    decisions = _decision_programs(results, apps, decision_states, now)
    if not decisions:
        return ('<div class="card"><h3>Executive decisions</h3><p class="cap">'
                "No remediation decision is required from the controls assessed this scan. "
                "Review coverage gaps and continue monitoring.</p></div>"), decisions
    cards = []
    for index, decision in enumerate(decisions, 1):
        controls = decision["controls"]
        high = sum(1 for t in controls if t["risk"] == "High")
        scope = ("%d current failed control(s) &middot; %d named evidence item(s)"
                 % (len(controls), decision["evidence_items"]))
        evidence = " ".join(decision["evidence"]) or (
            "No current failed controls in this program. This does not close the "
            "persisted workflow or establish that unassessed controls passed.")
        workflow = decision["workflow"]
        state_class = ("expired" if workflow.get("data_error") or workflow["acceptance_expired"]
                       or workflow["evidence_conflict"]
                       else ("overdue" if workflow["overdue"] else ""))
        owner = workflow["owner"] or "Unassigned"
        due = workflow["due_date"] or "Not assigned"
        acceptance = ""
        if workflow.get("acceptance"):
            accepted = workflow["acceptance"]
            acceptance = (
                '<div class="acceptance"><b>Risk acceptance:</b> %s<br>'
                'Approved by %s (self-reported) &middot; expires %s</div>'
                % (esc(accepted.get("rationale")), esc(accepted.get("approved_by")),
                   esc(accepted.get("expires_at"))))
        elif workflow.get("compensating_control"):
            acceptance = ('<div class="acceptance"><b>Compensating control:</b> %s</div>'
                          % esc(workflow["compensating_control"]))
        if workflow["data_error"]:
            acceptance += ('<div class="acceptance"><b>Workflow data invalid:</b> %s</div>'
                           % esc(workflow["data_error"]))
        if workflow.get("notes"):
            acceptance += ('<div class="acceptance"><b>Decision notes:</b> %s</div>'
                           % esc(workflow["notes"]))
        if workflow["evidence_conflict"]:
            acceptance += ('<p class="workflow-message error">Evidence conflict: manually '
                           'Verified, but controls failed in this scan. Verification needs review.</p>')
        effect = ("%d control(s) enter one accountable campaign; each retains its canonical "
                  "verification criteria; %s."
                  % (len(controls), ", ".join(t["id"] for t in controls)) if controls else
                  "Review and explicitly resolve the persisted workflow; "
                  "no current failed controls are being claimed.")
        why = decision["why"] if controls else (
            "A persisted decision still needs governance review, renewal or explicit closure.")
        choice = decision["choice"] if controls else (
            "Review the recorded decision and supporting evidence, correct invalid records "
            "and resolve overdue or expired exceptions before marking the program complete.")
        priority = "Immediate" if high or state_class else "Planned"
        cards.append(
            '<article class="decision" aria-labelledby="decision-%d"><h4 id="decision-%d">'
            '<span class="u">Decision %d</span><br>%s</h4><div class="scope">%s</div>'
            '<div data-workflow="%s"><span class="dstatus %s">%s</span>'
            '<div class="dmeta"><span>Assigned owner (self-reported)</span><b>%s</b>'
            '<span>Due date</span><b>%s</b></div>%s</div>'
            '<div class="dmeta"><span>Recommended owner</span><b>%s</b>'
            '<span>Target SLA</span><b>%s</b><span>Scan priority</span><b>%s</b></div>'
            '<p class="why"><b>Why now:</b> %s</p><p class="why"><b>Observed evidence:</b> '
            '%s</p><p class="choice"><b>Executive choice:</b> %s</p>'
            '<div class="workflow-actions"><button class="workflow-btn" data-edit-decision="%s">'
            'Review snapshot</button><button class="workflow-btn" data-evidence="%s">'
            'Review control evidence</button></div><div class="effect">%s</div></article>'
            % (index, index, index, esc(decision["title"]), scope, esc(decision["key"]), state_class,
               esc(workflow["display_status"]), esc(owner), esc(due), acceptance,
               esc(decision["owner"]), esc(decision["sla"]), priority,
               esc(why), esc(evidence), esc(choice), esc(decision["key"]),
               esc(" ".join(sorted(decision["ids"]))), esc(effect)))
    campaigns = "".join(
        '<div class="campaign"><b>%s</b><span>%d current failed control(s); program owner: '
        '%s</span></div>'
        % (esc(d["title"]), len(d["controls"]), esc(d["owner"])) for d in decisions)
    return (
        '<div class="card"><h3>%d executive %s that %s the risk</h3>'
        '<p class="pn">Control failures are consolidated by root cause. Persisted decisions '
        'remain visible until resolved, even with no current failed controls. The complete '
        '26-control evidence backlog remains below.</p><div class="decisiongrid">%s</div>'
        '<details class="details-block"><summary>Remediation campaigns</summary>'
        '<div class="campaigns">%s</div></details></div>'
        % (len(decisions), "decision" if len(decisions) == 1 else "decisions",
           "moves" if len(decisions) == 1 else "move", "".join(cards), campaigns),
        decisions,
    )


def _narrative(results, decisions):
    failed = [t for t in results if t["status"] == assessment.FAILED]
    if not failed:
        if decisions:
            return ("<p>No control in this catalogue failed this scan. "
                    "<b>%d persisted decision program(s) still require governance attention.</b> "
                    "Review open decisions, overdue work, expired acceptances and invalid "
                    "records; continue closing coverage gaps and monitoring.</p>" % len(decisions))
        return ("<p>No control in this catalogue failed this scan. The remaining work is "
                "closing coverage gaps and sustaining monitoring.</p>")
    routed = sum(len(d["controls"]) for d in decisions)
    persisted_only = sum(not d["controls"] for d in decisions)
    high = sum(1 for t in failed if t["risk"] == "High")
    return ("<p><b>%d control failure(s) are consolidated into %d executive decision(s).</b> "
            "%d are High risk. This separates what leadership must approve from the "
            "evidence backlog the security team must execute.</p>"
            % (len(failed), len(decisions), high)
            + ("<p>%d failed control(s) are routed into accountable remediation campaigns.</p>"
               % routed)
            + ("<p>%d additional persisted program(s) have no current failed controls "
               "but still require governance attention.</p>" % persisted_only
               if persisted_only else ""))


def _scan_as_of(context):
    now = (context or {}).get("now")
    return now.isoformat() if isinstance(now, datetime) else (
        (context or {}).get("finished") or "not recorded")


def _workflow_states(results, stored=None, now=None):
    return {p["key"]: decisionstate.view_state(
        p["key"], (stored or {}).get(p["key"]), now=now,
        failed_controls=sum(t["status"] == assessment.FAILED and t["id"] in p["ids"]
                            for t in results)) for p in DECISION_PROGRAMS}


def _visual_summary(results, apps, estate, coverage, score, band):
    """Render observed inventory and control outcomes, without inferring missing data."""
    counts = {level: sum(a.get("risk_level") == level for a in apps)
              for level in report.LEVELS}
    unscored = len(apps) - sum(counts.values())
    risk_colors = {"Critical": "var(--cp-danger)", "High": "var(--cp-accent)",
                   "Medium": "var(--cp-warning)", "Low": "var(--cp-success)"}
    segments = [(level, counts[level], risk_colors[level]) for level in report.LEVELS]
    if unscored:
        segments.append(("Unrated", unscored, "var(--cp-border-strong)"))
    risk_chart = charts.donut(segments, len(apps), "inventory records", size=156, stroke=18)
    risk_legend = charts.legend([(label, color, value) for label, value, color in segments])
    statuses = [assessment.FAILED, assessment.PASSED, assessment.NOT_ASSESSED, assessment.SKIPPED]
    status_colors = {
        assessment.FAILED: "var(--cp-danger)", assessment.PASSED: "var(--cp-success)",
        assessment.NOT_ASSESSED: "var(--cp-border-strong)", assessment.SKIPPED: "var(--cp-warning)"}
    totals = assessment.summary(results)["by_status"]
    rows = [(assessment.PILLAR_SHORT[p], {
        status: sum(t["pillar"] == p and t["status"] == status for t in results)
        for status in statuses}) for p in assessment.PILLARS]
    controls = charts.stacked_bar(rows, statuses, status_colors, width=420, label_w=110,
                                  bar=18, gap=18)
    control_legend = charts.legend([(s, status_colors[s], totals.get(s, 0)) for s in statuses])
    posture = (charts.gauge(score, "Tenant AI posture") if apps else
               '<p class="dashboard-empty">Not measured</p>')
    band_text = band + " exposure" if apps else "No assessed inventory"
    vendors = len((estate or {}).get("vendors", []))
    agents = sum(a.get("asset_type") == "agent" for a in apps)
    unattended = sum(bool(a.get("has_app_only_access")) for a in apps)
    return """
<section class="dashboard-visuals" aria-label="AI security posture dashboard">
 <div class="dashboard-kpis">
  <div class="card dashboard-kpi"><span>AI vendors observed</span><strong>%(vendors)d</strong>
   <small>Across the available discovery sources</small></div>
  <div class="card dashboard-kpi"><span>Assessed inventory</span><strong>%(assets)d</strong>
   <small>Non-Microsoft records &middot; %(agents)d agent-labelled</small></div>
  <div class="card dashboard-kpi"><span>Critical / High risk</span><strong>%(high_risk)d</strong>
   <small>%(critical)d Critical &middot; %(high)d High inventory records</small></div>
  <div class="card dashboard-kpi"><span>Unattended access</span><strong>%(unattended)d</strong>
   <small>App-only permissions &middot; no user session required</small></div>
 </div>
 <div class="dashboard-charts">
  <article class="card dashboard-posture">
   <h2>AI security posture</h2><p class="dashboard-subtitle">Exposure index &middot; higher is worse</p>
   %(posture)s
   <strong class="dashboard-band">%(band)s</strong>
   <p class="dashboard-subtitle">Permission, consent and unattended-access findings.
   Not a compliance score or a probability of breach.</p>
  </article>
  <article class="card">
   <h2>Where risk sits</h2><p class="dashboard-subtitle">Risk distribution of assessed inventory</p>
   <div class="dashboard-donut">%(risk_chart)s</div>%(risk_legend)s
  </article>
  <article class="card">
   <h2>Control outcomes</h2><p class="dashboard-subtitle">Observed results across five security pillars</p>
   %(controls)s %(control_legend)s
   <p class="dashboard-subtitle">Each bar is one pillar; the number is its total controls.
   Unknown and skipped are never counted as passed.</p>
  </article>
 </div>
 <div class="card dashboard-coverage">
  <div><span class="dashboard-eyebrow">Visibility &amp; evidence</span>
   <strong>%(confidence)s coverage confidence</strong></div>
  <div><span>Controls with complete evidence <b>%(assessable)d / %(total)d</b></span>
   <div class="confbar"><i style="width:%(assessment_pct)d%%"></i></div></div>
  <div><span>Sources completed collection <b>%(connected)d / %(operational)d</b></span>
   <div class="confbar telemetry"><i style="width:%(telemetry_pct)d%%"></i></div></div>
  <p>Available sources only, not total tenant visibility. Collection completion does not
  establish source-event freshness.</p>
 </div>
</section>
""" % {
        "vendors": vendors, "assets": len(apps), "agents": agents,
        "high_risk": counts.get("Critical", 0) + counts.get("High", 0),
        "critical": counts.get("Critical", 0), "high": counts.get("High", 0),
        "unattended": unattended, "posture": posture, "band": esc(band_text),
        "risk_chart": risk_chart, "risk_legend": risk_legend,
        "controls": controls, "control_legend": control_legend, **coverage}


def _cockpit(results, apps, estate, health, changes, context=None, decision_states=None):
    """
    The hero: one screen a decision-maker can act on without opening a single row.
    Composed entirely from data the page already renders below it — the table remains
    the source of truth, this is its summary, not a second opinion.
    """
    shadow_apps = [a for a in apps if not a.get("first_party_microsoft")]
    score, band = _posture(shadow_apps)
    trend_cls, trend_text = _trend(changes)
    coverage = _coverage_confidence(results, health, shadow_apps)
    scan_counts = assessment.summary(results)["by_status"]
    counts = {lv: sum(1 for app in shadow_apps if app.get("risk_level") == lv)
              for lv in report.LEVELS}
    decisions_html, decisions = _decisions_html(
        results, apps, decision_states, (context or {}).get("now"))
    conc_html = _concentration(results, apps)
    narrative = _narrative(results, decisions)
    scan_as_of = _scan_as_of(context)
    states = _workflow_states(results, decision_states, (context or {}).get("now"))
    attention = decisionstate.attention([d["workflow"] for d in decisions])
    review = dashboard_workflow.markup([
        {"key": p["key"], "title": p["title"],
         "failed_controls": states[p["key"]]["failed_controls"]}
        for p in DECISION_PROGRAMS], states, scan_as_of)

    return """
<div class="cockpit">
%(visual_summary)s
  <div class="executive-strip">
    <span><strong>Leadership action queue</strong></span>
    <span>%(failed)d failed · %(unknown)d not assessed · %(skipped)d skipped</span>
    <button class="workflow-btn" id="print-brief">Print / board brief</button>
    <p>Coverage is not risk reduction or compliance certification. Unassessed and skipped
    controls remain unknown. Source event freshness may be unknown.</p>
  </div>
  <p class="dashboard-change trend %(trend_cls)s"><b>Since the previous scan:</b> %(trend_text)s</p>
  <div class="attention" id="decision-attention" role="status" aria-live="polite">%(attention)s</div>
  %(decisions)s
  %(review)s
  <details class="details-block">
   <summary>Detailed coverage, exposure and scan narrative</summary>
   <div class="narrative">
    <h2>Scan summary (immutable)</h2>
    %(narrative)s
    <p class="trend %(trend_cls)s" style="margin-top:10px">%(trend_text)s</p>
  </div>
  <div class="grid cockpit-grid">
    <div class="card">
      <h3>Posture</h3>
      <div class="postrow">%(gauge)s
        <div><p class="pn">Exposure score, not a compliance score — weighted by
        finding severity and by unattended (app-only) access.</p>
        <p class="pn"><b>Drivers:</b> %(critical)d Critical, %(high)d High-risk asset(s).
        No target score is configured; the decisions below measure control evidence,
        not a promised score reduction.</p></div>
      </div>
    </div>
    <div class="card">
      <h3>Coverage confidence <span class="confbadge">%(confidence)s</span></h3>
      <p class="pn">A coverage/completeness label, not probabilistic evidence confidence
      or a source-freshness assessment.</p>
      <p class="pn"><b>Assessment coverage:</b> %(assessable)d of %(total)d controls
      answerable (%(assessment_pct)d%%).</p>
      <div class="confbar"><i style="width:%(assessment_pct)d%%"></i></div>
      <p class="pn"><b>Telemetry coverage:</b> %(connected)d of %(operational)d operational
      sources completed collection (%(telemetry_pct)d%%). Completion does not prove
      informative evidence. Partial and no-data sources reduce completeness;
      roadmap sources are not in this denominator.</p>
      <div class="confbar telemetry"><i style="width:%(telemetry_pct)d%%"></i></div>
      <p class="fresh">%(freshness)s</p>
      <ul class="conflist">%(conn_rows)s</ul>
    </div>
    <div class="card">
      <h3>Risk concentration</h3>
      <p class="pn">Named evidence ranked by failing-control count. These are not unique
      identities or a measurement of tenant-wide blast radius.</p>
      %(conc)s
    </div>
  </div>
  </details>
</div>
""" % {"narrative": narrative, "trend_cls": trend_cls, "trend_text": trend_text,
       "visual_summary": _visual_summary(results, shadow_apps, estate, coverage, score, band),
       "score": score, "band": band, "scan_as_of": esc(scan_as_of), "review": review,
       "failed": scan_counts.get(assessment.FAILED, 0),
       "unknown": scan_counts.get(assessment.NOT_ASSESSED, 0),
       "skipped": scan_counts.get(assessment.SKIPPED, 0),
       "attention": esc(
           "%d overdue · %d acceptances expiring within 7 days · %d expired · "
           "%d unassigned · %d evidence conflicts — snapshot as of %s" %
           (attention["overdue"], attention["expiring"], attention["expired"],
            attention["unassigned"], attention["conflicting"], scan_as_of)),
       "gauge": (charts.gauge(score, "Tenant AI posture") if shadow_apps else
                 '<p class="dashboard-empty">Not measured: no assessed inventory</p>'),
       "critical": counts.get("Critical", 0), "high": counts.get("High", 0),
       "assessable": coverage["assessable"], "total": coverage["total"],
       "assessment_pct": coverage["assessment_pct"],
       "connected": coverage["connected"], "operational": coverage["operational"],
       "telemetry_pct": coverage["telemetry_pct"], "confidence": coverage["confidence"],
       "freshness": esc(coverage["freshness"]), "conn_rows": coverage["rows"],
       "conc": conc_html, "decisions": decisions_html}


def _overview(ctx, results, apps, estate, tenant_id, context, changes=None,
              decision_states=None):
    summary = assessment.summary(results)
    profile = (context or {}).get("tenant_profile") or {}
    org = profile.get("display_name") or "This tenant"

    pillars = [(assessment.PILLAR_SHORT[p], summary["by_pillar"][p]["passed"],
                summary["by_pillar"][p]["total"], PILLAR_COLOR[p])
               for p in assessment.PILLARS if summary["by_pillar"][p]["total"]]
    pillrows = "".join(
        '<div class="pillrow"><span>%s</span><span><b>%d/%d</b>'
        '<span class="u">tests</span></span></div>' % (esc(l), d, t)
        for l, d, t, _c in pillars)

    unknown = [t for t in results if t["status"] in (assessment.NOT_ASSESSED, assessment.SKIPPED)]
    gaps = "".join(
        '<div class="gap"><span>&#128683;</span><div><b>%s</b><div class="gapwhy">%s</div>'
        "</div></div>" % (esc(t["status"] + ": " + t["name"]), esc(t["verdict"])) for t in unknown)
    if not gaps:
        gaps = ('<p class="cap" style="margin-top:0">Every test in the catalogue could be '
                "evaluated against this tenant.</p>")

    flow_svg, flow_cap = _flow(ctx, estate)
    shadow = [a for a in apps if not a.get("first_party_microsoft")]
    top = sorted(shadow, key=lambda a: a.get("user_count", 0), reverse=True)[:8]
    risky = sorted(shadow, key=lambda a: a.get("risk_score", 0), reverse=True)[:8]
    users = sum(a.get("user_count", 0) for a in shadow)
    agents = sum(1 for a in shadow if a.get("asset_type") == "agent")

    scanned = (context or {}).get("identity") or {}
    finished = (context or {}).get("finished") or ""
    cockpit_html = _cockpit(results, apps, estate, ctx["health"], changes, context,
                            decision_states)

    return """
<header class="dashboard-header">
 <div><span class="dashboard-eyebrow">AI-SPM / Security command center</span>
 <h1>AI security, in focus.</h1>
 <p>%(org)s &middot; Identity, data exposure, Shadow AI and governance</p></div>
 <div class="dashboard-context">%(data_label)s<span>Scan as of %(scan_as_of)s</span></div>
</header>
%(cockpit)s
<details class="details-block"><summary>Tenant, estate and full assessment coverage</summary>
<div class="grid top3">
  <div class="card">
    <h2>Tenant</h2>
    <dl class="kv" style="margin-top:14px">
      <dt>Organisation</dt><dd>%(org)s</dd>
      <dt>Primary domain</dt><dd>%(domain)s</dd>
      <dt>Tenant ID</dt><dd class="mono">%(tenant)s</dd>
      <dt>Scanned by</dt><dd>%(scanner)s</dd>
      <dt>Finished</dt><dd>%(finished)s</dd>
    </dl>
  </div>
  <div class="tiles">%(tiles)s</div>
  <div class="card">
    <h2>Assessment</h2>
    <div style="display:flex;gap:14px;align-items:center;margin-top:10px">
      <div style="flex:1">%(pillrows)s</div>
      <div>%(radial)s</div>
    </div>
    <div class="foots">
      <div><div class="fl">Passed</div><div class="fn" style="color:#0f7b0f">%(passed)d</div></div>
      <div><div class="fl">Failed</div><div class="fn" style="color:#c4314b">%(failed)d</div></div>
      <div><div class="fl">Not assessed</div><div class="fn">%(unknown)d</div></div>
      <div><div class="fl">Skipped</div><div class="fn">%(skipped)d</div></div>
    </div>
  </div>
</div>

<div class="grid two" style="margin-top:16px">
  <div class="card">
    <h2>How AI gets in</h2>
    %(flow)s
    <p class="cap">%(flowcap)s</p>
  </div>
  <div class="card">
    <h2>Consent footprint</h2>
    %(reach)s
    <p class="cap">Summed consent-user counts, not unique people, usage, tenant-wide
    reach or application-permission scope. Users may recur across applications;
    admin consent and app-only access cannot be sized using these totals.</p>
    <div class="foots">
      <div><div class="fl">Consent-user counts</div><div class="fn">%(users)s</div></div>
      <div><div class="fl">Applications</div><div class="fn">%(napps)d</div></div>
      <div><div class="fl">Agents</div><div class="fn">%(agents)d</div></div>
    </div>
  </div>
</div>

<div class="grid two" style="margin-top:16px">
  <div class="card">
    <h2>Highest risk first</h2>
    %(risk)s
    <p class="cap">Scores are built from permissions held, consent scope and consent-user
    counts, which do not measure unique people or actual reach. Every point carries its reason on the OAuth assessment —
    nothing here is a black box.</p>
  </div>
  <div class="card">
    <h2>Not assessed / skipped</h2>
    %(gaps)s
    <p class="cap">These are shown rather than hidden on purpose. A test that could not
    run is a gap in visibility, and a gap in visibility is itself a finding — it is never
    reported as a zero.</p>
  </div>
</div>
</details>
""" % {"org": esc(org), "domain": esc(profile.get("primary_domain") or "&#8212;"),
       "data_label": ("<b>DEMO / SYNTHETIC DATA</b>" if (context or {}).get("sample_data") else
                      "<b>ASSESSMENT SNAPSHOT</b>"),
       "scan_as_of": esc(_scan_as_of(context)),
       "tenant": esc(tenant_id), "scanner": esc(scanned.get("app_name") or "AI-SPM"),
       "finished": esc(finished or "this scan"), "cockpit": cockpit_html,
       "tiles": _tiles(ctx, estate, shadow), "pillrows": pillrows,
       "radial": radial(pillars),
       "passed": summary["by_status"].get(assessment.PASSED, 0),
       "failed": summary["by_status"].get(assessment.FAILED, 0),
       "unknown": summary["by_status"].get(assessment.NOT_ASSESSED, 0),
       "skipped": summary["by_status"].get(assessment.SKIPPED, 0),
       "flow": flow_svg, "flowcap": esc(flow_cap),
       "reach": hbars([(a.get("display_name") or "-", a.get("user_count", 0)) for a in top],
                      "#8764b8"),
       "risk": hbars([(a.get("display_name") or "-", a.get("risk_score", 0)) for a in risky],
                     "#c4314b"),
       "users": "{:,}".format(users), "napps": len(shadow), "agents": agents,
       "gaps": gaps}


def _assessment_view(results):
    summary = assessment.summary(results)
    counts = summary["by_status"]
    rcounts = {r: sum(1 for t in results if t["risk"] == r) for r in ("High", "Medium", "Low")}
    pcounts = {p: sum(1 for t in results if t["pillar"] == p) for p in assessment.PILLARS}

    chips = "".join(
        '<button class="chip" data-f="risk" data-v="%s" title="%s (%d tests)" '
        'aria-pressed="false">%s</button>'
        % (r, r, rcounts[r], r) for r in ("High", "Medium", "Low") if rcounts[r])
    schips = "".join(
        '<button class="chip" data-f="status" data-v="%s" title="%s (%d tests)" '
        'aria-pressed="false">%s</button>'
        % (esc(s), esc(s), counts.get(s, 0), esc(s))
        for s in assessment.STATUSES if counts.get(s))
    pchips = "".join(
        '<button class="chip" data-f="pillar" data-v="%s" title="%s (%d tests)" '
        'aria-pressed="false">%s</button>'
        % (html.escape(p, quote=True), esc(p), pcounts[p],
           esc(assessment.PILLAR_SHORT[p]))
        for p in assessment.PILLARS if pcounts[p])

    return """
<h1>Assessment results</h1>
<div class="card">
  <h2>%(n)d tests</h2>
  <p class="sub">Each test is answered from data this scan already collected. Where the
  answer needs a source that is not connected, the test reports <b>Not assessed</b> and
  names the source — it is never reported as a pass or a zero.</p>
  <div class="filters">
    <label for="q">Search controls</label>
    <input class="search" id="q" placeholder="Search by name...">
    <span class="lbl">Risk:</span>%(chips)s
    <span class="lbl">Status:</span>%(schips)s
  </div>
  <div class="filters"><span class="lbl" style="margin-left:0">Pillar:</span>%(pchips)s
   <button class="workflow-btn" id="all-controls">Show all controls</button></div>
  <div class="count" id="count"></div>
  <div class="tbl-wrap"><table id="t-tests"><thead><tr>
    <th data-sort="0" tabindex="0" role="button" aria-sort="none">Name &#8645;</th>
    <th data-sort="1" tabindex="0" role="button" aria-sort="none">Risk &#8645;</th>
    <th data-sort="2" tabindex="0" role="button" aria-sort="none">Status &#8645;</th></tr></thead>
  <tbody id="tbody">%(rows)s</tbody></table></div>
  <div class="empty" id="none" style="display:none">No test matches these filters.</div>
</div>
""" % {"n": len(results), "chips": chips, "schips": schips, "pchips": pchips,
       "rows": _rows(results)}


JS = """
var $=function(s){return document.querySelector(s)};
function fireOnEnterOrSpace(el){
  el.addEventListener('keydown', function(e){
    if(e.key==='Enter'||e.key===' '||e.key==='Spacebar'){
      e.preventDefault(); el.click();
    }
  });
}
document.querySelectorAll('nav a[data-view]').forEach(function(a){
  fireOnEnterOrSpace(a);
  a.onclick=function(){
    document.querySelectorAll('nav a[data-view]').forEach(function(x){
      x.classList.remove('on'); x.removeAttribute('aria-current');
    });
    a.classList.add('on'); a.setAttribute('aria-current', 'page');
    document.querySelectorAll('.view').forEach(function(v){v.classList.remove('on')});
    $('#v-'+a.getAttribute('data-view')).classList.add('on');
    window.scrollTo(0,0);
  };
});
$('#theme').onclick=function(){
  var r=document.documentElement;
  r.setAttribute('data-theme', r.getAttribute('data-theme')==='dark'?'light':'dark');
};
var state={risk:null,status:null,pillar:null,q:'',ids:null};
function apply(){
  var shown=0,total=0;
  document.querySelectorAll('#tbody tr').forEach(function(tr){
    total++;
    var ok=true;
    if(state.ids && !state.ids.includes(tr.id.replace('control-',''))) ok=false;
    if(state.risk && tr.getAttribute('data-risk')!==state.risk) ok=false;
    if(state.status && tr.getAttribute('data-status')!==state.status) ok=false;
    if(state.pillar && tr.getAttribute('data-pillar')!==state.pillar) ok=false;
    if(state.q && tr.getAttribute('data-name').indexOf(state.q)<0) ok=false;
    tr.style.display=ok?'':'none';
    if(ok) shown++;
  });
  $('#count').textContent='Showing '+shown+' of '+total+' tests';
  $('#none').style.display=shown?'none':'';
}
document.querySelectorAll('.chip').forEach(function(c){
  c.onclick=function(){
    var f=c.getAttribute('data-f'),v=c.getAttribute('data-v'),was=state[f]===v;
    state.ids=null;
    document.querySelectorAll('.chip[data-f="'+f+'"]').forEach(function(x){
      x.classList.remove('on'); x.setAttribute('aria-pressed', 'false');
    });
    state[f]=was?null:v;
    if(!was){ c.classList.add('on'); c.setAttribute('aria-pressed', 'true'); }
    apply();
  };
});
$('#q').oninput=function(){state.q=this.value.toLowerCase();apply();};
apply();
function resetControls(){
  state={risk:null,status:null,pillar:null,q:'',ids:null};$('#q').value='';
  document.querySelectorAll('.chip').forEach(function(c){
    c.classList.remove('on');c.setAttribute('aria-pressed','false');
  });
}
$('#all-controls').onclick=function(){resetControls();apply();};
document.querySelectorAll('[data-evidence]').forEach(function(button){
  button.onclick=function(){
    resetControls();state.ids=button.getAttribute('data-evidence').split(' ');
    document.querySelector('nav [data-view="assessment"]').click();apply();
    $('#q').focus();
  };
});
var order={};
document.querySelectorAll('th[data-sort]').forEach(function(th){
  fireOnEnterOrSpace(th);
  th.onclick=function(){
    var i=+th.getAttribute('data-sort'),table=th.closest('table'),
        body=table.querySelector('tbody'),key=table.id+i,dir=order[key]=-(order[key]||-1);
    var rows=[].slice.call(body.querySelectorAll('tr'));
    rows.sort(function(a,b){
      var x=a.children[i].innerText.trim(),y=b.children[i].innerText.trim();
      return x<y?-dir:(x>y?dir:0);
    });
    rows.forEach(function(r){body.appendChild(r)});
    table.querySelectorAll('th[data-sort]').forEach(function(h){h.setAttribute('aria-sort','none')});
    th.setAttribute('aria-sort', dir>0?'ascending':'descending');
  };
});
var panelOpener=null;
function openPanel(html, opener){
  $('#pbody').innerHTML=html;
  $('#panel').removeAttribute('inert');
  $('#panel').setAttribute('aria-modal','true');
  $('#panel').setAttribute('aria-hidden','false');
  $('#panel').classList.add('on');$('#scrim').classList.add('on');$('#panel').scrollTop=0;
  panelOpener=opener||null;
  $('#pclose').focus();
}
function closePanel(){
  $('#panel').classList.remove('on');$('#scrim').classList.remove('on');
  $('#panel').setAttribute('inert','');
  $('#panel').removeAttribute('aria-modal');
  $('#panel').setAttribute('aria-hidden','true');
  if(panelOpener && panelOpener.focus){panelOpener.focus();}
  panelOpener=null;
}
document.querySelectorAll('[data-panel]').forEach(function(el){
  fireOnEnterOrSpace(el);
  el.onclick=function(){openPanel(el.getAttribute('data-panel'), el);};
});
$('#scrim').onclick=closePanel;$('#pclose').onclick=closePanel;
document.onkeydown=function(e){
  var panel=$('#panel');
  if(e.key==='Escape' && panel.classList.contains('on')){closePanel();return;}
  if(e.key!=='Tab' || !panel.classList.contains('on')) return;
  var focusable=[].slice.call(panel.querySelectorAll(
    'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),'+
    'textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'));
  if(!focusable.length){e.preventDefault();return;}
  var first=focusable[0],last=focusable[focusable.length-1];
  if(e.shiftKey && document.activeElement===first){e.preventDefault();last.focus();}
  else if(!e.shiftKey && document.activeElement===last){e.preventDefault();first.focus();}
};
"""


def html_string(results, apps, tenant_id, estate=None, health=None, context=None,
                detail_href=None, changes=None, decision_states=None) -> str:
    """The whole page, self-contained."""
    estate = estate or {"vendors": [], "unattached_agents": []}
    ctx = assessment.context(apps, estate, health)
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="decision-context" content="snapshot">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width,initial-scale=1">
<script>%(theme)s</script>
<title>AI-SPM &#8212; AI security assessment</title><style>%(css)s</style></head>
<body>
<noscript>This is a read-only scan snapshot. JavaScript is required for live workflow
 review, theme controls and evidence panels. No edits are saved without the live API.</noscript>
<a class="skiplink" href="#main">Skip to content</a>
<header class="topbar">
  <div class="brand"><span class="logo"><i></i><i></i><i></i><i></i></span> AI-SPM</div>
  <nav aria-label="Report sections">%(nav)s</nav>
  <div class="topright">
    <button class="iconbtn" id="theme" title="Switch theme" aria-label="Switch color theme">&#9788;</button>
    <span>%(org)s</span>
  </div>
</header>
<main class="wrap" id="main">
  <div class="view on" id="v-overview">%(overview)s</div>
  <div class="view" id="v-assessment">%(assessment)s</div>
  <div class="view" id="v-estate">%(estate)s</div>
  <footer>
    <div><b>AI-SPM</b> &#8212; tenant collection is read-only. Workflow recording does not
    change Microsoft 365 configuration. Remediation stays with your team.</div>
    <div>%(finished)s</div>
  </footer>
</main>
<div class="scrim" id="scrim"></div>
<div class="panel" id="panel" role="dialog" aria-hidden="true" aria-label="Test detail" inert>
  <button class="pclose" id="pclose" aria-label="Close detail panel">&#10005;</button>
  <div id="pbody"></div></div>
<script>%(js)s</script>
</body></html>
""" % {"css": CSS + charts.CSS + dashboard_theme.CSS,
       "theme": dashboard_theme.DETECT, "js": JS + dashboard_workflow.JS,
       "nav": _nav("overview", detail_href),
       "org": esc(((context or {}).get("tenant_profile") or {}).get("display_name")
                  or "AI-SPM"),
       "overview": _overview(ctx, results, apps, estate, tenant_id, context, changes,
                             decision_states),
       "assessment": _assessment_view(results),
       "estate": _estate_view(estate),
       "finished": esc((context or {}).get("finished") or "")}


def json_string(results, decision_states=None, now=None) -> str:
    """The assessment as data — the same verdicts, for a pipeline rather than a person."""
    import json
    workflow = _workflow_states(results, decision_states, now)
    active = _decision_programs(results, [], decision_states, now)
    payload = {"summary": assessment.summary(results),
               "tests": [{k: v for k, v in t.items() if k != "checked"} for t in results],
               "decision_workflow": workflow,
               "scan_as_of": now.isoformat() if isinstance(now, datetime) else None,
               "workflow_as_of": now.isoformat() if isinstance(now, datetime) else None,
               "decision_attention": decisionstate.attention([p["workflow"] for p in active])}
    return json.dumps(payload, indent=2, ensure_ascii=False)
