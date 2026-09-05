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

import assessment
import charts
import executive
import report

STATUS_COLOR = {assessment.FAILED: "#c4314b", assessment.PASSED: "#0f7b0f",
                assessment.NOT_ASSESSED: "#8a8886", assessment.SKIPPED: "#a19f9d"}
RISK_COLOR = {"High": "#c4314b", "Medium": "#c07000", "Low": "#5f6b7a"}
PILLAR_COLOR = {assessment.P_ID: "#8764b8", assessment.P_DATA: "#c4314b",
                assessment.P_GOV: "#0f7b0f", assessment.P_SURF: "#c07000",
                assessment.P_MON: "#0f6cbd"}
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
            '<tr data-status="%s" data-risk="%s" data-pillar="%s" data-name="%s" data-panel="%s" '
            'tabindex="0" role="button" aria-haspopup="dialog">'
            '<td class="tname">%s<span class="tid">%s</span></td>'
            '<td class="risk" style="color:%s"><i>&#8593;</i>%s</td><td>%s</td></tr>'
            % (esc(t["status"]), esc(t["risk"]), esc(t["pillar"]), esc(t["name"].lower()),
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
             ("People reached", ("%.1fk" % (users / 1000.0)) if users >= 1000 else users,
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
        cap = ("All %d AI vendors arrive by a single route, so each one can be cut off "
               "with one action." % len(vendors))
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
            + "<div><span>People reached:</span> <b>%s</b></div>" % v.get("users", 0)
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
    for entry in (health or {}).values():
        for key in ("collected_at", "checked_at", "last_success", "timestamp"):
            value = entry.get(key)
            if value:
                timestamps.append(str(value))
                break
    if not timestamps:
        return "Source-level freshness is not reported by the connected APIs."
    return ("Freshness reported by %d connector(s); oldest reported source time: %s."
            % (len(timestamps), min(timestamps)))


def _coverage_confidence(results, health):
    """
    What share of the catalogue could actually be answered this scan, and which source
    each remaining gap needs — so a page full of green never quietly includes a
    `Not assessed` row read as a pass.
    """
    summary = assessment.summary(results)
    total = summary["total"]
    answerable = (summary["by_status"].get(assessment.PASSED, 0)
                  + summary["by_status"].get(assessment.FAILED, 0))
    assessment_pct = round(100 * answerable / total) if total else 0
    sources = executive.connector_status(health)
    operational = [(name, ok, detail) for name, ok, detail in sources if ok is not None]
    connected = 1  # Entra ID / Microsoft Graph; producing this report proves it ran.
    connected += sum(1 for key in _HEALTH_BY_LABEL.values()
                     if (health or {}).get(key, {}).get("status") == "CONNECTED")
    telemetry_pct = round(100 * connected / len(operational)) if operational else 0
    degraded = any((entry or {}).get("status") in
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
        if ok is None:
            css, label = "roadmap", "Roadmap"
        elif status == "PARTIALLY_CONNECTED":
            css, label = "warn", "Partial"
        elif status == "NO_DATA":
            css, label = "warn", "No data"
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


def _decision_programs(results, apps):
    """Collapse control failures into no more than three accountable root-cause decisions."""
    failed = {t["id"]: t for t in results if t["status"] == assessment.FAILED}
    decisions = []
    for definition in DECISION_PROGRAMS:
        controls = [failed[tid] for tid in definition["ids"] if tid in failed]
        if not controls:
            continue
        names = {name for control in controls for name, _detail in control["assets"]}
        decisions.append({
            **definition,
            "controls": sorted(controls, key=lambda t: (assessment.RISK_ORDER[t["risk"]],
                                                        t["id"])),
            # Assessment evidence currently carries display labels, not stable IDs or a
            # cross-application user union. Call these evidence items rather than
            # pretending they are unique identities or people.
            "evidence_items": len(names),
            "evidence": [t["verdict"] for t in controls[:2]],
        })
    return decisions


def _decisions_html(results, apps):
    decisions = _decision_programs(results, apps)
    if not decisions:
        return ('<div class="card"><h3>Executive decisions</h3><p class="cap">'
                "No remediation decision is required from the controls assessed this scan. "
                "Review coverage gaps and continue monitoring.</p></div>"), decisions
    cards = []
    for index, decision in enumerate(decisions, 1):
        controls = decision["controls"]
        high = sum(1 for t in controls if t["risk"] == "High")
        scope = ("%d control(s) &middot; %d named evidence item(s)"
                 % (len(controls), decision["evidence_items"]))
        evidence = " ".join(decision["evidence"]) or "See the control backlog for evidence."
        effect = ("%d control(s) enter one accountable campaign; each retains its canonical "
                  "verification criteria" % len(controls))
        cards.append(
            '<article class="decision" aria-labelledby="decision-%d"><h4 id="decision-%d">'
            '<span class="u">Decision %d</span><br>%s</h4><div class="scope">%s</div>'
            '<div class="dmeta"><span>Accountable owner</span><b>%s</b>'
            '<span>Due</span><b>%s</b><span>Priority</span><b>%s</b></div>'
            '<p class="why"><b>Why now:</b> %s</p><p class="why"><b>Observed evidence:</b> '
            '%s</p><p class="choice"><b>Executive choice:</b> %s</p>'
            '<div class="effect">%s; %s.</div></article>'
            % (index, index, index, esc(decision["title"]), scope, esc(decision["owner"]),
               esc(decision["sla"]), "Immediate" if high else "Planned",
               esc(decision["why"]), esc(evidence), esc(decision["choice"]), esc(effect),
               esc(", ".join(t["id"] for t in controls))))
    campaigns = "".join(
        '<div class="campaign"><b>%s</b><span>%d control(s) routed to %s</span></div>'
        % (esc(d["title"]), len(d["controls"]), esc(d["owner"])) for d in decisions)
    return (
        '<div class="card"><h3>%d executive %s that %s the risk</h3>'
        '<p class="pn">Control failures are consolidated by root cause. The complete '
        '26-control evidence backlog remains below.</p><div class="decisiongrid">%s</div>'
        '<h3 style="margin-top:20px">Remediation campaigns</h3>'
        '<div class="campaigns">%s</div></div>'
        % (len(decisions), "decision" if len(decisions) == 1 else "decisions",
           "moves" if len(decisions) == 1 else "move", "".join(cards), campaigns),
        decisions,
    )


def _narrative(results, decisions):
    failed = [t for t in results if t["status"] == assessment.FAILED]
    if not failed:
        return ("<p>No control in this catalogue failed this scan. The remaining work is "
                "closing coverage gaps and sustaining monitoring.</p>")
    routed = sum(len(d["controls"]) for d in decisions)
    high = sum(1 for t in failed if t["risk"] == "High")
    return ("<p><b>%d control failure(s) are consolidated into %d executive decision(s).</b> "
            "%d are High risk. This separates what leadership must approve from the "
            "evidence backlog the security team must execute.</p>"
            % (len(failed), len(decisions), high)
            + ("<p>%d failed control(s) are routed into accountable remediation campaigns.</p>"
               % routed))


def _cockpit(results, apps, estate, health, changes, context=None):
    """
    The hero: one screen a decision-maker can act on without opening a single row.
    Composed entirely from data the page already renders below it — the table remains
    the source of truth, this is its summary, not a second opinion.
    """
    shadow_apps = [a for a in apps if not a.get("first_party_microsoft")]
    score, band = _posture(shadow_apps)
    trend_cls, trend_text = _trend(changes)
    coverage = _coverage_confidence(results, health)
    counts = {lv: sum(1 for app in shadow_apps if app.get("risk_level") == lv)
              for lv in report.LEVELS}
    decisions_html, decisions = _decisions_html(results, apps)
    conc_html = _concentration(results, apps)
    narrative = _narrative(results, decisions)

    return """
<div class="cockpit">
  <div class="narrative">
    <h2>Executive summary</h2>
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
      <h3>Evidence confidence <span class="confbadge">%(confidence)s</span></h3>
      <p class="pn"><b>Assessment coverage:</b> %(assessable)d of %(total)d controls
      answerable (%(assessment_pct)d%%).</p>
      <div class="confbar"><i style="width:%(assessment_pct)d%%"></i></div>
      <p class="pn"><b>Telemetry coverage:</b> %(connected)d of %(operational)d operational
      sources fully informative (%(telemetry_pct)d%%). Partial and no-data sources reduce
      confidence; roadmap sources are not in this denominator.</p>
      <div class="confbar telemetry"><i style="width:%(telemetry_pct)d%%"></i></div>
      <p class="fresh">%(freshness)s</p>
      <ul class="conflist">%(conn_rows)s</ul>
    </div>
    <div class="card">
      <h3>Risk concentration</h3>
      <p class="pn">Assets named by more than one failing control — the blast radius
      if one of them is compromised, or the leverage if one of them is fixed.</p>
      %(conc)s
    </div>
  </div>
  %(decisions)s
</div>
""" % {"narrative": narrative, "trend_cls": trend_cls, "trend_text": trend_text,
       "gauge": charts.gauge(score, "Tenant AI posture"),
       "critical": counts.get("Critical", 0), "high": counts.get("High", 0),
       "assessable": coverage["assessable"], "total": coverage["total"],
       "assessment_pct": coverage["assessment_pct"],
       "connected": coverage["connected"], "operational": coverage["operational"],
       "telemetry_pct": coverage["telemetry_pct"], "confidence": coverage["confidence"],
       "freshness": esc(coverage["freshness"]), "conn_rows": coverage["rows"],
       "conc": conc_html, "decisions": decisions_html}


def _overview(ctx, results, apps, estate, tenant_id, context, changes=None):
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

    unknown = [t for t in results if t["status"] == assessment.NOT_ASSESSED]
    gaps = "".join(
        '<div class="gap"><span>&#128683;</span><div><b>%s</b><div class="gapwhy">%s</div>'
        "</div></div>" % (esc(t["name"]), esc(t["verdict"])) for t in unknown)
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
    cockpit_html = _cockpit(results, apps, estate, ctx["health"], changes, context)

    return """
<h1>%(org)s</h1>
%(cockpit)s
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
    <h2>Who it reaches</h2>
    %(reach)s
    <p class="cap">Consent counts, not usage. The gap between the two is what the sign-in
    activity tests measure; where Entra ID P1 is missing, that gap cannot be seen at all.</p>
    <div class="foots">
      <div><div class="fl">People reached</div><div class="fn">%(users)s</div></div>
      <div><div class="fl">Applications</div><div class="fn">%(napps)d</div></div>
      <div><div class="fl">Agents</div><div class="fn">%(agents)d</div></div>
    </div>
  </div>
</div>

<div class="grid two" style="margin-top:16px">
  <div class="card">
    <h2>Highest risk first</h2>
    %(risk)s
    <p class="cap">Scores are built from the permissions held, how they were consented and
    how many people they reach. Every point carries its reason on the OAuth assessment —
    nothing here is a black box.</p>
  </div>
  <div class="card">
    <h2>What is not being assessed</h2>
    %(gaps)s
    <p class="cap">These are shown rather than hidden on purpose. A test that could not
    run is a gap in visibility, and a gap in visibility is itself a finding — it is never
    reported as a zero.</p>
  </div>
</div>
""" % {"org": esc(org), "domain": esc(profile.get("primary_domain") or "&#8212;"),
       "tenant": esc(tenant_id), "scanner": esc(scanned.get("app_name") or "AI-SPM"),
       "finished": esc(finished or "this scan"), "cockpit": cockpit_html,
       "tiles": _tiles(ctx, estate, shadow), "pillrows": pillrows,
       "radial": radial(pillars),
       "passed": summary["by_status"].get(assessment.PASSED, 0),
       "failed": summary["by_status"].get(assessment.FAILED, 0),
       "unknown": len(unknown), "flow": flow_svg, "flowcap": esc(flow_cap),
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
    <input class="search" id="q" placeholder="Search by name...">
    <span class="lbl">Risk:</span>%(chips)s
    <span class="lbl">Status:</span>%(schips)s
  </div>
  <div class="filters"><span class="lbl" style="margin-left:0">Pillar:</span>%(pchips)s</div>
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
var state={risk:null,status:null,pillar:null,q:''};
function apply(){
  var shown=0,total=0;
  document.querySelectorAll('#tbody tr').forEach(function(tr){
    total++;
    var ok=true;
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
/* Function App routes carry a ?code=; carry it to the sibling dashboards so the links
   keep working there, and leave them alone on a page opened off disk. */
if(location.pathname.indexOf('/api/')===0){
  var code=new URLSearchParams(location.search).get('code');
  if(code){
    document.querySelectorAll('nav a.out').forEach(function(a){
      var h=a.getAttribute('href');
      if(h && h.indexOf('/api/')===0)
        a.setAttribute('href', h+(h.indexOf('?')<0?'?':'&')+'code='+encodeURIComponent(code));
    });
  }
}
"""


def html_string(results, apps, tenant_id, estate=None, health=None, context=None,
                detail_href=None, changes=None) -> str:
    """The whole page, self-contained."""
    estate = estate or {"vendors": [], "unattached_agents": []}
    ctx = assessment.context(apps, estate, health)
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI-SPM &#8212; AI security assessment</title><style>%(css)s</style></head>
<body>
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
    <div><b>AI-SPM</b> &#8212; read-only. It observes, scores and reports; remediation
    stays with your team.</div>
    <div>%(finished)s</div>
  </footer>
</main>
<div class="scrim" id="scrim"></div>
<div class="panel" id="panel" role="dialog" aria-hidden="true" aria-label="Test detail" inert>
  <button class="pclose" id="pclose" aria-label="Close detail panel">&#10005;</button>
  <div id="pbody"></div></div>
<script>%(js)s</script>
</body></html>
""" % {"css": CSS + charts.CSS, "js": JS, "nav": _nav("overview", detail_href),
       "org": esc(((context or {}).get("tenant_profile") or {}).get("display_name")
                  or "AI-SPM"),
       "overview": _overview(ctx, results, apps, estate, tenant_id, context, changes),
       "assessment": _assessment_view(results),
       "estate": _estate_view(estate),
       "finished": esc((context or {}).get("finished") or "")}


def json_string(results) -> str:
    """The assessment as data — the same verdicts, for a pipeline rather than a person."""
    import json
    payload = {"summary": assessment.summary(results),
               "tests": [{k: v for k, v in t.items() if k != "checked"} for t in results]}
    return json.dumps(payload, indent=2, ensure_ascii=False)
