"""
The assessment page — AI-SPM's landing view.

Modelled on Microsoft's Zero Trust Assessment, deliberately: it is the visual language a
Microsoft customer already trusts for exactly this kind of answer, and copying a proven
pattern is cheaper than teaching a new one. The shape it borrows is a poor table and a
rich panel — three columns (Name / Risk / Status) and every piece of depth behind a
click, because a table that tries to carry the depth ends up carrying neither.

What it adds beyond that pattern: a failing test names the assets that failed it, and a
test whose source is missing says so instead of passing quietly.

Self-contained HTML — no external CSS, fonts or scripts. These pages are served from Blob
storage and opened off disk, where a CDN reference is a blank page.
"""
import html
import math

import assessment

STATUS_COLOR = {assessment.FAILED: "#c4314b", assessment.PASSED: "#0f7b0f",
                assessment.NOT_ASSESSED: "#8a8886", assessment.SKIPPED: "#a19f9d"}
RISK_COLOR = {"High": "#c4314b", "Medium": "#c07000", "Low": "#5f6b7a"}
PILLAR_COLOR = {assessment.P_ID: "#8764b8", assessment.P_DATA: "#c4314b",
                assessment.P_GOV: "#0f7b0f", assessment.P_SURF: "#c07000",
                assessment.P_MON: "#0f6cbd"}
STATUS_MARK = {assessment.FAILED: "&#10060;", assessment.PASSED: "&#9989;",
               assessment.NOT_ASSESSED: "&#128683;", assessment.SKIPPED: "&#9899;"}

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
            '<tr data-status="%s" data-risk="%s" data-pillar="%s" data-name="%s" data-panel="%s">'
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
            '<tr data-name="%s" data-panel="%s">'
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
    <th data-sort="0">Vendor &#8645;</th><th data-sort="1">Risk &#8645;</th>
    <th data-sort="2">Score &#8645;</th></tr></thead>
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
        cls = ' class="on"' if key == current else ""
        out.append('<a data-view="%s"%s>%s</a>' % (key, cls, label))
    if detail_href:
        out.append('<span class="navsep"></span>')
        out.append('<a href="%s" class="out">Detail<i>&#8599;</i></a>' % esc(detail_href))
    return "".join(out)


def _overview(ctx, results, apps, estate, tenant_id, context):
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

    return """
<h1>%(org)s</h1>
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
       "finished": esc(finished or "this scan"),
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
        '<button class="chip" data-f="risk" data-v="%s" title="%s (%d tests)">%s</button>'
        % (r, r, rcounts[r], r) for r in ("High", "Medium", "Low") if rcounts[r])
    schips = "".join(
        '<button class="chip" data-f="status" data-v="%s" title="%s (%d tests)">%s</button>'
        % (esc(s), esc(s), counts.get(s, 0), esc(s))
        for s in assessment.STATUSES if counts.get(s))
    pchips = "".join(
        '<button class="chip" data-f="pillar" data-v="%s" title="%s (%d tests)">%s</button>'
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
    <th data-sort="0">Name &#8645;</th><th data-sort="1">Risk &#8645;</th>
    <th data-sort="2">Status &#8645;</th></tr></thead>
  <tbody id="tbody">%(rows)s</tbody></table></div>
  <div class="empty" id="none" style="display:none">No test matches these filters.</div>
</div>
""" % {"n": len(results), "chips": chips, "schips": schips, "pchips": pchips,
       "rows": _rows(results)}


JS = """
var $=function(s){return document.querySelector(s)};
document.querySelectorAll('nav a[data-view]').forEach(function(a){
  a.onclick=function(){
    document.querySelectorAll('nav a[data-view]').forEach(function(x){x.classList.remove('on')});
    a.classList.add('on');
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
    document.querySelectorAll('.chip[data-f="'+f+'"]').forEach(function(x){x.classList.remove('on')});
    state[f]=was?null:v;
    if(!was) c.classList.add('on');
    apply();
  };
});
$('#q').oninput=function(){state.q=this.value.toLowerCase();apply();};
apply();
var order={};
document.querySelectorAll('th[data-sort]').forEach(function(th){
  th.onclick=function(){
    var i=+th.getAttribute('data-sort'),body=th.closest('table').querySelector('tbody'),
        key=th.closest('table').id+i,dir=order[key]=-(order[key]||-1);
    var rows=[].slice.call(body.querySelectorAll('tr'));
    rows.sort(function(a,b){
      var x=a.children[i].innerText.trim(),y=b.children[i].innerText.trim();
      return x<y?-dir:(x>y?dir:0);
    });
    rows.forEach(function(r){body.appendChild(r)});
  };
});
function closePanel(){$('#panel').classList.remove('on');$('#scrim').classList.remove('on');}
document.querySelectorAll('tr[data-panel]').forEach(function(tr){
  tr.onclick=function(){
    $('#pbody').innerHTML=tr.getAttribute('data-panel');
    $('#panel').classList.add('on');$('#scrim').classList.add('on');$('#panel').scrollTop=0;
  };
});
$('#scrim').onclick=closePanel;$('#pclose').onclick=closePanel;
document.onkeydown=function(e){if(e.key==='Escape')closePanel();};
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
                detail_href=None) -> str:
    """The whole page, self-contained."""
    estate = estate or {"vendors": [], "unattached_agents": []}
    ctx = assessment.context(apps, estate, health)
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI-SPM &#8212; AI security assessment</title><style>%(css)s</style></head>
<body>
<div class="topbar">
  <div class="brand"><span class="logo"><i></i><i></i><i></i><i></i></span> AI-SPM</div>
  <nav>%(nav)s</nav>
  <div class="topright">
    <button class="iconbtn" id="theme" title="Switch theme">&#9788;</button>
    <span>%(org)s</span>
  </div>
</div>
<div class="wrap">
  <div class="view on" id="v-overview">%(overview)s</div>
  <div class="view" id="v-assessment">%(assessment)s</div>
  <div class="view" id="v-estate">%(estate)s</div>
  <footer>
    <div><b>AI-SPM</b> &#8212; read-only. It observes, scores and reports; remediation
    stays with your team.</div>
    <div>%(finished)s</div>
  </footer>
</div>
<div class="scrim" id="scrim"></div>
<div class="panel" id="panel"><button class="pclose" id="pclose">&#10005;</button>
  <div id="pbody"></div></div>
<script>%(js)s</script>
</body></html>
""" % {"css": CSS, "js": JS, "nav": _nav("overview", detail_href),
       "org": esc(((context or {}).get("tenant_profile") or {}).get("display_name")
                  or "AI-SPM"),
       "overview": _overview(ctx, results, apps, estate, tenant_id, context),
       "assessment": _assessment_view(results),
       "estate": _estate_view(estate),
       "finished": esc((context or {}).get("finished") or "")}


def json_string(results) -> str:
    """The assessment as data — the same verdicts, for a pipeline rather than a person."""
    import json
    payload = {"summary": assessment.summary(results),
               "tests": [{k: v for k, v in t.items() if k != "checked"} for t in results]}
    return json.dumps(payload, indent=2, ensure_ascii=False)
