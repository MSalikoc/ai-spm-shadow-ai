"""
Inline-SVG chart library shared by both dashboards.

Everything renders to a self-contained SVG string with no script and no external
request, because the reports are served straight out of Blob Storage and opened as
standalone files — a CDN dependency would simply not load.

Color follows three jobs, and each job has one rule:

  severity  — status, not identity. The four risk levels use the fixed status palette
              and are ALWAYS drawn with a visible text label beside them, never color
              alone: red/amber/green severity is inherently hard to separate under
              red-green color-vision deficiency, and the label is the mitigation.
  identity  — vendors, categories, sources. The eight categorical slots, assigned in
              fixed order and never cycled; a ninth series folds into "Other" so two
              entities can never share a hue.
  magnitude — heat and intensity. One blue hue, light to dark.

The categorical and sequential slots are emitted as CSS custom properties (see `CSS`)
so light and dark each get steps chosen for their own surface. Status hex is
mode-invariant and inlined directly.
"""
import html
import math

# --- severity (status palette — fixed, never themed) ------------------------
SEVERITY = {
    "Critical": "#d03b3b",
    "High": "#ec835a",
    "Medium": "#fab219",
    "Low": "#0ca30c",
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

# --- identity (categorical slots, fixed order) ------------------------------
# Validated as a set against this dashboard's own surfaces (#ffffff / #171e26):
# every slot inside the lightness band and over the chroma floor, worst adjacent
# CVD dE 9.1 light / 8.4 dark, worst adjacent normal-vision dE 19.6 light / 19.3 dark.
CATEGORICAL_LIGHT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100",
                     "#e87ba4", "#008300", "#4a3aa7", "#e34948"]
CATEGORICAL_DARK = ["#3987e5", "#d95926", "#199e70", "#c98500",
                    "#d55181", "#008300", "#9085e9", "#e66767"]
CATEGORICAL_SLOTS = len(CATEGORICAL_LIGHT)

# --- magnitude (one hue, light to dark) -------------------------------------
SEQUENTIAL_LIGHT = ["#e8f1fd", "#cde2fb", "#9ec5f4", "#6da7ec",
                    "#3987e5", "#256abf", "#184f95", "#0d366b"]
SEQUENTIAL_DARK = ["#16233a", "#0d366b", "#184f95", "#256abf",
                   "#3987e5", "#6da7ec", "#9ec5f4", "#cde2fb"]

CSS = """
/* Chart tokens. Categorical and sequential steps are chosen per surface; status
   colors are mode-invariant and inlined at the mark. */
:root{
 --viz-grid:#e1e0d9; --viz-axis:#c3c2b7; --viz-label:#898781;
""" + "".join(f" --viz-cat-{i + 1}:{c};" for i, c in enumerate(CATEGORICAL_LIGHT)) + "\n" \
    + "".join(f" --viz-seq-{i + 1}:{c};" for i, c in enumerate(SEQUENTIAL_LIGHT)) + """
}
@media (prefers-color-scheme:dark){
 :root:not([data-theme=light]){
  --viz-grid:#2c2c2a; --viz-axis:#383835; --viz-label:#898781;
""" + "".join(f"  --viz-cat-{i + 1}:{c};" for i, c in enumerate(CATEGORICAL_DARK)) + "\n" \
    + "".join(f"  --viz-seq-{i + 1}:{c};" for i, c in enumerate(SEQUENTIAL_DARK)) + """
 }
}
:root[data-theme=dark]{
 --viz-grid:#2c2c2a; --viz-axis:#383835; --viz-label:#898781;
""" + "".join(f" --viz-cat-{i + 1}:{c};" for i, c in enumerate(CATEGORICAL_DARK)) + "\n" \
    + "".join(f" --viz-seq-{i + 1}:{c};" for i, c in enumerate(SEQUENTIAL_DARK)) + """
}
:root[data-theme=light]{
 --viz-grid:#e1e0d9; --viz-axis:#c3c2b7; --viz-label:#898781;
""" + "".join(f" --viz-cat-{i + 1}:{c};" for i, c in enumerate(CATEGORICAL_LIGHT)) + "\n" \
    + "".join(f" --viz-seq-{i + 1}:{c};" for i, c in enumerate(SEQUENTIAL_LIGHT)) + """
}
.viz{display:block;max-width:100%;height:auto;overflow:visible}
.viz text{font:11px/1.3 'Segoe UI',-apple-system,Roboto,sans-serif;fill:var(--ink)}
.viz .ax{fill:var(--viz-label);font-size:10px;font-variant-numeric:tabular-nums}
.viz .val{font-size:11px;font-weight:600;font-variant-numeric:tabular-nums;fill:var(--ink)}
.viz .lbl{font-size:11px;fill:var(--ink)}
.viz .sub{font-size:10px;fill:var(--muted)}
.viz .grid{stroke:var(--viz-grid);stroke-width:1}
.viz .axis{stroke:var(--viz-axis);stroke-width:1}
.viz .mark{transition:opacity .12s}
.viz g:hover > .mark{opacity:.78}
.viz-legend{display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:12px;font-size:12px}
.viz-legend span.k{display:inline-flex;align-items:center;gap:6px;color:var(--ink)}
.viz-legend i{width:10px;height:10px;border-radius:3px;flex:0 0 auto}
.viz-legend b{font-variant-numeric:tabular-nums;color:var(--muted);font-weight:600}
.viz-empty{color:var(--muted);font-size:12px;padding:14px 0}
.viz [data-tip]{cursor:default}
.viz [data-tip]:hover .mark,.viz [data-tip]:focus .mark{opacity:1;filter:brightness(1.08)}
.viz [data-tip]:focus{outline:none}
.viz [data-tip]:focus .mark{stroke:var(--ink);stroke-width:2}
#viz-tip{position:fixed;z-index:60;pointer-events:none;opacity:0;transition:opacity .1s;
 background:var(--ink);color:var(--panel);font:12px/1.45 'Segoe UI',-apple-system,Roboto,sans-serif;
 padding:6px 10px;border-radius:7px;max-width:320px;box-shadow:0 4px 14px rgba(0,0,0,.28)}
#viz-tip.on{opacity:1}
"""

# Attached once per page; every chart mark carries data-tip, so one listener covers all
# eight forms. Keyboard focus shows the same tooltip, so the marks are not mouse-only.
JS = """
(function(){
  var tip=document.getElementById('viz-tip');
  if(!tip){tip=document.createElement('div');tip.id='viz-tip';document.body.appendChild(tip);}
  function show(el,x,y){
    var t=el.getAttribute('data-tip'); if(!t){return;}
    tip.textContent=t; tip.classList.add('on');
    var r=tip.getBoundingClientRect();
    var left=Math.min(Math.max(8,x-r.width/2),window.innerWidth-r.width-8);
    var top=y-r.height-12; if(top<8){top=y+18;}
    tip.style.left=left+'px'; tip.style.top=top+'px';
  }
  function hide(){tip.classList.remove('on');}
  document.addEventListener('mouseover',function(e){
    var el=e.target.closest && e.target.closest('[data-tip]');
    if(el){show(el,e.clientX,e.clientY);}else{hide();}
  });
  document.addEventListener('mousemove',function(e){
    var el=e.target.closest && e.target.closest('[data-tip]');
    if(el&&tip.classList.contains('on')){show(el,e.clientX,e.clientY);}
  });
  document.addEventListener('mouseout',function(e){
    if(e.target.closest && e.target.closest('[data-tip]')){hide();}
  });
  document.addEventListener('focusin',function(e){
    var el=e.target.closest && e.target.closest('[data-tip]');
    if(el){var b=el.getBoundingClientRect();show(el,b.left+b.width/2,b.top);}
  });
  document.addEventListener('focusout',hide);
  window.addEventListener('scroll',hide,{passive:true});
})();
"""


def cat(i: int) -> str:
    """Categorical slot by index, assigned in fixed order and never cycled past 8."""
    return f"var(--viz-cat-{min(i, CATEGORICAL_SLOTS - 1) + 1})"


def seq(level: float) -> str:
    """Sequential step for a 0..1 magnitude."""
    n = len(SEQUENTIAL_LIGHT)
    idx = 0 if level <= 0 else min(n - 1, int(level * n))
    return f"var(--viz-seq-{idx + 1})"


def severity_color(level: str) -> str:
    return SEVERITY.get(level, "#8b98a6")


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def hover(text) -> str:
    """
    Attributes that make a mark identify itself on hover.

    `<title>` was doing this, but the browser's native tooltip waits about a second,
    cannot be styled, and is easy to miss entirely — on a scatter of unlabelled dots
    that left the reader with no way to tell which vendor was which. `data-tip` drives
    the styled tooltip in JS; `aria-label` keeps the same text available to screen
    readers without triggering a second, native tooltip on top of it.
    """
    safe = _e(text)
    return f' data-tip="{safe}" aria-label="{safe}"'


def _empty(msg="No data") -> str:
    return f'<div class="viz-empty">{_e(msg)}</div>'


def _nice_ticks(maxv: float, count: int = 4) -> list[float]:
    """Round axis ticks — 1/2/5 x 10^n, so labels read as human numbers."""
    if maxv <= 0:
        return [0, 1]
    raw = maxv / count
    mag = 10 ** math.floor(math.log10(raw)) if raw > 0 else 1
    for m in (1, 2, 2.5, 5, 10):
        if raw <= m * mag:
            step = m * mag
            break
    else:
        step = 10 * mag
    ticks, t = [], 0.0
    while t <= maxv + step / 2:
        ticks.append(round(t, 6))
        t += step
    return ticks


def legend(entries, show_values: bool = True) -> str:
    """
    Identity is never carried by color alone — every chart with two or more series
    ships this. `entries` is [(label, color, value)].
    """
    if not entries:
        return ""
    out = []
    for label, color, value in entries:
        val = f" <b>{_e(value)}</b>" if show_values and value is not None else ""
        out.append(f'<span class="k"><i style="background:{color}"></i>{_e(label)}{val}</span>')
    return f'<div class="viz-legend">{"".join(out)}</div>'


# --- hero / single-number forms --------------------------------------------
def gauge(score: int, caption: str = "", width: int = 210) -> str:
    """
    A single headline number with its 0-100 position — a stat tile with an arc, used
    where the story really is one number rather than a comparison.
    """
    score = max(0, min(100, int(score or 0)))
    r, cx, cy = 74, width / 2, 96
    start, end = math.pi, 2 * math.pi          # 180 degree arc, left to right

    def pt(frac):
        a = start + (end - start) * frac
        return cx + r * math.cos(a), cy + r * math.sin(a)

    x0, y0 = pt(0)
    x1, y1 = pt(1)
    xs, ys = pt(score / 100)
    band = ("Critical" if score >= 75 else "High" if score >= 50
            else "Medium" if score >= 25 else "Low")
    color = severity_color(band)
    # The gauge sweeps 180 degrees end to end, so the value arc is never more than a
    # half circle: large-arc-flag stays 0, or the arc takes the long way round.
    large = 0
    # Explicit width/height: without them the shared `max-width:100%` rule stretches a
    # 210-wide viewBox to the full card and the arc bleeds outside its container.
    return (
        f'<svg viewBox="0 0 {width} 118" width="{width}" height="118" class="viz" role="img" '
        f'aria-label="{_e(caption)}: {score} of 100, {band}">'
        f'<path d="M{x0:.1f},{y0:.1f} A{r},{r} 0 0 1 {x1:.1f},{y1:.1f}" fill="none" '
        f'stroke="var(--track)" stroke-width="13" stroke-linecap="round"/>'
        f'<path d="M{x0:.1f},{y0:.1f} A{r},{r} 0 {large} 1 {xs:.1f},{ys:.1f}" fill="none" '
        f'stroke="{color}" stroke-width="13" stroke-linecap="round" class="mark"/>'
        f'<text x="{cx}" y="{cy - 14}" text-anchor="middle" style="font-size:34px;'
        f'font-weight:700;fill:var(--ink)">{score}</text>'
        f'<text x="{cx}" y="{cy + 6}" text-anchor="middle" class="sub">{_e(band)} · of 100</text>'
        f'<text x="{cx - r}" y="{cy + 20}" text-anchor="middle" class="ax">0</text>'
        f'<text x="{cx + r}" y="{cy + 20}" text-anchor="middle" class="ax">100</text>'
        f'</svg>')


def donut(segments, center_value=None, center_label="", size: int = 190,
          stroke: int = 26) -> str:
    """
    Part-to-whole at a glance. `segments` is [(label, value, color)].

    Segments are separated by a 2px surface gap rather than an outline, and the
    accompanying legend carries the labels — a donut alone never has to be read by hue.
    """
    segments = [(lb, v, c) for lb, v, c in segments if v and v > 0]
    total = sum(v for _, v, _ in segments)
    if not total:
        return _empty("Nothing to chart yet")

    r = (size - stroke) / 2
    cx = cy = size / 2
    circ = 2 * math.pi * r
    gap = 2 if len(segments) > 1 else 0        # surface gap, not a border
    arcs, offset = [], 0.0
    for label, value, color in segments:
        dash = circ * (value / total)
        arcs.append(
            f'<g{hover(f"{label}: {value} ({round(100 * value / total)}%)")}>'
            f'<circle cx="{cx}" cy="{cy}" r="{r:.2f}" fill="none" stroke="{color}" '
            f'stroke-width="{stroke}" class="mark" '
            f'stroke-dasharray="{max(dash - gap, 0.5):.2f} {circ - max(dash - gap, 0.5):.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/></g>')
        offset += dash

    mid = center_value if center_value is not None else total
    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" class="viz" '
        f'role="img" aria-label="{_e(center_label)}: {mid}">'
        f'<circle cx="{cx}" cy="{cy}" r="{r:.2f}" fill="none" stroke="var(--track)" '
        f'stroke-width="{stroke}"/>{"".join(arcs)}'
        f'<text x="{cx}" y="{cy - 2}" text-anchor="middle" style="font-size:27px;'
        f'font-weight:700;fill:var(--ink)">{_e(mid)}</text>'
        f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" class="sub">{_e(center_label)}</text>'
        f'</svg>')


# --- magnitude comparison ---------------------------------------------------
def hbar(rows, width: int = 560, bar: int = 18, gap: int = 12,
         label_w: int = 190, unit: str = "") -> str:
    """
    Ranked magnitude. `rows` is [(label, sublabel, value, color)].

    Bars anchor to the baseline with rounded data-ends, and every bar is directly
    labelled with its value — no legend needed, since one bar is one entity.
    """
    rows = list(rows)
    if not rows:
        return _empty()
    maxv = max((v for _, _, v, _ in rows), default=0) or 1
    plot_w = width - label_w - 54
    height = len(rows) * (bar + gap) + 8

    out = []
    for i, (label, sub, value, color) in enumerate(rows):
        y = i * (bar + gap) + 4
        w = max(2.0, plot_w * (value / maxv))
        sub_txt = (f'<tspan class="sub" dx="6">{_e(sub)}</tspan>' if sub else "")
        out.append(
            f'<g{hover(f"{label}: {value}{unit}" + (f" — {sub}" if sub else ""))}>'
            f'<text x="0" y="{y + bar * 0.72:.1f}" class="lbl">'
            f'{_e(_clip(label, 26))}{sub_txt}</text>'
            f'<rect x="{label_w}" y="{y}" width="{plot_w}" height="{bar}" rx="4" '
            f'fill="var(--track)"/>'
            f'<rect x="{label_w}" y="{y}" width="{w:.1f}" height="{bar}" rx="4" '
            f'fill="{color}" class="mark"/>'
            f'<text x="{label_w + plot_w + 8}" y="{y + bar * 0.72:.1f}" class="val">'
            f'{_e(value)}{_e(unit)}</text></g>')
    return (f'<svg viewBox="0 0 {width} {height}" class="viz" role="img">'
            f'{"".join(out)}</svg>')


def _clip(s, n):
    s = str(s or "—")
    return s if len(s) <= n else s[:n - 1] + "…"


def stacked_bar(rows, keys, colors, width: int = 560, bar: int = 20, gap: int = 14,
                label_w: int = 170) -> str:
    """
    Composition across categories. `rows` is [(label, {key: value})]; `keys` fixes the
    segment order so a category keeps its color when the data changes.
    """
    rows = [(lb, d) for lb, d in rows if sum(d.get(k, 0) for k in keys) > 0]
    if not rows:
        return _empty()
    plot_w = width - label_w - 48
    height = len(rows) * (bar + gap) + 8
    out = []
    for i, (label, data) in enumerate(rows):
        y = i * (bar + gap) + 4
        total = sum(data.get(k, 0) for k in keys) or 1
        x = float(label_w)
        out.append(f'<text x="0" y="{y + bar * 0.7:.1f}" class="lbl">{_e(_clip(label, 24))}</text>')
        for k in keys:
            v = data.get(k, 0)
            if not v:
                continue
            w = plot_w * (v / total)
            out.append(
                f'<g{hover(f"{label} — {k}: {v} ({round(100 * v / total)}%)")}>'
                f'<rect x="{x:.1f}" y="{y}" width="{max(w - 2, 1):.1f}" height="{bar}" '
                f'rx="3" fill="{colors.get(k, "var(--track)")}" class="mark"/></g>')
            x += w                                  # 2px of the step is left as surface gap
        out.append(f'<text x="{label_w + plot_w + 8}" y="{y + bar * 0.7:.1f}" '
                   f'class="val">{total}</text>')
    return (f'<svg viewBox="0 0 {width} {height}" class="viz" role="img">'
            f'{"".join(out)}</svg>')


# --- change over time -------------------------------------------------------
def timeseries(values, labels=None, width: int = 660, height: int = 150,
               unit: str = "", color: str = "var(--accent)") -> str:
    """
    A single measure over time, as a line with a soft area under it. One axis only —
    a second measure of a different scale gets its own chart, never a second y-scale.
    """
    values = [v or 0 for v in (values or [])]
    if not values or max(values) <= 0:
        return _empty("No activity data yet")

    pad_l, pad_r, pad_t, pad_b = 38, 10, 12, 22
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    ticks = _nice_ticks(max(values))
    top = ticks[-1] or 1
    n = len(values)
    dx = plot_w / (n - 1) if n > 1 else plot_w

    def xy(i, v):
        return pad_l + i * dx, pad_t + plot_h - (v / top) * plot_h

    pts = [xy(i, v) for i, v in enumerate(values)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = f"{pad_l},{pad_t + plot_h} {line} {pad_l + plot_w:.1f},{pad_t + plot_h}"

    grid = "".join(
        f'<line x1="{pad_l}" y1="{pad_t + plot_h - (t / top) * plot_h:.1f}" '
        f'x2="{pad_l + plot_w:.1f}" y2="{pad_t + plot_h - (t / top) * plot_h:.1f}" class="grid"/>'
        f'<text x="{pad_l - 6}" y="{pad_t + plot_h - (t / top) * plot_h + 3:.1f}" '
        f'text-anchor="end" class="ax">{_fmt(t)}</text>' for t in ticks)

    # Hover targets are full-height columns so the pointer never has to find the dot.
    hover_cols = "".join(
        f'<g{hover((labels[i] if labels and i < len(labels) else f"point {i + 1}") + f": {_fmt(v)}{unit}")}>'
        f'<rect x="{pts[i][0] - dx / 2:.1f}" y="{pad_t}" width="{max(dx, 3):.1f}" '
        f'height="{plot_h}" fill="transparent"/></g>' for i, v in enumerate(values))

    lx, ly = pts[-1]
    peak_i = max(range(n), key=lambda i: values[i])
    px, py = pts[peak_i]
    peak_lbl = ""
    if peak_i not in (n - 1,) and values[peak_i] > 0:
        anchor = "start" if px < pad_l + plot_w * 0.8 else "end"
        peak_lbl = (f'<circle cx="{px:.1f}" cy="{py:.1f}" r="3" fill="{color}"/>'
                    f'<text x="{px + (5 if anchor == "start" else -5):.1f}" y="{py - 7:.1f}" '
                    f'text-anchor="{anchor}" class="val">{_fmt(values[peak_i])}</text>')

    x_labels = ""
    if labels:
        for i in (0, n - 1):
            if i < len(labels):
                x_labels += (f'<text x="{pts[i][0]:.1f}" y="{height - 6}" class="ax" '
                             f'text-anchor="{"start" if i == 0 else "end"}">'
                             f'{_e(labels[i])}</text>')

    return (f'<svg viewBox="0 0 {width} {height}" class="viz" role="img" '
            f'preserveAspectRatio="none">{grid}'
            f'<line x1="{pad_l}" y1="{pad_t + plot_h}" x2="{pad_l + plot_w:.1f}" '
            f'y2="{pad_t + plot_h}" class="axis"/>'
            f'<polygon points="{area}" fill="{color}" opacity="0.10"/>'
            f'<polyline points="{line}" fill="none" stroke="{color}" stroke-width="2" '
            f'stroke-linejoin="round"/>{peak_lbl}'
            f'<circle cx="{lx:.1f}" cy="{ly:.1f}" r="4" fill="{color}" '
            f'stroke="var(--panel)" stroke-width="2"/>'
            f'<text x="{lx - 6:.1f}" y="{ly - 9:.1f}" text-anchor="end" class="val">'
            f'{_fmt(values[-1])}{_e(unit)}</text>{x_labels}{hover_cols}</svg>')


def _fmt(v):
    v = round(float(v), 2)
    if v >= 1_000_000:
        return f"{v / 1_000_000:.1f}M"
    if v >= 1000:
        return f"{v / 1000:.1f}k"
    return str(int(v)) if float(v).is_integer() else str(v)


# --- the triage chart -------------------------------------------------------
def risk_scatter(points, width: int = 620, height: int = 300) -> str:
    """
    Risk score against blast radius — the chart that actually drives triage.

    `points` is [(name, risk_score, user_count, severity_level, permission_count)].
    A high score reaching one user is a different problem from a medium score reaching
    the whole tenant, and no ranked list shows that; position does. The user axis is
    log-scaled because consent counts span orders of magnitude, and it is labelled as
    such. Dot area (never radius) carries permission count.
    """
    points = [p for p in points if p[1] is not None]
    if not points:
        return _empty("No scored applications yet")

    # The top pad has to clear the largest dot plus its label, or a cluster of
    # 100-score apps is drawn half outside the plot with the names sliced off.
    pad_l, pad_r, pad_t, pad_b = 44, 16, 30, 40
    plot_w, plot_h = width - pad_l - pad_r, height - pad_t - pad_b
    max_users = max((p[2] or 0) for p in points)

    def ux(users):
        """
        log10 position, so 1 / 10 / 100 / 1000 users sit an equal distance apart.
        Clamping at 1 rather than adding 1 keeps the decades evenly spaced; an app with
        no consenting users shares the origin with a one-user app, and the tooltip
        carries the exact count.
        """
        top = math.log10(max(max_users, 10))
        return pad_l + (math.log10(max(users or 0, 1)) / top) * plot_w

    def ry(score):
        return pad_t + plot_h - (max(0, min(100, score)) / 100) * plot_h

    grid = ""
    for s in (0, 25, 50, 75, 100):
        y = ry(s)
        grid += (f'<line x1="{pad_l}" y1="{y:.1f}" x2="{pad_l + plot_w}" y2="{y:.1f}" '
                 f'class="grid"/><text x="{pad_l - 6}" y="{y + 3:.1f}" text-anchor="end" '
                 f'class="ax">{s}</text>')
    decade = 1
    while decade <= max(max_users, 10):
        x = ux(decade)
        grid += (f'<line x1="{x:.1f}" y1="{pad_t}" x2="{x:.1f}" y2="{pad_t + plot_h}" '
                 f'class="grid"/><text x="{x:.1f}" y="{height - 22}" text-anchor="middle" '
                 f'class="ax">{_fmt(decade)}</text>')
        decade *= 10

    max_perms = max((p[4] or 0) for p in points) or 1
    dots = []
    for name, score, users, level, perms in sorted(points, key=lambda p: -(p[4] or 0)):
        # Area scales with permission count; radius would exaggerate it. The floor keeps
        # a zero-permission app visible, the range is wide enough for size to read.
        r = math.sqrt(16 + 150 * ((perms or 0) / max_perms))
        dots.append(
            f'<g{hover(f"{name} — risk {score}/100 ({level}), {users or 0} users, {perms or 0} permissions")}>'
            f'<circle cx="{ux(users):.1f}" cy="{ry(score):.1f}" r="{r:.1f}" '
            f'fill="{severity_color(level)}" fill-opacity="0.72" class="mark" '
            f'stroke="var(--panel)" stroke-width="2"/>'
            f'<circle cx="{ux(users):.1f}" cy="{ry(score):.1f}" r="{max(r, 11):.1f}" '
            f'fill="transparent"/></g>')

    # Name only the handful that matter, rather than a label on every dot — and drop a
    # name outright when it would land on one already placed. In a real tenant the
    # top-scoring apps cluster in the same corner, so unconditional labelling prints
    # three names on top of each other and none of them can be read. The test is the
    # label's real horizontal extent, which depends on which way it is anchored: two
    # labels 120px apart still collide if they point at each other.
    names, placed = "", []
    for name, score, users, level, _perms in sorted(points, key=lambda p: -(p[1] or 0)):
        if len(placed) >= 3:
            break
        x, y = ux(users), ry(score)
        label_y = y - 11
        text = _clip(name, 20)
        text_w = len(text) * 6.1                       # ~6.1px per char at 11px semibold
        anchor = "end" if x > pad_l + plot_w * 0.7 else "start"
        lo = (x + 8) if anchor == "start" else (x - 8 - text_w)
        hi = lo + text_w
        if any(abs(py - label_y) < 13 and lo < phi and plo < hi
               for plo, phi, py in placed):
            continue
        placed.append((lo, hi, label_y))
        names += (f'<text x="{x + (8 if anchor == "start" else -8):.1f}" y="{label_y:.1f}" '
                  f'text-anchor="{anchor}" class="val">{_e(text)}</text>')

    return (f'<svg viewBox="0 0 {width} {height}" class="viz" role="img" '
            f'aria-label="Risk score against number of consenting users">{grid}'
            f'<line x1="{pad_l}" y1="{pad_t + plot_h}" x2="{pad_l + plot_w}" '
            f'y2="{pad_t + plot_h}" class="axis"/>'
            f'<line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{pad_t + plot_h}" class="axis"/>'
            f'{"".join(dots)}{names}'
            f'<text x="{pad_l + plot_w / 2}" y="{height - 5}" text-anchor="middle" '
            f'class="ax">Users with access (log scale) · dot size = permissions held</text>'
            f'<text x="12" y="{pad_t + plot_h / 2}" class="ax" text-anchor="middle" '
            f'transform="rotate(-90 12 {pad_t + plot_h / 2})">Risk score</text></svg>')


# --- concentration ----------------------------------------------------------
def heatmap(row_labels, col_labels, values, width: int = 620, cell_h: int = 22,
            label_w: int = 150, legend_title: str = "") -> str:
    """
    Where sensitive access concentrates: applications down the side, permissions
    across the top, one blue hue light-to-dark for magnitude.
    """
    if not row_labels or not col_labels:
        return _empty("Not enough overlap to chart")
    # Column labels are rotated, so the header has to be deep enough to hold their
    # vertical reach (label length x sin(40 degrees)) or they clip off the top.
    col_chars = 16
    head_h = 34 + int(col_chars * 6.2 * math.sin(math.radians(40)))
    cell_w = (width - label_w - 12) / len(col_labels)
    height = head_h + len(row_labels) * cell_h + 8
    flat = [v for row in values for v in row]
    top = max(flat) if flat else 0

    cells = []
    for c, col in enumerate(col_labels):
        x = label_w + c * cell_w + cell_w / 2
        cells.append(f'<text x="{x:.1f}" y="{head_h - 8}" class="ax" text-anchor="start" '
                     f'transform="rotate(-40 {x:.1f} {head_h - 8})">'
                     f'{_e(_clip(col, col_chars))}</text>')
    for r, row in enumerate(row_labels):
        y = head_h + r * cell_h
        cells.append(f'<text x="0" y="{y + cell_h * 0.68:.1f}" class="lbl">'
                     f'{_e(_clip(row, 20))}</text>')
        for c, col in enumerate(col_labels):
            v = values[r][c] if r < len(values) and c < len(values[r]) else 0
            x = label_w + c * cell_w
            fill = seq(v / top) if (top and v) else "var(--track)"
            cells.append(
                f'<g{hover(f"{row} — {col}: {v}")}>'
                f'<rect x="{x + 1:.1f}" y="{y + 1}" width="{cell_w - 2:.1f}" '
                f'height="{cell_h - 2}" rx="3" fill="{fill}" class="mark"/></g>')
    scale = ""
    if legend_title:
        scale = (f'<text x="0" y="{head_h - 30}" class="sub">{_e(legend_title)} '
                 f'(0 – {_fmt(top)})</text>')
    return (f'<svg viewBox="0 0 {width} {height}" class="viz" role="img">'
            f'{scale}{"".join(cells)}</svg>')


def treemap(items, width: int = 560, height: int = 220) -> str:
    """
    Share of a total across entities. `items` is [(label, value, color)].

    A squarified layout, so tiles stay close to square and areas remain comparable —
    long thin slivers are exactly what makes a treemap unreadable.
    """
    items = [(lb, v, c) for lb, v, c in items if v and v > 0]
    if not items:
        return _empty()
    items.sort(key=lambda t: -t[1])
    total = sum(v for _, v, _ in items)
    tiles = _squarify([v for _, v, _ in items], 0.0, 0.0, float(width), float(height), total)

    out = []
    for (label, value, color), (x, y, w, h) in zip(items, tiles):
        pct = round(100 * value / total)
        # A label is drawn only where it fits; the tooltip carries the rest.
        text = ""
        if w > 62 and h > 30:
            text = (f'<text x="{x + 8:.1f}" y="{y + 19:.1f}" class="lbl" '
                    f'style="fill:#fff;font-weight:600">{_e(_clip(label, int(w / 7)))}</text>'
                    f'<text x="{x + 8:.1f}" y="{y + 34:.1f}" class="sub" '
                    f'style="fill:#fff;opacity:.85">{value} · {pct}%</text>')
        out.append(
            f'<g{hover(f"{label}: {value} ({pct}%)")}>'
            f'<rect x="{x + 1:.1f}" y="{y + 1:.1f}" width="{max(w - 2, 1):.1f}" '
            f'height="{max(h - 2, 1):.1f}" rx="4" fill="{color}" class="mark"/>{text}</g>')
    return (f'<svg viewBox="0 0 {width} {height}" class="viz" role="img">'
            f'{"".join(out)}</svg>')


def _squarify(values, x, y, w, h, total):
    """Squarified treemap layout — returns a rect per value, in the input order."""
    if not values:
        return []
    scale = (w * h) / total if total else 0
    areas = [v * scale for v in values]
    rects = []

    def worst(row, side):
        if not row or side <= 0:
            return math.inf
        s = sum(row)
        side_sq = side * side
        s_sq = s * s
        return max(side_sq * max(row) / s_sq, s_sq / (side_sq * min(row)))

    def layout(row, x, y, w, h, horizontal):
        s = sum(row)
        if s <= 0:
            return x, y, w, h
        if horizontal:
            row_h = s / w if w else 0
            cx = x
            for a in row:
                cw = a / row_h if row_h else 0
                rects.append((cx, y, cw, row_h))
                cx += cw
            return x, y + row_h, w, h - row_h
        row_w = s / h if h else 0
        cy = y
        for a in row:
            ch = a / row_w if row_w else 0
            rects.append((x, cy, row_w, ch))
            cy += ch
        return x + row_w, y, w - row_w, h

    remaining = list(areas)
    row = []
    while remaining:
        horizontal = w >= h
        side = w if horizontal else h
        if not row or worst(row + [remaining[0]], side) <= worst(row, side):
            row.append(remaining.pop(0))
            continue
        x, y, w, h = layout(row, x, y, w, h, horizontal)
        row = []
    if row:
        layout(row, x, y, w, h, w >= h)
    return rects
