"""JSON + tek-dosya HTML dashboard (bağımlılıksız, light/dark)."""
import html
import json
import math
from datetime import datetime, timezone

from config import SENSITIVE_SCOPES, SCOPE_HEURISTICS

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
        f'<details class="finding" data-perm="{ptype}">'
        f'<summary>'
        f'<span class="pill" style="background:{color}">{app["risk_score"]}</span>'
        f'<span class="f-name">{html.escape(app.get("display_name") or "—")}'
        f'<span class="f-vendor">{html.escape(app.get("vendor",""))}</span></span>'
        f'<span class="ptype" style="background:{chip_color}">{chip_label}</span>'
        f'<span class="f-meta">{tag} · {html.escape(consent)} · {app.get("user_count",0)} kullanıcı</span>'
        f'<span class="f-level" style="color:{color}">{html.escape(app["risk_level"])}</span>'
        f'</summary>'
        f'<div class="f-body">'
        f'<div class="f-col"><h4>Delegated izinler</h4><code>{scopes}</code>'
        f'{app_block}<p class="f-pub">{ver}</p></div>'
        f'<div class="f-col"><h4>Neden riskli</h4><ul>{reasons}</ul></div>'
        f'<div class="f-col"><h4>Öneri</h4><ul>{remed}</ul></div>'
        f'</div></details>')


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
main{max-width:1120px;margin:0 auto;padding:22px}
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
.kpi.med .n{color:#b8860b}.kpi.low .n{color:#2e8b57}
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
.f-body{display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px;padding:4px 16px 16px;
 border-top:1px solid var(--line)}
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
.foot{color:var(--muted);font-size:12px;text-align:center;padding:18px}
@media(max-width:820px){.cols-4,.cols-2{grid-template-columns:1fr}
 .f-body{grid-template-columns:1fr}.bar-label{width:130px}
 .f-meta,.ptype{display:none}}
"""

THEME_JS = """
(function(){var b=document.getElementById('tg');
b.onclick=function(){var r=document.documentElement;
var d=(r.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light'))==='dark';
r.setAttribute('data-theme',d?'light':'dark');b.textContent=d?'\\u263C':'\\u263E';};
var fb=document.querySelectorAll('.filters button');
fb.forEach(function(btn){btn.onclick=function(){
 fb.forEach(function(x){x.classList.remove('active')});btn.classList.add('active');
 var f=btn.getAttribute('data-filter');
 document.querySelectorAll('.finding').forEach(function(el){
  el.style.display=(f==='all'||el.getAttribute('data-perm')===f
   ||(f==='apponly'&&el.getAttribute('data-perm')==='both'))?'':'none';});};});
})();
"""


def html_string(apps: list[dict], tenant_id: str) -> str:
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

    findings_html = "".join(_finding_row(a) for a in shadow) or \
        '<div class="empty">Shadow AI bulgusu yok.</div>'

    ms_list = "".join(f"<li>{html.escape(a.get('display_name') or '—')}</li>"
                      for a in microsoft)
    ms_section = ""
    if microsoft:
        ms_section = (
            f'<div class="card" style="margin-top:16px"><details class="governed">'
            f'<summary>{len(microsoft)} Microsoft first-party AI uygulaması '
            f'(yönetiliyor — risk sayımına dahil değil)</summary>'
            f'<ul>{ms_list}</ul></details></div>')

    ts = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")

    body = f"""
<header>
  <span class="logo"></span>
  <h1>AI-SPM · Shadow AI Assessment</h1>
  <span class="spacer"></span>
  <span class="tenant">Tenant: {html.escape(tenant_id)}</span>
  <button id="tg" class="themebtn" title="Tema">&#9790;</button>
</header>
<main>
  <div class="grid cols-2" style="align-items:stretch">
    <div class="card">
      <h3>Tenant</h3>
      <div class="tenant-facts">
        <b>Tenant ID</b><span>{html.escape(tenant_id)}</span>
        <b>Toplam AI entegrasyonu</b><span>{len(apps)}</span>
        <b>Shadow AI (3. parti/iç)</b><span>{len(shadow)}</span>
        <b>Microsoft first-party</b><span>{len(microsoft)}</span>
        <b>Tarama zamanı</b><span>{ts}</span>
      </div>
    </div>
    <div class="card">
      <h3>Risk dağılımı</h3>
      <div class="summary">{donut}<div class="legend">{legend}</div></div>
    </div>
  </div>

  <div class="grid cols-4" style="margin-top:16px">
    <div class="card kpi"><span class="n">{len(shadow)}</span><span class="l">Shadow AI uygulaması</span></div>
    <div class="card kpi crit"><span class="n">{counts['Kritik']}</span><span class="l">Kritik</span></div>
    <div class="card kpi high"><span class="n">{counts['Yüksek']}</span><span class="l">Yüksek</span></div>
    <div class="card kpi med"><span class="n">{counts['Orta']}</span><span class="l">Orta</span></div>
  </div>

  <div class="grid cols-2" style="margin-top:16px">
    <div class="card"><h3>En riskli uygulamalar</h3>{top_bars}</div>
    <div class="card"><h3>En çok verilen hassas izinler</h3>{scope_bars}</div>
  </div>

  <div class="grid cols-4" style="margin-top:16px">
    <div class="card kpi"><span class="n">{admin}</span><span class="l">Admin (tüm org) onayı</span></div>
    <div class="card kpi"><span class="n">{third}</span><span class="l">Dış 3. parti</span></div>
    <div class="card kpi"><span class="n">{persist}</span><span class="l">Kalıcı erişim (offline)</span></div>
    <div class="card kpi"><span class="n">{unverified}</span><span class="l">Doğrulanmamış publisher</span></div>
  </div>

  <h3 style="margin:22px 4px 10px;font-size:13px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)">Erişim tipi</h3>
  <div class="grid cols-4">
    <div class="card kpi"><span class="n">{delegated_n}</span><span class="l">Delegated erişim</span></div>
    <div class="card kpi high"><span class="n">{apponly_n}</span><span class="l">App-only erişim (kullanıcısız)</span></div>
    <div class="card kpi"><span class="n">{both_n}</span><span class="l">Her iki erişim tipi</span></div>
    <div class="card kpi crit"><span class="n">{highpriv_apponly}</span><span class="l">Yüksek ayrıcalıklı app-only</span></div>
  </div>

  <div class="card" style="margin-top:16px">
    <h3>Bulgular ({len(shadow)})</h3>
    <div class="filters">
      <button data-filter="all" class="active">Tümü</button>
      <button data-filter="delegated">Delegated</button>
      <button data-filter="apponly">App-only</button>
      <button data-filter="both">Her ikisi</button>
    </div>
    <div class="findings">{findings_html}</div>
  </div>
  {ms_section}
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
