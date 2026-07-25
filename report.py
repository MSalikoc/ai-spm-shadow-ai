"""JSON + tek-dosya HTML rapor üretimi (bağımlılıksız)."""
import html
import json
from datetime import datetime, timezone

_LEVEL_COLOR = {"Kritik": "#b91c1c", "Yüksek": "#c2410c", "Orta": "#a16207", "Düşük": "#15803d"}


def json_string(apps: list[dict]) -> str:
    return json.dumps(
        {"generated": datetime.now(timezone.utc).isoformat(), "findings": apps},
        ensure_ascii=False, indent=2)


def write_json(apps: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(json_string(apps))


def _row(app: dict) -> str:
    color = _LEVEL_COLOR.get(app["risk_level"], "#334155")
    scopes = ", ".join(html.escape(s) for s in app["scopes"]) or "—"
    reasons = "".join(f"<li>{html.escape(r)}</li>" for r in app["reasons"])
    remed = "".join(f"<li>{html.escape(r)}</li>" for r in app["remediation"])
    return f"""
    <tr>
      <td><span class="pill" style="background:{color}">{app['risk_score']} · {html.escape(app['risk_level'])}</span></td>
      <td><b>{html.escape(app['display_name'] or '—')}</b><br><small>{html.escape(app['vendor'])}</small></td>
      <td>{html.escape(app['publisher'])}{' ✓' if app['verified_publisher'] else ' ⚠'}<br>
          <small>{'3. parti' if app['third_party'] else 'iç/first-party'} · {app['consent_type'] or 'consent yok'} · {app['user_count']} kullanıcı</small></td>
      <td><small>{scopes}</small></td>
      <td><ul>{reasons}</ul></td>
      <td><ul>{remed}</ul></td>
    </tr>"""


def html_string(apps: list[dict], tenant_id: str) -> str:
    total = len(apps)
    crit = sum(1 for a in apps if a["risk_level"] == "Kritik")
    high = sum(1 for a in apps if a["risk_level"] == "Yüksek")
    rows = "".join(_row(a) for a in apps) or '<tr><td colspan="6">Shadow AI bulgusu yok.</td></tr>'
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc = f"""<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI-SPM · Shadow AI Envanteri</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}}
 header{{padding:24px 28px;background:#111827;border-bottom:1px solid #1f2937}}
 h1{{margin:0 0 4px;font-size:20px}} .sub{{color:#94a3b8;font-size:13px}}
 .cards{{display:flex;gap:14px;padding:18px 28px;flex-wrap:wrap}}
 .card{{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:14px 18px;min-width:130px}}
 .card b{{font-size:26px;display:block}}
 table{{width:100%;border-collapse:collapse;margin:8px 0 40px}}
 th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #1f2937;vertical-align:top}}
 th{{position:sticky;top:0;background:#0b1220;font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:#94a3b8}}
 ul{{margin:0;padding-left:16px}} small{{color:#94a3b8}}
 .pill{{color:#fff;padding:3px 9px;border-radius:999px;font-weight:600;white-space:nowrap;font-size:12px}}
 .wrap{{padding:0 28px}}
</style></head><body>
<header>
  <h1>AI-SPM · Shadow AI Envanteri</h1>
  <div class="sub">Tenant: {html.escape(tenant_id)} · Üretim: {ts} · Read-only Entra/Graph taraması</div>
</header>
<div class="cards">
  <div class="card"><b>{total}</b>AI entegrasyonu</div>
  <div class="card" style="border-color:#7f1d1d"><b style="color:#f87171">{crit}</b>Kritik</div>
  <div class="card" style="border-color:#7c2d12"><b style="color:#fb923c">{high}</b>Yüksek</div>
</div>
<div class="wrap">
<table>
 <thead><tr><th>Risk</th><th>Uygulama</th><th>Publisher / Kapsam</th><th>Verilen izinler</th><th>Gerekçe</th><th>Öneri</th></tr></thead>
 <tbody>{rows}</tbody>
</table>
</div>
</body></html>"""
    return doc


def write_html(apps: list[dict], path: str, tenant_id: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_string(apps, tenant_id))
