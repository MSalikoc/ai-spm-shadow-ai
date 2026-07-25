"""
Haftalık özet e-postası — Microsoft Graph sendMail (Managed Identity ile).

Gerekli app ayarları:
  AISPM_MAIL_SENDER : gönderen mailbox (UPN/e-posta) — MI bu kutudan gönderir
  AISPM_MAIL_TO     : alıcı(lar), virgülle ayrılmış
  AISPM_REPORT_URL  : (opsiyonel) dashboard endpoint tam URL'i (buton için)

MI'ın Graph 'Mail.Send' application iznine sahip olması gerekir. Güvenlik için
Exchange Application Access Policy ile yalnızca AISPM_MAIL_SENDER kutusuna kısıtla.
"""
import base64
import html
import os
from datetime import datetime, timezone

import requests

import auth
import report

LEVEL_COLORS = {"Kritik": "#c0392b", "Yüksek": "#d35400", "Orta": "#b8860b", "Düşük": "#2e8b57"}


def _shadow(scored):
    return [a for a in scored if not a.get("first_party_microsoft")]


def _report_url():
    """Dashboard için TEMİZ URL — function key İÇERMEZ (Entra ile korunuyor)."""
    explicit = os.environ.get("AISPM_REPORT_URL")
    if explicit:
        return explicit.split("?")[0]  # yanlışlıkla eklenmiş ?code=... varsa at
    host = os.environ.get("WEBSITE_HOSTNAME")
    return f"https://{host}/api/report" if host else None


def _digest_html(scored, tenant_id, report_url):
    shadow = sorted(_shadow(scored), key=lambda a: a["risk_score"], reverse=True)
    crit = sum(1 for a in shadow if a["risk_level"] == "Kritik")
    high = sum(1 for a in shadow if a["risk_level"] == "Yüksek")
    notable = [a for a in shadow if a["risk_level"] in ("Kritik", "Yüksek")][:10]

    def stat(n, label, color="#1a1a1a"):
        return (f'<td style="padding:10px 16px;text-align:center">'
                f'<div style="font:700 26px Segoe UI,sans-serif;color:{color}">{n}</div>'
                f'<div style="font:12px Segoe UI,sans-serif;color:#5f6b7a">{label}</div></td>')

    rows = ""
    for a in notable:
        c = LEVEL_COLORS.get(a["risk_level"], "#555")
        reason = html.escape((a.get("reasons") or [""])[0])
        rows += (
            f'<tr>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #eee">'
            f'<span style="background:{c};color:#fff;border-radius:6px;padding:2px 8px;'
            f'font:700 13px Segoe UI,sans-serif">{a["risk_score"]}</span></td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #eee;font:600 14px Segoe UI,sans-serif">'
            f'{html.escape(a.get("display_name") or "—")}'
            f'<div style="font:12px Segoe UI,sans-serif;color:#5f6b7a">{html.escape(a.get("vendor",""))}</div></td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #eee;font:13px Segoe UI,sans-serif;color:#333">'
            f'{reason}</td></tr>')
    if not rows:
        rows = ('<tr><td colspan="3" style="padding:14px;font:14px Segoe UI,sans-serif;'
                'color:#2e8b57">Kritik/yüksek Shadow AI bulgusu yok. 👍</td></tr>')

    button = ""
    if report_url:
        button = (
            f'<div style="margin:22px 0"><a href="{html.escape(report_url)}" '
            f'style="background:#0f6cbd;color:#fff;text-decoration:none;padding:11px 22px;'
            f'border-radius:8px;font:600 14px Segoe UI,sans-serif">Dashboard\'u aç →</a></div>')

    return f"""
<div style="max-width:640px;margin:0 auto;font-family:Segoe UI,sans-serif;color:#1a1a1a">
  <h2 style="margin:0 0 4px">AI-SPM · Haftalık Shadow AI Özeti</h2>
  <div style="color:#5f6b7a;font-size:13px;margin-bottom:16px">Tenant: {html.escape(tenant_id)}</div>
  <table style="border-collapse:collapse;background:#f7f9fb;border-radius:10px;margin-bottom:8px">
    <tr>{stat(len(shadow), "Shadow AI")}{stat(crit, "Kritik", "#c0392b")}{stat(high, "Yüksek", "#d35400")}</tr>
  </table>
  {button}
  <h3 style="margin:18px 0 8px;font-size:15px">Dikkat gerektiren uygulamalar</h3>
  <table style="border-collapse:collapse;width:100%">{rows}</table>
  <p style="background:#eef4fb;border-radius:8px;padding:12px 14px;margin:20px 0 0;
     font:13px Segoe UI,sans-serif;color:#0f4c81">
    📎 <b>Tam rapor ekte:</b> <code>shadow-ai-report.html</code> — tarayıcıda açarak
    tüm bulguları, gerekçeleri ve öneri adımlarını interaktif dashboard'da görün.</p>
  <p style="color:#8b98a6;font-size:12px;margin-top:16px">
    AI-SPM · read-only Entra/Graph taraması. Bu e-posta otomatik oluşturuldu.</p>
</div>"""


def send_email_digest(scored, tenant_id):
    sender = os.environ.get("AISPM_MAIL_SENDER")
    to = os.environ.get("AISPM_MAIL_TO")
    if not sender or not to:
        return {"sent": False, "reason": "AISPM_MAIL_SENDER / AISPM_MAIL_TO tanımlı değil"}

    recipients = [{"emailAddress": {"address": a.strip()}} for a in to.split(",") if a.strip()]
    shadow = _shadow(scored)
    crit = sum(1 for a in shadow if a["risk_level"] == "Kritik")
    subject = f"[AI-SPM] Haftalık Shadow AI özeti — {len(shadow)} uygulama, {crit} kritik"

    body = _digest_html(scored, tenant_id, _report_url())

    # Tam dashboard'u HTML eki olarak iliştir (okunurluk için)
    dashboard = report.html_string(scored, tenant_id)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    attachment = {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "name": f"shadow-ai-report-{stamp}.html",
        "contentType": "text/html",
        "contentBytes": base64.b64encode(dashboard.encode("utf-8")).decode("ascii"),
    }

    msg = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body},
            "toRecipients": recipients,
            "attachments": [attachment],
        },
        "saveToSentItems": False,
    }
    token = auth.get_token_managed_identity()
    r = requests.post(
        f"https://graph.microsoft.com/v1.0/users/{sender}/sendMail",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=msg, timeout=30)
    if r.status_code in (202, 200):
        return {"sent": True, "to": [x["emailAddress"]["address"] for x in recipients]}
    return {"sent": False, "status": r.status_code, "error": r.text[:300]}
