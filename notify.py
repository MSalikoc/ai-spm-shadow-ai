"""
Weekly digest email — Microsoft Graph sendMail (via Managed Identity).

Required app settings:
  AISPM_MAIL_SENDER : sender mailbox (UPN/email) — MI sends from this mailbox
  AISPM_MAIL_TO     : recipient(s), comma-separated
  AISPM_REPORT_URL  : (optional) full dashboard endpoint URL (for the button)

The MI needs the Graph 'Mail.Send' application permission. For safety, restrict
it to only AISPM_MAIL_SENDER via an Exchange Application Access Policy.
"""
import base64
import html
import os
from datetime import datetime, timezone

import requests

import auth
import report

LEVEL_COLORS = {"Critical": "#c0392b", "High": "#d35400", "Medium": "#b8860b", "Low": "#2e8b57"}


def _shadow(scored):
    return [a for a in scored if not a.get("first_party_microsoft")]


def _report_url():
    """Dashboard link. Uses AISPM_REPORT_URL as-is if set (may include a function
    key); otherwise derives it from WEBSITE_HOSTNAME."""
    explicit = os.environ.get("AISPM_REPORT_URL")
    if explicit:
        return explicit
    host = os.environ.get("WEBSITE_HOSTNAME")
    return f"https://{host}/api/report" if host else None


def _changes_block(changes):
    if not changes:
        return ('<h3 style="margin:18px 0 8px;font-size:15px">This week</h3>'
                '<p style="font:14px Segoe UI,sans-serif;color:#5f6b7a">'
                'No changes since the previous scan.</p>')
    import drift
    lines = drift.executive_summary(changes)
    items = "".join(f'<li style="margin:4px 0">{html.escape(l)}</li>' for l in lines) \
        or f'<li>{len(changes)} changes recorded.</li>'
    return (f'<h3 style="margin:18px 0 8px;font-size:15px">This week ({len(changes)} changes)</h3>'
            f'<ul style="font:14px Segoe UI,sans-serif;color:#1a1a1a;padding-left:18px">{items}</ul>')


def _digest_html(scored, tenant_id, report_url, changes=None):
    shadow = sorted(_shadow(scored), key=lambda a: a["risk_score"], reverse=True)
    crit = sum(1 for a in shadow if a["risk_level"] == "Critical")
    high = sum(1 for a in shadow if a["risk_level"] == "High")
    notable = [a for a in shadow if a["risk_level"] in ("Critical", "High")][:10]

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
                'color:#2e8b57">No critical/high Shadow AI findings. 👍</td></tr>')

    button = ""
    if report_url:
        button = (
            f'<div style="margin:22px 0"><a href="{html.escape(report_url)}" '
            f'style="background:#0f6cbd;color:#fff;text-decoration:none;padding:11px 22px;'
            f'border-radius:8px;font:600 14px Segoe UI,sans-serif">Open Dashboard →</a></div>')

    return f"""
<div style="max-width:640px;margin:0 auto;font-family:Segoe UI,sans-serif;color:#1a1a1a">
  <h2 style="margin:0 0 4px">AI-SPM · Weekly Shadow AI Digest</h2>
  <div style="color:#5f6b7a;font-size:13px;margin-bottom:16px">Tenant: {html.escape(tenant_id)}</div>
  <table style="border-collapse:collapse;background:#f7f9fb;border-radius:10px;margin-bottom:8px">
    <tr>{stat(len(shadow), "Shadow AI")}{stat(crit, "Critical", "#c0392b")}{stat(high, "High", "#d35400")}</tr>
  </table>
  {_changes_block(changes)}
  {button}
  <h3 style="margin:18px 0 8px;font-size:15px">Apps needing attention</h3>
  <table style="border-collapse:collapse;width:100%">{rows}</table>
  <p style="background:#eef4fb;border-radius:8px;padding:12px 14px;margin:20px 0 0;
     font:13px Segoe UI,sans-serif;color:#0f4c81">
    📎 <b>Full report attached:</b> <code>ai-spm-portal.html</code> — open it in a browser
    to see all findings, reasons, and remediation steps in the interactive dashboard.</p>
  <p style="color:#8b98a6;font-size:12px;margin-top:16px">
    AI-SPM · read-only Entra/Graph scan. This email was generated automatically.</p>
</div>"""


def send_email_digest(scored, tenant_id, changes=None, connectors_result=None):
    sender = os.environ.get("AISPM_MAIL_SENDER")
    to = os.environ.get("AISPM_MAIL_TO")
    if not sender or not to:
        return {"sent": False, "reason": "AISPM_MAIL_SENDER / AISPM_MAIL_TO not set"}

    recipients = [{"emailAddress": {"address": a.strip()}} for a in to.split(",") if a.strip()]
    shadow = _shadow(scored)
    crit = sum(1 for a in shadow if a["risk_level"] == "Critical")
    n_ch = len(changes or [])
    subject = f"[AI-SPM] Weekly digest — {n_ch} changes, {len(shadow)} apps, {crit} critical"

    body = _digest_html(scored, tenant_id, _report_url(), changes)

    # Attach the full dashboard as an HTML attachment (readability)
    # The portal, not the core dashboard: it carries every tab in one file, so tab
    # switching works from the attachment. Its links out to the two standalone pages are
    # suppressed — nothing is attached beside it for them to point at.
    try:
        import portal
        dashboard = portal.html_string(scored, tenant_id, connectors_result,
                                       standalone_links=False)
    except Exception:
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
