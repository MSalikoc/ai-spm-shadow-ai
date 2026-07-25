"""
AI-SPM Azure Function (Python v2 modeli).

İki tetikleyici:
  daily_scan  — timer, varsayılan her gün 06:00 UTC. Otomatik "takip eden assessment".
  scan_now    — HTTP, on-demand tarama. İleride Security Copilot plugin'i buraya bağlanacak.

Kimlik: Managed Identity (secret yok). Gerekli app env-var: AISPM_TENANT_ID.
Rapor: Blob Storage'a (AzureWebJobsStorage + REPORT_CONTAINER).
"""
import json
import logging
import os

import azure.functions as func

import auth
import authz
import notify
import pipeline
import storage
from graph_client import GraphClient

app = func.FunctionApp()

# CRON: {saniye} {dakika} {saat} {gün} {ay} {haftagünü}
SCAN_SCHEDULE = os.environ.get("SCAN_SCHEDULE", "0 0 6 * * *")     # her gün 06:00 UTC
EMAIL_SCHEDULE = os.environ.get("EMAIL_SCHEDULE", "0 0 8 * * 1")   # Pazartesi 08:00 UTC


def _run_scan(source: str):
    tenant_id = os.environ.get("AISPM_TENANT_ID", "")
    if not tenant_id:
        raise RuntimeError("AISPM_TENANT_ID env-var tanımlı değil.")

    token = auth.get_token_managed_identity()
    graph = GraphClient(token)

    scored = pipeline.run(graph, tenant_id)
    published = storage.publish(scored, tenant_id)
    summ = pipeline.summary(scored)

    logging.info("AI-SPM scan (%s): %s bulgu, %s kritik, %s yüksek → %s",
                 source, summ["total"], summ["critical"], summ["high"], published)
    return {"summary": summ, "published": published, "tenant": tenant_id}, scored, tenant_id


@app.timer_trigger(schedule=SCAN_SCHEDULE, arg_name="timer",
                   run_on_startup=False, use_monitor=True)
def daily_scan(timer: func.TimerRequest) -> None:
    if timer.past_due:
        logging.warning("AI-SPM timer gecikmeli çalışıyor.")
    _run_scan("timer")


@app.timer_trigger(schedule=EMAIL_SCHEDULE, arg_name="timer",
                   run_on_startup=False, use_monitor=True)
def weekly_digest(timer: func.TimerRequest) -> None:
    _, scored, tenant_id = _run_scan("weekly")
    outcome = notify.send_email_digest(scored, tenant_id)
    logging.info("AI-SPM haftalık digest: %s", outcome)


def _deny(status: int, message: str) -> func.HttpResponse:
    return func.HttpResponse(json.dumps({"error": message, "status": status},
                                        ensure_ascii=False),
                             status_code=status, mimetype="application/json")


def _guard(req: func.HttpRequest, allowed_roles: set) -> func.HttpResponse | None:
    """Yetkiliyse None, değilse 401/403 yanıtı döner."""
    res = authz.authorize(req.headers, allowed_roles)
    if res is None:
        return None
    return _deny(res[0], res[1])


@app.route(route="scan", auth_level=func.AuthLevel.ANONYMOUS)
def scan_now(req: func.HttpRequest) -> func.HttpResponse:
    denied = _guard(req, {authz.ROLE_ASSESSMENT})
    if denied:
        return denied
    try:
        result, _, _ = _run_scan("http")
        return func.HttpResponse(json.dumps(result, ensure_ascii=False),
                                 mimetype="application/json", status_code=200)
    except Exception as e:
        logging.exception("scan_now hata")
        return func.HttpResponse(json.dumps({"error": str(e)}),
                                 mimetype="application/json", status_code=500)


@app.route(route="digest", auth_level=func.AuthLevel.ANONYMOUS)
def digest_now(req: func.HttpRequest) -> func.HttpResponse:
    """On-demand: tara + haftalık özet e-postasını hemen gönder."""
    denied = _guard(req, {authz.ROLE_NOTIFICATION})
    if denied:
        return denied
    try:
        result, scored, tenant_id = _run_scan("digest")
        outcome = notify.send_email_digest(scored, tenant_id)
        return func.HttpResponse(
            json.dumps({"digest": outcome, "summary": result["summary"]}, ensure_ascii=False),
            mimetype="application/json", status_code=200)
    except Exception as e:
        logging.exception("digest_now hata")
        return func.HttpResponse(json.dumps({"error": str(e)}),
                                 mimetype="application/json", status_code=500)


@app.route(route="report", auth_level=func.AuthLevel.ANONYMOUS)
def report_view(req: func.HttpRequest) -> func.HttpResponse:
    """En son dashboard'u canlı HTML olarak sunar (tarayıcıda aç)."""
    res = authz.authorize(req.headers, {authz.ROLE_READER})
    if res is not None:
        status, message = res
        if status == 401:
            # Tarayıcı kullanıcısına Entra login linki göster
            login = "/.auth/login/aad?post_login_redirect_uri=/api/report"
            return func.HttpResponse(
                f'<html><body style="font-family:Segoe UI,sans-serif;padding:48px;text-align:center">'
                f'<h2>Oturum gerekli</h2><p>{message}</p>'
                f'<p><a href="{login}" style="background:#0f6cbd;color:#fff;padding:10px 20px;'
                f'border-radius:8px;text-decoration:none">Entra ile giriş yap →</a></p></body></html>',
                status_code=401, mimetype="text/html")
        return _deny(status, message)
    doc = storage.read_latest("latest.html")
    if doc is None:
        return func.HttpResponse(
            "Henüz rapor yok. Önce /api/scan çalıştırın.",
            status_code=404, mimetype="text/plain")
    return func.HttpResponse(doc, mimetype="text/html", status_code=200)
