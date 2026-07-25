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


@app.route(route="scan", auth_level=func.AuthLevel.FUNCTION)
def scan_now(req: func.HttpRequest) -> func.HttpResponse:
    try:
        result, _, _ = _run_scan("http")
        return func.HttpResponse(json.dumps(result, ensure_ascii=False),
                                 mimetype="application/json", status_code=200)
    except Exception as e:
        logging.exception("scan_now hata")
        return func.HttpResponse(json.dumps({"error": str(e)}),
                                 mimetype="application/json", status_code=500)


@app.route(route="digest", auth_level=func.AuthLevel.FUNCTION)
def digest_now(req: func.HttpRequest) -> func.HttpResponse:
    """On-demand: tara + haftalık özet e-postasını hemen gönder (test için)."""
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


@app.route(route="report", auth_level=func.AuthLevel.FUNCTION)
def report_view(req: func.HttpRequest) -> func.HttpResponse:
    """En son dashboard'u canlı HTML olarak sunar (tarayıcıda aç)."""
    doc = storage.read_latest("latest.html")
    if doc is None:
        return func.HttpResponse(
            "Henüz rapor yok. Önce /api/scan çalıştırın.",
            status_code=404, mimetype="text/plain")
    return func.HttpResponse(doc, mimetype="text/html", status_code=200)
