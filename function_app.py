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
import traceback
from datetime import datetime, timezone

import azure.functions as func

import auth
import connectors_drift
import connectors_report
import drift
import findings as findingsvc
import metadata
import notify
import pipeline
import storage
from graph_client import GraphClient

app = func.FunctionApp()

# CRON: {saniye} {dakika} {saat} {gün} {ay} {haftagünü}
SCAN_SCHEDULE = os.environ.get("SCAN_SCHEDULE", "0 0 6 * * *")     # her gün 06:00 UTC
EMAIL_SCHEDULE = os.environ.get("EMAIL_SCHEDULE", "0 0 8 * * 1")   # Pazartesi 08:00 UTC


def _run_scan(source: str):
    """
    NOT: Tüm gövde try/except ile sarılı — bir istisna (özellikle `pipeline.run()`'ın
    kendisinden) queue-trigger/timer-trigger içinde sessizce kaybolup rapor hiç
    yazılmadan bitebiliyordu; kullanıcı Portal'da log aramak zorunda kalıyordu. Artık
    her başarısız denemenin sebebi `last_error.json`'a yazılıyor ve /api/report,
    /api/connectors bunu "henüz rapor yok" mesajının içinde gösteriyor.
    """
    try:
        tenant_id = os.environ.get("AISPM_TENANT_ID", "")
        if not tenant_id:
            raise RuntimeError("AISPM_TENANT_ID env-var tanımlı değil.")

        token = auth.get_token_managed_identity()
        graph = GraphClient(token)

        scored = pipeline.run(graph, tenant_id)
        try:  # drift: önceki snapshot ile diff + kaydet (ilk scan baseline → boş)
            this_scan_changes = drift.process(scored)
            changes = drift.recent(14)
        except Exception:
            logging.exception("drift hata")
            this_scan_changes, changes = [], []
        try:  # yönetilebilir finding kayıtları (üret + uzlaştır + kalıcılaştır)
            finding_records = findingsvc.process(scored)
        except Exception:
            logging.exception("findings hata")
            finding_records = []
        try:  # connector drift (Adım 8) + AI Data Sources dashboard cache (Adım 7) — flag
              # kapalıysa run_connectors None döner, ikisi de no-op
            connectors_result = pipeline.run_connectors(graph)
            connectors_drift.process(connectors_result)
            if connectors_result is not None:
                storage.publish_connectors(
                    connectors_report.html_string(connectors_result, tenant_id),
                    connectors_report.json_string(connectors_result))
        except Exception:
            logging.exception("connector drift/dashboard hata")
        published = storage.publish(scored, tenant_id, changes, finding_records)
        summ = pipeline.summary(scored)

        logging.info("AI-SPM scan (%s): %s bulgu, %s kritik, %s yüksek, %s değişiklik → %s",
                     source, summ["total"], summ["critical"], summ["high"],
                     len(this_scan_changes), published)
        try:
            storage.write_json("last_error.json", {})   # başarılı → önceki hatayı temizle
        except Exception:
            pass
        return {"summary": summ, "published": published, "tenant": tenant_id}, scored, tenant_id
    except Exception as e:
        logging.exception("AI-SPM scan (%s) BAŞARISIZ", source)
        try:
            storage.write_json("last_error.json", {
                "source": source, "error": str(e)[:500],
                "traceback": traceback.format_exc()[-3000:],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            pass
        raise


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
    weekly_changes = drift.recent(7)
    outcome = notify.send_email_digest(scored, tenant_id, weekly_changes)
    logging.info("AI-SPM haftalık digest: %s (%s değişiklik)", outcome, len(weekly_changes))


@app.queue_trigger(arg_name="msg", queue_name=storage.SCAN_QUEUE, connection="AzureWebJobsStorage")
def scan_worker(msg: func.QueueMessage) -> None:
    source = msg.get_body().decode("utf-8") or "queue"
    _run_scan(source)


@app.route(route="scan", auth_level=func.AuthLevel.FUNCTION)
def scan_now(req: func.HttpRequest) -> func.HttpResponse:
    """
    Taramayı kuyruğa koyar ve hemen döner (büyük tenant'larda çekirdek + 4 connector
    taraması, Consumption planının HTTP için sabit ~230s front-end limitini aşabiliyor —
    bkz. storage.enqueue_scan). Sonuç birkaç dakika içinde /api/report ve
    /api/connectors'ta görünür. Kuyruk yapılandırılmamışsa (lokal/test) eski senkron
    davranışa düşer.
    """
    try:
        if storage.enqueue_scan("http"):
            return func.HttpResponse(json.dumps({
                "status": "queued",
                "message": "Tarama kuyruğa alındı, arka planda çalışıyor. Birkaç dakika "
                           "sonra /api/report ve /api/connectors sayfalarını kontrol edin.",
            }, ensure_ascii=False), mimetype="application/json", status_code=202)
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
        outcome = notify.send_email_digest(scored, tenant_id, drift.recent(7))
        return func.HttpResponse(
            json.dumps({"digest": outcome, "summary": result["summary"]}, ensure_ascii=False),
            mimetype="application/json", status_code=200)
    except Exception as e:
        logging.exception("digest_now hata")
        return func.HttpResponse(json.dumps({"error": str(e)}),
                                 mimetype="application/json", status_code=500)


def _last_scan_error_note() -> str:
    """Son `_run_scan` denemesi başarısız olduysa okunabilir bir not döner (yoksa "").
    Portal'a girmeden, doğrudan /api/report ve /api/connectors'ta neden başarısız
    olduğunu görebilmek için — bkz. `_run_scan`'in `last_error.json` kaydı."""
    err = storage.read_json("last_error.json")
    if not err or not err.get("error"):
        return ""
    return (f"\n\nSon tarama denemesi başarısız oldu — kaynak: {err.get('source')}, "
           f"zaman: {err.get('timestamp')}\nHata: {err.get('error')}")


@app.route(route="report", auth_level=func.AuthLevel.FUNCTION)
def report_view(req: func.HttpRequest) -> func.HttpResponse:
    """En son dashboard'u canlı HTML olarak sunar (tarayıcıda aç)."""
    doc = storage.read_latest("latest.html")
    if doc is None:
        return func.HttpResponse(
            "Henüz rapor yok. Önce /api/scan çalıştırın." + _last_scan_error_note(),
            status_code=404, mimetype="text/plain")
    return func.HttpResponse(doc, mimetype="text/html", status_code=200)


@app.route(route="connectors", auth_level=func.AuthLevel.FUNCTION)
def connectors_now(req: func.HttpRequest) -> func.HttpResponse:
    """
    Microsoft AI Data Sources dashboard'unu sunar (en son tarama sırasında `_run_scan`
    tarafından önceden hesaplanıp Blob'a yazılan kopyayı okur). Read-only.

    Eskiden 4 connector'ı (Agent 365, Entra Agent ID, Defender for Cloud Apps, Purview)
    her istekte CANLI çalıştırıyordu — büyük/E7 tenant'larda bu, Consumption planının
    HTTP için sabit ~230s front-end limitini aşıp 504/sonsuz yüklenmeye yol açtı (gerçek
    tenant'ta gözlemlendi). `/api/report` ile aynı "önceden hesapla + oku" desenine
    geçirildi — bkz. `storage.publish_connectors`.

    Hiçbir ENABLE_* flag'i açık değilse (varsayılan) NOT_CONFIGURED JSON'u döner —
    Blob okuması bile yapılmaz. ?format=html ile standalone HTML sayfası döner.
    """
    if not pipeline.connectors_enabled():
        return func.HttpResponse(
            json.dumps({"status": "NOT_CONFIGURED",
                       "message": "Hiçbir ENABLE_AGENT365/ENABLE_ENTRA_AGENT_ID/"
                                  "ENABLE_DEFENDER_CLOUD_APPS/ENABLE_PURVIEW_AUDIT/"
                                  "PURVIEW_DSPM_IMPORT_PATH flag'i açık değil."},
                      ensure_ascii=False),
            mimetype="application/json", status_code=200)
    html_fmt = (req.params.get("format") or "").lower() == "html"
    doc = storage.read_latest("connectors_latest.html" if html_fmt else "connectors_latest.json")
    if doc is None:
        msg = ("Henüz AI Data Sources raporu yok. Önce /api/scan çalıştırın (birkaç dakika sürebilir)."
              + _last_scan_error_note())
        if html_fmt:
            return func.HttpResponse(msg, status_code=404, mimetype="text/plain")
        return func.HttpResponse(json.dumps({"status": "NO_DATA", "message": msg}, ensure_ascii=False),
                                 mimetype="application/json", status_code=404)
    return func.HttpResponse(doc, mimetype="text/html" if html_fmt else "application/json",
                             status_code=200)


@app.route(route="metadata", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def metadata_set(req: func.HttpRequest) -> func.HttpResponse:
    """
    Bir app'in business/lifecycle metadata'sını günceller (JSON config veya dashboard editör).
    Body: {"app_id": "...", "ownership": {...}, "business_context": {...},
           "lifecycle": {"status": "...", "next_review_date": "..."}, "notes": "..."}
    """
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse('{"error":"geçersiz JSON"}', status_code=400,
                                 mimetype="application/json")
    app_id = (body or {}).get("app_id")
    if not app_id:
        return func.HttpResponse('{"error":"app_id gerekli"}', status_code=400,
                                 mimetype="application/json")
    store = metadata.load()
    entry = metadata.set_metadata(store, app_id, body)
    metadata.save(store)
    return func.HttpResponse(json.dumps({"app_id": app_id, "metadata": entry}, ensure_ascii=False),
                             mimetype="application/json", status_code=200)


@app.route(route="finding", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def finding_set(req: func.HttpRequest) -> func.HttpResponse:
    """Bir finding'in lifecycle alanlarını günceller (owner/team/due_date/status/…)."""
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse('{"error":"geçersiz JSON"}', status_code=400,
                                 mimetype="application/json")
    fid = (body or {}).get("finding_id")
    if not fid:
        return func.HttpResponse('{"error":"finding_id gerekli"}', status_code=400,
                                 mimetype="application/json")
    store = storage.read_json("findings.json") or {}
    rec = findingsvc.set_finding(store, fid, body)
    if rec is None:
        return func.HttpResponse('{"error":"finding bulunamadı"}', status_code=404,
                                 mimetype="application/json")
    storage.write_json("findings.json", store)
    return func.HttpResponse(json.dumps({"finding": rec}, ensure_ascii=False),
                             mimetype="application/json", status_code=200)
