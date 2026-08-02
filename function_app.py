"""
AI-SPM Azure Function (Python v2 model).

Two triggers:
  daily_scan  — timer, default every day at 06:00 UTC. Automatic "follow-up assessment".
  scan_now    — HTTP, on-demand scan. A future Security Copilot plugin will hook in here.

Auth: Managed Identity (no secrets). Required app env-var: AISPM_TENANT_ID.
Report: written to Blob Storage (AzureWebJobsStorage + REPORT_CONTAINER).
"""
import json
import logging
import os
import traceback
from datetime import datetime, timezone

import azure.functions as func

import auth
import collectors
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

# CRON: {second} {minute} {hour} {day} {month} {day-of-week}
SCAN_SCHEDULE = os.environ.get("SCAN_SCHEDULE", "0 0 6 * * *")     # every day at 06:00 UTC
EMAIL_SCHEDULE = os.environ.get("EMAIL_SCHEDULE", "0 0 8 * * 1")   # Monday 08:00 UTC


def _run_scan(source: str):
    """
    NOTE: The whole body is wrapped in try/except — an exception (especially from
    `pipeline.run()` itself) could vanish silently inside a queue-trigger/timer-trigger
    without the report ever being written, forcing the user to dig through Portal logs.
    Now every failed attempt's reason is written to `last_error.json`, and /api/report,
    /api/connectors surface it inside the "no report yet" message.
    """
    try:
        tenant_id = os.environ.get("AISPM_TENANT_ID", "")
        if not tenant_id:
            raise RuntimeError("AISPM_TENANT_ID env-var is not set.")

        token = auth.get_token_managed_identity()
        graph = GraphClient(token)

        scored = pipeline.run(graph, tenant_id)
        try:  # drift: diff against the previous snapshot + save (first scan is baseline → empty)
            this_scan_changes = drift.process(scored)
            changes = drift.recent(14)
        except Exception:
            logging.exception("drift error")
            this_scan_changes, changes = [], []
        try:  # manageable finding records (generate + reconcile + persist)
            finding_records = findingsvc.process(scored)
        except Exception:
            logging.exception("findings error")
            finding_records = []
        connectors_result = None
        try:  # connector drift (Step 8) + AI Data Sources dashboard cache (Step 7) — both
              # are no-ops if the flag is off (run_connectors returns None)
            connectors_result = pipeline.run_connectors(graph)
            connectors_drift.process(connectors_result)
            if connectors_result is not None:
                storage.publish_connectors(
                    connectors_report.html_string(connectors_result, tenant_id,
                                                  portal_href="portal"),
                    connectors_report.json_string(connectors_result))
        except Exception:
            logging.exception("connector drift/dashboard error")
        try:  # the unified portal — one estate over both scans, the landing page
            import portal
            storage.publish_portal(
                portal.html_string(scored, tenant_id, connectors_result,
                                   report_href="report", connectors_href="connectors"),
                portal.json_string(scored, connectors_result, tenant_id))
        except Exception:
            logging.exception("portal render error")
        published = storage.publish(scored, tenant_id, changes, finding_records,
                                    (connectors_result or {}).get("health"))
        summ = pipeline.summary(scored)

        logging.info("AI-SPM scan (%s): %s findings, %s critical, %s high, %s changes → %s",
                     source, summ["total"], summ["critical"], summ["high"],
                     len(this_scan_changes), published)
        try:
            storage.write_json("last_error.json", {})   # success → clear the previous error
        except Exception:
            pass
        return ({"summary": summ, "published": published, "tenant": tenant_id},
                scored, tenant_id, connectors_result)
    except Exception as e:
        logging.exception("AI-SPM scan (%s) FAILED", source)
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
        logging.warning("AI-SPM timer is running late.")
    _run_scan("timer")


@app.timer_trigger(schedule=EMAIL_SCHEDULE, arg_name="timer",
                   run_on_startup=False, use_monitor=True)
def weekly_digest(timer: func.TimerRequest) -> None:
    _, scored, tenant_id, connectors_result = _run_scan("weekly")
    weekly_changes = drift.recent(7)
    outcome = notify.send_email_digest(scored, tenant_id, weekly_changes, connectors_result)
    logging.info("AI-SPM weekly digest: %s (%s changes)", outcome, len(weekly_changes))


@app.queue_trigger(arg_name="msg", queue_name=storage.SCAN_QUEUE, connection="AzureWebJobsStorage")
def scan_worker(msg: func.QueueMessage) -> None:
    source = msg.get_body().decode("utf-8") or "queue"
    result = _run_scan(source)
    if source == "digest":  # request queued from digest_now: send the email once the scan finishes
        _, scored, tenant_id, connectors_result = result
        weekly_changes = drift.recent(7)
        outcome = notify.send_email_digest(scored, tenant_id, weekly_changes, connectors_result)
        logging.info("AI-SPM on-demand digest (queue): %s (%s changes)",
                     outcome, len(weekly_changes))


@app.route(route="scan", auth_level=func.AuthLevel.FUNCTION)
def scan_now(req: func.HttpRequest) -> func.HttpResponse:
    """
    Enqueues the scan and returns immediately (on large tenants, the core + 4 connector
    scan can exceed the Consumption plan's fixed ~230s HTTP front-end limit — see
    storage.enqueue_scan). The result shows up in /api/report and /api/connectors within
    a few minutes. Falls back to the old synchronous behavior if the queue isn't
    configured (local/test).
    """
    try:
        if storage.enqueue_scan("http"):
            return func.HttpResponse(json.dumps({
                "status": "queued",
                "message": "Scan queued, running in the background. Check /api/report and "
                           "/api/connectors again in a few minutes.",
            }, ensure_ascii=False), mimetype="application/json", status_code=202)
        result, _, _, _ = _run_scan("http")
        return func.HttpResponse(json.dumps(result, ensure_ascii=False),
                                 mimetype="application/json", status_code=200)
    except Exception as e:
        logging.exception("scan_now error")
        return func.HttpResponse(json.dumps({"error": str(e)}),
                                 mimetype="application/json", status_code=500)


@app.route(route="digest", auth_level=func.AuthLevel.FUNCTION)
def digest_now(req: func.HttpRequest) -> func.HttpResponse:
    """
    On-demand: enqueues the scan, `scan_worker` sends the email once the scan finishes
    (for testing). Moved from sync to queued for the same reason as `/api/scan` — a full
    scan could exceed the Consumption plan's fixed ~230s HTTP limit.
    """
    try:
        if storage.enqueue_scan("digest"):
            return func.HttpResponse(json.dumps({
                "status": "queued",
                "message": "Scan queued; the email will be sent automatically once it "
                           "finishes (may take a few minutes).",
            }, ensure_ascii=False), mimetype="application/json", status_code=202)
        result, scored, tenant_id, connectors_result = _run_scan("digest")
        outcome = notify.send_email_digest(scored, tenant_id, drift.recent(7), connectors_result)
        return func.HttpResponse(
            json.dumps({"digest": outcome, "summary": result["summary"]}, ensure_ascii=False),
            mimetype="application/json", status_code=200)
    except Exception as e:
        logging.exception("digest_now error")
        return func.HttpResponse(json.dumps({"error": str(e)}),
                                 mimetype="application/json", status_code=500)


def _last_scan_error_note() -> str:
    """Returns a readable note if the last `_run_scan` attempt failed (else "").
    Lets you see why a scan failed directly in /api/report and /api/connectors without
    going into the Portal — see `_run_scan`'s `last_error.json` record."""
    err = storage.read_json("last_error.json")
    if not err or not err.get("error"):
        return ""
    return (f"\n\nThe last scan attempt failed — source: {err.get('source')}, "
           f"time: {err.get('timestamp')}\nError: {err.get('error')}")


@app.route(route="report", auth_level=func.AuthLevel.FUNCTION)
def report_view(req: func.HttpRequest) -> func.HttpResponse:
    """Serves the latest dashboard as live HTML (open in a browser)."""
    doc = storage.read_latest("latest.html")
    if doc is None:
        return func.HttpResponse(
            "No report yet. Run /api/scan first." + _last_scan_error_note(),
            status_code=404, mimetype="text/plain")
    return func.HttpResponse(doc, mimetype="text/html", status_code=200)


@app.route(route="connectors", auth_level=func.AuthLevel.FUNCTION)
def connectors_now(req: func.HttpRequest) -> func.HttpResponse:
    """
    Serves the Microsoft AI Data Sources dashboard. First tries the copy pre-computed by
    `_run_scan` and written to Blob (fast path — see `storage.publish_connectors`); if
    not found (scan_worker hasn't run yet / is still queued), falls back to the OLD LIVE
    COMPUTE behavior — this keeps AI Data Sources data visible regardless of whether
    scan_worker has processed its queue messages yet (large tenants still risk exceeding
    the Consumption plan's ~230s HTTP limit, but that's better than showing no data at
    all — making connectors_now depend on scan_worker was a regression found in live
    testing, this fallback fixes it).

    Returns a NOT_CONFIGURED JSON if no ENABLE_* flag is on (the default) — not even a
    Graph call is made. ?format=html returns a standalone HTML page.
    """
    if not pipeline.connectors_enabled():
        return func.HttpResponse(
            json.dumps({"status": "NOT_CONFIGURED",
                       "message": "None of ENABLE_AGENT365/ENABLE_ENTRA_AGENT_ID/"
                                  "ENABLE_DEFENDER_CLOUD_APPS/ENABLE_PURVIEW_AUDIT/"
                                  "PURVIEW_DSPM_IMPORT_PATH is enabled."},
                      ensure_ascii=False),
            mimetype="application/json", status_code=200)
    html_fmt = (req.params.get("format") or "").lower() == "html"
    doc = storage.read_latest("connectors_latest.html" if html_fmt else "connectors_latest.json")
    if doc is not None:
        return func.HttpResponse(doc, mimetype="text/html" if html_fmt else "application/json",
                                 status_code=200)
    try:
        tenant_id = os.environ.get("AISPM_TENANT_ID", "")
        graph = GraphClient(auth.get_token_managed_identity()) if tenant_id else None
        result = pipeline.run_connectors(graph)
        if html_fmt:
            return func.HttpResponse(connectors_report.html_string(result, tenant_id),
                                     mimetype="text/html", status_code=200)
        return func.HttpResponse(connectors_report.json_string(result),
                                 mimetype="application/json", status_code=200)
    except Exception as e:
        logging.exception("connectors_now (live fallback) error")
        return func.HttpResponse(json.dumps({"error": str(e)}, ensure_ascii=False),
                                 mimetype="application/json", status_code=500)


@app.route(route="portal", auth_level=func.AuthLevel.FUNCTION)
def portal_view(req: func.HttpRequest) -> func.HttpResponse:
    """
    The landing page: one AI estate over both scans, with /api/report and
    /api/connectors as its detail views. Pre-computed by _run_scan.
    """
    doc = storage.read_latest("portal_latest.html")
    if doc is None:
        return func.HttpResponse(
            "No portal yet. Run /api/scan first." + _last_scan_error_note(),
            status_code=404, mimetype="text/plain")
    return func.HttpResponse(doc, mimetype="text/html", status_code=200)


@app.route(route="doctor", auth_level=func.AuthLevel.FUNCTION)
def doctor_view(req: func.HttpRequest) -> func.HttpResponse:
    """
    Same preflight the local CLI runs, against the Managed Identity.

    This is how you tell an empty dashboard section apart from a permission that was
    never granted, without reading Portal logs: each source reports readable, denied,
    or not provisioned, plus the permission to grant. ?format=json for the raw rows.
    """
    import preflight
    try:
        tenant_id = os.environ.get("AISPM_TENANT_ID", "")
        if not tenant_id:
            raise RuntimeError("AISPM_TENANT_ID env-var is not set.")
        graph = GraphClient(auth.get_token_managed_identity())
        rows = preflight.run(graph)
    except Exception as e:
        logging.exception("doctor error")
        return func.HttpResponse(json.dumps({"error": str(e)}, ensure_ascii=False),
                                 mimetype="application/json", status_code=500)

    if (req.params.get("format") or "").lower() == "json":
        return func.HttpResponse(
            json.dumps({"tenant": tenant_id, "scan_scope": collectors.scan_scope(),
                        "blocking": [r["key"] for r in preflight.blocking(rows)],
                        "sources": rows}, ensure_ascii=False),
            mimetype="application/json", status_code=200)
    body = (f"Tenant: {tenant_id}\nScan scope: {collectors.scan_scope()}\n"
            + preflight.format_text(rows))
    return func.HttpResponse(body, mimetype="text/plain", status_code=200)


@app.route(route="metadata", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def metadata_set(req: func.HttpRequest) -> func.HttpResponse:
    """
    Updates an app's business/lifecycle metadata (JSON config or the dashboard editor).
    Body: {"app_id": "...", "ownership": {...}, "business_context": {...},
           "lifecycle": {"status": "...", "next_review_date": "..."}, "notes": "..."}
    """
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse('{"error":"invalid JSON"}', status_code=400,
                                 mimetype="application/json")
    app_id = (body or {}).get("app_id")
    if not app_id:
        return func.HttpResponse('{"error":"app_id is required"}', status_code=400,
                                 mimetype="application/json")
    store = metadata.load()
    entry = metadata.set_metadata(store, app_id, body)
    metadata.save(store)
    return func.HttpResponse(json.dumps({"app_id": app_id, "metadata": entry}, ensure_ascii=False),
                             mimetype="application/json", status_code=200)


@app.route(route="finding", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def finding_set(req: func.HttpRequest) -> func.HttpResponse:
    """Updates a finding's lifecycle fields (owner/team/due_date/status/…)."""
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse('{"error":"invalid JSON"}', status_code=400,
                                 mimetype="application/json")
    fid = (body or {}).get("finding_id")
    if not fid:
        return func.HttpResponse('{"error":"finding_id is required"}', status_code=400,
                                 mimetype="application/json")
    store = storage.read_json("findings.json") or {}
    rec = findingsvc.set_finding(store, fid, body)
    if rec is None:
        return func.HttpResponse('{"error":"finding not found"}', status_code=404,
                                 mimetype="application/json")
    storage.write_json("findings.json", store)
    return func.HttpResponse(json.dumps({"finding": rec}, ensure_ascii=False),
                             mimetype="application/json", status_code=200)
