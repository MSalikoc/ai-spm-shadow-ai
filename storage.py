"""
Report publishing. Writes to Blob Storage on Azure, to the `out/` folder locally.

For Blob:  AzureWebJobsStorage (connection string)  +  REPORT_CONTAINER (default aispm-reports)
Every run writes two copies:
  - shadow_ai_<UTCtimestamp>.html/json   (history / archive)
  - latest.html / latest.json             (fixed name the dashboard reads)
"""
import json
import os
from datetime import datetime, timezone

import report


def read_json(name: str):
    """Reads a JSON file from Blob (drift snapshot/changes, metadata). None if missing."""
    raw = read_latest(name)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def write_json(name: str, obj) -> None:
    """Writes a JSON object to Blob (or under out/ if unavailable)."""
    payload = json.dumps(obj, ensure_ascii=False, indent=2)
    conn = os.environ.get("AzureWebJobsStorage") or os.environ.get("REPORT_STORAGE_CONNECTION")
    if not conn or conn.lower().startswith("usedevelopmentstorage"):
        os.makedirs("out", exist_ok=True)
        with open(os.path.join("out", name), "w", encoding="utf-8") as f:
            f.write(payload)
        return
    from azure.storage.blob import BlobServiceClient, ContentSettings
    container = os.environ.get("REPORT_CONTAINER", "aispm-reports")
    cc = BlobServiceClient.from_connection_string(conn).get_container_client(container)
    try:
        cc.create_container()
    except Exception:
        pass
    cc.upload_blob(name, payload.encode("utf-8"), overwrite=True,
                   content_settings=ContentSettings(content_type="application/json"))


SCAN_QUEUE = "aispm-scan-queue"


def enqueue_scan(source: str) -> bool:
    """
    Puts a scan request onto `SCAN_QUEUE`; `scan_worker` (queue-trigger) processes it in
    the background. On the Consumption plan, HTTP-triggered functions get cut off by
    Azure's own front-end load balancer at a fixed ~230s (host.json's functionTimeout
    doesn't affect this) — on large tenants the core + 4 connector scan can exceed that.
    Moving the real work out of the HTTP request into a queue-trigger sidesteps this
    limit (queue-triggers aren't subject to that LB constraint).

    Returns False if there's no connection (local/test environment) — the caller then
    falls back to the old synchronous behavior (`_run_scan` is called directly), so local
    development/tests are unaffected.
    """
    conn = os.environ.get("AzureWebJobsStorage") or os.environ.get("REPORT_STORAGE_CONNECTION")
    if not conn or conn.lower().startswith("usedevelopmentstorage"):
        return False
    from azure.storage.queue import QueueClient
    qc = QueueClient.from_connection_string(conn, queue_name=SCAN_QUEUE)
    try:
        qc.create_queue()
    except Exception:
        pass  # already exists
    qc.send_message(source)
    return True


def publish_connectors(html: str, js: str) -> dict:
    """
    Writes the AI Data Sources dashboard (connectors_report) as
    `connectors_latest.html/json` — same as what `publish()` does for the core dashboard.

    `/api/connectors` used to compute this LIVE on every request (synchronously pulling
    all 4 connectors from Graph and rendering); on large/E7 tenants this could exceed the
    Consumption plan's fixed ~230s HTTP front-end limit, causing 504s/infinite loading
    (observed on a real tenant — see `_run_scan`). Now `_run_scan` (queue/timer, not
    subject to the HTTP limit) pre-computes and saves it via this function;
    `/api/connectors` just reads it.
    """
    conn = os.environ.get("AzureWebJobsStorage") or os.environ.get("REPORT_STORAGE_CONNECTION")
    if conn and not conn.lower().startswith("usedevelopmentstorage"):
        try:
            from azure.storage.blob import BlobServiceClient, ContentSettings
            container = os.environ.get("REPORT_CONTAINER", "aispm-reports")
            cc = BlobServiceClient.from_connection_string(conn).get_container_client(container)
            try:
                cc.create_container()
            except Exception:
                pass
            cc.upload_blob("connectors_latest.html", html.encode("utf-8"), overwrite=True,
                           content_settings=ContentSettings(content_type="text/html"))
            cc.upload_blob("connectors_latest.json", js.encode("utf-8"), overwrite=True,
                           content_settings=ContentSettings(content_type="application/json"))
            return {"target": "blob", "container": container}
        except Exception as e:
            print(f"[!] Could not write connectors to Blob ({e}); writing locally.")
    os.makedirs("out", exist_ok=True)
    with open(os.path.join("out", "connectors_latest.html"), "w", encoding="utf-8") as f:
        f.write(html)
    with open(os.path.join("out", "connectors_latest.json"), "w", encoding="utf-8") as f:
        f.write(js)
    return {"target": "local", "dir": "out"}


def read_metadata() -> dict:
    """Reads the persistent business/lifecycle metadata store (metadata.json). {} if missing."""
    return read_json("metadata.json") or {}


def write_metadata(store: dict) -> None:
    write_json("metadata.json", store)


def read_latest(name: str = "latest.html") -> str | None:
    """Reads a file from Blob (or local out/ if unavailable). Symmetric with write_json."""
    conn = os.environ.get("AzureWebJobsStorage") or os.environ.get("REPORT_STORAGE_CONNECTION")
    if not conn or conn.lower().startswith("usedevelopmentstorage"):
        path = os.path.join("out", name)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return f.read()
        return None
    try:
        from azure.storage.blob import BlobServiceClient
        container = os.environ.get("REPORT_CONTAINER", "aispm-reports")
        svc = BlobServiceClient.from_connection_string(conn)
        bc = svc.get_blob_client(container, name)
        return bc.download_blob().readall().decode("utf-8")
    except Exception:
        return None


def publish(scored: list[dict], tenant_id: str, changes=None, findings=None) -> dict:
    html = report.html_string(scored, tenant_id, changes, findings)
    js = report.json_string(scored)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    conn = os.environ.get("AzureWebJobsStorage") or os.environ.get("REPORT_STORAGE_CONNECTION")
    if conn and not conn.lower().startswith("usedevelopmentstorage"):
        try:
            return _publish_blob(conn, html, js, stamp)
        except Exception as e:  # fall back to local on Blob failure, don't silently lose it
            print(f"[!] Could not write to Blob ({e}); writing locally.")
    return _publish_local(html, js, stamp)


def _publish_blob(conn: str, html: str, js: str, stamp: str) -> dict:
    from azure.storage.blob import BlobServiceClient, ContentSettings
    container = os.environ.get("REPORT_CONTAINER", "aispm-reports")
    svc = BlobServiceClient.from_connection_string(conn)
    cc = svc.get_container_client(container)
    try:
        cc.create_container()
    except Exception:
        pass  # already exists

    def up(name, data, ctype):
        cc.upload_blob(name, data.encode("utf-8"), overwrite=True,
                       content_settings=ContentSettings(content_type=ctype))

    up(f"shadow_ai_{stamp}.html", html, "text/html")
    up(f"shadow_ai_{stamp}.json", js, "application/json")
    up("latest.html", html, "text/html")
    up("latest.json", js, "application/json")
    return {"target": "blob", "container": container, "stamp": stamp}


def _publish_local(html: str, js: str, stamp: str) -> dict:
    os.makedirs("out", exist_ok=True)
    for name, data in [("shadow_ai.html", html), ("shadow_ai.json", js),
                       (f"shadow_ai_{stamp}.html", html)]:
        with open(os.path.join("out", name), "w", encoding="utf-8") as f:
            f.write(data)
    return {"target": "local", "dir": "out", "stamp": stamp}
