"""
Rapor yayınlama. Azure'da Blob Storage'a, lokalde `out/` klasörüne yazar.

Blob için:  AzureWebJobsStorage (connection string)  +  REPORT_CONTAINER (varsayılan aispm-reports)
Her çalıştırma iki kopya yazar:
  - shadow_ai_<UTCzaman>.html/json   (geçmiş / tarihçe)
  - latest.html / latest.json         (dashboard'un okuyacağı sabit isim)
"""
import json
import os
from datetime import datetime, timezone

import report


def read_json(name: str):
    """Blob'daki bir JSON dosyasını okur (drift snapshot/changes, metadata). Yoksa None."""
    raw = read_latest(name)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def write_json(name: str, obj) -> None:
    """Bir JSON nesnesini Blob'a (yoksa out/ altına) yazar."""
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
    `SCAN_QUEUE`'ya bir tarama isteği koyar; `scan_worker` (queue-trigger) bunu arka
    planda işler. Consumption planında HTTP-tetikleyicili fonksiyonlar Azure'un kendi
    front-end load balancer'ında sabit ~230s'de kesiliyor (host.json'daki
    functionTimeout bunu etkilemez) — büyük tenant'larda çekirdek + 4 connector taraması
    bunu aşabiliyor. Gerçek işi HTTP isteğinin dışına, queue-trigger'a taşıyarak bu
    limitten kaçıyoruz (queue-trigger'lar bu LB kısıtına tabi değil).

    Connection yoksa (lokal/test ortamı) False döner — çağıran eski senkron davranışa
    düşer (`_run_scan` doğrudan çağrılır), böylece lokal geliştirme/testler etkilenmez.
    """
    conn = os.environ.get("AzureWebJobsStorage") or os.environ.get("REPORT_STORAGE_CONNECTION")
    if not conn or conn.lower().startswith("usedevelopmentstorage"):
        return False
    from azure.storage.queue import QueueClient
    qc = QueueClient.from_connection_string(conn, queue_name=SCAN_QUEUE)
    try:
        qc.create_queue()
    except Exception:
        pass  # zaten var
    qc.send_message(source)
    return True


def publish_connectors(html: str, js: str) -> dict:
    """
    AI Data Sources dashboard'unu (connectors_report) `connectors_latest.html/json`
    olarak yazar — `publish()`'in çekirdek dashboard için yaptığının aynısı.

    `/api/connectors` eskiden bunu her istekte CANLI hesaplıyordu (4 connector'ı Graph'tan
    senkron çekip render ediyordu); büyük/E7 tenant'larda bu, Consumption planının
    HTTP için sabit ~230s front-end limitini aşıp 504/sonsuz yüklenmeye yol açtı (gerçek
    tenant'ta gözlemlendi — bkz. `_run_scan`). Artık `_run_scan` (queue/timer, HTTP
    limitine tabi değil) bu fonksiyonla önceden hesaplayıp burada kaydediyor;
    `/api/connectors` sadece okuyor.
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
            print(f"[!] connectors Blob'a yazılamadı ({e}); lokale yazılıyor.")
    os.makedirs("out", exist_ok=True)
    with open(os.path.join("out", "connectors_latest.html"), "w", encoding="utf-8") as f:
        f.write(html)
    with open(os.path.join("out", "connectors_latest.json"), "w", encoding="utf-8") as f:
        f.write(js)
    return {"target": "local", "dir": "out"}


def read_metadata() -> dict:
    """Kalıcı business/lifecycle metadata deposunu (metadata.json) okur. Yoksa {}."""
    return read_json("metadata.json") or {}


def write_metadata(store: dict) -> None:
    write_json("metadata.json", store)


def read_latest(name: str = "latest.html") -> str | None:
    """Blob'dan (yoksa lokal out/'tan) bir dosyayı okur. write_json ile simetrik."""
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
        except Exception as e:  # blob başarısızsa lokale düş, sessizce kaybetme
            print(f"[!] Blob'a yazılamadı ({e}); lokale yazılıyor.")
    return _publish_local(html, js, stamp)


def _publish_blob(conn: str, html: str, js: str, stamp: str) -> dict:
    from azure.storage.blob import BlobServiceClient, ContentSettings
    container = os.environ.get("REPORT_CONTAINER", "aispm-reports")
    svc = BlobServiceClient.from_connection_string(conn)
    cc = svc.get_container_client(container)
    try:
        cc.create_container()
    except Exception:
        pass  # zaten var

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
