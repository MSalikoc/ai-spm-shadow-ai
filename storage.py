"""
Rapor yayınlama. Azure'da Blob Storage'a, lokalde `out/` klasörüne yazar.

Blob için:  AzureWebJobsStorage (connection string)  +  REPORT_CONTAINER (varsayılan aispm-reports)
Her çalıştırma iki kopya yazar:
  - shadow_ai_<UTCzaman>.html/json   (geçmiş / tarihçe)
  - latest.html / latest.json         (dashboard'un okuyacağı sabit isim)
"""
import os
from datetime import datetime, timezone

import report


def publish(scored: list[dict], tenant_id: str) -> dict:
    html = report.html_string(scored, tenant_id)
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
