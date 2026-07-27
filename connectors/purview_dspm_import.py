"""
Purview DSPM import adapter — DSPM Activity Explorer/Reports export'u (JSON/CSV) içe alır (Adım 5).
Doğrudan DSPM analytics extraction API'si olmadığı için desteklenen export dosyası
import edilir. Kaynak açıkça PURVIEW_DSPM_EXPORT olarak işaretlenir. Versioned schema.
Portal HTML scraping YOK. Adım 1'de iskelet.
"""
import os

from .base import BaseCollector, Source

IMPORT_SCHEMA_VERSION = "1.0"


class PurviewDspmImportCollector(BaseCollector):
    name = "purview_dspm_import"
    source = Source.PURVIEW_DSPM_EXPORT

    def __init__(self, import_path=None):
        super().__init__()
        self._import_path = import_path or os.environ.get("PURVIEW_DSPM_IMPORT_PATH")

    def is_configured(self) -> bool:
        return bool(self._import_path)

    def collect(self, since=None) -> list:
        return []          # Adım 5 (JSON/CSV parse)

    def normalize(self, raw_records: list) -> list:
        return []          # Adım 5

    def get_coverage(self) -> dict:
        return {"status": self._status, "schema_version": IMPORT_SCHEMA_VERSION,
                "records": self._count}
