"""
Purview DSPM import adapter — DSPM/Activity Explorer export'unu (JSON/CSV) içe alır (Adım 5).

Microsoft DSPM analytics için doğrudan bir extraction API'si YOKTUR; bu yüzden desteklenen
bir export dosyası (PURVIEW_DSPM_IMPORT_PATH) import edilir. Kayıtlar birleşik
**SENSITIVE_INTERACTION** modeline yazılır ve kaynak açıkça **PURVIEW_DSPM_EXPORT** olur
(audit'ten ayrı; Adım 6 ikisini app bazında birleştirir).

Versioned schema (IMPORT_SCHEMA_VERSION). Uyumsuz major sürüm → ApiUnavailable (dürüst hata).
Portal HTML scraping YOK.
"""
import csv
import json
import os

from .base import ApiUnavailable, BaseCollector, EntityType, Source
from .model import make_asset, raw_reference

IMPORT_SCHEMA_VERSION = "1.0"


class PurviewDspmImportCollector(BaseCollector):
    name = "purview_dspm_import"
    source = Source.PURVIEW_DSPM_EXPORT

    def __init__(self, import_path=None):
        super().__init__()
        self._import_path = import_path or os.environ.get("PURVIEW_DSPM_IMPORT_PATH")
        self._file_schema = None

    def is_configured(self) -> bool:
        return bool(self._import_path)

    def collect(self, since=None) -> list:
        path = self._import_path
        if not path or not os.path.exists(path):
            raise ApiUnavailable(f"DSPM import dosyası yok: {path}")
        ext = os.path.splitext(path)[1].lower()
        try:
            if ext == ".json":
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self._file_schema = str(data.get("schema_version") or "")
                    rows = data.get("records") or []
                else:
                    rows = data
            elif ext == ".csv":
                with open(path, encoding="utf-8-sig", newline="") as f:
                    rows = list(csv.DictReader(f))
            else:
                raise ApiUnavailable(f"desteklenmeyen format: {ext} (JSON/CSV bekleniyor)")
        except ValueError as e:
            raise ApiUnavailable(f"DSPM import parse hatası: {str(e)[:160]}")

        if self._file_schema and _major(self._file_schema) != _major(IMPORT_SCHEMA_VERSION):
            raise ApiUnavailable(
                f"uyumsuz DSPM export şeması {self._file_schema} "
                f"(desteklenen major {_major(IMPORT_SCHEMA_VERSION)})")
        return rows or []

    def normalize(self, raw_records: list) -> list:
        out = []
        for i, row in enumerate(raw_records):
            out.append(self._normalize_row(row, i))
        return out

    def _normalize_row(self, row: dict, idx: int) -> dict:
        app = _pick(row, "app", "application", "appName", "AppName", "CloudApp")
        user = _pick(row, "user", "upn", "userPrincipalName", "User", "UserId")
        ts = _pick(row, "timestamp", "date", "Date", "activityTime", "CreationTime")
        action = _pick(row, "action", "Action", "dlpAction")
        direction = (_pick(row, "direction", "Direction", "activity", "Activity")
                     or "UNKNOWN_DIRECTION")
        label = _pick(row, "label", "sensitivityLabel", "SensitivityLabel")
        rec_id = _pick(row, "id", "recordId", "RecordId") or f"dspm:{idx}"

        sits = []
        raw_sit = _pick(row, "sit", "sensitiveInfoType", "SensitiveInfoType", "sensitiveInfoTypes")
        if isinstance(raw_sit, list):
            sits = [{"name": s} for s in raw_sit if s]
        elif isinstance(raw_sit, str) and raw_sit:
            sits = [{"name": s.strip()} for s in raw_sit.split(";") if s.strip()]

        asset = make_asset(
            EntityType.SENSITIVE_INTERACTION,
            f"DSPM {action or direction} — {user or 'unknown'}",
            self.source,
            external_ids={"purview_record_id": f"dspm:{rec_id}"},
            first_seen=ts,
            last_seen=ts,
        )
        asset["interaction"] = {
            "interaction_id": f"dspm:{rec_id}",
            "operation": "DspmActivity",
            "user": user,
            "timestamp": ts,
            "app_host": app,
            "app_id": None,
            "sensitivity_label_id": label,
            "sensitive_info_types": sits,
            "referenced_resources": [],
            "dlp_action": action,
            "direction": _norm_direction(direction),
            "import_schema_version": self._file_schema or IMPORT_SCHEMA_VERSION,
            "raw_reference": raw_reference(self.source, record_id=rec_id),
        }
        return asset

    def get_coverage(self) -> dict:
        return {"status": self._status, "schema_version": IMPORT_SCHEMA_VERSION,
                "file_schema": self._file_schema, "records": self._count}


def _major(v):
    return str(v).split(".")[0]


def _pick(row, *keys):
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return None


def _norm_direction(d):
    s = str(d).strip().upper().replace(" ", "_")
    known = {"ACCESSED", "SHARED", "UPLOADED", "GENERATED", "BLOCKED", "ALLOWED"}
    return s if s in known else "UNKNOWN_DIRECTION"
