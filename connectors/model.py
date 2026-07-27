"""
Birleşik veri modeli — bütün connector'ların yazdığı ortak asset/entity şeması.

Deterministic asset_id: en güçlü external_id'den türetilir (korelasyon önceliğiyle
aynı sıra); hiçbiri yoksa tip+ad hash'i. Böylece aynı varlık farklı taramalarda ve
farklı kaynaklardan aynı id'yi (veya korele edilebilir id'leri) alır.
"""
import hashlib

# Korelasyon önceliğiyle hizalı external id anahtarları (güçlü → zayıf).
EXTERNAL_ID_KEYS = [
    "entra_app_id", "agent_identity_id", "agent_blueprint_id",
    "agent365_package_id", "agent365_asset_id", "manifest_id",
    "entra_object_id", "mdca_app_id",
]

# Alan-availability durumları (özellikle Purview için — API'de olmayan alan gizlenmez).
AVAILABLE = "AVAILABLE"
NOT_PRESENT = "NOT_PRESENT"
NOT_EXPOSED_BY_API = "NOT_EXPOSED_BY_API"
NOT_LICENSED = "NOT_LICENSED"
UNKNOWN = "UNKNOWN"


def new_external_ids(**kw) -> dict:
    """Tüm external id anahtarlarını içeren (None ile dolu) sözlük döner."""
    return {k: kw.get(k) for k in EXTERNAL_ID_KEYS}


def _provisional_id(asset_type: str, ext: dict, display_name: str) -> str:
    """En güçlü external id'den deterministic iç id üretir; yoksa tip+ad hash'i."""
    for key in EXTERNAL_ID_KEYS:
        if ext.get(key):
            return f"{key}:{ext[key]}"
    seed = f"{asset_type}|{(display_name or '').strip().lower()}"
    return "name:" + hashlib.sha1(seed.encode()).hexdigest()[:16]


def make_asset(asset_type, display_name, source, external_ids=None,
               first_seen=None, last_seen=None, **extra) -> dict:
    """Birleşik asset kaydı üretir (ortak alanlar + connector'a özel `extra`)."""
    ext = new_external_ids(**(external_ids or {}))
    asset = {
        "asset_id": _provisional_id(asset_type, ext, display_name),
        "asset_type": asset_type,
        "display_name": display_name or "—",
        "external_ids": ext,
        "sources": [source],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "correlation_confidence": 100,   # tek kaynak → korelasyon riski yok
    }
    asset.update(extra)
    return asset


def field(status=UNKNOWN, values=None):
    """API'de olmayan/olan alanları availability ile sarmalar."""
    return {"status": status, "values": values if values is not None else []}


def raw_reference(source, **kw) -> dict:
    """Parse edilemeyen ham tanımları kaybetmeden saklamak için."""
    return {"source": source, **kw}
