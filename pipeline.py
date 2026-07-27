"""
Ortak tarama boru hattı — hem CLI (main.py) hem Azure Function (function_app.py)
bunu çağırır. Tek bir "run" fonksiyonu: keşif → izin eşleme → skorlama.
"""
import os

import collectors
import scoring

# Microsoft AI Data Sources connector'larını açan env flag'ler (Adım 3-5).
_CONNECTOR_FLAGS = ["ENABLE_AGENT365", "ENABLE_ENTRA_AGENT_ID",
                    "ENABLE_DEFENDER_CLOUD_APPS", "ENABLE_PURVIEW_AUDIT"]


def connectors_enabled() -> bool:
    """Hiçbir connector açık değilse framework hiç çalışmaz → mevcut pipeline'a sıfır etki."""
    if any(os.environ.get(f, "").lower() == "true" for f in _CONNECTOR_FLAGS):
        return True
    return bool(os.environ.get("PURVIEW_DSPM_IMPORT_PATH"))


def run_connectors(graph) -> dict | None:
    """
    Birleşik AI+agent connector framework'ünü (Adım 1-6) canlı pipeline'da çalıştırır.
    Env flag kapalıysa None döner (mevcut Entra/Graph taramasını ETKİLEMEZ). Dayanıklı:
    registry ve connector'lar exception yutar; çağıran ayrıca try/except ile sarmalı.
    """
    if not connectors_enabled():
        return None
    import connectors as C
    result = C.registry.run(C.default_collectors(graph))
    profiles = C.sensitive_data.build_app_profiles(result["assets"])
    result["profiles"] = profiles
    result["portfolio"] = C.sensitive_data.portfolio_summary(profiles)
    return result


def run(graph, tenant_id: str) -> list[dict]:
    """Graph istemcisiyle tam taramayı çalıştırır, risk-sıralı bulguları döner."""
    discovered = collectors.collect_service_principals(graph, tenant_id)
    collectors.enrich_with_oauth_grants(graph, discovered)          # delegated
    collectors.enrich_with_app_role_assignments(graph, discovered)  # application (app-only)
    try:
        collectors.enrich_with_ownership(graph, discovered)        # teknik owner + envanter
    except Exception:
        pass
    try:
        collectors.enrich_with_signin_activity(graph, discovered)  # gerçek kullanım (P1)
    except Exception:
        for a in discovered:                                       # kriter 10: kesintisiz devam
            a.setdefault("usage", None)

    scored = scoring.score_all(discovered)
    try:  # kalıcı business/lifecycle metadata'yı işle (manuel veri kaybolmaz)
        import metadata
        metadata.merge(scored, metadata.load())
    except Exception:
        pass
    try:  # sınıflandırma (metadata override + lifecycle sonrası)
        import classifier
        classifier.classify_all(scored, tenant_id)
    except Exception:
        pass
    return scored


def summary(scored: list[dict]) -> dict:
    """Alarm/log/HTTP yanıtı için özet sayaçlar."""
    return {
        "total": len(scored),
        "critical": sum(1 for a in scored if a["risk_level"] == "Kritik"),
        "high": sum(1 for a in scored if a["risk_level"] == "Yüksek"),
        "medium": sum(1 for a in scored if a["risk_level"] == "Orta"),
        "low": sum(1 for a in scored if a["risk_level"] == "Düşük"),
        "delegated_access": sum(1 for a in scored if a.get("delegated_permissions")),
        "app_only_access": sum(1 for a in scored if a.get("has_app_only_access")),
        "both_access": sum(1 for a in scored
                           if a.get("delegated_permissions") and a.get("has_app_only_access")),
        "activity_available": any((a.get("usage") or {}).get("available") for a in scored),
        "inactive_apps": sum(1 for a in scored if (a.get("usage") or {}).get("inactive_30d")),
        "top": [
            {"name": a["display_name"], "vendor": a["vendor"],
             "score": a["risk_score"], "level": a["risk_level"]}
            for a in scored[:5]
        ],
    }
