"""
Ortak tarama boru hattı — hem CLI (main.py) hem Azure Function (function_app.py)
bunu çağırır. Tek bir "run" fonksiyonu: keşif → izin eşleme → skorlama.
"""
import collectors
import scoring


def run(graph, tenant_id: str) -> list[dict]:
    """Graph istemcisiyle tam taramayı çalıştırır, risk-sıralı bulguları döner."""
    discovered = collectors.collect_service_principals(graph, tenant_id)
    collectors.enrich_with_oauth_grants(graph, discovered)          # delegated
    collectors.enrich_with_app_role_assignments(graph, discovered)  # application (app-only)
    try:
        collectors.enrich_with_signin_activity(graph, discovered)  # gerçek kullanım (P1)
    except Exception:
        for a in discovered:                                       # kriter 10: kesintisiz devam
            a.setdefault("usage", None)
    return scoring.score_all(discovered)


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
