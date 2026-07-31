"""
Shared scan pipeline — called by both the CLI (main.py) and the Azure Function
(function_app.py). A single "run" function: discovery → permission mapping → scoring.
"""
import os

import collectors
import scoring

# Env flags that turn on the Microsoft AI Data Sources connectors (Steps 3-5).
_CONNECTOR_FLAGS = ["ENABLE_AGENT365", "ENABLE_ENTRA_AGENT_ID",
                    "ENABLE_DEFENDER_CLOUD_APPS", "ENABLE_PURVIEW_AUDIT"]


def connectors_enabled() -> bool:
    """If no connector is enabled the framework never runs → zero impact on the existing pipeline."""
    if any(os.environ.get(f, "").lower() == "true" for f in _CONNECTOR_FLAGS):
        return True
    return bool(os.environ.get("PURVIEW_DSPM_IMPORT_PATH"))


def run_connectors(graph) -> dict | None:
    """
    Runs the unified AI+agent connector framework (Steps 1-6) in the live pipeline.
    Returns None if the env flag is off (does NOT affect the existing Entra/Graph scan).
    Resilient: the registry and connectors swallow exceptions; the caller should still
    wrap this in try/except.
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
    """Runs the full scan with the Graph client, returns risk-sorted findings."""
    discovered = collectors.collect_service_principals(graph, tenant_id)
    collectors.enrich_with_oauth_grants(graph, discovered)          # delegated
    collectors.enrich_with_app_role_assignments(graph, discovered)  # application (app-only)
    try:
        collectors.enrich_with_ownership(graph, discovered)        # technical owner + inventory
    except Exception:
        pass
    try:
        collectors.enrich_with_signin_activity(graph, discovered)  # real usage (P1)
    except Exception:
        for a in discovered:                                       # criterion 10: continue uninterrupted
            a.setdefault("usage", None)

    scored = scoring.score_all(discovered)
    try:  # apply persistent business/lifecycle metadata (manual data isn't lost)
        import metadata
        metadata.merge(scored, metadata.load())
    except Exception:
        pass
    try:  # classification (after metadata override + lifecycle)
        import classifier
        classifier.classify_all(scored, tenant_id)
    except Exception:
        pass
    return scored


def summary(scored: list[dict]) -> dict:
    """Summary counters for alert/log/HTTP responses."""
    return {
        "total": len(scored),
        "critical": sum(1 for a in scored if a["risk_level"] == "Critical"),
        "high": sum(1 for a in scored if a["risk_level"] == "High"),
        "medium": sum(1 for a in scored if a["risk_level"] == "Medium"),
        "low": sum(1 for a in scored if a["risk_level"] == "Low"),
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
