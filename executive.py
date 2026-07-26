"""
Executive katmanı — AI estate özetini, yönetici narrative'lerini ve coverage'ı üretir.

DÜRÜSTLÜK NOTU: Uygulama & (isim-sinyalli) agent verisi Entra/Graph'tan gerçek gelir.
Local AI agent (cihaz), MCP server, AI model ve Purview görünürlüğü ayrı CONNECTOR
gerektirir; bağlı olmadıkları sürece sayıları 0'dır ve Coverage bunu açıkça gösterir
(uydurma envanter YOK).
"""
from datetime import datetime, timezone

# Veri kaynağı / connector durumu. Bağlı olmayanlar coverage boşluğu üretir.
CONNECTORS = [
    ("Entra ID / Microsoft Graph", True, "AI uygulama & OAuth consent keşfi"),
    ("Microsoft Purview", False, "Hassas veri görünürlüğü (DSPM)"),
    ("Defender for Endpoint / Intune", False, "Local AI agent & cihaz keşfi"),
    ("Azure AI Foundry", False, "AI model envanteri"),
    ("MCP server envanteri", False, "MCP server keşfi"),
]

_IMP_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _pct(part, whole):
    return round(100 * part / whole) if whole else 0


def _has_owner(a):
    return bool((a.get("ownership") or {}).get("business_owner"))


def _agents(apps):
    return [a for a in apps if a.get("asset_type") == "agent"]


def _applications(apps):
    return [a for a in apps if a.get("asset_type") != "agent"]


def _unapproved(apps):
    return [a for a in apps if (a.get("classification") or {}).get("category")
            not in ("Approved Enterprise AI", "Microsoft First-Party AI")]


def estate_metrics(apps, changes=None, findings=None):
    changes = changes or []
    findings = findings or []
    non_ms = [a for a in apps if not a.get("first_party_microsoft")]
    agents = _agents(apps)
    active_users = sum((a.get("usage") or {}).get("active_users_30d", 0) for a in apps)
    open_f = sum(1 for f in findings
                 if f.get("status") in ("Open", "Assigned", "In Progress", "Pending Review", "Reopened"))
    now = datetime.now(timezone.utc)
    overdue_f = 0
    for f in findings:
        d = f.get("due_date")
        if d and f.get("status") not in ("Resolved", "Accepted", "False Positive"):
            try:
                dt = datetime.fromisoformat(str(d).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt < now:
                    overdue_f += 1
            except (ValueError, AttributeError):
                pass
    # Assessment coverage: sahip + sınıflı + review edilmiş (Discovered değil) oranı
    governed = sum(1 for a in non_ms if _has_owner(a)
                   and (a.get("classification") or {}).get("category") not in ("Unknown AI", None)
                   and (a.get("lifecycle") or {}).get("status") not in ("Discovered", None))
    return {
        "total_applications": len(_applications(apps)),
        "total_agents": len(agents),
        "active_users": active_users,
        "unapproved": len(_unapproved(apps)),
        "local_agents": 0,          # connector gerektirir (endpoint)
        "mcp_servers": 0,           # connector gerektirir
        "ai_models": 0,             # connector gerektirir (Foundry)
        "new_this_week": sum(1 for e in changes if e.get("change_type") == "NEW_APPLICATION"),
        "unknown_assets": sum(1 for a in apps
                              if (a.get("classification") or {}).get("category") == "Unknown AI"),
        "apps_without_owner": sum(1 for a in non_ms if not _has_owner(a)),
        "agents_without_purpose": sum(1 for a in agents
                                      if not (a.get("business_context") or {}).get("purpose")),
        "open_findings": open_f,
        "overdue_findings": overdue_f,
        "assessment_coverage": _pct(governed, len(non_ms)),
    }


def usage_surface(apps):
    """Enterprise (admin-sanctioned) / Web (user-consent) / Local (connector) ayrımı."""
    enterprise = sum(1 for a in apps if a.get("consent_type") == "AllPrincipals")
    web = sum(1 for a in apps if a.get("consent_type") == "Principal")
    return {"enterprise": enterprise, "web": web, "local": 0}


def coverage(apps):
    non_ms = [a for a in apps if not a.get("first_party_microsoft")]
    agents = _agents(apps)
    return {
        "owner_coverage": _pct(sum(1 for a in non_ms if _has_owner(a)), len(non_ms)),
        "purpose_coverage": _pct(sum(1 for a in agents
                                     if (a.get("business_context") or {}).get("purpose")), len(agents)),
        "connectors": CONNECTORS,
    }


def top_changes(changes, n=5):
    return sorted(changes or [], key=lambda e: _IMP_ORDER.get(e.get("importance"), 5))[:n]


def needs_attention(apps, changes=None, findings=None):
    """Rule-based yönetici hikâyeleri — yalnızca gerçek veriden (uydurma yok)."""
    changes = changes or []
    findings = findings or []
    lines = []
    m = estate_metrics(apps, changes, findings)

    # Yeni uygulamalar business unit bazında
    id_map = {a.get("app_id"): a for a in apps}
    new_by_bu = {}
    for e in changes:
        if e.get("change_type") == "NEW_APPLICATION":
            a = id_map.get(e.get("asset_id")) or {}
            bu = (a.get("business_context") or {}).get("business_unit") or "Atanmamış"
            new_by_bu[bu] = new_by_bu.get(bu, 0) + 1
    for bu, n in sorted(new_by_bu.items(), key=lambda kv: -kv[1]):
        if bu != "Atanmamış":
            lines.append(f"{bu} biriminde {n} yeni AI uygulaması keşfedildi.")

    # Aktivite artışları (drift)
    acts = [e for e in changes if e.get("change_type") == "ACTIVITY_INCREASED"]
    for e in sorted(acts, key=lambda x: (x.get("new_value") or 0) - (x.get("old_value") or 0),
                    reverse=True)[:2]:
        pct = round(((e.get("new_value") or 0) - (e.get("old_value") or 0))
                    / max(e.get("old_value") or 1, 1) * 100)
        lines.append(f"Son 7 günde {e.get('asset_name')} kullanımı %{pct} arttı.")

    if m["apps_without_owner"]:
        lines.append(f"{m['apps_without_owner']} AI uygulamasının business owner bilgisi eksik.")
    if m["agents_without_purpose"]:
        lines.append(f"{m['agents_without_purpose']} agent'ın business purpose bilgisi bulunmuyor.")
    if m["unknown_assets"]:
        lines.append(f"{m['unknown_assets']} AI uygulaması sınıflandırma bekliyor (Unknown).")
    if m["overdue_findings"]:
        lines.append(f"{m['overdue_findings']} finding gecikmiş (overdue) — SLA ihlali.")

    # Connector boşlukları (dürüst coverage narrative'leri)
    for name, connected, purpose in CONNECTORS:
        if not connected:
            if "Purview" in name:
                lines.append("Purview connector bağlı olmadığı için hassas veri görünürlüğü sağlanamıyor.")
            elif "Endpoint" in name:
                lines.append("Endpoint connector bağlı olmadığı için local AI agent görünürlüğü yok.")
            elif "Foundry" in name:
                lines.append("Azure AI Foundry bağlı olmadığı için AI model envanteri görünmüyor.")
            elif "MCP" in name:
                lines.append("MCP connector bağlı olmadığı için MCP server görünürlüğü yok.")
    return lines
