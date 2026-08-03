"""
Regenerates the sample dashboards in docs/ from synthetic data, through the real code.

The README points at these so the tool can be judged without deploying anything, which
only works if they are (a) reproducible and (b) dense enough that the charts show what
they are for. Nothing here talks to a tenant; the data is invented, but every number on
the page is computed by the same scoring, drift, and rendering code a real scan uses.

    python scripts/make_sample.py
"""
import math
import os
import random
import sys
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

NOW = datetime(2026, 8, 1, 9, 0, 0, tzinfo=timezone.utc)
TENANT = "contoso-sample-0000-0000-000000000000"

# What a real `--auth app` run reports about itself.
SAMPLE_CONTEXT = {
    "auth_mode": "app",
    "identity": {"kind": "application", "app_name": "AI-SPM Scanner",
                 "client_id": "04ca4c1c-0000-0000-0000-000000000000", "scope_count": 6},
    "scan_scope": "consented",
    "activity_days": 90,
    "duration_s": 74,
    "graph": {"requests": 412, "batch_calls": 18, "batched_requests": 344, "throttled": 3},
    "tenant_profile": {"display_name": "Contoso Ltd", "primary_domain": "contoso.com",
                       "domain_count": 4, "country": "GB"},
    "subscription_name": "Contoso Security — Production",
    "subscription_id": "8d1f2c77-0000-0000-0000-9a4b2e5c1d33",
}

# (name, vendor, publisher, verified, scopes, app_perms, consent, users, active30, trend)
FLEET = [
    ("MeetingNotes AI Bot", "Otter.ai", "notecorp-io", False,
     ["mail.read", "files.readwrite.all", "chat.read", "offline_access", "user.read"],
     ["Mail.Read", "Files.Read.All"], "AllPrincipals", 340, 288, "flat-high"),
    ("ChatGPT Enterprise Connector", "OpenAI (ChatGPT)", "OpenAI", True,
     ["files.read.all", "sites.read.all", "offline_access", "user.read", "openid"],
     [], "AllPrincipals", 512, 470, "growing"),
    ("Zephyr Workspace Assistant", None, "Zephyr Labs", False,
     ["mail.readwrite", "files.readwrite.all", "directory.read.all", "offline_access"],
     ["Directory.Read.All", "User.Read.All"], "AllPrincipals", 78, 61, "growing"),
    ("Claude for Teams", "Anthropic (Claude)", "Anthropic", True,
     ["files.read.all", "chat.read", "offline_access", "user.read"],
     [], "AllPrincipals", 264, 240, "growing"),
    ("Glean Enterprise Search", "Glean", "Glean Technologies", True,
     ["sites.read.all", "files.read.all", "user.read.all", "group.read.all", "offline_access"],
     ["Sites.Read.All", "Files.Read.All", "User.Read.All"], "AllPrincipals", 190, 155, "flat"),
    ("Fireflies Meeting Recorder", "Fireflies", "Fireflies.ai", False,
     ["calendars.readwrite", "chat.read", "offline_access", "user.read"],
     ["OnlineMeetings.Read.All"], "AllPrincipals", 96, 44, "declining"),
    ("Perplexity Workspace", "Perplexity", "Perplexity AI", True,
     ["files.read.all", "user.read", "offline_access"], [], "Principal", 43, 31, "growing"),
    ("Grammarly for Office", "Grammarly", "Grammarly Inc", True,
     ["user.read", "openid", "profile"], [], "Principal", 220, 180, "flat"),
    ("Notion AI Connector", "Notion AI", "Notion Labs", True,
     ["files.readwrite.all", "sites.read.all", "offline_access"], [], "Principal", 61, 38, "flat"),
    ("Read AI Meeting Copilot", "Read AI", "Read AI Inc", False,
     ["calendars.read", "chat.read", "offline_access"], [], "AllPrincipals", 134, 88, "growing"),
    ("Otter Transcription Sync", "Otter.ai", "Otter.ai", True,
     ["calendars.read", "user.read", "offline_access"], [], "Principal", 57, 22, "declining"),
    ("Tactiq Live Captions", "Tactiq", "Tactiq Pty", False,
     ["calendars.read", "user.read"], [], "Principal", 29, 12, "flat"),
    ("Gamma Deck Generator", "Gamma", "Gamma Tech", True,
     ["files.read.all", "user.read"], [], "Principal", 18, 9, "flat"),
    ("Jasper Brand Voice", "Jasper", "Jasper AI", True,
     ["user.read", "openid"], [], "Principal", 12, 4, "declining"),
    ("Copy.ai Workflow Bot", "Copy.ai", "Copy.ai", False,
     ["mail.send", "user.read", "offline_access"], ["Mail.Send"], "Principal", 9, 3, "flat"),
    ("ElevenLabs Voice Sync", "ElevenLabs", "ElevenLabs", True,
     ["files.read.all", "user.read"], [], "Principal", 7, 2, "flat"),
    ("Writer Enterprise", "Writer", "Writer Inc", True,
     ["files.read.all", "sites.read.all", "user.read"], [], "Principal", 24, 14, "flat"),
    ("Hugging Face Spaces Link", "Hugging Face", "Hugging Face", True,
     ["user.read", "openid"], [], "Principal", 15, 5, "flat"),
    ("Mistral Assistant", "Mistral", "Mistral AI", True,
     ["files.read.all", "user.read", "offline_access"], [], "Principal", 21, 11, "growing"),
    ("Cohere Embed Service", "Cohere", "Cohere Inc", True,
     [], ["Files.Read.All", "Sites.Read.All"], None, 0, 0, "apponly"),
    ("Acme GPT Helper", None, "—", False,
     ["user.read", "calendars.read"], [], "Principal", 6, 1, "flat"),
    ("Internal Support Copilot", None, "Contoso IT", True,
     ["user.read", "chat.read"], [], "Principal", 88, 70, "flat"),
    ("Skywork Doc Agent", "Skywork AI", "Skywork", False,
     ["files.readwrite.all", "offline_access"], ["Files.ReadWrite.All"], "AllPrincipals",
     31, 19, "growing"),
    ("Character Chat Bridge", "Character.AI", "Character Technologies", False,
     ["user.read", "offline_access"], [], "Principal", 4, 1, "declining"),
]

_SHAPES = {
    "growing": lambda i: 0.25 + 0.75 * (i / 29) ** 1.4,
    "declining": lambda i: 1.0 - 0.7 * (i / 29) ** 0.9,
    "flat": lambda i: 0.8 + 0.2 * math.sin(i / 3),
    "flat-high": lambda i: 0.9 + 0.1 * math.sin(i / 2),
    "apponly": lambda _i: 0.0,
}


def _daily(active30, shape, rng):
    f = _SHAPES[shape]
    return [max(0, int(active30 * f(i) * rng.uniform(0.72, 1.0) / 3)) for i in range(30)]


def build_fleet():
    rng = random.Random(20260801)          # deterministic: reruns produce the same page
    out = []
    for idx, (name, vendor, pub, verified, scopes, app_perms, consent,
              users, active30, shape) in enumerate(FLEET):
        last_used = NOW - timedelta(days=(1 if active30 else 140))
        daily = _daily(active30, shape, rng)
        prev7 = max(1, sum(daily[16:23]) // 7)
        app = {
            "sp_id": f"sp-{idx}", "app_id": f"app-{idx:04d}", "display_name": name,
            "publisher": pub, "verified_publisher": verified,
            "owner_tenant": f"ext-{idx}", "third_party": pub != "Contoso IT",
            "first_party_microsoft": False,
            "vendor": vendor or "Not an AI catalog match",
            "confidence": "high" if vendor else "none",
            "match_signal": "pattern" if vendor else "scope",
            "ai_match": bool(vendor),
            "asset_type": "agent" if any(w in name.lower() for w in ("bot", "agent", "copilot"))
                          else "application",
            "scopes": scopes,
            "delegated_permissions": [{"resource": "Microsoft Graph", "permission": s,
                                       "consent_type": consent} for s in scopes],
            "application_permissions": [{"resource": "Microsoft Graph", "permission": p,
                                         "permission_id": f"role-{i}"}
                                        for i, p in enumerate(app_perms)],
            "has_app_only_access": bool(app_perms),
            "consent_type": consent, "user_count": users,
            "ownership": {"application_owners": [],
                          "service_principal_owners": ([{"id": "u1", "name": "Alice Admin"}]
                                                       if idx % 3 == 0 else [])},
            "technical_inventory": {"enabled": True, "publisher": pub, "homepage": "",
                                    "tags": [], "description": "", "sp_type": "Application",
                                    "credential_count": 1 if app_perms else 0,
                                    "credential_next_expiry": None},
            "usage": {
                "available": True, "consent_user_count": users,
                "active_users_7d": max(0, active30 // 4),
                "active_users_30d": active30, "active_users_90d": int(active30 * 1.2),
                "last_delegated_signin": last_used.isoformat() if users else None,
                "last_service_principal_signin": (NOW - timedelta(days=2)).isoformat()
                                                 if app_perms else None,
                "successful_signins_30d": active30 * 6, "failed_signins_30d": idx % 5,
                "unique_user_count": users, "unique_ip_count": max(1, users // 3),
                "country_count": 1 + idx % 4,
                "last_used_date": last_used.isoformat() if (users or app_perms) else None,
                "never_used": not (users or app_perms),
                "inactive_30d": active30 == 0 and not app_perms,
                "inactive_90d": False,
                "growth_7d": max(0, active30 // 4) - prev7,
                "daily_active_30d": daily,
            },
        }
        out.append(app)
    return out


def main():
    import connectors_report
    import pipeline
    import portal
    import report
    import scoring
    from sample_tenant import SampleGraph

    for flag in ("ENABLE_AGENT365", "ENABLE_ENTRA_AGENT_ID", "ENABLE_DEFENDER_CLOUD_APPS",
                 "ENABLE_PURVIEW_AUDIT", "ENABLE_PREVIEW_CONNECTORS"):
        os.environ[flag] = "true"

    docs = os.path.join(ROOT, "docs")
    os.makedirs(docs, exist_ok=True)

    scored = scoring.score_all(build_fleet())
    try:
        import classifier
        classifier.classify_all(scored, TENANT)
    except Exception:
        pass

    # A week-ago snapshot, diffed by the real drift engine, so the Changes tab shows what
    # a second scan actually looks like — the question a customer asks first is "what
    # changed since last week", and an empty tab does not answer it.
    changes = sample_changes(scored)

    # Through the real connectors, so the sample is engine output rather than a mock-up.
    result = pipeline.run_connectors(SampleGraph())
    health = (result or {}).get("health")

    core = os.path.join(docs, "sample-report.html")
    with open(core, "w", encoding="utf-8") as f:
        f.write(report.html_string(scored, TENANT, changes, connector_health=health,
                                   connectors_href="sample-connectors.html",
                                   portal_href="sample-portal.html"))

    conn = os.path.join(docs, "sample-connectors.html")
    with open(conn, "w", encoding="utf-8") as f:
        f.write(connectors_report.html_string(result, TENANT,
                                              portal_href="sample-portal.html",
                                              report_href="sample-report.html"))

    hub = os.path.join(docs, "sample-portal.html")
    with open(hub, "w", encoding="utf-8") as f:
        f.write(portal.html_string(scored, TENANT, result, changes,
                                   report_href="sample-report.html",
                                   connectors_href="sample-connectors.html",
                                   context=SAMPLE_CONTEXT))

    counts = {lv: sum(1 for a in scored if a["risk_level"] == lv)
              for lv in ("Critical", "High", "Medium", "Low")}
    estate = portal.build_estate(scored, result)
    both = [v for v in estate["vendors"] if {"oauth", "web"} <= v["evidence"]]
    print(f"{len(scored)} applications — {counts}")
    print(f"{len(changes)} changes since the previous scan")
    print(f"{len(estate['vendors'])} AI vendors, {len(both)} seen through both routes")
    print(f"  {len(estate['unattached_agents'])} agents/packages held out of the estate")
    print(f"  portal     : {hub}")
    print(f"  core       : {core}")
    print(f"  connectors : {conn}")



def sample_changes(scored):
    """
    What a second scan produces, generated by the real drift engine.

    A synthetic "last week" is built by walking the current estate backwards — an app
    that did not exist, one whose consent was still per-user, one that has since gained
    app-only access — and drift.diff() turns the pair into the same events a live
    follow-up scan emits. Nothing here is a hand-written change record.
    """
    import drift

    current = drift.snapshot(scored)
    previous = {}
    for i, (app_id, snap) in enumerate(sorted(current.items())):
        prev = dict(snap)
        if i == 0:
            continue                                    # newly discovered this week
        if i == 1:                                      # was user-consent, now org-wide
            prev["admin_consent"] = False
        if i == 2:                                      # gained unattended access
            prev["has_app_only"] = False
            prev["application"] = []
        if i == 3:                                      # permissions were narrower
            prev["delegated"] = snap["delegated"][:1]
            prev["max_weight"] = max(snap["max_weight"] - 4, 0)
        if i == 4:                                      # usage climbing
            prev["active_30d"] = int((snap["active_30d"] or 40) * 0.55) or 22
        if i == 5:                                      # was disabled, now back on
            prev["enabled"] = False
        if i == 6:                                      # nobody owned it before
            prev["owners"] = []
        previous[app_id] = prev

    # An app that has since been removed from the tenant.
    previous["app-retired-01"] = {
        "name": "Writesonic Draft Assistant", "vendor": "Writesonic", "enabled": True,
        "delegated": ["Microsoft Graph|Files.Read.All"], "application": [],
        "has_app_only": False, "admin_consent": False, "owners": [],
        "business_owner": "", "classification": "Third-Party Shadow AI",
        "lifecycle": "Pilot", "business_unit": "", "max_weight": 9,
        "active_30d": 12, "last_signin": None,
    }
    return drift.diff(previous, current, now=NOW)

if __name__ == "__main__":
    main()
