"""
A synthetic tenant, dense enough to show what the dashboards are for.

Every number here is invented, but nothing is faked *past* this file: the data is fed
to the real collectors through a stand-in Graph client, so the sample pages are produced
by the same normalisation, correlation, scoring and rendering a live scan uses. If a
chart is wrong here it is wrong in production too, which is the point of shipping it.

Shaped deliberately so the portal has something to show:
  * vendors visible through BOTH OAuth consent and browser traffic, which is the join
    the portal exists to make;
  * a Teams/agent catalogue large enough that "agents attach, they never create" matters;
  * sensitive interactions with real DLP outcomes, both blocked and allowed.
"""
import hashlib
import random
from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 8, 1, 9, 0, 0, tzinfo=timezone.utc)
TENANT = "contoso-sample-0000-0000-000000000000"

# (name, category, domain, publisher, users, upload GB, download GB, MDCA risk, sanction)
# MDCA scores 0-10 where LOW means risky, matching the real API.
WEB_APPS = [
    ("ChatGPT (Consumer & Enterprise)", "OpenAI", "chat.openai.com", 486, 21.6, 84.5, 9, "sanctioned"),
    ("Anthropic Claude", "Anthropic", "claude.ai", 490, 17.0, 77.2, 8, "sanctioned"),
    ("Google Gemini", "Google", "gemini.google.com", 475, 17.5, 79.7, 10, "sanctioned"),
    ("Microsoft Copilot", "Microsoft", "copilot.microsoft.com", 523, 14.5, 96.8, 10, "unsanctioned"),
    ("Deepseek", "DeepSeek", "chat.deepseek.com", 470, 36.3, 51.1, 5, "unreviewed"),
    ("CopyAI", "Copy.ai", "copy.ai", 424, 29.1, 50.5, 8, "unsanctioned"),
    ("Perplexity AI", "Perplexity", "perplexity.ai", 394, 6.2, 41.3, 9, "unreviewed"),
    ("Mistral AI Le Chat", "Mistral AI", "chat.mistral.ai", 469, 14.6, 44.9, 8, "unreviewed"),
    ("Grok", "xAI", "grok.com", 479, 8.9, 39.4, 9, "unsanctioned"),
    ("Midjourney", "Midjourney", "midjourney.com", 354, 17.9, 22.6, 5, "unreviewed"),
    ("Poe", "Quora", "poe.com", 353, 0.6, 18.2, 6, "unreviewed"),
    ("Character.AI", "Character Technologies", "character.ai", 354, 0.6, 19.4, 4, "unsanctioned"),
    ("Hugging Face", "Hugging Face", "huggingface.co", 429, 6.2, 33.1, 7, "unreviewed"),
    ("Notion", "Notion Labs", "notion.so", 350, 1.1, 27.9, 9, "sanctioned"),
    ("Glean", "Glean Technologies", "glean.com", 188, 3.4, 29.8, 9, "sanctioned"),
    ("Otter.ai", "Otter.ai", "otter.ai", 96, 4.8, 9.1, 6, "unreviewed"),
]

# Agent 365 packages. The first group matches AI vendors and should ATTACH to them; the
# rest is an ordinary Teams catalogue and must not become vendors of its own.
AI_PACKAGES = [
    ("Glean Enterprise Search", "Glean Technologies"),
    ("Otter.ai Meeting Notes", "Otter.ai"),
    ("Notion AI Workspace", "Notion Labs"),
    ("Writer Enterprise Assistant", "Writer Inc"),
]
CATALOGUE_PACKAGES = [
    "Jira Cloud", "Viva Goals", "Lucidchart for Microsoft Teams", "iPlanner Pro for Teams",
    "Lexis Create DMS for Copilot", "Writing Coach", "Adobe Acrobat", "Trello",
    "ServiceNow Virtual Agent", "Workday", "SAP SuccessFactors", "Zoom for Teams",
    "Miro", "Asana", "Smartsheet", "Polly", "Kudos", "ShiftWizard",
    "Bookings Helper", "Expense Tracker", "Contract Review Bot", "Onboarding Buddy",
    "IT Helpdesk Bot", "Travel Approver", "Payroll Lookup", "Meeting Room Finder",
]

# Copilot Studio agents — all roll up under the one vendor.
STUDIO_AGENTS = [
    "Procurement", "Quality Assurance", "Distribution", "Change Management",
    "Compliance", "Learning Guide", "Ledger", "Atlas", "Spark", "Forge",
]

SITS = ["Credit Card Number", "U.S. Social Security Number (SSN)", "IBAN",
        "EU Passport Number", "Azure Storage Account Key", "Employee ID"]

INTERACTION_HOSTS = [
    ("ChatGPT", "AIAppInteraction", 14),
    ("Anthropic Claude", "AIAppInteraction", 9),
    ("Microsoft Teams", "CopilotInteraction", 11),
    ("Deepseek", "ConnectedAIAppInteraction", 7),
    ("CopyAI", "AIAppInteraction", 5),
    ("Glean", "ConnectedAIAppInteraction", 4),
]

USERS = ["alice@contoso.com", "bilal@contoso.com", "chen@contoso.com", "dana@contoso.com",
         "emre@contoso.com", "farah@contoso.com", "gita@contoso.com", "hugo@contoso.com"]


def _iso(days_ago):
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _id(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _mdca_app(rng, name, publisher, domain, users, up_gb, down_gb, risk, sanction, share):
    gb = 1024 ** 3
    return {
        "id": f"mdca-{_id(name)}",
        "displayName": name,
        "category": "generativeAi",
        "domain": domain,
        "publisher": publisher,
        "userCount": int(users * share),
        "deviceCount": int(users * share * 0.82),
        "ipAddressCount": int(users * share * 0.95),
        "transactionCount": int(users * share * rng.uniform(3.5, 5.5)),
        "uploadedBytes": int(up_gb * gb * share),
        "downloadedBytes": int(down_gb * gb * share),
        "riskScore": risk,
        "sanctionedState": sanction,
        "firstSeenDateTime": _iso(88),
        "lastSeenDateTime": _iso(2),
    }


def _package(name, publisher, idx, blocked=False, scope="everyone"):
    return {
        "id": f"pkg-{_id(name)}",
        "displayName": name,
        "packageType": "declarativeAgent",
        "publisher": publisher,
        "applicationId": f"APP-{_id(name).upper()}",
        "assetId": f"asset-{_id(name)}",
        "manifestId": f"manifest-{_id(name)}",
        "version": "1.4.2",
        "manifestVersion": "1.17",
        "platform": "M365Copilot",
        "supportedHosts": ["Teams", "Outlook"],
        "blocked": blocked,
        "availableToScope": scope,
        "deployedToScope": "everyone" if idx % 3 == 0 else "Pilot-Group",
        "lastModifiedDateTime": _iso(idx % 40),
        "categories": ["Productivity"],
        "elementDetails": [{"elementType": "declarativeAgent",
                            "definition": {"declarativeAgentId": f"da-{_id(name)}",
                                           "scopes": ["Files.Read.All"]}}],
    }


def _identity(name, idx, owners=True, sponsors=True):
    oid = f"OID-{_id(name)}"
    rec = {
        "sp": {
            "id": oid, "appId": f"APP-{_id(name).upper()}", "displayName": name,
            "accountEnabled": idx % 9 != 0,
            "createdDateTime": _iso(120 - idx),
            "servicePrincipalType": "Application",
            "signInAudience": "AzureADMyOrg",
            "blueprintId": "BP-STUDIO" if "Copilot Studio" in name else None,
            "appOwnerOrganizationId": "TENANT-1",
        },
        "owners": ([{"@odata.type": "#microsoft.graph.user", "id": f"USR-{idx}",
                     "displayName": "Alice Admin",
                     "userPrincipalName": "alice@contoso.com"}] if owners else []),
        "sponsors": ([{"@odata.type": "#microsoft.graph.user", "id": f"SPN-{idx}",
                       "displayName": "Bob Sponsor",
                       "userPrincipalName": "bob@contoso.com"}] if sponsors else []),
        "appRoleAssignments": [{"appRoleId": "role-1", "resourceId": "graph",
                                "resourceDisplayName": "Microsoft Graph"}],
        "oauth2PermissionGrants": [{"clientId": oid, "resourceId": "graph",
                                    "scope": "Files.Read.All Sites.Read.All"}],
        "memberOf": [{"@odata.type": "#microsoft.graph.group", "id": f"GRP-{idx % 4}",
                      "displayName": f"AI Pilot Group {idx % 4}"}],
    }
    return rec


def _audit_record(rng, idx, host, operation):
    """A Purview record; roughly a third are blocked by DLP, the rest allowed."""
    blocked = idx % 3 == 0
    sit = SITS[idx % len(SITS)]
    user = USERS[idx % len(USERS)]
    return {
        "id": f"rec-{idx}",
        "createdDateTime": _iso(rng.randint(1, 29)),
        "userPrincipalName": user,
        "operation": operation,
        "auditData": {
            "Operation": operation,
            "Workload": "Copilot" if operation == "CopilotInteraction" else "AIApp",
            "UserId": user,
            "CopilotEventData": {
                "AppHost": host,
                "SensitivityLabelId": "label-confidential" if idx % 4 == 0 else None,
                "Contexts": [{"Id": f"https://contoso.sharepoint.com/finance/doc-{idx}.xlsx",
                              "Type": "File", "Name": f"doc-{idx}.xlsx"}] if idx % 2 else [],
            },
            "PolicyDetails": [{
                "PolicyName": "Sensitive data to AI services",
                "Rules": [{
                    "RuleName": f"{sit} rule",
                    "Actions": ["BlockAccess"] if blocked else ["Audit"],
                    "ConditionsMatched": {
                        "SensitiveInformation": [{"SensitiveInformationTypeName": sit,
                                                  "Count": rng.randint(1, 12)}]},
                }],
            }],
        },
    }


class SampleGraph:
    """
    A stand-in Graph client serving the synthetic tenant.

    Implements only what the connectors actually call, and answers in the real response
    shapes, so the collectors do their normal parsing rather than being bypassed.
    """

    def __init__(self, seed=20260801):
        rng = random.Random(seed)
        self.packages = (
            [_package(n, p, i) for i, (n, p) in enumerate(AI_PACKAGES)]
            + [_package(n, None, i + 10, blocked=(i % 11 == 0),
                        scope="everyone" if i % 4 else "Pilot-Group")
               for i, n in enumerate(CATALOGUE_PACKAGES)])
        self.identities = (
            [_identity(f"{n} Agent (Microsoft Copilot Studio)", i,
                       owners=(i % 3 != 0), sponsors=(i % 4 != 0))
             for i, n in enumerate(STUDIO_AGENTS)]
            + [_identity("Glean Search Agent", 50),
               _identity("Otter.ai Notetaker Agent", 51, owners=False)])
        self.blueprints = [{
            "id": "BP-STUDIO", "displayName": "Copilot Studio blueprint",
            "createdDateTime": _iso(200),
        }]
        # Two collection streams, so the aggregation across streams is exercised.
        self.streams = [{"id": "stream-fw-1", "displayName": "Palo Alto Firewall"},
                        {"id": "stream-proxy-2", "displayName": "Zscaler Proxy"}]
        self.apps_by_stream = {
            "stream-fw-1": [_mdca_app(rng, *a, share=0.62) for a in WEB_APPS],
            "stream-proxy-2": [_mdca_app(rng, *a, share=0.38) for a in WEB_APPS],
        }
        records, idx = [], 0
        for host, op, count in INTERACTION_HOSTS:
            for _ in range(count):
                records.append(_audit_record(rng, idx, host, op))
                idx += 1
        self.records = records

    # --- Graph surface -----------------------------------------------------
    def get_all(self, path, params=None, max_items=None, beta=False):
        if path == "/copilot/admin/catalog/packages":
            return self.packages
        if path == "/servicePrincipals/microsoft.graph.agentIdentity":
            return [r["sp"] for r in self.identities]
        if path == "/applications/microsoft.graph.agentIdentityBlueprint":
            return self.blueprints
        if "/uploadedStreams" in path and "aggregatedAppsDetails" not in path:
            return self.streams
        if "aggregatedAppsDetails" in path:
            sid = path.split("/uploadedStreams/", 1)[1].split("/aggregatedAppsDetails", 1)[0]
            return self.apps_by_stream.get(sid, [])
        if path.endswith("/records"):
            return self.records
        for suffix, key in (("/owners", "owners"), ("/sponsors", "sponsors"),
                            ("/appRoleAssignments", "appRoleAssignments"),
                            ("/oauth2PermissionGrants", "oauth2PermissionGrants"),
                            ("/memberOf", "memberOf")):
            if path.endswith(suffix):
                oid = path.split("/")[2]
                rec = next((r for r in self.identities if r["sp"]["id"] == oid), None)
                return (rec or {}).get(key, [])
        return []

    def get(self, path, params=None, beta=False):
        pid = path.rsplit("/", 1)[-1]
        pkg = next((p for p in self.packages if p["id"] == pid), None)
        if pkg:
            return pkg
        if "/auditLog/queries/" in path:
            return {"id": "query-1", "status": "succeeded"}
        return {}

    def post(self, path, body, beta=False):
        return {"id": "query-1", "status": "succeeded"}
