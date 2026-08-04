"""
The AI security assessment: a catalogue of tests, each answered from a finished scan.

Why this is its own module: every dashboard before it answered "what do I have", which
reads as an inventory. The question a security owner actually asks is "what do I fix",
and that is a list of controls with a pass or a fail against each. Nothing here talks to
Graph — it is handed a scored scan and turns it into verdicts, so the same catalogue runs
against a live scan, the sample estate, or a stored report.

Three rules the catalogue keeps to:

  * A test is only here if the data to answer it is already collected. A catalogue full
    of N/A rows measures the tool, not the tenant.
  * A test whose source is not connected reports NOT_ASSESSED and names the source. It
    never passes by default and is never drawn as a zero: "looked, found none" and
    "could not look" are different answers, and telling them apart is the product.
  * A failure names the assets that failed it. A verdict nobody can act on is a statistic.
"""
from datetime import datetime, timezone

PASSED = "Passed"
FAILED = "Failed"
NOT_ASSESSED = "Not assessed"
SKIPPED = "Skipped"
STATUSES = (PASSED, FAILED, NOT_ASSESSED, SKIPPED)

P_ID = "Protect identities and secrets"
P_DATA = "Protect data"
P_GOV = "Govern the AI estate"
P_SURF = "Reduce attack surface"
P_MON = "Monitor and detect"
PILLARS = (P_ID, P_DATA, P_GOV, P_SURF, P_MON)

PILLAR_SHORT = {P_ID: "Identities", P_DATA: "Data", P_GOV: "Governance",
                P_SURF: "Attack surface", P_MON: "Monitoring"}

SENSITIVE_SCOPES = ("files.read.all", "files.readwrite.all", "sites.read.all", "mail.read",
                    "mail.readwrite", "directory.read.all", "user.read.all",
                    "group.read.all", "chat.read", "calendars.readwrite")


def context(apps, estate=None, health=None, changes=None, now=None):
    """Everything the catalogue is allowed to read, gathered in one place."""
    return {"apps": list(apps or []),
            "estate": estate or {"vendors": [], "unattached_agents": []},
            "health": dict(health or {}),
            "changes": list(changes or []),
            "now": now or datetime.now(timezone.utc)}


def connected(ctx, *names):
    """True when at least one of the named connectors actually returned data."""
    for n in names:
        h = ctx["health"].get(n)
        if (h and h.get("status") in ("CONNECTED", "PARTIALLY_CONNECTED")
                and (h.get("count") or 0) > 0):
            return True
    return False


# ---------------------------------------------------------------- helpers

def scopes(a):
    return [s.lower() for s in a.get("scopes", [])]


def approles(a):
    return [(p.get("permission") or "") for p in a.get("application_permissions", [])]


def shadow(ctx):
    """Third-party AI. Microsoft's own first-party apps are inventoried, not assessed."""
    return [a for a in ctx["apps"] if not a.get("first_party_microsoft")]


def owner(a):
    return ((a.get("ownership") or {}).get("business_owner") or "").strip()


NO_SIGNIN = (NOT_ASSESSED,
             "Sign-in activity could not be read, so use cannot be told apart from "
             "consent. This test needs Entra ID P1 and AuditLog.Read.All.", [])


def usage_seen(ctx):
    return any((a.get("usage") or {}).get("available") for a in ctx["apps"])


def review_overdue(a, now):
    d = (a.get("lifecycle") or {}).get("next_review_date")
    if not d:
        return False
    try:
        dt = datetime.fromisoformat(str(d).replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt < now


def verdict(bad, singular, plural, clean):
    """One sentence, with the count folded into it rather than left to the reader."""
    if not bad:
        return PASSED, clean
    n = len(bad)
    return FAILED, (singular if n == 1 else plural).replace("{n}", str(n))


def rows(bad, detail):
    return [(a.get("display_name") or "-", detail(a)) for a in bad]


# ---------------------------------------------------------------- the tests

def t_admin_consent(ctx):
    bad = [a for a in shadow(ctx)
           if a.get("consent_type") == "AllPrincipals"
           and any(s in SENSITIVE_SCOPES for s in scopes(a))]
    st, v = verdict(bad,
                    "1 AI application holds org-wide admin consent for a sensitive data permission.",
                    "{n} AI applications hold org-wide admin consent for sensitive data permissions.",
                    "No AI application holds org-wide consent for a sensitive data permission.")
    return st, v, rows(bad, lambda a: ", ".join(s for s in scopes(a) if s in SENSITIVE_SCOPES))


def t_app_only(ctx):
    bad = [a for a in shadow(ctx) if a.get("has_app_only_access")]
    st, v = verdict(bad,
                    "1 AI application has unattended (app-only) access to the tenant.",
                    "{n} AI applications have unattended (app-only) access to the tenant.",
                    "No AI application holds app-only permissions.")
    return st, v, rows(bad, lambda a: ", ".join(approles(a)))


def t_write_all_files(ctx):
    bad = [a for a in shadow(ctx)
           if "files.readwrite.all" in scopes(a)
           or any(p.lower() == "files.readwrite.all" for p in approles(a))]
    st, v = verdict(bad,
                    "1 AI application can write to every file in the tenant.",
                    "{n} AI applications can write to every file in the tenant.",
                    "No AI application holds tenant-wide file write access.")
    return st, v, rows(bad, lambda a: f'{a.get("user_count", 0)} users · {a.get("risk_level")}')


def t_directory_read(ctx):
    bad = [a for a in shadow(ctx)
           if "directory.read.all" in scopes(a)
           or any(p.lower() in ("directory.read.all", "user.read.all")
                  for p in approles(a))]
    st, v = verdict(bad,
                    "1 AI application can read the whole directory.",
                    "{n} AI applications can read the whole directory.",
                    "No AI application can enumerate the directory.")
    return st, v, rows(bad, lambda a: a.get("publisher") or "—")


def t_mail_send(ctx):
    bad = [a for a in shadow(ctx)
           if "mail.send" in scopes(a) or any(p.lower() == "mail.send" for p in approles(a))]
    st, v = verdict(bad,
                    "1 AI application can send mail as your users.",
                    "{n} AI applications can send mail as your users.",
                    "No AI application can send mail on a user's behalf.")
    return st, v, rows(bad, lambda a: a.get("consent_type") or "—")


def t_verified_publisher(ctx):
    bad = [a for a in shadow(ctx) if a.get("third_party") and not a.get("verified_publisher")]
    st, v = verdict(bad,
                    "1 third-party AI application comes from an unverified publisher.",
                    "{n} third-party AI applications come from unverified publishers.",
                    "Every third-party AI application has a verified publisher.")
    return st, v, rows(bad, lambda a: a.get("publisher") or "—")


def t_offline_access(ctx):
    bad = [a for a in shadow(ctx) if "offline_access" in scopes(a)]
    st, v = verdict(bad,
                    "1 AI application holds a refresh token that outlives the session.",
                    "{n} AI applications hold refresh tokens that outlive the session.",
                    "No AI application holds offline access.")
    # Widespread and not automatically wrong — reported at Low.
    return st, v, rows(bad, lambda a: f'{a.get("user_count", 0)} users')


def t_credentials(ctx):
    bad = [a for a in shadow(ctx)
           if (a.get("technical_inventory") or {}).get("credential_count", 0) > 0]
    st, v = verdict(bad,
                    "1 AI service principal holds a client secret or certificate.",
                    "{n} AI service principals hold client secrets or certificates.",
                    "No AI service principal holds a long-lived credential.")
    return st, v, rows(bad, lambda a: f'{(a.get("technical_inventory") or {}).get("credential_count", 0)} credential(s)')


def t_owner(ctx):
    bad = [a for a in shadow(ctx) if not owner(a)]
    st, v = verdict(bad,
                    "1 AI application has no business owner.",
                    "{n} AI applications have no business owner recorded.",
                    "Every AI application has a business owner.")
    return st, v, rows(bad, lambda a: a.get("vendor") or "—")


def t_lifecycle(ctx):
    bad = [a for a in shadow(ctx)
           if ((a.get("lifecycle") or {}).get("status") or "Discovered") in ("Discovered", "Unknown")]
    st, v = verdict(bad,
                    "1 AI application has never been through a decision.",
                    "{n} AI applications are still sitting at Discovered — nobody has approved or rejected them.",
                    "Every AI application has a decided lifecycle state.")
    return st, v, rows(bad, lambda a: f'{a.get("user_count", 0)} users already use it')


def t_classification(ctx):
    bad = [a for a in shadow(ctx)
           if (a.get("classification") or {}).get("category") == "Unknown AI"]
    st, v = verdict(bad,
                    "1 application could not be classified.",
                    "{n} applications could not be classified and are sitting in the review queue.",
                    "Every discovered application has been classified.")
    return st, v, rows(bad, lambda a: f'confidence {(a.get("classification") or {}).get("confidence", 0)}%')


def t_review_overdue(ctx):
    bad = [a for a in shadow(ctx) if review_overdue(a, ctx["now"])]
    st, v = verdict(bad,
                    "1 lifecycle review is past its date.",
                    "{n} lifecycle reviews are past their date.",
                    "No lifecycle review is overdue.")
    return st, v, rows(bad, lambda a: (a.get("lifecycle") or {}).get("next_review_date") or "—")


def t_blocked_in_use(ctx):
    if not usage_seen(ctx):
        return NO_SIGNIN
    bad = [a for a in shadow(ctx)
           if (a.get("lifecycle") or {}).get("status") == "Blocked"
           and (a.get("usage") or {}).get("active_users_30d", 0) > 0]
    st, v = verdict(bad,
                    "1 blocked AI application is still being used.",
                    "{n} blocked AI applications are still being used.",
                    "No application marked Blocked is still in use.")
    return st, v, rows(bad, lambda a: f'{(a.get("usage") or {}).get("active_users_30d", 0)} active users')


def t_unused_privileged(ctx):
    if not usage_seen(ctx):
        return NO_SIGNIN
    bad = [a for a in shadow(ctx)
           if (a.get("usage") or {}).get("inactive_30d") and a.get("risk_score", 0) >= 50]
    st, v = verdict(bad,
                    "1 high-risk AI application has not been used in 30 days.",
                    "{n} high-risk AI applications have not been used in 30 days.",
                    "No unused application is holding high privilege.")
    return st, v, rows(bad, lambda a: f'risk {a.get("risk_score")} · last used {(a.get("usage") or {}).get("last_used_date") or "never"}')


def t_never_used(ctx):
    if not usage_seen(ctx):
        return NO_SIGNIN
    bad = [a for a in shadow(ctx) if (a.get("usage") or {}).get("never_used")]
    st, v = verdict(bad,
                    "1 AI application has never been signed in to.",
                    "{n} AI applications have never been signed in to.",
                    "Every consented AI application has actually been used.")
    return st, v, rows(bad, lambda a: ", ".join(scopes(a)) or "app-only")


def t_growth(ctx):
    if not usage_seen(ctx):
        return NO_SIGNIN
    bad = [a for a in shadow(ctx)
           if (a.get("usage") or {}).get("growth_7d", 0) > 0
           and (a.get("usage") or {}).get("active_users_30d", 0) >= 30
           and (a.get("usage") or {}).get("growth_7d", 0) >=
           0.25 * max((a.get("usage") or {}).get("active_users_30d", 1) / 4, 1)]
    st, v = verdict(bad,
                    "1 AI application is growing fast enough to deserve a look.",
                    "{n} AI applications are spreading through the tenant faster than 25% a week.",
                    "No AI application is growing sharply.")
    return st, v, rows(bad, lambda a: f'+{(a.get("usage") or {}).get("growth_7d", 0)} users in 7 days')


def t_agents_purpose(ctx):
    agents = [a for a in shadow(ctx) if a.get("asset_type") == "agent"]
    bad = [a for a in agents if not (a.get("business_context") or {}).get("purpose")]
    if not agents:
        return "Skipped", "No AI agents were found in this tenant.", []
    st, v = verdict(bad,
                    "1 agent has no stated business purpose.",
                    "{n} agents have no stated business purpose.",
                    "Every agent has a stated business purpose.")
    return st, v, rows(bad, lambda a: a.get("vendor") or "—")


def t_shadow_discovery(ctx):
    if not connected(ctx, "defender_cloud_apps"):
        return ("Not assessed",
                "Defender for Cloud Apps is not connected, so AI used through the browser "
                "cannot be seen at all.", [])
    web = [v for v in ctx["estate"]["vendors"] if "web" in v["evidence"]]
    unsanctioned = [v for v in web if not v.get("sanctioned")]
    st, vtx = verdict(unsanctioned,
                      "1 AI service is reached through the browser without being sanctioned.",
                      "{n} AI services are reached through the browser without being sanctioned.",
                      "Every AI service seen in web traffic has been reviewed.")
    return st, vtx, [(v["vendor"], f'{v.get("users", 0)} users · {v.get("interactions", 0)} transactions')
                     for v in unsanctioned]


def t_sensitive_flow(ctx):
    if not connected(ctx, "purview_audit"):
        return ("Not assessed",
                "Purview audit is not connected, so what data reaches AI cannot be "
                "established.", [])
    bad = [v for v in ctx["estate"]["vendors"] if v.get("sensitive_types")]
    st, vtx = verdict(bad,
                      "1 AI vendor has received data carrying a sensitivity label.",
                      "{n} AI vendors have received data carrying sensitivity labels.",
                      "No labelled data has been observed reaching an AI vendor.")
    return st, vtx, [(v["vendor"], ", ".join(sorted(v["sensitive_types"]))) for v in bad]


def t_dlp_block(ctx):
    if not connected(ctx, "purview_audit"):
        return ("Not assessed",
                "Purview audit is not connected, so DLP outcomes for AI destinations "
                "are unknown.", [])
    leaked = [v for v in ctx["estate"]["vendors"]
              if v.get("sensitive_types") and not v.get("blocked")]
    st, vtx = verdict(leaked,
                      "1 AI vendor received sensitive data with nothing blocking it.",
                      "{n} AI vendors received sensitive data with nothing blocking it.",
                      "Sensitive data reaching AI is being blocked by DLP.")
    return st, vtx, [(v["vendor"], f'{v.get("interactions", 0)} interactions · 0 blocked')
                     for v in leaked]


def t_agent_inventory(ctx):
    if not connected(ctx, "agent365", "entra_agent_id"):
        return ("Not assessed",
                "Neither Agent 365 nor Entra Agent ID is connected, so agents built "
                "inside the tenant are invisible to this assessment.", [])
    agents = ctx["estate"]["unattached_agents"]
    st, v = verdict(agents,
                    "1 agent could not be attributed to a known AI vendor.",
                    "{n} agents could not be attributed to a known AI vendor.",
                    "Every discovered agent maps to a known vendor.")
    return st, v, [(a, "no vendor match") for a in agents[:12]]


def t_signin_visibility(ctx):
    unavailable = [a for a in shadow(ctx) if not (a.get("usage") or {}).get("available")]
    if unavailable:
        return ("Not assessed",
                "Sign-in logs are unavailable — real usage needs Entra ID P1. Consent "
                "counts are not usage.", [])
    return ("Passed",
            "Sign-in activity is available, so consent can be told apart from actual use.",
            [])


def t_drift(ctx):
    if not ctx["changes"]:
        return ("Not assessed",
                "Only one scan exists, so nothing can be compared yet. The first scan is "
                "the baseline.", [])
    return ("Passed",
            f'{len(ctx["changes"])} changes were detected against the previous scan, so the '
            f'estate is being tracked over time rather than photographed once.',
            [(c["asset_name"], c["description"]) for c in ctx["changes"][:8]])


def t_high_reach(ctx):
    bad = [a for a in shadow(ctx)
           if a.get("user_count", 0) >= 250 and a.get("risk_score", 0) >= 60]
    st, v = verdict(bad,
                    "1 high-risk AI application reaches more than 250 people.",
                    "{n} high-risk AI applications each reach more than 250 people.",
                    "No high-risk AI application has organisation-wide reach.")
    return st, v, rows(bad, lambda a: f'{a.get("user_count")} users · risk {a.get("risk_score")}')


def t_duplicate_vendor(ctx):
    dupes = [v for v in ctx["estate"]["vendors"] if len(v.get("oauth_apps", [])) > 1]
    st, vtx = verdict(dupes,
                      "1 vendor holds more than one consented application.",
                      "{n} vendors hold more than one consented application each.",
                      "No vendor has duplicate consented applications.")
    return st, vtx, [(v["vendor"], f'{len(v["oauth_apps"])} applications') for v in dupes]


def t_both_routes(ctx):
    both = [v for v in ctx["estate"]["vendors"] if {"oauth", "web"} <= v["evidence"]]
    st, vtx = verdict(both,
                      "1 vendor is reached both by consented app and through the browser.",
                      "{n} vendors are reached both by consented app and through the browser — "
                      "revoking consent alone would not cut them off.",
                      "No vendor has a second, unmanaged route into the tenant.")
    return st, vtx, [(v["vendor"], "OAuth consent + browser traffic") for v in both]


TESTS = [
    # id, name, pillar, risk, user impact, effort, requirement, fn, checked, recommendation, actions
    ("AISPM-1001", "AI applications do not hold org-wide consent for sensitive data",
     P_ID, "High", "Medium", "Medium", "Directory.Read.All", t_admin_consent,
     ["Admin consent grants a permission on behalf of every person in the tenant at once. "
      "When the permission is a sensitive one — mail, files, sites, directory — a single "
      "consent decision hands a third party a copy of the organisation's data, and no "
      "individual user is ever asked.",
      "The test looks at each AI application's OAuth grants, keeps the ones consented for "
      "AllPrincipals, and fails when any of those carries a permission from the sensitive "
      "set. Per-user consent on the same permission is reported separately and at a lower "
      "risk, because its blast radius is one person."],
     "Review each org-wide grant and re-consent per user, or scope the application to a "
     "group. Where the application genuinely needs org-wide access, record the business "
     "owner and the approval so the grant stops being anonymous.",
     [("Enterprise applications — Permissions", "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade"),
      ("Review admin consent requests", "https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow")]),

    ("AISPM-1002", "No AI application holds unattended (app-only) access",
     P_ID, "High", "Low", "Medium", "Application.Read.All", t_app_only,
     ["App-only permissions belong to the application itself, not to a person. They work "
      "at 3am, they survive the departure of whoever installed them, and no Conditional "
      "Access policy written for users applies to them.",
      "The test reads appRoleAssignments for each AI service principal and resolves the "
      "role IDs to names. Any assignment at all fails the test; the panel lists the exact "
      "roles so a reviewer can tell a narrow one from a tenant-wide one."],
     "Remove app-only roles that are not required. Where unattended access is genuinely "
     "needed, restrict it — for Exchange, an application access policy limits the "
     "application to named mailboxes instead of all of them.",
     [("Application permissions", "https://learn.microsoft.com/graph/permissions-reference"),
      ("Limit application access to mailboxes", "https://learn.microsoft.com/graph/auth-limit-mailbox-access")]),

    ("AISPM-1003", "No AI application can write to every file in the tenant",
     P_ID, "High", "High", "Medium", "Directory.Read.All", t_write_all_files,
     ["Files.ReadWrite.All is the widest data permission in Microsoft 365: it covers every "
      "SharePoint site and every OneDrive, including the ones the person who consented has "
      "never heard of. Read access leaks; write access also lets an application modify or "
      "destroy what it can see.",
      "The test checks delegated scopes and application roles for tenant-wide file write. "
      "Site-scoped alternatives exist — Sites.Selected in particular — so a failure here "
      "is usually a permission that was never narrowed rather than one that had to be wide."],
     "Move the application to Sites.Selected and grant it only the sites it needs. If the "
     "vendor does not support scoped access, that is a procurement question worth raising.",
     [("Sites.Selected permission", "https://learn.microsoft.com/sharepoint/dev/solution-guidance/security-apponly-azuread")]),

    ("AISPM-1004", "No AI application can read the whole directory",
     P_ID, "Medium", "Low", "Low", "Directory.Read.All", t_directory_read,
     ["Directory.Read.All and User.Read.All return every user, group and membership in the "
      "tenant. For an AI vendor this is an org chart — names, titles, managers, email "
      "addresses — which is exactly the raw material for convincing phishing.",
      "The test looks for directory-wide read in both delegated scopes and application "
      "roles. Applications that read only the signed-in user's profile pass."],
     "Replace directory-wide read with User.Read where the application only needs the "
     "current user, or scope it to a group.",
     [("Least privilege for applications", "https://learn.microsoft.com/entra/identity-platform/secure-least-privileged-access")]),

    ("AISPM-1005", "No AI application can send mail as your users",
     P_ID, "High", "Medium", "Low", "Directory.Read.All", t_mail_send,
     ["Mail.Send lets an application send messages that arrive from a real internal "
      "address, pass SPF and DKIM, and carry the sender's signature. An AI tool with this "
      "permission is a phishing platform with your own domain attached.",
      "The test fails on any AI application holding Mail.Send as a delegated scope or an "
      "application role."],
     "Remove Mail.Send unless the workflow genuinely requires it. Where it is required, "
     "scope the application to a single service mailbox with an application access policy.",
     [("Application access policies", "https://learn.microsoft.com/exchange/permissions-exo/application-rbac")]),

    ("AISPM-1006", "Third-party AI applications come from verified publishers",
     P_ID, "Medium", "Low", "Low", "Directory.Read.All", t_verified_publisher,
     ["Publisher verification means Microsoft has confirmed the developer's identity "
      "against a real, verified organisation. It is a weak signal on its own, but its "
      "absence on an application already holding data permissions is worth a question: "
      "impersonating a known AI brand is a standard consent-phishing move.",
      "The test fails for any third-party application whose service principal has no "
      "verified publisher. Applications registered inside your own tenant are excluded."],
     "Confirm each unverified publisher against the vendor you believe you are dealing "
     "with. Consider a consent policy that only allows applications from verified publishers.",
     [("Publisher verification", "https://learn.microsoft.com/entra/identity-platform/publisher-verification-overview"),
      ("App consent policies", "https://learn.microsoft.com/entra/identity/enterprise-apps/manage-app-consent-policies")]),

    ("AISPM-1007", "Refresh tokens are granted deliberately",
     P_ID, "Low", "Low", "Low", "Directory.Read.All", t_offline_access,
     ["offline_access is what lets an application keep working after the user closes the "
      "browser — it holds a refresh token and renews its own access. That is normal for a "
      "background integration and unnecessary for a tool a person uses interactively.",
      "This test does not assume a failure is wrong. It exists so the set of applications "
      "with persistent access is a list somebody has actually read, rather than a default "
      "nobody noticed."],
     "Read the list. Where a tool is only used interactively, the refresh token is "
     "unnecessary persistence and the grant can be narrowed.",
     [("Refresh tokens", "https://learn.microsoft.com/entra/identity-platform/refresh-tokens")]),

    ("AISPM-1008", "AI service principals do not hold long-lived credentials",
     P_ID, "Medium", "Low", "Medium", "Application.Read.All", t_credentials,
     ["A client secret is a password that does not expire on its own, is often pasted into "
      "a pipeline, and is rarely rotated. Certificates are better; workload identity "
      "federation is better still, because there is no stored secret at all.",
      "The test counts credentials on each AI service principal and reports the nearest "
      "expiry where one exists."],
     "Move to workload identity federation where the vendor supports it, and put an expiry "
     "and an owner on every credential that remains.",
     [("Workload identity federation", "https://learn.microsoft.com/entra/workload-id/workload-identity-federation")]),

    ("AISPM-2001", "Sensitive data reaching AI is blocked by DLP",
     P_DATA, "High", "Medium", "High", "Purview audit", t_dlp_block,
     ["Knowing that labelled data reached an AI vendor is a finding. Knowing that nothing "
      "stopped it is the finding that matters — it is the difference between a policy that "
      "exists and a policy that works.",
      "The test pairs Purview's record of what reached each AI destination with whether a "
      "DLP policy blocked it. A vendor that received sensitive content with zero blocks "
      "fails; a vendor whose traffic was blocked is scored at zero risk on purpose."],
     "Extend DLP policies to cover generative AI destinations, then re-run. A block that "
     "appears here is the cheapest evidence that the control is live.",
     [("DLP for generative AI", "https://learn.microsoft.com/purview/dlp-learn-about-dlp")]),

    ("AISPM-2002", "What sensitive data reaches AI is known",
     P_DATA, "High", "Low", "High", "Purview audit", t_sensitive_flow,
     ["The question a board asks is not how many AI tools exist, it is which of them saw "
      "regulated data. That cannot be inferred from permissions — a permission says what "
      "could be read, not what was.",
      "The test reads Purview audit interactions per AI destination and groups them by "
      "sensitive information type. Without the connector it reports Not assessed rather "
      "than an empty list, because zero and unknown are not the same answer."],
     "Connect Purview audit and re-run. Until then, treat every permission-based finding "
     "as an upper bound on exposure rather than a measurement of it.",
     [("Purview audit", "https://learn.microsoft.com/purview/audit-solutions-overview")]),

    ("AISPM-2003", "No vendor has a second, unmanaged route into the tenant",
     P_DATA, "High", "Medium", "Medium", "Defender for Cloud Apps", t_both_routes,
     ["A vendor reached both by a consented application and through the browser has two "
      "doors. Revoking the OAuth grant closes one and leaves the other open, which is how "
      "a remediation gets signed off while the data keeps flowing.",
      "The test correlates the OAuth estate with browser traffic observed by Defender for "
      "Cloud Apps, by vendor rather than by application ID — Defender's records carry "
      "neither an appId nor a domain, so an ID-based merge would invent a correlation that "
      "is not in the data."],
     "For each vendor listed, close both routes together: revoke consent and block or "
     "sanction the web destination in Defender for Cloud Apps in the same change.",
     [("Govern discovered apps", "https://learn.microsoft.com/defender-cloud-apps/governance-discovery")]),

    ("AISPM-2004", "AI used through the browser has been reviewed",
     P_DATA, "Medium", "Low", "Medium", "Defender for Cloud Apps", t_shadow_discovery,
     ["Most Shadow AI never asks for consent. Somebody pastes a document into a chat box, "
      "and no OAuth grant, no application object and no audit record in Entra ever exists.",
      "The test lists AI destinations seen in proxy or endpoint traffic that have not been "
      "tagged sanctioned or unsanctioned. An untagged destination is not a verdict — it is "
      "a decision nobody has made."],
     "Tag each AI destination sanctioned or unsanctioned in Defender for Cloud Apps. The "
     "tag is what later lets a policy act automatically.",
     [("Discovered apps", "https://learn.microsoft.com/defender-cloud-apps/discovered-apps")]),

    ("AISPM-3001", "Every AI application has a business owner",
     P_GOV, "Medium", "Low", "Low", "—", t_owner,
     ["An unowned application has nobody to ask at 2am. It is also the reason findings sit "
      "open: a finding with no owner is a finding with no due date.",
      "The test reads the business owner from AI-SPM's own metadata store, which survives "
      "every scan. Service principal owners in Entra are shown alongside but do not count "
      "— a technical owner is not accountable for the business decision."],
     "Assign an owner on the Governance page. It persists across scans and each change is "
     "recorded on the timeline.",
     []),

    ("AISPM-3002", "Every AI application has a decided lifecycle state",
     P_GOV, "Medium", "Medium", "Low", "—", t_lifecycle,
     ["Discovered means the tool found it and no human has ruled on it. An estate where "
      "everything is Discovered is an inventory, not a governance programme.",
      "The test counts applications still at Discovered or Unknown. Approved, Pilot, "
      "Restricted, Blocked and Retired all pass — the test is about a decision existing, "
      "not about which decision it was."],
     "Work the list top-down by user count: the tools most people already use are the ones "
     "where an unstated decision costs the most.",
     []),

    ("AISPM-3003", "Every discovered application has been classified",
     P_GOV, "Medium", "Low", "Low", "—", t_classification,
     ["An application AI-SPM cannot classify is not therefore safe. Unknown is routed to a "
      "review queue precisely so it never quietly counts as approved.",
      "Classification ranks its signals: a manual override beats a catalogue app ID, which "
      "beats a publisher or domain match, which beats a generic name pattern. The "
      "confidence percentage in the panel is that ranking made visible."],
     "Classify each entry manually. A manual classification is stored as an override and "
     "outranks every automatic signal from then on.",
     []),

    ("AISPM-3004", "Lifecycle reviews are up to date",
     P_GOV, "Low", "Low", "Low", "—", t_review_overdue,
     ["A review date that has passed is the governance equivalent of an expired "
      "certificate: the control was designed, it just is not running.",
      "The test compares each application's next review date with today."],
     "Complete the review and set the next date. Both actions are recorded in the history "
     "for that application.",
     []),

    ("AISPM-3005", "No blocked application is still in use",
     P_GOV, "High", "High", "Low", "AuditLog.Read.All", t_blocked_in_use,
     ["A tool marked Blocked that still shows active users means the decision was recorded "
      "and never enforced. This is the single clearest gap between policy and reality that "
      "AI-SPM can measure.",
      "The test pairs the lifecycle state a human set with sign-in activity from the audit "
      "log over the last 30 days."],
     "Enforce it technically: revoke the consent, disable the service principal, or block "
     "the destination. A lifecycle state is a record, not a control.",
     []),

    ("AISPM-3006", "Every agent has a stated business purpose",
     P_GOV, "Medium", "Low", "Low", "Agent 365", t_agents_purpose,
     ["An agent acts on its own. Without a recorded purpose there is no way to judge later "
      "whether what it did was in scope.",
      "The test covers assets classified as agents rather than applications, and reads the "
      "purpose from the metadata store."],
     "Record a purpose and an owner for each agent before it moves out of pilot.",
     []),

    ("AISPM-4001", "No unused application retains high privilege",
     P_SURF, "Medium", "Low", "Low", "AuditLog.Read.All", t_unused_privileged,
     ["An application nobody uses still holds its permissions. It is pure attack surface: "
      "all of the risk, none of the business value, and nobody watching it.",
      "The test crosses 30-day sign-in activity with the risk score, so it only fires "
      "where the dormancy actually matters."],
     "Remove the consent. This is the cheapest remediation in the whole assessment — "
     "there is no user to migrate and no workflow to redesign.",
     []),

    ("AISPM-4002", "Every consented application has actually been used",
     P_SURF, "Low", "Low", "Low", "AuditLog.Read.All", t_never_used,
     ["A consented application that has never been signed in to is often a trial somebody "
      "authorised and abandoned. The grant outlives the interest in the product.",
      "The test looks for applications with no recorded sign-in at all, delegated or "
      "service principal."],
     "Revoke these grants. If the tool is later needed, consenting again takes a minute.",
     []),

    ("AISPM-4003", "No high-risk AI application has organisation-wide reach",
     P_SURF, "High", "Medium", "Medium", "Directory.Read.All", t_high_reach,
     ["Risk and reach multiply. A high-risk application used by four people is contained; "
      "the same application in front of five hundred is an incident waiting for a trigger.",
      "The test combines the transparent risk score with the number of people holding a "
      "grant — the same pair of axes the triage chart on the overview plots."],
     "Work these first. They are the top-right corner of the triage chart and the shortest "
     "path to lowering the tenant posture score.",
     []),

    ("AISPM-4004", "AI adoption is not spreading unreviewed",
     P_SURF, "Medium", "Low", "Low", "AuditLog.Read.All", t_growth,
     ["A tool doubling its users in a week is a tool that is about to be everywhere. "
      "Governing it while it has thirty users is a conversation; governing it at three "
      "hundred is a migration.",
      "The test compares the last seven days of active users with the preceding period."],
     "Get ahead of the curve: decide the lifecycle state now, while the population is "
     "small enough that a rejection is still cheap.",
     []),

    ("AISPM-4005", "No vendor holds duplicate consented applications",
     P_SURF, "Low", "Low", "Low", "Directory.Read.All", t_duplicate_vendor,
     ["Two applications from one vendor usually means two consent events, two permission "
      "sets and one forgotten grant. Revoking the obvious one leaves the other in place.",
      "The test groups the OAuth estate by vendor through the AI catalogue and reports any "
      "vendor holding more than one application object."],
     "Consolidate onto one application and revoke the rest.",
     []),

    ("AISPM-5001", "Real usage can be told apart from consent",
     P_MON, "High", "Low", "Medium", "Entra ID P1", t_signin_visibility,
     ["Consent counts measure permission; sign-in logs measure behaviour. Without the "
      "second, an application 500 people authorised two years ago and nobody has opened "
      "since looks identical to one in daily use.",
      "The test checks whether sign-in activity could be read at all. Entra ID P1 is "
      "required for the sign-in logs API; without it the assessment continues, but every "
      "usage-based test degrades to Not assessed."],
     "Confirm Entra ID P1 licensing and that the scanning identity holds "
     "AuditLog.Read.All. This one prerequisite unlocks five other tests.",
     [("Sign-in logs", "https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins")]),

    ("AISPM-5002", "Agents built inside the tenant are inventoried",
     P_MON, "Medium", "Low", "High", "Agent 365", t_agent_inventory,
     ["Third-party AI arrives by consent and is visible in Entra. Agents built in Copilot "
      "Studio or Foundry never appear there at all — they are a separate estate with a "
      "separate blind spot.",
      "The test reports agents discovered through Agent 365 or Entra Agent ID that could "
      "not be attributed to a known vendor. Note the deliberate rule: an agent attaches to "
      "a vendor, it never creates one, because the Agent 365 catalogue is the tenant's "
      "whole Teams app list."],
     "Connect Agent 365 and Entra Agent ID. Where they cannot be connected, say so in the "
     "report — an uninventoried estate is a finding, not a blank section.",
     []),

    ("AISPM-5003", "The estate is tracked over time, not photographed once",
     P_MON, "Medium", "Low", "Low", "—", t_drift,
     ["A posture score on its own says nothing about direction. The useful question is "
      "what changed since last week: a new application, a consent escalated from one user "
      "to the whole organisation, an application that suddenly gained unattended access.",
      "The test confirms a previous snapshot exists and a diff was produced. The first "
      "scan is the baseline and deliberately emits no events — inventing changes on the "
      "first run would make every deployment look like a breach."],
     "Deploy the scheduled scan so the timeline keeps filling. A single manual scan gives "
     "a position; a schedule gives a trend.",
     []),
]


RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2}
# Failures first, then the gaps in visibility, then what is already fine — a reader who
# stops after the first screen should have seen the things that need them.
STATUS_ORDER = {FAILED: 0, NOT_ASSESSED: 1, PASSED: 2, SKIPPED: 3}


def run(apps, estate=None, health=None, changes=None, now=None) -> list:
    """Evaluates the whole catalogue. A broken test degrades to Skipped, never raises."""
    ctx = context(apps, estate, health, changes, now)
    out = []
    for (tid, name, pillar, risk, impact, effort, req, fn,
         checked, recommendation, actions) in TESTS:
        try:
            status, verdict_text, assets = fn(ctx)
        except Exception as exc:                    # one bad test must not blank the page
            status, verdict_text, assets = SKIPPED, "This test could not run: %s" % exc, []
        out.append({"id": tid, "name": name, "pillar": pillar, "risk": risk,
                    "impact": impact, "effort": effort, "requirement": req,
                    "status": status, "verdict": verdict_text, "assets": assets,
                    "checked": checked, "recommendation": recommendation,
                    "actions": actions})
    out.sort(key=lambda t: (STATUS_ORDER[t["status"]], RISK_ORDER[t["risk"]], t["name"]))
    return out


def summary(results) -> dict:
    """What the assessment says about itself: by status, by pillar, by risk."""
    by_status = {s: 0 for s in STATUSES}
    by_pillar = {p: {"passed": 0, "total": 0} for p in PILLARS}
    for t in results:
        by_status[t["status"]] = by_status.get(t["status"], 0) + 1
        p = by_pillar.setdefault(t["pillar"], {"passed": 0, "total": 0})
        p["total"] += 1
        if t["status"] == PASSED:
            p["passed"] += 1
    return {"total": len(results), "by_status": by_status, "by_pillar": by_pillar,
            "failed_high": sum(1 for t in results
                               if t["status"] == FAILED and t["risk"] == "High"),
            "assessable": len(results) - by_status.get(NOT_ASSESSED, 0)}
