# AI-SPM — Shadow AI Posture Management

**Discover, risk-score, and continuously track the third-party AI applications your
organization has granted access to — straight from Entra ID and Microsoft Graph.**

AI-SPM surfaces the fastest-growing and least-governed attack surface in the modern
enterprise: employees signing into external AI services ("Sign in with Microsoft")
and consenting them to sensitive data such as `Mail.Read` or `Files.ReadWrite.All`.
It runs as a scheduled Azure Function, authenticates with a Managed Identity (no
secrets), and produces a ranked, explainable posture report on every run.

> **100% read-only.** AI-SPM never revokes a permission, deletes an app, or changes a
> setting. It observes, scores, and reports — remediation decisions stay with your team.

---

## Key capabilities

- **Automated discovery** — enumerates every third-party AI application connected to
  your tenant (ChatGPT, Gemini, Glean, Grammarly, Otter, and more) via OAuth consent.
- **Explainable risk scoring** — a transparent 0–100 score per app/agent/finding, driven
  by additive, named factors (data-scope sensitivity, blast radius, publisher trust,
  persistence). Every score ships with the exact list of reasons that produced it.
- **Actionable remediation** — concrete, prioritized next steps for each finding.
- **Secretless & scheduled** — daily automated scans using a system-assigned Managed
  Identity; findings published to Blob Storage as a self-contained HTML report plus JSON.
- **On-demand API** — an HTTP endpoint to trigger a scan and retrieve a summary at any time.
- **Microsoft AI Data Sources (optional, opt-in)** — a second, richer dashboard fed by
  four Microsoft-native connectors (Agent 365, Entra Agent ID, Defender for Cloud Apps,
  Purview Audit): a multi-page assessment with flow diagrams, an MDCA-style traffic grid
  per Shadow AI app, and a transparent risk score for every agent/app/finding. Off by
  default — see **[Part 2](#part-2--microsoft-ai-data-sources-optional)** below.

---

## Setup roadmap

Two independent parts. Part 1 is the core product; Part 2 is optional and adds nothing
until you explicitly turn it on.

| # | Step | Where |
| - | --- | --- |
| 1 | Deploy the infrastructure (one click) | [Part 1, Step 1](#step-1--deploy-the-infrastructure) |
| 2 | Run the post-deploy script (code + core Graph permissions) | [Part 1, Step 2](#step-2--post-deploy-script) |
| 3 | Trigger the first scan and view the dashboard | [Part 1, Step 3](#step-3--first-scan--dashboard) |
| 4 | *(optional)* Set up the weekly email digest | [Part 1, Step 4](#step-4--optional-weekly-email-digest) |
| 5 | *(optional)* Grant the extra Microsoft AI Data Sources permissions | [Part 2, Step 5](#step-5--grant-the-extra-permissions) |
| 6 | *(optional)* Turn the four connectors on | [Part 2, Step 6](#step-6--turn-the-connectors-on) |
| 7 | *(optional)* View the Microsoft AI Data Sources dashboard | [Part 2, Step 7](#step-7--view-the-dashboard) |

---

## Part 1 — Core scan (Entra ID / OAuth consent)

### Step 1 — Deploy the infrastructure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMSalikoc%2Fai-spm-shadow-ai%2Fmain%2Fdeploy%2Fazuredeploy.json)

One click provisions everything: Function App, system-assigned Managed Identity, and
Storage account. The portal form asks for the target tenant, scan schedule, and report
container name — fill those in and click Create.

### Step 2 — Post-deploy script

In **Azure Cloud Shell** (or any terminal with `az` logged into the subscription):

```bash
git clone https://github.com/MSalikoc/ai-spm-shadow-ai.git
cd ai-spm-shadow-ai
```

Then set these two lines to your own resource group and Function App name — you'll find
both on the deployment's **Overview** page in the Azure Portal — and run them together
with the command below:

```bash
RESOURCE_GROUP="aispm-rg"
FUNCTION_APP="aispm-xxxxxxxxxx"

./scripts/postdeploy.sh "$RESOURCE_GROUP" "$FUNCTION_APP"
```

> **Only edit the text inside the quotes** on the `RESOURCE_GROUP=` and `FUNCTION_APP=`
> lines. Every command in the rest of this guide reuses `$RESOURCE_GROUP` and
> `$FUNCTION_APP` — set them once per Cloud Shell session and every copy-pasted block
> below just works. (If you ever see a literal `<...>` placeholder anywhere, replace the
> whole `<...>` including the angle brackets — but this guide no longer uses that style
> for anything you'd paste into a terminal.)

This does two things:
1. Deploys the application code (`func azure functionapp publish`, remote build — Linux
   Consumption doesn't support URL-based run-from-package).
2. Grants the Managed Identity three read-only Graph **application** permissions:
   `Directory.Read.All`, `Application.Read.All`, `AuditLog.Read.All`.

> Step 2 requires a directory role that can grant application permissions
> (Privileged Role Administrator or Global Administrator). If you don't have it, ask
> whoever does to run this one command — everything else needs no special access.

### Step 3 — First scan & dashboard

Trigger a scan immediately (or just wait — it also runs daily at 06:00 UTC):

```bash
KEY=$(az functionapp keys list -g "$RESOURCE_GROUP" -n "$FUNCTION_APP" --query functionKeys.default -o tsv)
curl -s "https://$FUNCTION_APP.azurewebsites.net/api/scan?code=$KEY" ; echo
```

Then print the dashboard URL and open it in a browser:

```bash
echo "https://$FUNCTION_APP.azurewebsites.net/api/report?code=$KEY"
```

That's the whole core product working. Everything below is optional.

### Step 4 — *(optional)* Weekly email digest

Sends a weekly posture summary (headline numbers, notable findings, dashboard link) via
Microsoft Graph `sendMail` — no SMTP secrets, sent by the Managed Identity.

```bash
az functionapp config appsettings set -g "$RESOURCE_GROUP" -n "$FUNCTION_APP" --settings \
  AISPM_MAIL_SENDER="secops@contoso.com" \
  AISPM_MAIL_TO="team@contoso.com,ciso@contoso.com" \
  AISPM_REPORT_URL="https://$FUNCTION_APP.azurewebsites.net/api/report?code=$KEY"
```

Replace `secops@contoso.com` and `team@contoso.com,ciso@contoso.com` with your own sender
and recipient addresses (keep the quotes, no angle brackets anywhere here).

`Mail.Send` was already granted in Step 2 — but that permission can send as *any*
mailbox, so restrict it to your sender. This one runs in **PowerShell**, not the bash
Cloud Shell — switch to it (Cloud Shell has a PowerShell/Bash toggle), then set the same
two values in quotes:

```powershell
$AppId = "PASTE_MANAGED_IDENTITY_APP_ID_HERE"
$MailGroup = "PASTE_MAIL_ENABLED_GROUP_CONTAINING_SENDER_HERE"
New-ApplicationAccessPolicy -AppId $AppId `
  -PolicyScopeGroupId $MailGroup `
  -AccessRight RestrictAccess -Description "AI-SPM digest sender only"
```

Test it:

```bash
curl "https://$FUNCTION_APP.azurewebsites.net/api/digest?code=$KEY"
```

### Configuration reference (Part 1)

| Setting | Default | Description |
| --- | --- | --- |
| `AISPM_TENANT_ID` | deployment tenant | Entra tenant to scan |
| `SCAN_SCHEDULE` | `0 0 6 * * *` | NCRONTAB scan schedule (sec min hour day month dow) |
| `REPORT_CONTAINER` | `aispm-reports` | Blob container for published reports |
| `EMAIL_SCHEDULE` | `0 0 8 * * 1` | Weekly digest schedule (default Mon 08:00 UTC) |
| `AISPM_MAIL_SENDER` | — | Sender mailbox (UPN) for the weekly digest |
| `AISPM_MAIL_TO` | — | Recipient(s), comma-separated |
| `AISPM_REPORT_URL` | — | Full `/api/report` URL used for the dashboard button |

What counts as an "AI application" and how each permission is weighted is defined in a
single place — [`config.py`](config.py) — so the catalog and scoring policy are easy to
tune to your environment.

### Running a scan from a workstation (no deployment needed)

For a one-off scan against a tenant without deploying anything:

```bash
pip install -r requirements.txt
python main.py --tenant YOUR_TENANT_ID --client-id YOUR_APP_ID     # interactive device-code sign-in
```

Replace `YOUR_TENANT_ID` and `YOUR_APP_ID` with your own values (no angle brackets).

---

## Part 2 — Microsoft AI Data Sources (optional)

Part 1 answers *"which third-party AI apps have OAuth access, and how risky is that
access?"* Part 2 adds four more Microsoft-native sources to answer a different
question: **which AI application or agent actually handled sensitive data, how much
traffic did it generate, and was that data blocked or allowed?**

| Connector | Source | What it discovers |
| --- | --- | --- |
| **Agent 365** | `copilot/admin/catalog/packages` | Registered Copilot/agent packages — build type, blocked state, deployment scope |
| **Entra Agent ID** | `servicePrincipals/…agentIdentity` + blueprints | Agent identities: owners, sponsors, app-only vs. delegated permissions |
| **Defender for Cloud Apps** | `dataDiscovery/cloudAppDiscovery` (beta) | Shadow AI usage: which AI sites, traffic/users/devices/IP counts, sanctioned state |
| **Purview Audit** | `security/auditLog/queries` | Sensitive-data AI interactions: SIT, sensitivity label, DLP action, direction |

**It is entirely opt-in.** Every connector is gated by its own environment variable and
defaults to off. With nothing enabled, Part 2 has **zero effect** on Part 1 — none of
that code is touched (see [What Part 2 doesn't touch](#what-part-2-deliberately-does-not-touch)).

### The dashboard you get

> **See it before you deploy anything:** [**docs/sample-report.html**](docs/sample-report.html)
> is a full, interactive example built with realistic mock data (10 agents, 18 Shadow AI
> apps, 33 sensitive interactions) using the real rendering code — nothing hand-drawn.
> [Open it rendered](https://htmlpreview.github.io/?https://github.com/MSalikoc/ai-spm-shadow-ai/blob/main/docs/sample-report.html)
> or download the file and open it in any browser. It's clearly marked as sample data —
> your own deployment shows your tenant's real numbers.

One page, six tabs, all served from a single endpoint (`/api/connectors?format=html`):

- **Overview** — headline KPIs, a findings-by-severity donut, two flow diagrams
  (Shadow AI: sanction status → risk; Agent Identity: owner/sponsor coverage → risk),
  and the 5 highest-scoring items across every source.
- **Agents** — Agent 365 packages + Entra Agent Identities, each with a transparent
  0–100 risk score.
- **Shadow AI** — a traffic grid styled like Defender for Cloud Apps' own *Discovered
  apps* view: Risk Score, Tag (Sanctioned/Unsanctioned), Traffic, Upload, Transactions,
  Users, IP Addresses, Devices, Last Seen.
- **Sensitive Data** — the "Applications with Sensitive Data Exposure" table plus the
  Purview interaction log.
- **Findings** — every finding, scored and explained the same way.
- **Gaps** — an honest list of what each connector could *not* see (never fabricated).

Click any row anywhere to open a detail panel: **facts → risk score with its full
point-by-point breakdown → result → what was checked → remediation action.** A score
of, say, 65 always comes with the exact reasons that add up to it — never a bare number.

### Step 5 — Grant the extra permissions

> **Cloud Shell resets its variables after ~20 minutes idle** (the files stay, but
> `$RESOURCE_GROUP`/`$FUNCTION_APP` don't). If it's been a while since Step 2, or you see
> a `Kullanim: ... <RESOURCE_GROUP> <FUNCTION_APP_NAME>` usage error below, set the two
> lines again first — same as in Step 2:
> ```bash
> RESOURCE_GROUP="aispm-rg"
> FUNCTION_APP="aispm-xxxxxxxxxx"
> ```

```bash
MI=$(az resource show -g "$RESOURCE_GROUP" -n "$FUNCTION_APP" --resource-type "Microsoft.Web/sites" --query identity.principalId -o tsv)
echo "$MI"
```

`echo "$MI"` should print a GUID. If it's empty or `az` errors out, get it from the
**Portal instead**: your Function App → left menu **Identity** → **System assigned** tab
→ copy the **Object (principal) ID**, then set `MI="paste-it-here"` yourself before
continuing.

```bash
./scripts/grant_connector_roles.sh "$MI"
```

This grants 5 read-only Graph application roles (`CopilotPackages.Read.All`,
`Application.Read.All`, `Directory.Read.All`, `CloudApp-Discovery.Read.All`,
`AuditLogsQuery.Read.All`). Two of them may already be granted from Step 2 — the script
is safe to re-run, it just skips those.

> Requires the same directory role as Step 2 (Privileged Role Administrator / Global
> Administrator).

### Step 6 — Turn the connectors on

```bash
./scripts/enable_connectors.sh "$RESOURCE_GROUP" "$FUNCTION_APP"
```

Sets the five `ENABLE_*` application settings and restarts the Function App. Give it a
couple of minutes — both the app restart and the Graph role propagation from Step 5
need a little time.

### Step 7 — View the dashboard

```bash
echo "https://$FUNCTION_APP.azurewebsites.net/api/connectors?code=$KEY&format=html"
```

Open the printed URL in a browser. Or drop `&format=html` from it to get the same data
as JSON for scripting/integration.

If a connector still shows `PERMISSION_MISSING` after a few minutes, the two most common
causes are: Microsoft 365 Copilot isn't licensed in the tenant (blocks Agent 365), or
Microsoft Purview **Audit (Standard/Premium)** recording isn't turned on in the
[Purview compliance portal](https://purview.microsoft.com) (blocks Purview Audit) —
neither is a bug in this connector, both are tenant-side prerequisites.
`LICENSE_MISSING` (e.g. Defender for Cloud Apps) means the tenant doesn't hold that
license — shown honestly, never faked.

### Configuration reference (Part 2)

| Setting | Default | Description |
| --- | --- | --- |
| `ENABLE_AGENT365` | off | Agent 365 package/agent inventory |
| `ENABLE_ENTRA_AGENT_ID` | off | Entra Agent Identity + blueprint inventory |
| `ENABLE_DEFENDER_CLOUD_APPS` | off | Shadow AI usage discovery (needs `ENABLE_PREVIEW_CONNECTORS=true` too — beta Graph API) |
| `ENABLE_PREVIEW_CONNECTORS` | off | Unlocks beta/preview Graph endpoints (currently only Defender for Cloud Apps) |
| `ENABLE_PURVIEW_AUDIT` | off | Sensitive AI-interaction audit records |
| `STORE_RAW_AI_CONTENT` | off | If `true`, persists raw prompt/response text with each interaction — **leave off**; every score/coverage field works without it |
| `PURVIEW_DSPM_IMPORT_PATH` | — | Optional: path to a manually exported Purview DSPM JSON/CSV file, imported as a fifth, separate source |

> **`PURVIEW_DSPM_IMPORT_PATH` is hidden from the dashboard on purpose — skip it.** There
> is no Graph/API endpoint for DSPM analytics, so this can only read a file that's
> manually placed on the Function App's own disk (via Kudu); there's no upload button and
> no simple way to wire it in. Since it's not something a normal setup can actually use, it
> doesn't appear as a row in the dashboard's coverage list or gap notes, so it never shows
> up as a confusing permanently-empty item. **Sensitive-data detection does not depend on
> it at all** — that's handled entirely by the Purview **Audit** connector above
> (`ENABLE_PURVIEW_AUDIT`), which is fully automatic. This setting only exists for the rare
> case where someone wants to feed in an extra, manually-exported DSPM report on top of
> that — safe to ignore.

### What Part 2 deliberately does *not* touch

`report.py`, `executive.py`, `drift.py`, and the `daily_scan`/`weekly_digest`/`scan_now`/
`digest_now` endpoints from Part 1 are **unmodified**. Part 2's dashboard
(`connectors_report.py`) and change-tracking (`connectors_drift.py`) live in their own
files behind their own endpoint — so turning Part 2 on or off can never break Part 1.

---

## Architecture

```
function_app.py              Azure Function entry points (timers + HTTP routes)
pipeline.py                  Part 1 scan flow, plus the opt-in Part 2 entry point
collectors.py, scoring.py    Part 1: OAuth-consent discovery + transparent risk scoring
report.py, executive.py      Part 1: HTML dashboard + executive KPIs
findings.py, drift.py        Part 1: managed findings + change-tracking
notify.py                    Part 1: weekly email digest

connectors/                  Part 2: the four connectors + correlation engine
connectors_report.py         Part 2: the assessment dashboard (6-tab, /api/connectors)
connectors_drift.py          Part 2: change-tracking (parallel to drift.py, untouched)

auth.py, graph_client.py,    shared: authentication, Graph client, tunable AI-app catalog
config.py
deploy/                      ARM template (one-click Deploy to Azure)
scripts/                     setup scripts for Step 2 and Steps 5-6
.github/                     CI/CD (auto-deploy on push to main)
```

## Local testing

```bash
pip install -r requirements.txt pytest
python -m compileall -q .                     # syntax check
python -c "import function_app"               # import smoke (catches missing modules)
pytest                                        # unit + smoke tests
```

CI runs the same checks on every pull request (`.github/workflows/ci.yml`), and the deploy
workflow runs them before deploying — a failing test blocks deployment.

## Continuous deployment (optional)

Pushes to `main` auto-deploy to your Function App via GitHub Actions. To enable it on
your own deployment, set once:

- Repository **variable** `AZURE_FUNCTIONAPP_NAME` = your function app name
- Repository **secret** `AZURE_FUNCTIONAPP_PUBLISH_PROFILE` = the app's publish profile
  (`az functionapp deployment list-publishing-profiles -g "$RESOURCE_GROUP" -n "$FUNCTION_APP" --xml`)

Without these, the deploy workflow is skipped — the one-click button + `postdeploy.sh`
remain the primary path.

---

## Security & privacy

- **Read-only.** AI-SPM only reads directory and audit data; it makes no changes.
- **No stored secrets.** Authentication uses a system-assigned Managed Identity in Azure.
- **Least privilege.** Part 1 needs only three read-only Graph application permissions;
  Part 2 adds a few more, and only for the connectors you explicitly enable.
- **Your data stays in your tenant.** Reports are written to your own Storage account.
- **No raw AI content by default.** Sensitive-interaction records keep metadata (user,
  app, data type, DLP action) but never the prompt/response text itself unless you
  explicitly set `STORE_RAW_AI_CONTENT=true`.

## License

MIT
