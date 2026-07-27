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
- **Explainable risk scoring** — a transparent 0–100 score per app driven by data-scope
  sensitivity, blast radius (admin vs. user consent, number of users), publisher
  verification, and persistence (`offline_access`). Every score ships with its reasons.
- **Actionable remediation** — concrete, prioritized next steps for each finding.
- **Secretless & scheduled** — daily automated scans using a system-assigned Managed
  Identity; findings published to Blob Storage as a self-contained HTML report plus JSON.
- **On-demand API** — an HTTP endpoint to trigger a scan and retrieve a summary at any time.
- **Microsoft AI Data Sources (optional, opt-in)** — four additional Microsoft-native
  connectors — Agent 365, Entra Agent ID, Defender for Cloud Apps (Shadow AI), Purview
  Audit — correlate *which* AI app/agent handled *which* sensitive data, for how many
  users, and whether it was blocked or allowed. Off by default; see
  [Microsoft AI Data Sources](#microsoft-ai-data-sources-optional-extended-phase) below.

---

## Deploy to Azure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMSalikoc%2Fai-spm-shadow-ai%2Fmain%2Fdeploy%2Fazuredeploy.json)

One click provisions the infrastructure — Function App, system-assigned Managed Identity,
and Storage. The portal form lets you set the target tenant, scan schedule, and report
container.

### Post-deployment (one step, in Azure Cloud Shell)

Run the post-deploy script once. It deploys the application code (remote build) and grants
the Managed Identity the read-only Microsoft Graph permissions it needs.

```bash
git clone https://github.com/MSalikoc/ai-spm-shadow-ai.git
cd ai-spm-shadow-ai
./scripts/postdeploy.sh <RESOURCE_GROUP> <FUNCTION_APP_NAME>
```

The script performs:
1. `func azure functionapp publish` — deploys the code (Python is built remotely; Linux
   Consumption does not support URL-based run-from-package).
2. Assigns Graph **application** permissions to the Managed Identity:
   `Directory.Read.All`, `Application.Read.All`, `AuditLog.Read.All`.

> Assigning Graph roles requires a directory role that can grant app permissions
> (e.g. Privileged Role Administrator / Global Administrator).

Trigger the first scan immediately (or wait for the schedule):

```bash
KEY=$(az functionapp keys list -g <RESOURCE_GROUP> -n <FUNCTION_APP_NAME> --query functionKeys.default -o tsv)
curl -s "https://<FUNCTION_APP_NAME>.azurewebsites.net/api/scan?code=$KEY" ; echo
```

On each run (06:00 UTC by default) AI-SPM scans your tenant and writes `latest.html` plus
a timestamped history to the `aispm-reports` Blob container.

---

## How it works

```
[Deploy to Azure]  ──►  ARM template
        │
        ├─ Storage + Consumption plan
        └─ Function App (Python 3.11, system-assigned Managed Identity)
        ▼
[post-deploy]  postdeploy.sh  ──►  deploy code (remote build) + grant read-only Graph roles
        ▼
[daily 06:00 UTC]  timer  ──►  enumerate AI apps  ──►  map OAuth consents
                            ──►  score risk  ──►  publish HTML + JSON to Blob
```

The engine is standalone by design: it holds state, runs on a schedule, and does not
depend on any interactive session — the foundation for continuous posture tracking.

---

## Configuration

Set as Function App application settings (the template wires these up for you):

| Setting            | Default            | Description                                       |
| ------------------ | ------------------ | ------------------------------------------------- |
| `AISPM_TENANT_ID`  | deployment tenant  | Entra tenant to scan                              |
| `SCAN_SCHEDULE`    | `0 0 6 * * *`      | NCRONTAB scan schedule (sec min hour day month dow) |
| `REPORT_CONTAINER` | `aispm-reports`    | Blob container for published reports              |
| `EMAIL_SCHEDULE`   | `0 0 8 * * 1`      | Weekly digest schedule (default Mon 08:00 UTC)    |
| `AISPM_MAIL_SENDER`| —                  | Sender mailbox (UPN) for the weekly digest        |
| `AISPM_MAIL_TO`    | —                  | Recipient(s), comma-separated                     |
| `AISPM_REPORT_URL` | —                  | Full `/api/report` URL used for the dashboard button |

What counts as an "AI application" and how each permission is weighted is defined in a
single place — [`config.py`](config.py) — so the catalog and scoring policy are easy to
tune to your environment.

---

## Viewing the dashboard

The published report is served live from the Function — open one URL in a browser:

```
https://<FUNCTION_APP>.azurewebsites.net/api/report?code=<FUNCTION_KEY>
```

## Weekly email digest

AI-SPM can email a weekly posture digest (headline numbers, notable findings, and a link
to the live dashboard) via Microsoft Graph, sent by the Managed Identity — no SMTP secrets.

1. The post-deploy script already grants the Managed Identity `Mail.Send`.
2. Set the mail settings:
   ```bash
   az functionapp config appsettings set -g <RG> -n <FUNC> --settings \
     AISPM_MAIL_SENDER="secops@contoso.com" \
     AISPM_MAIL_TO="team@contoso.com,ciso@contoso.com" \
     AISPM_REPORT_URL="https://<FUNC>.azurewebsites.net/api/report?code=<KEY>"
   ```
3. **Harden `Mail.Send`** — this application permission can otherwise send as any mailbox.
   Scope it to only the sender with an Exchange application access policy:
   ```powershell
   New-ApplicationAccessPolicy -AppId <MANAGED_IDENTITY_APPID> `
     -PolicyScopeGroupId <mail-enabled-group-containing-sender> `
     -AccessRight RestrictAccess -Description "AI-SPM digest sender only"
   ```
4. Test immediately: `curl "https://<FUNC>.azurewebsites.net/api/digest?code=<KEY>"`

---

## Microsoft AI Data Sources (optional, extended phase)

The core scan above answers *"which third-party AI apps have OAuth access, and how
risky is that access?"* This optional, opt-in phase adds four more Microsoft-native
sources to answer a different question: **which AI application or agent actually
handled sensitive data, how much, for how many users, and was it blocked or allowed?**

| Connector | Source | What it discovers |
| --- | --- | --- |
| **Agent 365** | `copilot/admin/catalog/packages` | Registered Copilot/agent packages — build type, blocked state, deployment scope |
| **Entra Agent ID** | `servicePrincipals/…agentIdentity` + blueprints | Agent identities: owners, sponsors, app-only vs. delegated permissions |
| **Defender for Cloud Apps** | `dataDiscovery/cloudAppDiscovery` (beta) | Shadow AI web usage: which AI sites, how many users, sanctioned/unsanctioned |
| **Purview Audit** | `security/auditLog/queries` | Sensitive-data AI interactions: SIT, sensitivity label, DLP action, direction |

All four correlate into one picture (`connectors_report.py`): a 15-section assessment
with an executive summary, an **"Applications with Sensitive Data Exposure"** table,
per-application and per-agent detail, and a coverage section that is honest about what
each connector could and couldn't see — no source is ever faked as "connected."

**It is entirely opt-in.** Every connector is gated by its own environment variable
and defaults to off; with nothing enabled, this phase has **zero effect** on the core
scan, dashboard, or weekly digest — none of that code is touched.

### Turn it on (one-time setup)

Same pattern as the core deploy: grant read-only Graph roles to the Managed Identity,
then flip the feature flags. Run both from Azure Cloud Shell (or anywhere `az` is
logged into the subscription):

```bash
git clone https://github.com/MSalikoc/ai-spm-shadow-ai.git
cd ai-spm-shadow-ai

# 1) Grant the additional read-only Graph application roles this phase needs
#    (Application.Read.All / Directory.Read.All are no-ops if the core setup already
#    granted them — this script is safe to re-run).
MI=$(az functionapp identity show -g <RESOURCE_GROUP> -n <FUNCTION_APP_NAME> --query principalId -o tsv)
./scripts/grant_connector_roles.sh "$MI"

# 2) Turn the connectors on
./scripts/enable_connectors.sh <RESOURCE_GROUP> <FUNCTION_APP_NAME>
```

> Both steps require a directory role that can grant application permissions
> (Privileged Role Administrator / Global Administrator) — same requirement as the
> core `grant_graph_roles.sh`.

Give the Function App a minute to pick up the new settings, then check it:

```bash
KEY=$(az functionapp keys list -g <RESOURCE_GROUP> -n <FUNCTION_APP_NAME> --query functionKeys.default -o tsv)
curl -s "https://<FUNCTION_APP_NAME>.azurewebsites.net/api/connectors?code=$KEY" | python3 -m json.tool
```

Or open the standalone dashboard page directly in a browser:

```
https://<FUNCTION_APP_NAME>.azurewebsites.net/api/connectors?code=<FUNCTION_KEY>&format=html
```

If any `ENABLE_*` flag is still off, this returns `{"status": "NOT_CONFIGURED", ...}` —
by design, never fabricated data. The response also tells you, per connector, whether
it's `CONNECTED`, `PERMISSION_MISSING` (role not yet propagated — wait a few minutes and
retry), or `LICENSE_MISSING` (e.g. Defender for Cloud Apps requires its own license;
its `CloudApp-Discovery.Read.All` permission is still in **preview**).

### Configuration

| Setting | Default | Description |
| --- | --- | --- |
| `ENABLE_AGENT365` | off | Agent 365 package/agent inventory |
| `ENABLE_ENTRA_AGENT_ID` | off | Entra Agent Identity + blueprint inventory |
| `ENABLE_DEFENDER_CLOUD_APPS` | off | Shadow AI web-usage discovery (requires `ENABLE_PREVIEW_CONNECTORS=true` too — beta Graph API) |
| `ENABLE_PREVIEW_CONNECTORS` | off | Unlocks beta/preview Graph endpoints (currently only Defender for Cloud Apps) |
| `ENABLE_PURVIEW_AUDIT` | off | Sensitive AI-interaction audit records |
| `STORE_RAW_AI_CONTENT` | off | If `true`, persists raw prompt/response text with each interaction — **off is strongly recommended**; every honesty/coverage field still works without it |
| `PURVIEW_DSPM_IMPORT_PATH` | — | Optional: path to a manually exported Purview DSPM JSON/CSV file, imported as a fifth, separate source |

### What this phase deliberately does *not* touch

To keep the already-deployed scan/dashboard/email flow risk-free, this phase ships as
genuinely additive code: `report.py`, `executive.py`, `drift.py`, and the
`daily_scan`/`weekly_digest`/`scan_now`/`digest_now` endpoints are **unmodified**.
The new assessment lives in its own module (`connectors_report.py`) behind its own
endpoint (`/api/connectors`), change-tracking lives in its own engine
(`connectors_drift.py`, own snapshot files), and neither one renders inside the
existing dashboard yet — that integration is a natural next step, not done here.

---

## Running on demand

Trigger a scan and get a JSON summary from the HTTP endpoint:

```bash
curl "https://<FUNCTION_APP>.azurewebsites.net/api/scan?code=<FUNCTION_KEY>"
```

Operators can also run a scan from a workstation against a tenant using the CLI:

```bash
pip install -r requirements.txt
python main.py --tenant <TENANT_ID> --client-id <APP_ID>     # interactive device-code sign-in
```

---

## Architecture

```
function_app.py → Azure Function: daily_scan (timer) + scan_now (HTTP) + connectors_now (HTTP)
pipeline.py     → shared scan flow (discovery → consent mapping → scoring)
                  + run_connectors() (opt-in, stateless — None while all ENABLE_* are off)
collectors.py   → Graph: servicePrincipals + oauth2PermissionGrants → normalized findings
config.py       → AI application catalog + sensitive-scope weights (single tuning point)
scoring.py      → transparent 0–100 risk score with reasons + remediation
report.py       → HTML + JSON report rendering (core scan — unmodified by connectors/)
storage.py      → report publishing to Blob (latest.* + history)
auth.py         → Entra token (Managed Identity / device code / client credentials)
graph_client.py → Microsoft Graph paging + throttling (+ post() for audit log queries)
main.py         → command-line entry point
notify.py       → weekly digest email via Microsoft Graph sendMail
executive.py    → executive dashboard KPIs/narratives (core scan)
findings.py     → managed finding records + lifecycle
drift.py        → core scan snapshot/change-tracking (snapshot.json / changes.json)
deploy/         → azuredeploy.json (ARM template, one-click Deploy to Azure)
scripts/        → postdeploy.sh, grant_graph_roles.{sh,ps1}
                  grant_connector_roles.{sh,ps1}, enable_connectors.sh (opt-in phase)
.github/        → deploy.yml (CI/CD: auto-deploy on push to main)

connectors/                → Microsoft AI Data Sources connector framework (opt-in)
  base.py                    BaseCollector interface, connector states, resilient safe_run()
  model.py                   unified asset model, deterministic asset IDs, field availability
  correlation.py              priority-based cross-source merge (appId > identity > blueprint > …)
  registry.py                 runs all connectors resiliently (one failure never stops the rest)
  agent365.py                 Agent 365 package/agent inventory
  entra_agent_id.py           Entra Agent Identity + blueprint inventory
  defender_cloud_apps.py       Shadow AI web-usage discovery (beta)
  purview_audit.py             sensitive AI-interaction audit records
  purview_dspm_import.py       optional manual DSPM export (JSON/CSV) import
  sensitive_data.py            per-app/agent correlation, findings, portfolio summary
  catalogs/ai_applications.json  code-free AI-app catalog (used by defender_cloud_apps.py)
connectors_report.py       → 15-section assessment + standalone HTML (own page, own endpoint)
connectors_drift.py        → change-tracking for the four connectors (own snapshot/changes files,
                              runs alongside drift.py without modifying it)
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
  (`az functionapp deployment list-publishing-profiles -g <RG> -n <FUNC> --xml`)

Without these, the deploy workflow is skipped — the one-click button + `postdeploy.sh`
remain the primary path.

---

## Security & privacy

- **Read-only.** AI-SPM only reads directory and audit data; it makes no changes.
- **No stored secrets.** Authentication uses a system-assigned Managed Identity in Azure.
- **Least privilege.** The core scan needs only three read-only Graph application
  permissions; the optional [Microsoft AI Data Sources](#microsoft-ai-data-sources-optional-extended-phase)
  phase adds a few more read-only roles, and only for the connectors you explicitly enable.
- **Your data stays in your tenant.** Reports are written to your own Storage account.
- **No raw AI content by default.** Sensitive-interaction records keep metadata (user,
  app, data type, DLP action) but never the prompt/response text itself unless you
  explicitly set `STORE_RAW_AI_CONTENT=true`.

## License

MIT
