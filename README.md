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
| `SCAN_SCHEDULE`    | `0 0 6 * * *`      | NCRONTAB schedule (sec min hour day month dow)    |
| `REPORT_CONTAINER` | `aispm-reports`    | Blob container for published reports              |

What counts as an "AI application" and how each permission is weighted is defined in a
single place — [`config.py`](config.py) — so the catalog and scoring policy are easy to
tune to your environment.

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
function_app.py → Azure Function: daily_scan (timer) + scan_now (HTTP)
pipeline.py     → shared scan flow (discovery → consent mapping → scoring)
collectors.py   → Graph: servicePrincipals + oauth2PermissionGrants → normalized findings
config.py       → AI application catalog + sensitive-scope weights (single tuning point)
scoring.py      → transparent 0–100 risk score with reasons + remediation
report.py       → HTML + JSON report rendering
storage.py      → report publishing to Blob (latest.* + history)
auth.py         → Entra token (Managed Identity / device code / client credentials)
graph_client.py → Microsoft Graph paging + throttling
main.py         → command-line entry point
deploy/         → azuredeploy.json (ARM template, one-click Deploy to Azure)
scripts/        → grant_graph_roles.{sh,ps1} (Managed Identity Graph roles)
```

---

## Security & privacy

- **Read-only.** AI-SPM only reads directory and audit data; it makes no changes.
- **No stored secrets.** Authentication uses a system-assigned Managed Identity in Azure.
- **Least privilege.** Only three read-only Graph application permissions are required.
- **Your data stays in your tenant.** Reports are written to your own Storage account.

## License

MIT
