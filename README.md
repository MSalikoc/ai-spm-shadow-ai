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

Then set up **authentication** (see below) and trigger the first scan. On each run
(06:00 UTC by default) AI-SPM scans your tenant and writes `latest.html` plus a
timestamped history to the `aispm-reports` Blob container.

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
| `AISPM_REPORT_URL` | —                  | Clean `/api/report` URL for the dashboard button (no key) |
| `AISPM_AUTH_DEV_BYPASS` | —             | Local dev only: `true` skips auth. Ignored in Azure (see below). |

What counts as an "AI application" and how each permission is weighted is defined in a
single place — [`config.py`](config.py) — so the catalog and scoring policy are easy to
tune to your environment.

---

## Authentication & authorization (Entra RBAC)

HTTP endpoints are protected by **Entra ID** via App Service Authentication (Easy Auth),
not function keys. Authorization is enforced in code against **app roles**:

| Endpoint | Required role (or `AI-SPM.Administrator`) |
| --- | --- |
| `/api/report` | `AI-SPM.Report.Reader` |
| `/api/scan` | `AI-SPM.Assessment.Operator` |
| `/api/digest` | `AI-SPM.Notification.Operator` |

Unauthenticated → **401**; authenticated but missing the role → **403**.

### Set up (one time)

```bash
./scripts/setup_entra_auth.sh <RESOURCE_GROUP> <FUNCTION_APP_NAME>
```

This creates the app registration with the four app roles, sets the identifier URI and
Easy Auth redirect, and enables Entra authentication on the Function App (AllowAnonymous,
so the code returns precise 401/403).

### Assign roles

Portal → **Entra ID → Enterprise applications → "AI-SPM (&lt;func&gt;)" → Users and groups
→ Add** → pick a user/group and one of the four roles. For app-to-app access, assign the
app role to the calling application's service principal instead.

### Calling a protected endpoint

Browsers are redirected to sign in. Programmatic callers send an Entra access token:

```bash
TOKEN=$(az account get-access-token --resource api://<CLIENT_ID> --query accessToken -o tsv)
curl -H "Authorization: Bearer $TOKEN" "https://<FUNC>.azurewebsites.net/api/scan"
```

### Local development

Set `AISPM_AUTH_DEV_BYPASS=true` in `local.settings.json` to skip auth while running
`func start`. This is **rejected automatically in Azure** (guarded by `WEBSITE_INSTANCE_ID`),
so it can never weaken production.

---

## Viewing the dashboard

Open the report in a browser — a clean URL, no key. You are redirected to Entra sign-in;
after login (with `AI-SPM.Report.Reader` or `Administrator`) the dashboard loads:

```
https://<FUNCTION_APP>.azurewebsites.net/api/report
```

## Weekly email digest

AI-SPM emails a weekly posture digest (headline numbers, notable findings, a link to the
dashboard, and the full dashboard as an HTML attachment) via Microsoft Graph, sent by the
Managed Identity — no SMTP secrets.

1. The post-deploy script grants the Managed Identity `Mail.Send`.
2. Set the mail settings (portal Environment variables, or CLI):
   ```bash
   az functionapp config appsettings set -g <RG> -n <FUNC> --settings \
     AISPM_MAIL_SENDER="secops@contoso.com" \
     AISPM_MAIL_TO="team@contoso.com,ciso@contoso.com"
   ```
   The dashboard link is derived automatically (clean URL, no key).
3. **Harden `Mail.Send`** — this application permission can otherwise send as any mailbox.
   Scope it to only the sender with an Exchange application access policy:
   ```powershell
   New-ApplicationAccessPolicy -AppId <MANAGED_IDENTITY_APPID> `
     -PolicyScopeGroupId <mail-enabled-group-containing-sender> `
     -AccessRight RestrictAccess -Description "AI-SPM digest sender only"
   ```
4. Test (needs the `Notification.Operator` role token):
   `curl -H "Authorization: Bearer $TOKEN" "https://<FUNC>.azurewebsites.net/api/digest"`

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
notify.py       → weekly digest email via Microsoft Graph sendMail
deploy/         → azuredeploy.json (ARM template, one-click Deploy to Azure)
scripts/        → postdeploy.sh, grant_graph_roles.{sh,ps1}
.github/        → deploy.yml (CI/CD: auto-deploy on push to main)
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
- **Least privilege.** Only three read-only Graph application permissions are required.
- **Your data stays in your tenant.** Reports are written to your own Storage account.

## License

MIT
