<div align="center">

# AI-SPM

**Find every AI application, agent and Shadow AI tool in your Microsoft 365 tenant —
and know which one to fix first.**

Read-only. Runs from your laptop in two minutes, or on a schedule in Azure.

[Quick start](#quick-start) · [Live sample](#see-it-before-you-run-it) ·
[Permissions](#permissions) · [Troubleshooting](#troubleshooting)

</div>

<div align="center">
  <img src="docs/img/portal.png" alt="The AI-SPM portal: AI estate, risk distribution and triage view" width="820">
</div>

---

## What it finds

| | |
| --- | --- |
|  **Consented AI apps** | Every third-party AI app holding an OAuth grant, and exactly which permissions |
|  **Shadow AI** | AI used through the browser — who, how much data, sanctioned or not |
|  **Agents** | Copilot agents and Entra agent identities, with owners and permissions |
|  **Sensitive data** | What Purview saw reaching AI, blocked versus allowed |

Everything lands on **one page**: one row per vendor, whichever route it came in by.
ChatGPT consented as an app *and* used in the browser is one row, not two. The two detail
dashboards are one click away, and every page carries the same three-way switch.

> **100% read-only.** AI-SPM never revokes a permission, deletes an app, or changes a
> setting. It observes, scores and reports — remediation stays with your team.

---

## Quick start

Pick the row that matches how far you want to go. Each one includes everything above it.

| | You get | You need | Time |
| --- | --- | --- | --- |
| **1 · Sign in** | Consented AI apps, permissions, usage | `az login` | 2 min |
| **2 · App registration** | **+ Shadow AI, agents, sensitive data** | One script, admin consent | 10 min |
| **3 · Deploy** | **+ daily scans, change history, email digest** | An Azure subscription | 20 min |

<br>

### 1 · Sign in — nothing to create

Works on your laptop, or in Azure Cloud Shell where `az` is already signed in.

```bash
git clone https://github.com/MSalikoc/ai-spm-shadow-ai.git && cd ai-spm-shadow-ai
```

```bash
python3 -m pip install -r requirements.txt
```

```bash
az login
```

```bash
python3 aispm.py doctor
```

```bash
python3 aispm.py scan --open
```

Opens `out/portal.html`. A read-only directory role — **Global Reader** or **Security
Reader** — is enough.

<details>
<summary><b>PowerShell / Windows</b></summary>

Windows usually has none of Git, Python or the Azure CLI. Install all three with winget
— it ships with Windows 10 and 11:

```powershell
winget install --id Git.Git -e
winget install --id Python.Python.3.12 -e
winget install --id Microsoft.AzureCLI -e
```

**Then close PowerShell and open a new window** — installers add to `PATH`, and the
session you ran them in will not see it. Check it took:

```powershell
git --version; python --version; az version
```

Then the same five steps. Windows has `python`, not `python3`:

```powershell
git clone https://github.com/MSalikoc/ai-spm-shadow-ai.git; cd ai-spm-shadow-ai
python -m pip install -r requirements.txt
az login
python aispm.py doctor
python aispm.py scan --open
```

`python -m pip` rather than `pip`, because a fresh Windows Python does not always put
`pip` itself on `PATH`.
</details>

> In Cloud Shell, use `download out/portal.html` to get the file to your browser.

**Only Entra sources connect in this mode.** That is not a licensing problem — see
[Why only Entra connects](#why-only-entra-connects). Step 2 fixes it.

<br>

### 2 · App registration — all four data sources

One script creates the registration, grants six read-only Graph permissions and consents
them. No Azure resources are created.

```bash
./scripts/create_app_registration.sh
```

It prints three `export` lines. Paste them, then:

```bash
python3 aispm.py doctor --auth app
```

```bash
python3 aispm.py scan --auth app --scope consented --open
```

<details>
<summary><b>PowerShell / Windows</b></summary>

Use the PowerShell twin — it does the same work through the Azure CLI, so there is no
extra module to install, and it prints `$env:` lines instead of `export` ones.

```powershell
.\scripts\create_app_registration.ps1
```

```powershell
python aispm.py doctor --auth app
python aispm.py scan --auth app --scope consented --open
```

Setting the credentials by hand instead:

```powershell
$env:AISPM_TENANT_ID = "<TENANT>"
$env:AISPM_CLIENT_ID = "<APP_ID>"
$env:AISPM_CLIENT_SECRET = "<SECRET>"
```
</details>

### Who can run this

Creating the registration and consenting its permissions both write to the directory, so
this needs **Privileged Role Administrator**, **Cloud Application Administrator** or
**Global Administrator**.

**Global Reader is not enough.** It is read-only — it runs option 1 perfectly well, but
cannot create the registration or consent the permissions.

An `az login` token may still *list* scopes like `Application.ReadWrite.All`. Those
describe what the Azure CLI is allowed to ask for on your behalf, not what your directory
role permits, so seeing them is not evidence you can complete this step.

If you are a Global Reader: an admin runs the script once and gives you the three values
it prints. Nothing else about your setup changes — you keep running the scans.

<br>

### 3 · Deploy — continuous scanning

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMSalikoc%2Fai-spm-shadow-ai%2Fmain%2Fdeploy%2Fazuredeploy.json)

Then in **Cloud Shell**, one block at a time:

```bash
git clone https://github.com/MSalikoc/ai-spm-shadow-ai.git && cd ai-spm-shadow-ai
```

```bash
RESOURCE_GROUP="aispm-rg"
```

```bash
FUNCTION_APP="aispm-xxxxxxxxxx"
```

```bash
./scripts/postdeploy.sh "$RESOURCE_GROUP" "$FUNCTION_APP"
```

That deploys the code, grants every Graph permission and turns the connectors on. Then:

```bash
KEY=$(az functionapp keys list -g "$RESOURCE_GROUP" -n "$FUNCTION_APP" --query functionKeys.default -o tsv)
```

```bash
curl -s "https://$FUNCTION_APP.azurewebsites.net/api/scan?code=$KEY" ; echo
```

```bash
echo "https://$FUNCTION_APP.azurewebsites.net/api/portal?code=$KEY"
```

Give it a few minutes — role propagation and the first scan both take a moment.

<details>
<summary><b>PowerShell / Windows</b></summary>

`postdeploy.sh` is a Bash script, so run **step 3 in Cloud Shell's Bash** — it is a
dropdown at the top of the Cloud Shell window, and `az` is already signed in there.

Once deployed, the follow-up commands from PowerShell:

```powershell
$RG = "aispm-rg"; $FUNC = "aispm-xxxxxxxxxx"
$KEY = az functionapp keys list -g $RG -n $FUNC --query functionKeys.default -o tsv
Invoke-RestMethod "https://$FUNC.azurewebsites.net/api/scan?code=$KEY"
Start-Process "https://$FUNC.azurewebsites.net/api/portal?code=$KEY"
```

`curl` in PowerShell is an alias for `Invoke-WebRequest` and does not take `-s`; use
`Invoke-RestMethod`, or `curl.exe` if you want the real thing.
</details>

| Route | Serves |
| --- | --- |
| `/api/portal` | The portal — **start here** |
| `/api/report` | Entra OAuth assessment |
| `/api/connectors?format=html` | Microsoft AI data sources |
| `/api/doctor` | What the Managed Identity can read |
| `/api/scan` | Trigger a scan |

---

## See it before you run it

Rendered from a synthetic tenant, through the real scoring and charting code.

| | |
| --- | --- |
| **[▶ Portal](https://htmlpreview.github.io/?https://github.com/MSalikoc/ai-spm-shadow-ai/blob/main/docs/sample-portal.html)** | 27 AI vendors, 8 seen through two routes, and a week of drift |
| [Entra OAuth assessment](https://htmlpreview.github.io/?https://github.com/MSalikoc/ai-spm-shadow-ai/blob/main/docs/sample-report.html) | Per-application permissions and usage |
| [AI data sources](https://htmlpreview.github.io/?https://github.com/MSalikoc/ai-spm-shadow-ai/blob/main/docs/sample-connectors.html) | Agents, Shadow AI traffic, sensitive data |

Regenerate them with `python3 aispm.py sample`.

---

## Reading the results

Only apps matching the AI catalog are assessed by default — precise, but blind to any
vendor the catalog has not heard of. Widen it with `--scope consented` (every app holding
a real OAuth grant) or `--scope all`. Apps pulled in by scope rather than a catalog hit
are tagged `ai_match: false`; being in scope is never dressed up as an AI detection.

Every score is a sum of named signals, and the page shows the arithmetic — open any
vendor row:

```
+18   424 people reached it through the browser
+20   29.8k MB uploaded to it
+15   Large volume leaving the tenant, spread across many people
+12   Marked unsanctioned in Defender for Cloud Apps
 65   Risk score out of 100
```

**Bands:** 75+ Critical · 50–74 High · 25–49 Medium · under 25 Low. A DLP *block* scores
nothing — that is the control working.

---

## Permissions

All read-only, and granted for you by `create_app_registration.sh` or `postdeploy.sh`.

| Permission | Unlocks |
| --- | --- |
| `Application.Read.All`, `Directory.Read.All` | App inventory, OAuth grants, owners — **required** |
| `AuditLog.Read.All` | Usage and activity *(also needs Entra ID P1)* |
| `CloudApp-Discovery.Read.All` | Shadow AI web traffic |
| `CopilotPackages.Read.All` | Agent 365 catalogue |
| `AuditLogsQuery.Read.All` | Purview sensitive interactions |

### Why only Entra connects

With `az login` you get a **delegated** token, which can only carry Graph scopes the
*Azure CLI application* is authorised for. Directory reads are in that set — which is
why Entra discovery works. The three connector scopes are not, so they are simply absent
from the token. **Being Global Administrator does not change this**; the limit is on the
client application, not on your account. Option 2 or 3 fixes it — both use application
permissions instead.

---

## Troubleshooting

Start with `python3 aispm.py doctor` (or `/api/doctor`). It reports every source as
readable, denied, or not provisioned, and names the permission to grant.

| Symptom | Fix |
| --- | --- |
| `command not found: python` | macOS ships no bare `python` — use `python3` (Windows uses `python`) |
| Windows: `python` is not recognised, or opens the Microsoft Store | Python is not installed — `winget install --id Python.Python.3.12 -e`, then **open a new PowerShell window** |
| Windows: `pip` is not recognised | Use `python -m pip` — a fresh Windows Python does not always put `pip` on `PATH` |
| Windows: `git`/`az` not recognised right after installing | `PATH` only updates for new sessions — close and reopen PowerShell |
| `Could not determine the tenant` even though `az login` worked | Fixed in current `main` — `git pull`. If it persists, pass `--tenant <ID>` (`az account show --query tenantId -o tsv`) |
| `curl: -s is not recognised` | PowerShell aliases `curl` to `Invoke-WebRequest` — use `Invoke-RestMethod`, or `curl.exe` |
| `.ps1 cannot be loaded` | `Set-ExecutionPolicy -Scope Process RemoteSigned`, then re-run |
| `No module named 'azure'` | `python3 -m pip install -r requirements.txt` — and make sure it is the same interpreter you run `aispm.py` with |
| `Azure CLI is not installed` | `brew install azure-cli`, or use `--auth app` |
| `no such file or directory: T` | A `<PLACEHOLDER>` pasted literally — use the `export` lines the script prints |
| Only Entra sources connect | [See above](#why-only-entra-connects) — go to option 2 |
| Option 2 fails partway with `Insufficient privileges` | Your role cannot grant application permissions — see [Who can run this](#who-can-run-this) |
| Windows PowerShell 5.1: `The string is missing the terminator` | Fixed in current `main` — `git pull` |
| A source shows `N/A` | Not provisioned in the tenant: a licensing question, not a permission one |
| Purview "still running" | Audit searches take minutes — raise `PURVIEW_POLL_SECONDS` |
| Fewer apps than expected | Default scope is `ai` — use `--scope consented` |
| Slow on a large tenant | `--activity-days 30` |

---

## Configuration

Set by the setup scripts. Change these on a deployment with
`az functionapp config appsettings set`.

| Setting | Purpose |
| --- | --- |
| `AISPM_SCAN_SCOPE` | `ai` / `consented` / `all` |
| `AISPM_ACTIVITY_DAYS` | Sign-in history window, 7–90 (default 90) |
| `AISPM_CATALOG_PATH` | Your own AI vendor catalog |
| `PURVIEW_POLL_SECONDS` | How long to wait for a Purview audit search (default 300) |
| `SCAN_SCHEDULE`, `EMAIL_SCHEDULE` | Timers — daily 06:00 UTC, Monday 08:00 UTC |
| `STORE_RAW_AI_CONTENT` | Leave **off**; prompt and response text is never kept unless this is `true` |
| `AISPM_MAIL_SENDER`, `AISPM_MAIL_TO`, `AISPM_REPORT_URL` | Weekly email digest — sent by the Managed Identity via Graph, with the portal attached as one self-contained file |

---

## Security & privacy

- **Read-only.** Nothing is revoked, deleted or changed.
- **No stored secrets** on a deployment — Managed Identity only.
- **Your data stays in your tenant** — reports go to your own Storage account.
- **No raw AI content.** Sensitive-interaction records keep metadata only, never prompt
  or response text, unless `STORE_RAW_AI_CONTENT` is explicitly turned on.

Contributions welcome — `pytest` runs the full suite, and CI runs it on every pull
request.

## License

MIT
