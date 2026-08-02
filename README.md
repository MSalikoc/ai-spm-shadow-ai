# AI-SPM — Shadow AI Posture Management

**Discover, risk-score, and continuously track every AI application and AI agent in your
organization — third-party OAuth consent, Microsoft 365 Copilot agents, and Shadow AI web
usage, all from Entra ID and Microsoft Graph.**

Runs as a scheduled Azure Function, authenticates with a Managed Identity (no secrets),
and produces two ranked, explainable dashboards on every run.

> **100% read-only.** AI-SPM never revokes a permission, deletes an app, or changes a
> setting. It observes, scores, and reports — remediation stays with your team.

---

## Try it in two minutes, without deploying anything

The dashboards run locally against the sign-in you already have. No app registration,
no client secret, no Function App.

```bash
pip install -r requirements.txt
```

```bash
az login
```

See what your account is allowed to read — and exactly what to grant for anything it
can't:

```bash
python aispm.py doctor
```

Then scan, and open the result:

```bash
python aispm.py scan --open
```

That writes `out/report.html` and `out/connectors.html`. A read-only directory role
(Global Reader or Security Reader) is enough. Deploy to Azure when you want this to run
*continuously* — see [Setup](#setup) — but you don't need it to see what the tool finds.

### Choose how much to look at

By default only apps matching the AI catalog are assessed, which is precise but blind
to any AI vendor the catalog hasn't heard of. Widen it:

```bash
python aispm.py scan --scope consented
```

| `--scope` | Assesses | Use when |
| --- | --- | --- |
| `ai` *(default)* | Apps matching the AI catalog | You want a focused Shadow AI view |
| `consented` | The above **plus every app holding a real OAuth grant** | You want the honest consent surface, including AI tools nobody catalogued |
| `all` | Every third-party app | You're auditing the whole estate |

Apps pulled in by scope rather than by a catalog hit are labelled `ai_match: false` —
being in scope is never dressed up as an AI detection.

The same setting works on the deployed Function via the `AISPM_SCAN_SCOPE` app setting.

---

## What you get

- **Core dashboard** (`/api/report`) — every third-party AI app with OAuth access to
  your tenant, each with a transparent 0–100 risk score (reasons included). Charts:
  a triage scatter (risk against blast radius), a weighted posture gauge, a sensitive
  permission heatmap, and a vendor treemap.
- **AI Data Sources dashboard** (`/api/connectors?format=html`) — a 6-tab view (Overview,
  Agents, Shadow AI, Sensitive Data, Findings, Gaps) fed by four Microsoft sources:

  | Source | Discovers |
  | --- | --- |
  | **Agent 365** | Registered Copilot/agent packages |
  | **Entra Agent ID** | Agent identities — owners, sponsors, permissions |
  | **Defender for Cloud Apps** | Shadow AI web usage — traffic, users, devices, IPs |
  | **Purview Audit** | Sensitive-data AI interactions — blocked vs. allowed |

  Every agent, app, and finding gets the same transparent 0–100 score. Click any row to
  see exactly why: facts → score breakdown → what was checked → remediation.

  **Sample dashboards, no tenant required:**
  [core](https://htmlpreview.github.io/?https://github.com/MSalikoc/ai-spm-shadow-ai/blob/main/docs/sample-report.html)
  ·
  [AI data sources](https://htmlpreview.github.io/?https://github.com/MSalikoc/ai-spm-shadow-ai/blob/main/docs/sample-connectors.html)
  — a 24-application estate rendered through the real scoring and charting code.
  Regenerate them yourself with `python aispm.py sample`.

---

## Setup

Deploying gets you the scheduled scan, drift history across runs, and the weekly email
digest. For a one-off look, the local CLI above is enough.

### Step 1 — Deploy the infrastructure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMSalikoc%2Fai-spm-shadow-ai%2Fmain%2Fdeploy%2Fazuredeploy.json)

Fill in the target tenant, scan schedule, and report container name, then **Create**.

### Step 2 — Run the setup script

In **Azure Cloud Shell** (Portal → terminal icon, top right). Run each block **one at a
time** — click the copy icon on a single block, paste it, press Enter, wait for it to
finish, then move to the next. (Pasting several commands together can break if your
clipboard swaps straight quotes `"` for curly ones — one block at a time avoids that.)

Clone the repo:

```bash
git clone https://github.com/MSalikoc/ai-spm-shadow-ai.git
```

Enter it:

```bash
cd ai-spm-shadow-ai
```

Set your resource group name — only edit the text **inside the quotes**, keep the quotes:

```bash
RESOURCE_GROUP="aispm-rg"
```

Set your Function App name — both names are from Step 1:

```bash
FUNCTION_APP="aispm-xxxxxxxxxx"
```

Run the setup script:

```bash
./scripts/postdeploy.sh "$RESOURCE_GROUP" "$FUNCTION_APP"
```

> `$RESOURCE_GROUP` / `$FUNCTION_APP` only last for this Cloud Shell session (it resets
> after ~20 min idle). If a later command errors with a usage message, just redo the two
> `RESOURCE_GROUP=`/`FUNCTION_APP=` lines above and re-run.

This one script does everything: deploys the code, grants every Graph permission needed
(core scan + all four AI Data Sources connectors), and turns the connectors on. Requires
a directory role that can grant application permissions (Privileged Role Administrator
or Global Administrator) — if you don't have it, have someone who does run this one command.

### Step 3 — View your dashboards

Same Cloud Shell, one block at a time.

Get your function key:

```bash
KEY=$(az functionapp keys list -g "$RESOURCE_GROUP" -n "$FUNCTION_APP" --query functionKeys.default -o tsv)
```

Trigger the first scan:

```bash
curl -s "https://$FUNCTION_APP.azurewebsites.net/api/scan?code=$KEY" ; echo
```

Print your AI Data Sources dashboard link:

```bash
echo "https://$FUNCTION_APP.azurewebsites.net/api/connectors?code=$KEY&format=html"
```

Print your core dashboard link — **open this one first**:

```bash
echo "https://$FUNCTION_APP.azurewebsites.net/api/report?code=$KEY"
```

Give it a few minutes after Step 2 — role propagation and the Function App restart both
take a little time. On the AI Data Sources dashboard, `PERMISSION_MISSING` that doesn't
clear after ~15 min usually means your tenant doesn't have that Microsoft feature
provisioned yet (e.g. no Microsoft 365 Copilot license blocks Agent 365; Purview
**Audit** recording not turned on in the [Purview portal](https://purview.microsoft.com)
blocks Purview Audit). `LICENSE_MISSING` means the tenant doesn't hold that license.
Both are shown honestly — never faked — and aren't something a script can fix.

### Step 4 — *(optional)* Weekly email digest

The only optional step. Sends a weekly summary via Microsoft Graph `sendMail` — no SMTP
secrets, sent by the Managed Identity (`Mail.Send` was already granted in Step 2).

```bash
az functionapp config appsettings set -g "$RESOURCE_GROUP" -n "$FUNCTION_APP" --settings \
  AISPM_MAIL_SENDER="secops@contoso.com" \
  AISPM_MAIL_TO="team@contoso.com,ciso@contoso.com" \
  AISPM_REPORT_URL="https://$FUNCTION_APP.azurewebsites.net/api/report?code=$KEY"
```

`Mail.Send` can send as *any* mailbox — restrict it to your sender (PowerShell):

```powershell
$AppId = "PASTE_MANAGED_IDENTITY_APP_ID_HERE"
$MailGroup = "PASTE_MAIL_ENABLED_GROUP_CONTAINING_SENDER_HERE"
New-ApplicationAccessPolicy -AppId $AppId -PolicyScopeGroupId $MailGroup `
  -AccessRight RestrictAccess -Description "AI-SPM digest sender only"
```

Test:

```bash
curl "https://$FUNCTION_APP.azurewebsites.net/api/digest?code=$KEY"
```

---

## Configuration reference

Set automatically by `postdeploy.sh` — listed here for reference, not something you need
to set by hand.

| Setting | Purpose |
| --- | --- |
| `AISPM_TENANT_ID` | Entra tenant to scan |
| `AISPM_SCAN_SCOPE` | `ai` (default) / `consented` / `all` — see [Choose how much to look at](#choose-how-much-to-look-at) |
| `AISPM_ACTIVITY_DAYS` | Sign-in history window, 7–90 (default 90). Lower it on very large tenants |
| `SCAN_SCHEDULE` | Core scan schedule (default: daily 06:00 UTC) |
| `ENABLE_AGENT365`, `ENABLE_ENTRA_AGENT_ID`, `ENABLE_DEFENDER_CLOUD_APPS`, `ENABLE_PREVIEW_CONNECTORS`, `ENABLE_PURVIEW_AUDIT` | Turn on the four AI Data Sources connectors |
| `STORE_RAW_AI_CONTENT` | Leave **off** — sensitive-interaction records never keep prompt/response text unless this is explicitly `true` |
| `PURVIEW_DSPM_IMPORT_PATH` | Advanced, rarely-needed 5th source — a manually exported Purview DSPM file. No upload UI exists for this; skip it unless you specifically need it |
| `AISPM_MAIL_SENDER`, `AISPM_MAIL_TO`, `AISPM_REPORT_URL`, `EMAIL_SCHEDULE` | Weekly digest (Step 4 only) |

What counts as an "AI application" and how scores are weighted lives in
[`config.py`](config.py) — a single place to tune to your environment.

---

## Architecture

```
aispm.py                     local CLI — doctor / scan / sample
preflight.py                 permission + licence probes ("can this identity read X?")
function_app.py              Azure Function entry points (timers + HTTP routes)
pipeline.py                  core scan flow + AI Data Sources entry point
collectors.py, scoring.py    OAuth-consent discovery + transparent risk scoring
charts.py                    shared inline-SVG chart library (no external deps)
report.py, executive.py      core HTML dashboard + executive KPIs
findings.py, drift.py        managed findings + change-tracking
notify.py                    weekly email digest

connectors/                  the four AI Data Sources connectors + correlation engine
connectors_report.py         AI Data Sources dashboard (6-tab, /api/connectors)
connectors_drift.py          AI Data Sources change-tracking (parallel to drift.py)

auth.py, graph_client.py, config.py   shared: auth, Graph client, tunable AI catalog
deploy/                      ARM template (one-click Deploy to Azure)
scripts/                     postdeploy.sh, make_sample.py
.github/                     CI/CD (auto-deploy on push to main)
```

### Why a section can be empty

`doctor` answers this directly: for every source it says whether the identity is allowed
to read it, whether the tenant has the feature at all, and which permission to grant. An
empty section is never left ambiguous between "nothing there" and "not allowed to look".

```bash
python aispm.py doctor
```

The deployed Function exposes the same check, run against its Managed Identity:

```bash
curl "https://$FUNCTION_APP.azurewebsites.net/api/doctor?code=$KEY"
```

## Local testing

```bash
pip install -r requirements.txt pytest
```

```bash
pytest
```

```bash
python -c "import function_app"
```

CI runs the same checks on every pull request and before every deploy — a failing test
blocks deployment.

## Continuous deployment (optional)

Pushes to `main` auto-deploy via GitHub Actions if you set, once:
- Repository **variable** `AZURE_FUNCTIONAPP_NAME`
- Repository **secret** `AZURE_FUNCTIONAPP_PUBLISH_PROFILE`
  (`az functionapp deployment list-publishing-profiles -g "$RESOURCE_GROUP" -n "$FUNCTION_APP" --xml`)

Without these, the one-click button + `postdeploy.sh` remain the primary path.

---

## Security & privacy

- **Read-only** — no permission is revoked, no app deleted, no setting changed.
- **No stored secrets** — Managed Identity only.
- **Your data stays in your tenant** — reports are written to your own Storage account.
- **No raw AI content by default** — sensitive-interaction records keep metadata only
  (user, app, data type, DLP action), never prompt/response text.

## License

MIT
