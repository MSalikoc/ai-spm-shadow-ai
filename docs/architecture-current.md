# AI-SPM — Current Architecture (baseline)

_This documents the system **as currently built and deployed**. It is a baseline
reference; behavior described here must not change without an explicit decision._

## Overview

AI-SPM discovers third-party AI applications connected to a Microsoft Entra tenant via
OAuth consent, risk-scores them, and reports the posture — as a live dashboard, a stored
report, and a weekly email digest. It runs as an Azure Function (Linux Consumption,
Python 3.11), authenticates with a system-assigned Managed Identity, and is **read-only**.

```
[Entra ID / Microsoft Graph]
        │  (read-only: servicePrincipals, oauth2PermissionGrants)
        ▼
   collectors.py ──► pipeline.py ──► scoring.py ──► report.py / notify.py
        │                                              │
   Managed Identity token (auth.py)              storage.py ──► Blob (latest.* + history)
                                                       │
                                            /api/report, weekly email
```

## Components

| Module | Responsibility |
| --- | --- |
| `function_app.py` | Azure Functions app: triggers + HTTP endpoints. Entry point. |
| `pipeline.py` | Shared scan flow: `run()` (discover → enrich → score) and `summary()`. |
| `collectors.py` | Graph queries: service principals, delegated OAuth grants, application (app-only) permissions (`appRoleAssignments`, GUID→name), **and real sign-in activity** (`auditLogs/signIns`, delegated vs service-principal, 7/30/90d usage; P1-gated, degrades gracefully). Tags `third_party`, `first_party_microsoft`, `has_app_only_access`, per-app `usage`. |
| `scoring.py` | Transparent 0–100 risk score, level, reasons, remediation. |
| `classifier.py` | Classification engine: 8 governance categories + ownership, confidence + reasons; App ID strongest signal; manual override wins. |
| `catalog.json` | Code-free AI vendor catalog (app_ids / patterns / domains) loaded by `config.py`. |
| `config.py` | Loads `catalog.json`; sensitive-scope weights, governance/classification dictionaries, Microsoft owner tenants. |
| `report.py` | Dashboard HTML (light/dark) + JSON rendering. |
| `findings.py` | Managed finding records: rule engine → deterministic IDs, persistent lifecycle store (`findings.json`), auto-resolve/reopen, overdue tracking. |
| `ticketing.py` | Ticketing adapter interface only (`TicketAdapter`/`NoopAdapter`); Jira/ServiceNow not implemented. |
| `drift.py` | Change tracking: normalized snapshot per scan, diff vs. previous → change-event timeline (`snapshot.json` / `changes.json`); first scan is a no-event baseline; executive summary for the digest. |
| `metadata.py` | Persistent business/lifecycle metadata store (`metadata.json` in Blob), merged into each scan so manual data survives re-scans; lifecycle/review history. |
| `notify.py` | Weekly digest email via Microsoft Graph `sendMail`, with dashboard HTML attachment. |
| `storage.py` | Publish reports to Blob (`latest.*` + timestamped history); `read_latest()` for the report endpoint. |
| `auth.py` | Entra tokens: Managed Identity (Azure), device code + client credentials (CLI). |
| `graph_client.py` | Microsoft Graph client: paging + throttling. |
| `main.py` | Command-line entry point (operator/manual runs). |

## Endpoints & triggers (`function_app.py`)

| Name | Type | Schedule / Route | Action |
| --- | --- | --- | --- |
| `daily_scan` | Timer | `SCAN_SCHEDULE` (default `0 0 6 * * *`) | Scan → publish to Blob |
| `weekly_digest` | Timer | `EMAIL_SCHEDULE` (default `0 0 8 * * 1`) | Scan → publish → email digest |
| `scan_now` | HTTP (function key) | `/api/scan` | On-demand scan, returns JSON summary |
| `digest_now` | HTTP (function key) | `/api/digest` | Scan + send digest now (testing) |
| `report_view` | HTTP (function key) | `/api/report` | Serves the latest dashboard HTML |

`_run_scan()` is the shared helper returning `(result, scored, tenant_id)`.

## Data flow

1. `auth.get_token_managed_identity()` → Graph token (no secrets).
2. `collectors.collect_service_principals()` matches vendors (catalog + generic hints);
   `enrich_with_oauth_grants()` attaches delegated consent scopes, consent type, user count.
3. `scoring.score_all()` ranks by risk (scope sensitivity, blast radius, verification, persistence).
4. `storage.publish()` writes `latest.html`, `latest.json`, and timestamped history.
5. `report.html_string()` splits genuine Shadow AI from Microsoft first-party (governed).
6. `notify.send_email_digest()` emails a teaser + attaches the full dashboard HTML.

## Identity & permissions

- System-assigned Managed Identity on the Function App.
- Microsoft Graph **application** roles (granted by `scripts/grant_graph_roles.*`):
  `Directory.Read.All`, `Application.Read.All`, `AuditLog.Read.All`, `Mail.Send`.
- `Mail.Send` should be scoped to the sender mailbox via an Exchange application access policy.

## Storage

- Blob container `REPORT_CONTAINER` (default `aispm-reports`): `latest.html`, `latest.json`,
  `shadow_ai_<UTC>.html/json` history.
- Function runtime storage: `AzureWebJobsStorage`.

## Configuration (app settings)

`AISPM_TENANT_ID`, `SCAN_SCHEDULE`, `EMAIL_SCHEDULE`, `REPORT_CONTAINER`,
`AISPM_MAIL_SENDER`, `AISPM_MAIL_TO`, `AISPM_REPORT_URL`.

## Deployment

- **Infra:** `deploy/azuredeploy.json` (ARM) — one-click "Deploy to Azure". Storage +
  Consumption plan + Function App (system-assigned MI). Provisions mail app settings (empty)
  for portal editing.
- **Code:** `scripts/postdeploy.sh` — `func azure functionapp publish --python` (remote
  Oryx build); fallback path zips all root `*.py` + `host.json` + `requirements.txt`.
  Also grants Graph roles.
- **CI/CD:** `.github/workflows/deploy.yml` — on push to `main`, runs tests then deploys
  (deploy `needs: test`). `.github/workflows/ci.yml` — tests on pull requests.
- **Note:** Linux Consumption does **not** support URL-based `WEBSITE_RUN_FROM_PACKAGE`;
  code is deployed via remote build, not a package URL.

## Tests

`tests/test_smoke.py` — imports every module (catches missing-module regressions like a
deployment package omitting `notify.py`), plus scoring/report/notify behavior checks.
Run locally: `pip install -r requirements.txt pytest && pytest`.
