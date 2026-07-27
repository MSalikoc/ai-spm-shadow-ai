# Changelog

All notable changes to AI-SPM are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **Agent 365 collector (Step 2/8)** — `connectors/agent365.py` reads the Agent 365 catalog
  (`/copilot/admin/catalog/packages` + per-package detail, `CopilotPackages.Read.All`),
  normalizes each package into a unified `AI_AGENT` asset (package type, publisher/build-type,
  scopes, blocked, available/deployed scope, categories, sensitivity), parses `elementDetails`
  (declarative/custom-engine/bot IDs, scopes, file support, host) and keeps a `raw_reference` +
  raw definition for anything unparseable. Ready for entra-appId correlation. `metrics()` for the
  9 Agent 365 dashboard numbers. Resilient: 403→PERMISSION_MISSING, license→LICENSE_MISSING,
  404/400→API_UNAVAILABLE, never stops the scan. Offline mock fixtures + tests.
- **Unified connector framework (Microsoft AI data sources — Step 1/8)** — `connectors/`
  package: `BaseCollector` interface (is_configured/collect/normalize/get_health/
  get_coverage + resilient `safe_run`), 8 connector states, unified entity model
  (`model.py`: 14 entity types, external-id-based deterministic asset IDs, field
  availability wrappers), and a priority-based **correlation engine** (`correlation.py`:
  appId > agent identity > blueprint > package/asset id > manifest > publisher+domain;
  never merges on name alone) with confidence scoring. `registry.run()` runs all
  connectors resiliently (one failure never stops the scan). Skeleton connectors for
  Agent 365 / Entra Agent ID / Defender for Cloud Apps / Purview Audit / Purview DSPM
  import (all `NOT_CONFIGURED` until their steps). Offline mock fixtures + tests.
  Not yet wired into the live pipeline (architecture only).

### Changed
- **Dashboard redesign (tabbed, modern)** — modeled on Microsoft's Zero Trust Assessment:
  a top **hero** (Tenant card + stat tiles: AI Applications / Agents / Active Users /
  Unapproved + Assessment risk donut), and a **tab navigation** (Overview / Applications /
  Usage / Governance / Findings / Changes) that splits the content into focused pages.
  Executive KPI cards drill down by switching tabs. All existing information preserved,
  reorganized; light/dark and responsive retained.

### Added
- **Executive dashboard** (`executive.py`) — an AI-estate overview for leadership:
  - 14 estate KPIs (AI applications, AI agents, active users, unapproved, unknown, new
    this week, apps without owner, agents without purpose, open/overdue findings,
    assessment coverage, + connector-gated local agents / MCP servers / AI models).
  - **Application vs Agent** split (name-signal heuristic, `asset_type`) and
    enterprise / web / **local** usage-surface split.
  - **Rule-based "Needs Attention" narratives** ("Finance biriminde N yeni AI…",
    "Claude kullanımı %42 arttı", owner/purpose gaps, overdue findings).
  - **Top-5 changes**, **Coverage Overview** (owner% / agent-purpose% + connector status).
  - **Honesty by design:** local agents / MCP servers / AI models / Purview visibility
    require connectors that aren't wired yet — these are shown as **0 with an explicit
    "not connected" coverage gap** rather than fabricated inventory.
  - Drill-down: KPI cards link to the relevant dashboard section anchors.
  - `tests/test_executive.py`.
- **Managed finding records + lifecycle** (`findings.py`) — findings become tracked work
  items, not just text:
  - Rule engine generates findings (owner-missing, admin-consent-sensitive,
    app-only-highpriv, unknown-classification, unused-high-risk, lifecycle-review-overdue,
    blocked-still-active) with **deterministic ID** `finding-{asset_id}-{rule_key}` — no
    duplicates across scans.
  - Persistent store (`findings.json`): first_seen/last_seen, status (8 states), owner,
    responsible team, due date, priority, business impact, recommended action, resolution
    note, ticket reference, closed date, history. Scan updates last_seen + rule content but
    never overwrites manual fields.
  - Auto-resolve when a finding disappears; **Reopened** when a Resolved finding recurs.
  - Editable from the dashboard and `POST /api/finding` (or the `findings.json` config).
  - Dashboard: findings-by-status / by-owner, **overdue list**, per-finding record with
    inline editor.
  - `ticketing.py`: **adapter interface only** (`TicketAdapter` + `NoopAdapter`) — Jira/
    ServiceNow not implemented yet.
  - `tests/test_findings.py`.
- **Drift / change tracking** (`drift.py`) — "what changed since the last scan?":
  - Deterministic snapshot per scan (`snapshot.json`); diff vs. the previous snapshot
    produces change events into a timeline (`changes.json`). **First scan = baseline, no
    events.** Deterministic asset IDs (app_id; `resource|permission`) and change IDs.
  - 20 event types: NEW/REMOVED_APPLICATION, NEW/REMOVED_PERMISSION, PERMISSION_ESCALATED,
    NEW_APP_ONLY_ACCESS, ADMIN_CONSENT_ADDED/REMOVED, OWNER_ADDED/REMOVED/CHANGED,
    BUSINESS_OWNER_CHANGED, CLASSIFICATION_CHANGED, LIFECYCLE_CHANGED, FIRST_SIGNIN,
    ACTIVITY_INCREASED/DECREASED (with %), APP_DISABLED/REENABLED. Each event has
    change_id / type / asset id+name / timestamp / old / new / importance / description.
  - **Weekly digest is now change-focused** — an executive "Bu hafta:" summary
    ("N new AI apps", "Claude usage +32%", "1 app Under Review→Approved").
  - Dashboard: change **timeline** section (importance-colored).
  - Manual metadata edits surface as change events on the next scan (LIFECYCLE/OWNER/
    CLASSIFICATION_CHANGED).
  - `storage.read_latest` now falls back to local `out/` (symmetry with `write_json`).
  - `tests/test_drift.py`.
- **Classification engine** (`classifier.py`) — categorizes each AI app into 8 governance
  classes (Microsoft First-Party / Approved / Unapproved Enterprise / Third-Party Shadow /
  Internal Custom / Personal / Unknown / Retired) + ownership (Internal/External/Unknown),
  with a **confidence** score and **reasons**:
  - Signals ranked: manual override > App ID > publisher/name/domain > business metadata /
    lifecycle > generic. App ID is the strongest signal.
  - Vendor **catalog moved to `catalog.json`** (code-free, kriter 2), now with real global
    app IDs (ChatGPT/Skywork/Vectra) so App-ID classification is demonstrable; domains added.
  - **Unknown is never treated as safe/approved**; Unknown apps get a dedicated review queue.
  - **Manual override** stored in the metadata store → **persists across scans**; editable
    from the dashboard and `POST /api/metadata`.
  - **Microsoft first-party apps are now shown in the inventory** (classified, not hidden).
  - Dashboard: classification cards (unknown / approved / unapproved / avg confidence),
    by-category bars, internal-vs-external, Unknown review queue, per-finding classification
    block + category chip, and a category filter.
  - `tests/test_classifier.py`.
- **Business ownership & lifecycle governance**:
  - Technical inventory from Graph (`enrich_with_ownership`): service-principal owners,
    enabled status, publisher, homepage, tags, description, credential count + next expiry.
    Owners left empty when absent — never synthesized.
  - Separate, persistent business metadata store (`metadata.py` + `metadata.json` in Blob),
    keyed by `app_id`, merged into every scan so **manual metadata survives re-scans**.
    Fields: business/technical owner, sponsor, business unit, subsidiary, purpose, process,
    criticality, environment, lifecycle status (8 states), next review date, notes.
  - Lifecycle status & review-date changes recorded as `history`.
  - Editable via **JSON config / `POST /api/metadata`** and an inline **dashboard editor**.
  - Dashboard: lifecycle status chip + governance block per finding, governance KPI cards,
    **upcoming/overdue reviews** list, and **business-unit / subsidiary filters**.
  - `tests/test_metadata.py`.
- **Real usage / sign-in activity** from Graph `auditLogs/signIns` (uses the already-granted
  `AuditLog.Read.All`; requires Entra ID P1):
  - `collectors.enrich_with_signin_activity()` separates delegated user sign-ins from
    service-principal (app-only) sign-ins; per-app `usage` with active users 7/30/90d,
    last delegated/SP sign-in, successful/failed sign-ins (30d), unique users/IPs/countries,
    `last_used_date`, `never_used`, `inactive_30d/90d`, `growth_7d`, `daily_active_30d`.
  - Distinguishes **consent count vs actual active users**; flags unused/inactive apps.
  - Dashboard: usage cards (active usage, inactive apps, app-only active, growing), an
    active-user **trend sparkline**, most-used and fastest-growing bars, per-finding usage
    block + usage chip, and a **usage filter** (active / inactive / unused).
  - **Graceful degradation** (criterion 10): if sign-in logs are unavailable (no P1 / 403),
    `usage` is `None` and the assessment continues; dashboard shows a P1 notice.
  - `graph_client.get_all()` gained `max_items` to bound sign-in paging. `tests/test_activity.py`.
- **Application (app-only) permission discovery** alongside delegated OAuth consent:
  - `collectors.enrich_with_app_role_assignments()` reads
    `/servicePrincipals/{id}/appRoleAssignments`; resolves each `appRoleId` GUID to a
    readable permission name via the resource SP's `appRoles` (falls back to the GUID if
    unresolvable — never lost). Supports custom (non-Graph) enterprise APIs.
  - New fields: `delegated_permissions` (`[{resource, permission, consent_type}]`),
    `application_permissions` (`[{resource, permission, permission_id}]`),
    `has_app_only_access`. Existing `scopes`/`consent_type`/`user_count` unchanged.
  - Scoring now factors app-only permissions (higher weight: no user, tenant-wide) —
    closes the blind spot where app-only apps scored 0.
  - Dashboard: access-type cards (delegated / app-only / both / high-privilege app-only),
    a permission-type filter, and per-finding app-only permission list + type chip.
  - `tests/test_appperms.py`.
- Minimal test infrastructure: `tests/test_smoke.py` (module-import smoke tests +
  scoring/report/notify behavior), `pyproject.toml` (pytest config).
- `.github/workflows/ci.yml` — CI on pull requests (compileall + import smoke + pytest).
- Deploy is now gated on tests: `deploy.yml` runs a `test` job and deploys only if it passes.
- `docs/architecture-current.md` — baseline architecture documentation.
- README: local test commands.

### Fixed
- `scripts/postdeploy.sh` fallback zip now includes **all** root `*.py` files (previously
  omitted `notify.py`, which `function_app.py` imports — would cause `ModuleNotFoundError`
  on the config-zip fallback deployment path).

## [0.4.0] - 2026-07-25
### Added
- Weekly digest email attaches the full self-contained dashboard as `shadow-ai-report-<date>.html`.
- CI/CD: auto-deploy to Azure Functions on push to `main` (`deploy.yml`, functions-action).

## [0.3.0] - 2026-07-25
### Added
- `/api/report` endpoint serves the live dashboard from Blob (one URL).
- Weekly email digest via Microsoft Graph `sendMail` (Managed Identity, no SMTP secrets);
  `weekly_digest` timer + `/api/digest` test endpoint; `Mail.Send` in grant scripts.

## [0.2.0] - 2026-07-25
### Added
- Dashboard report (light/dark: KPI cards, risk donut, top-apps + sensitive-scope bars,
  expandable findings).
- Microsoft first-party AI apps separated from Shadow AI risk counts (governed).
- Skywork AI added to the vendor catalog.

### Changed
- Code deployment moved to remote build (`func publish`) — Linux Consumption does not
  support URL-based run-from-package.
- Application Insights removed from ARM (avoids `microsoft.operationalinsights` RP dependency).

## [0.1.0] - 2026-07-25
### Added
- Initial release: Entra/Graph OAuth-consent Shadow AI discovery, transparent risk scoring,
  HTML/JSON reporting, Azure Function (timer + HTTP), Managed Identity, one-click Deploy to Azure.
