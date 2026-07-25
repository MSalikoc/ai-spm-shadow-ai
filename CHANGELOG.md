# Changelog

All notable changes to AI-SPM are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
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
