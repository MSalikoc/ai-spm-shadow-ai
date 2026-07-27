# HANDOFF — Microsoft AI Data Sources Integration (8-step phase)

Bu dosya, session değişiminde işi kaldığı yerden sürdürmek için. AI-SPM'i dört
Microsoft veri kaynağından beslenen birleşik AI+agent assessment platformuna çeviriyoruz.
**Bu faz: yalnızca veri toplama/korelasyon/analiz/raporlama. Security hardening / auth
değişikliği / auto-remediation YOK.**

## Ana soru (ürünün cevaplaması gereken)
Hangi AI uygulaması/agent üzerinden HANGİ hassas veri paylaşıldı, hangi veri türleri,
kaç kullanıcı etkilendi, ne zaman, ve uygulamanın kurumsal onay durumu nedir?

## Çalışma kuralları (önemli)
- Repo: `/Users/cyberwise/Desktop/CLAUDEPRO/AISPM`, GitHub `MSalikoc/ai-spm-shadow-ai`.
- **Backup alındı:** git tag `v4-pre-connectors` + scratchpad tar.gz.
- Test venv: `/private/tmp/claude-501/.../scratchpad/venv` — `"$VENV/bin/python" -m pytest`.
- CI/CD: `main`'e push → GitHub Actions test+deploy otomatik. `func publish` GEREKMEZ.
- Her adım sonunda 9 çıktı ver: değişen dosyalar / eklenen modeller / kullanılan endpoint'ler /
  gerekli permission+lisans / örnek normalize JSON / mock test sonuçları / dashboard değişiklikleri /
  API'de olmayan alanlar / bilinen korelasyon eksikleri. **Kullanıcı her adımı onaylayınca sonrakine geç.**
- **Sahte envanter üretme.** Kaynak bağlı değilse coverage'da dürüstçe göster.

## Mimari kararlar (yerleşik)
- Klasör `connectors/` (NOT `collectors/` — mevcut `collectors.py` ile çakışmasın).
- Framework **canlı pipeline'a HENÜZ bağlı değil** (Adım 7'de bağlanacak) → runtime etkisi sıfır.
- `connectors/base.py`: `BaseCollector` (is_configured/collect/normalize/get_health/get_coverage +
  `safe_run` asla fırlatmaz). `ConnectorStatus` (8 durum). `Source`, `EntityType` (14 tip).
- `connectors/model.py`: `make_asset` (external-id'den deterministic asset_id), `field()` availability
  wrapper (AVAILABLE/NOT_PRESENT/NOT_EXPOSED_BY_API/NOT_LICENSED/UNKNOWN), `raw_reference`.
- `connectors/correlation.py`: union-find, öncelik entra_app_id 98 > agent_identity 96 > blueprint 90 >
  agent365_package 85 > agent365_asset 80 > manifest 75 > publisher+domain 65. **İsim-only ASLA merge
  etmez (40).** confidence hesaplanır.
- `connectors/registry.py`: `run(collectors)` dayanıklı — biri patlarsa diğerleri devam.
- Her connector env-gated: `ENABLE_AGENT365`, `ENABLE_ENTRA_AGENT_ID`, `ENABLE_DEFENDER_CLOUD_APPS`
  (+`ENABLE_PREVIEW_CONNECTORS`), `ENABLE_PURVIEW_AUDIT`, `PURVIEW_DSPM_IMPORT_PATH`.

## Durum (bugüne kadar)
- ✅ **Adım 1** — connector framework + birleşik model + korelasyon + registry + 5 iskelet + testler.
- ✅ **Adım 2** — `connectors/agent365.py`: `/copilot/admin/catalog/packages`(+detay) → AI_AGENT,
  elementDetails parse (declarative/custom-engine/bot ID, scopes, file_support), `raw_reference`,
  `metrics()` (9 metrik). Permission `CopilotPackages.Read.All`. Resilient. Mock testler.
- **89 test geçiyor**, hepsi CI/CD ile deploy edildi.

## SIRADAKİ: Adım 3 — Microsoft Entra Agent ID collector
`connectors/entra_agent_id.py` (iskelet mevcut, implement edilecek). Kullanıcı onayladı, başla.
- Endpoint: `GET /v1.0/servicePrincipals/microsoft.graph.agentIdentity`,
  `GET /v1.0/applications/microsoft.graph.agentIdentityBlueprint`,
  `GET /servicePrincipals/{id}/microsoft.graph.agentIdentity/owners|sponsors`,
  `/appRoleAssignments`, `/oauth2PermissionGrants`.
- Normalize → **AGENT_IDENTITY** (veya AI_AGENT) asset: agent_identity_id (object id), display_name,
  app_id, blueprint_id, account_enabled, created_date, owners[], sponsors[], application_permissions[],
  delegated_permissions[], group_memberships[]. external_ids: entra_app_id, agent_identity_id (entra_object_id),
  agent_blueprint_id → korelasyona hazır.
- Metrikler: total/enabled/disabled identities, without owner/sponsor/blueprint, with app-only/delegated
  perms, uncorrelated.
- Kabul: identities+blueprints listelenir; owner/sponsor gösterilir; app vs delegated perm ayrı; Agent365
  package ile appId üzerinden korele; owner/sponsor'suz filtrelenebilir; identity'siz Agent365 package ayrı gösterilir.
- Mock Graph ile offline test (bkz. tests/test_agent365.py deseni: FakeGraph get_all/get).

## Kalan adımlar (özet)
- **Adım 4** — Defender for Cloud Apps: `/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams`
  (+`aggregatedAppsDetails(period=duration'P30D')`), `CloudApp-Discovery.Read.All`, PREVIEW. Web Shadow AI:
  app + user/device/IP/traffic. AI filtresi: MDCA category + `catalogs/ai_applications.json` (kod dışı). Upload
  hacmini TEK BAŞINA "hassas paylaşım" sayma (Purview ile korele). USAGE_OBSERVATION kayıtları.
- **Adım 5** — Purview Audit + DSPM import: `POST /v1.0/security/auditLog/queries` → poll → records;
  op filtresi CopilotInteraction/ConnectedAIAppInteraction/AIAppInteraction; `AuditLogsQuery.Read.All`.
  SENSITIVE_INTERACTION modeli (SIT, sensitivity label, referenced resources, DLP policy/rule/action,
  direction). API'de olmayan alan → `field(NOT_EXPOSED_BY_API)`. Raw prompt SAKLAMA (`STORE_RAW_AI_CONTENT=false`).
  `purview_dspm_import.py` JSON/CSV import adapter (versioned schema). Portal scraping YOK.
- **Adım 6** — Uygulama bazlı hassas veri korelasyonu: 4 kaynağı app/agent bazında birleştir. `sensitive_data_summary`
  (7d/30d, affected users/agents, blocked/allowed, SIT/label/workload dağılımı). Yön ayrımı:
  ACCESSED/SHARED/UPLOADED/GENERATED/BLOCKED/ALLOWED/UNKNOWN_DIRECTION (erişim ≠ paylaşım). Findings:
  SENSITIVE_DATA_SHARED_WITH_UNSANCTIONED_AI vb.
- **Adım 7** — Rapor/dashboard: executive kartlar + "Applications with Sensitive Data Exposure" tablosu +
  Application Detail "Sensitive Data" sekmesi + Agent Detail "Data Access" sekmesi + coverage (kaynak bazlı).
  BURADA framework canlı `pipeline`/`report`'a bağlanır. 15-bölümlü final assessment yapısı.
- **Adım 8** — Snapshot/change-tracking: yeni event tipleri (NEW_AGENT_365_PACKAGE, NEW_SENSITIVE_INTERACTION,
  SENSITIVE_INTERACTION_BLOCKED/ALLOWED, AGENT_OWNER/SPONSOR_CHANGED, PURVIEW_COVERAGE_CHANGED vb.) +
  change-odaklı haftalık digest. Mevcut `drift.py` motoruna entegre.

## Mevcut AI-SPM (faz öncesi, canlı) — kısaca
Entra/Graph tabanlı: app+app-only permission keşfi, sign-in activity (P1), classification (8 kategori),
ownership/lifecycle governance, managed findings, drift/change-tracking, tab'lı executive dashboard.
Modüller: collectors.py, scoring.py, pipeline.py, report.py, storage.py, classifier.py, metadata.py,
findings.py, drift.py, executive.py, notify.py, function_app.py. Deploy: Function App `aispm-xdwdwjyegx6kc`
(RG `aispm`, West Europe), function-key endpoints (/api/scan|report|digest|metadata|finding).
