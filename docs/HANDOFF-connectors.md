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
- ✅ **Adım 3** — `connectors/entra_agent_id.py`: `/servicePrincipals/microsoft.graph.agentIdentity` +
  `/applications/microsoft.graph.agentIdentityBlueprint` + SP başına owners/sponsors/appRoleAssignments/
  oauth2PermissionGrants/memberOf → **AGENT_IDENTITY** & **AGENT_BLUEPRINT** asset. app-only vs delege perm
  ayrı; alt-kaynak hatası → PARTIALLY_CONNECTED (identity'ler yine gelir); blueprint listesi düşerse identity
  korunur. `metrics()` (10 metrik). Permission `Application.Read.All`+`Directory.Read.All`. Mock testler
  (tests/test_entra_agent_id.py, FakeGraph path router).
- ✅ **Adım 4** — `connectors/defender_cloud_apps.py`: beta `/security/dataDiscovery/cloudAppDiscovery/
  uploadedStreams` + `aggregatedAppsDetails(period=duration'P30D')` → keşfedilen web app'ler. AI filtresi:
  MDCA kategorisi + kod-dışı `connectors/catalogs/ai_applications.json` (isim/domain; `AI_APPLICATIONS_CATALOG_PATH`
  ile override). Her AI app → **AI_APPLICATION** (users/devices/IP/traffic özeti, stream'ler arası aggregate),
  her (stream,app) → **USAGE_OBSERVATION**. Upload hacmi TEK BAŞINA hassas sayılmaz
  (`data_sensitivity=UNDETERMINED_REQUIRES_PURVIEW`, `sensitive_data_types=field(NOT_EXPOSED_BY_API)`). Beta URL
  tam-URL geçilerek (client v1.0 sabit, değişmedi). Stream hatası → PARTIALLY_CONNECTED. `metrics()` (9 metrik).
  Permission `CloudApp-Discovery.Read.All`, ENABLE_DEFENDER_CLOUD_APPS+ENABLE_PREVIEW_CONNECTORS. Mock testler.
- ✅ **Adım 5** — `connectors/purview_audit.py`: `POST /security/auditLog/queries` → poll (`succeeded`) →
  `/records`; op filtresi CopilotInteraction/ConnectedAIAppInteraction/AIAppInteraction. Her kayıt →
  **SENSITIVE_INTERACTION** (user, app_host, SIT, sensitivity_label_id, referenced_resources, DLP policy/rule/
  action, direction BLOCKED/ALLOWED/ACCESSED/SHARED/UNKNOWN). `sensitivity_label_name=field(NOT_EXPOSED_BY_API)`.
  **Raw prompt/response STORE_RAW_AI_CONTENT=true değilse ASLA saklanmaz.** Permission `AuditLogsQuery.Read.All`.
  `metrics()` (10 metrik). Ayrıca `connectors/purview_dspm_import.py`: JSON/CSV DSPM export adapter (versioned
  schema, uyumsuz major → ApiUnavailable), kaynak PURVIEW_DSPM_EXPORT (audit'ten ayrı). Portal scraping YOK.
  Altyapı: `model.EXTERNAL_ID_KEYS`'e `purview_record_id` (event'lere benzersiz id; **korelasyon token'ı DEĞİL**),
  `GraphClient.post()` eklendi. Mock testler (poll/timeout/raw-gizlilik/CSV/schema-mismatch).
- ✅ **Adım 6** — `connectors/sensitive_data.py`: dört kaynağı app/agent bazında birleştirir. `build_app_profiles`
  (MDCA usage + Purview hassaslık aynı app altında; 7g/30g özet; etkilenen kullanıcı; SIT/label/workload dağılımı;
  yön taksonomisi ACCESSED/SHARED/UPLOADED/GENERATED/BLOCKED/ALLOWED/UNKNOWN). **erişim≠paylaşım**; upload hacmi
  tek başına paylaşım değil. `evaluate_findings` (SENSITIVE_DATA_SHARED_WITH_UNSANCTIONED_AI /
  _BLOCKED_TO_AI / UNSANCTIONED_AI_UPLOAD_UNDETERMINED / AI_APP_ACCESSING_LABELED_DATA). `portfolio_summary`.
  Event→app eşleştirme: entra_app_id > mdca_app_id > isim; eşleşmeyen → sentetik app (ayrı gösterilir).
  **Korelasyon düzeltmesi:** `agent_blueprint_id` artık MERGE token'ı değil → `correlation._relate_blueprints`
  ile identity↔blueprint "relate-not-merge" (aynı blueprint'ten çok identity collapse olmaz). Adım 3 açığı kapandı.
- ✅ **Adım 7** — `connectors_report.py`: `pipeline.run_connectors()` çıktısından **15-bölümlü assessment**
  (`assessment()` dict): 1-executive, 2-data_source_coverage, 3-sensitive_exposure ("Applications with
  Sensitive Data Exposure" tablosu), 4-agent_identities, 5-agent365_packages, 6-shadow_ai_usage,
  7-sensitive_interactions, 8-findings, 9-direction_analysis, 10-correlation_quality, 11-application_detail
  ("Sensitive Data" sekmesi), 12-agent_detail ("Data Access" sekmesi: owners/sponsors/perms/blueprint ilişkisi),
  13-sit_distribution, 14-users_and_groups, 15-known_gaps (dürüst API/korelasyon sınırları).
  `html_string()` standalone tek-dosya HTML (aynı CSS/tema `report.CSS`'ten içe aktarılır, kopyalanmaz).
  `pipeline.py`: `connectors_enabled()` + `run_connectors(graph)` (registry→correlate→profiles→portfolio; flag
  kapalıyken **None**, doğrulandı → mevcut Entra taramasına sıfır etki). `function_app.py`: yeni **`/api/connectors`**
  route'u (function-key, read-only) — flag kapalıysa Graph'a hiç dokunmadan `NOT_CONFIGURED` JSON döner; açıksa
  gerçek connector'ları çalıştırıp JSON (`?format=html` ile HTML) döner.
  **Bilinçli kapsam kararı: `report.py` (1007 satır) ve `_run_scan`/`daily_scan`/`weekly_digest`/`scan_now`
  HİÇ DEĞİŞTİRİLMEDİ** — yeni assessment tamamen ayrı bir modül+endpoint olarak eklendi ki mevcut, deploy'da
  çalışan dashboard/otomatik tarama/e-posta akışı hiçbir şekilde risk altına girmesin. `executive.CONNECTORS`
  da bu yüzden değiştirilmedi — connector health'i zaten `connectors_report.py`'nin kendi "data_source_coverage"
  bölümünde (dürüst, kaynak-bazlı) gösteriliyor; bu, aynı bilgiyi iki farklı yerde tutmadan tek yerde sağlıyor.
  Korelasyon notu: birleşik asset'lerde `asset_type` ilk üyeden miras kalabilir (ör. Agent365+Entra Identity
  merge'i `AI_AGENT` görünür) → bölümler `asset_type` değil alt-dict varlığına (`agent365`/`agent_identity`/…)
  göre filtreler (connector `metrics()` fonksiyonlarıyla aynı desen).
- ✅ **Adım 8** — `connectors_drift.py`: connector kaynaklı snapshot/change-tracking, **`drift.py`'ye PARALEL**
  (drift.py HİÇ DEĞİŞTİRİLMEDİ). Ayrı depolama anahtarları: `connectors_snapshot.json` / `connectors_changes.json`.
  Event tipleri: `NEW_AGENT_365_PACKAGE`, `AGENT_365_PACKAGE_BLOCKED/UNBLOCKED`, `NEW_AGENT_IDENTITY`,
  `AGENT_IDENTITY_DISABLED/ENABLED`, `AGENT_OWNER_CHANGED`, `AGENT_SPONSOR_CHANGED`,
  `NEW_UNSANCTIONED_AI_APP`, `AI_APP_SANCTIONED`, `NEW_SENSITIVE_INTERACTION`,
  `SENSITIVE_INTERACTION_BLOCKED/ALLOWED`, `PURVIEW_COVERAGE_CHANGED`, `DATA_SOURCE_CONNECTED/DISCONNECTED`.
  İlk scan baseline (event üretmez, drift.py ile aynı kural). Purview interaction'lar yalnızca **hassas
  içerikli + gerçekten yeni** olanlar için event üretir (30g pencere overlap'inde tekrar "yeni" sayılmaz).
  **Gizlilik:** snapshot'a interaction'ların yalnızca minimal alanları yazılır — `raw_content`
  (STORE_RAW_AI_CONTENT=true olsa bile) ASLA kalıcı depoya (Blob) kopyalanmaz (test ile doğrulandı).
  `function_app.py`'nin `_run_scan`'ına **tek satır, try/except'li** entegre edildi: her scan sonunda
  `pipeline.run_connectors(graph)` + `connectors_drift.process(...)` çağrılır — flag'ler kapalıyken
  `run_connectors` None döner, `process(None)` storage'a hiç dokunmadan no-op döner (doğrulandı).
  `daily_scan`/`weekly_digest`/`scan_now`'ın mevcut davranışı (scored/report/notify) DEĞİŞMEDİ, sadece bu tek
  ek adım eklendi. Henüz hiçbir dashboard'da render edilmiyor (mevcut `report.py`'nin `_timeline_section`'ı
  yalnızca klasik `drift.py` event'lerini gösterir) — bu bilinçli bir sonraki-adım notu, kapsam dışı bırakıldı.
- **153 test geçiyor** (Adım 3 +8, Adım 4 +8, Adım 5 +14, Adım 6 +8, Adım 7 +9, Adım 8 +16).

## 🎯 8 ADIMIN TAMAMI BİTTİ — deploy onayı bekleniyor
Tüm commit'ler **lokalde**, origin'e **henüz push edilmedi** (`git -C AISPM log --oneline origin/main..HEAD`
ile 8 commit görünür). Kullanıcı "hepsini bitirip sonda tek deploy" dedi — push/deploy için **açıkça onay
gerekiyor** (bkz. Git Safety Protocol — push kullanıcı onayı gerektiren bir eylem).

**Deploy sonrası bile hiçbir connector aktif olmaz** — tüm `ENABLE_*` env flag'leri Azure Function App
Configuration'da set edilmediği sürece (bugün itibarıyla set değiller) çerçevenin runtime etkisi sıfırdır;
mevcut Entra/OAuth scan+dashboard+e-posta akışı bire bir aynı çalışmaya devam eder. Connector'ları gerçekten
açmak için ayrıca: (1) Azure Function App → Configuration'a `ENABLE_AGENT365`, `ENABLE_ENTRA_AGENT_ID`,
`ENABLE_DEFENDER_CLOUD_APPS`, `ENABLE_PURVIEW_AUDIT` (+`ENABLE_PREVIEW_CONNECTORS` beta endpoint'ler için)
eklenmeli, (2) Graph app-only permission'ları (bkz. her adımın "gerekli permission" notu) admin consent
almalı, (3) opsiyonel `PURVIEW_DSPM_IMPORT_PATH` + DSPM export dosyası.

## Sonraki oturum için olası devam noktaları (Adım 8 sonrası, kapsam dışı bırakıldı)
- Connector change event'lerini (`connectors_drift.recent()`) bir dashboard'da göstermek (yeni sekme veya
  `connectors_report.py`'ye 16. bölüm olarak, ya da `report.py`'nin `_timeline_section`'ına opsiyonel ek).
- `notify.py`'ye connector-özel haftalık digest e-postası (şu an sadece klasik Entra digest'i var).
- Yukarıdaki "Bilinen korelasyon eksikleri / API şema belirsizlikleri" maddelerinin gerçek tenant'ta doğrulanması.

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
