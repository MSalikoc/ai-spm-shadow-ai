# AI-SPM — Shadow AI Posture Management

Entra ID / Microsoft Graph üzerinden **organizasyondaki 3. parti AI uygulamalarını
keşfeden, verilen veri izinlerini risk skorlayan ve sürekli takip eden** read-only
bir güvenlik ajanı. Security Copilot'ın kapsamı dışında kalan "AI attack surface"
tarafını hedefler. Tamamen okuma-modu — hiçbir izni değiştirmez, hiçbir app'i silmez.

## 🚀 Deploy to Azure (tek-tık)

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMSalikoc%2Fai-spm-shadow-ai%2Fmain%2Fdeploy%2Fazuredeploy.json)

Buton, Function App + Managed Identity + Storage + App Insights'ı kurar; Function
kodunu GitHub Release zip'inden (`WEBSITE_RUN_FROM_PACKAGE`) çeker. Deploy sonrası
**tek bir manuel adım** kalır: Managed Identity'ye Graph rollerini atamak.

> Not: Buton `releases/latest/download/aispm-function.zip` asset'ini kullanır — o yüzden
> en az bir `v*` tag'i push edilip Release oluşturulduktan **sonra** çalışır.

### Deploy sonrası (tek adım)
```bash
# ARM çıktısındaki managedIdentityPrincipalId'yi al:
az functionapp identity show -g <RG> -n <FUNC> --query principalId -o tsv
# MI'a Graph rollerini ata:
./scripts/grant_graph_roles.sh <PRINCIPAL_ID>      # veya .ps1 (PowerShell)
```
Bu kadar. Function ertesi sabah (varsayılan 06:00 UTC) otomatik taramaya başlar;
raporlar `aispm-reports` Blob container'ında `latest.html` + tarihçe olarak birikir.

### Nasıl çalışıyor (tek-tık akışı)
```
[Deploy to Azure butonu] → ARM template
        │
        ├─ Storage + App Insights + Consumption plan
        ├─ Function App (Python 3.11, System-assigned Managed Identity)
        └─ WEBSITE_RUN_FROM_PACKAGE → GitHub Release'deki aispm-function.zip
                                       (bağımlılıkları gömülü, release.yml üretir)
        ▼
[post-deploy] grant_graph_roles → MI'a Directory/Application/AuditLog.Read.All
        ▼
[her gün 06:00] daily_scan timer → Graph tara → risk skorla → Blob'a rapor
```

---

## Yerel kullanım

> Bulut gerekmez; hackathon demosu ve hızlı PoC için.

## Ne buluyor?
- "Sign in with Microsoft" ile bağlanmış AI SaaS'ları (ChatGPT, Otter, Grammarly, Glean, …)
- Bu uygulamalara verilmiş **hassas delegated izinler** (`Mail.Read`, `Files.ReadWrite.All`, …)
- **Blast radius**: admin (AllPrincipals) onayı mı, kaç kullanıcı vermiş
- Doğrulanmamış publisher / dış tenant / kalıcı erişim (`offline_access`) sinyalleri
- Her bulgu için **gerekçe + düzeltme adımları**

## Hızlı deneme (tenant gerekmez)
```bash
pip install -r requirements.txt
python demo.py          # out/shadow_ai.html üretir (sentetik veri)
```

## Gerçek tenant'ta çalıştırma

### 1) Entra app registration
1. Entra admin center > App registrations > New registration.
2. **API permissions** ekle (Microsoft Graph, **Application** veya **Delegated**):
   - `Directory.Read.All`
   - `Application.Read.All`
   - `AuditLog.Read.All`
   - (delegated modda `openid`, `profile`, `offline_access` otomatik gelir)
3. **Grant admin consent** butonuna bas.
4. Cihaz kodu (delegated) modu için: Authentication > "Allow public client flows" = **Yes**.

### 2) Çalıştır
```bash
# Cihaz kodu — secret gerekmez, analistin oturumuyla (demo/hackathon)
python main.py --tenant <TENANT_ID> --client-id <APP_ID>

# Otomasyon — client secret ile (CI / zamanlanmış tarama)
python main.py --mode app --tenant <T> --client-id <C> --client-secret <S>
```
Çıktı: `out/shadow_ai.html` ve `out/shadow_ai.json`.

## Azure Function olarak (otomatik, secret'siz "takip eden assessment")

Engine'i zamanlanmış çalışan bir servise çevirir: her gün otomatik tarar,
Managed Identity ile kimlik doğrular (secret yok), raporu Blob'a yazar.

- `daily_scan` (timer) — varsayılan her gün 06:00 UTC (`SCAN_SCHEDULE` ile değiştir).
- `scan_now` (HTTP) — on-demand tarama; ileride Security Copilot plugin'i buraya bağlanır.

### Deploy
```bash
# 1) Function App oluştur (Python 3.11, Linux, Consumption) + system-assigned identity
az functionapp create -g <RG> -n <FUNC> --consumption-plan-location westeurope \
  --runtime python --runtime-version 3.11 --functions-version 4 \
  --storage-account <STORAGE> --os-type Linux
az functionapp identity assign -g <RG> -n <FUNC>

# 2) MI'a Graph app-role'lerini ata (portal'dan yapılamaz)
MI_ID=$(az functionapp identity show -g <RG> -n <FUNC> --query principalId -o tsv)
./scripts/grant_graph_roles.sh "$MI_ID"

# 3) App ayarları
az functionapp config appsettings set -g <RG> -n <FUNC> --settings \
  AISPM_TENANT_ID=<TENANT_ID> SCAN_SCHEDULE="0 0 6 * * *" REPORT_CONTAINER=aispm-reports

# 4) Deploy (func core tools)
func azure functionapp publish <FUNC>
```

Lokal test: `cp local.settings.json.example local.settings.json`, doldur, `func start`.
`--mode managed` ile CLI de MI/`az login` kimliğiyle çalışır.

## Mimari
```
auth.py         → Entra token (device code / client secret / managed identity)
graph_client.py → Graph sayfalama + throttling
collectors.py   → servicePrincipals + oauth2PermissionGrants → normalize
config.py       → AI vendor kataloğu + hassas scope ağırlıkları  (tek ayar noktası)
scoring.py      → şeffaf risk skoru (0-100) + gerekçe + remediation
pipeline.py     → ortak tarama akışı (CLI + Function paylaşır)
report.py       → HTML + JSON (string + dosya)
storage.py      → rapor yayınlama (Blob / lokal), tarihçe + latest.*
main.py         → CLI
function_app.py → Azure Function: daily_scan (timer) + scan_now (HTTP)
deploy/         → azuredeploy.json (ARM — tek-tık "Deploy to Azure")
scripts/        → grant_graph_roles.{sh,ps1} (MI'a Graph rolleri)
.github/        → release.yml (self-contained Function zip'i → GitHub Release)
```

## Yeni sürüm yayınlama
```bash
git tag v0.2.0 && git push --tags        # release.yml self-contained zip'i üretir
```
Repo yolu (`MSalikoc/ai-spm-shadow-ai`) README butonu ve `deploy/azuredeploy.json > packageUri`
içinde ayarlıdır.

## Yol haritası
- **v1 — Agent Inventory:** Copilot Studio + Azure AI Foundry deployment'larını,
  bağlı data source ve tool izinlerini Azure Resource Graph ile haritala.
- **v2 — Red-Team modülü:** keşfedilen agent endpoint'lerine otomatik prompt
  injection / jailbreak / veri sızıntısı testi (OWASP LLM Top 10 eşlemeli).
- **v3 — Egress keşfi:** Defender for Cloud Apps Cloud Discovery ile network
  seviyesinde AI trafiği (api.openai.com vb.) + kullanıcı bazlı veri hacmi.
- **v4:** Sentinel'e bulgu gönderme (incident) + zamanlanmış posture drift takibi.

## Güvenlik notu
Tümüyle read-only. Hiçbir izni revoke etmez, hiçbir app'i silmez — yalnızca raporlar.
Remediation adımları operatöre öneri olarak sunulur; uygulama kararı insana bırakılır.
