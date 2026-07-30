# HANDOFF — Microsoft AI Data Sources (durum: 8/8 adım TAMAMLANDI, canlıda)

Bu dosya, önceki oturum context window'unu doldurduğu için yeni bir oturuma **kaldığı
yerden** devam edebilmek amacıyla yazıldı. Aşağıdakiler okunmadan devam edilmemeli.

## Genel durum

- Repo: `/Users/cyberwise/Desktop/CLAUDEPRO/AISPM`, GitHub `MSalikoc/ai-spm-shadow-ai`.
- `main` branch'i **tamamen push edilmiş ve temiz** (`git status` boş). Son commit:
  `585c77e` (bu dosyanın yazıldığı an itibarıyla).
- Test venv: `/private/tmp/claude-501/.../scratchpad/venv` — ama bu **session-specific**,
  yeni oturumda YOK olacak. Yeni oturumda: `pip install -r requirements.txt pytest` ile
  kur, sonra `pytest` çalıştır.
- **159 test geçiyor.** CI'da hem `python3.11` (GitHub Actions) hem manuel olarak
  `/usr/bin/python3` (macOS sistem Python'ı, 3.9) ile de derleme kontrolü yapıldı —
  **önemli**: bu makinedeki dev venv 3.13, ama f-string'lerde ifade içi backslash gibi
  3.12-öncesi kısıtlamalar CI'da (3.11) patlayabiliyor, 3.13 bunu yakalamıyor. Yeni kod
  yazarken `/usr/bin/python3 -m py_compile <dosya>` ile ekstra kontrol et.
- CI/CD: `.github/workflows/deploy.yml` — `test` job'u HER PUSH'TA çalışır (koşulsuz).
  `deploy` job'u yalnızca `vars.AZURE_FUNCTIONAPP_NAME` repo variable'ı set edilmişse
  çalışır. **Şu anda bu değişken KALDIRILMIŞ durumda** (aşağıya bak) — deploy job'u
  "skipped" olarak görünür, bu bir hata değil, bilinçli bir ayar.

## Neden deploy hedefi kaldırıldı

Eski Function App `aispm-xdwdwjyegx6kc` artık DNS'te yok (`NXDOMAIN`, `dig`/`curl` ile
doğrulandı — muhtemelen silinmiş). CI iki kez bu yüzden deploy adımında başarısız oldu.
`gh -R MSalikoc/ai-spm-shadow-ai variable delete AZURE_FUNCTIONAPP_NAME` ile kaldırıldı.

**Kullanıcının planı:** "Şuan canlıyla bir işimiz yok. Sen herşey okey dediğinde ben
sıfırdan deployment yapacağım tenant'ta." Yani bir sonraki adım muhtemelen **kullanıcının
sıfırdan yeni bir deploy denemesi** olacak. O deploy başarılı olup CI/CD otomatik
deploy'u tekrar bağlamak istenirse: README'nin "Continuous deployment (optional)"
bölümündeki adımları izle (`AZURE_FUNCTIONAPP_NAME` variable + `AZURE_FUNCTIONAPP_PUBLISH_PROFILE`
secret set et).

## Bu oturumda yapılanlar (özet, en yeniden eskiye değil, mantıksal sırayla)

### 1. Microsoft AI Data Sources — 8 adımın TAMAMI (önceki oturumdan devam)
4 connector (`connectors/agent365.py`, `entra_agent_id.py`, `defender_cloud_apps.py`,
`purview_audit.py` + `purview_dspm_import.py`), korelasyon motoru, `connectors_report.py`
(assessment), `connectors_drift.py` (change-tracking). Tamamı opt-in (`ENABLE_*` flag'leri),
flag'ler kapalıyken sıfır runtime etkisi. `report.py`/`executive.py`/`drift.py` (klasik
Entra/OAuth ürünü) bilerek hiç değiştirilmedi.

### 2. Dashboard tasarımı — kullanıcı geri bildirimiyle BİRÇOK kez evrildi
Sırasıyla: (a) tek sayfa, 4 basit bölüm → (b) agent envanteri + Shadow AI trafiği + detay
panelleri eklendi → (c) klasik dashboard'un görsel diliyle (hero/donut/MS logosu) yeniden
tasarlandı → (d) Microsoft Zero Trust Assessment aracındaki gibi tablo+slide-over detay
paneli deseni (Risk/Status/What was checked/Remediation) → (e) **şeffaf 0-100 risk skoru**
(her puanın "+N — sebep" gerekçesi var, `scoring.py`'nin felsefesiyle aynı) + **6 sekmeli
dashboard** (Overview/Agents/Shadow AI/Sensitive Data/Findings/Gaps) + 2 akış (Sankey-tarzı)
diyagram → (f) Shadow AI sekmesi artık **Defender for Cloud Apps'in kendi "Discovered
apps" grid'iyle birebir aynı sütunlar** (Risk Score bar/Tag/Traffic/Upload/Transactions/
Users/IP Addresses/Devices/Last Seen) → (g) kullanışsız "Purview DSPM import" satırı
dashboard'dan gizlendi (`_CONNECTOR_INFO`'dan çıkarıldı, ama collector kodu duruyor).

**Son hâli:** `connectors_report.py`, `/api/connectors?format=html` (veya `?code=...`
ile JSON). `report.CSS` içe aktarılıyor (kopyalanmıyor) — görsel dil tutarlı.

### 3. İki dashboard birbirine bağlandı (bugünün en son işi)
`report.py`'nin header'ına "AI Data Sources →" linki, `connectors_report.py`'nin
header'ına "← Core Dashboard" linki eklendi. JS ile mevcut `?code=...` otomatik taşınıyor.
**Önemli düzeltme:** İlk versiyon `location.search`'ü körlemesine kopyalıyordu — bu,
`docs/sample-report.html`'i `htmlpreview.github.io` üzerinden statik önizlerken kırık bir
URL'ye gidiyordu (kullanıcı canlı yakaladı). Düzeltme: link artık yalnızca
`location.pathname.indexOf('/api/')===0` ise (yani gerçekten Function App'te
çalışıyorsa) kendini yeniden yazıyor; statik/offline görünümde `.remove()` ile kendini
kaldırıyor. **Bu link canlıda hiç test edilmedi** — sadece syntax + statik dosya üzerinde
doğrulandı (aşağıdaki "Kanıtlanmamış" listesine bak).

### 4. Kurulum otomatikleştirildi (artık hiçbir şey opsiyonel değil, e-posta hariç)
`scripts/postdeploy.sh` artık TEK script'te her şeyi yapıyor: kod deploy + çekirdek Graph
rolleri + 4 connector'ın Graph rolleri (`grant_connector_roles.sh` çağrısı) + connector'ları
açma (`enable_connectors.sh` çağrısı). Kullanıcı tek komut çalıştırıyor, README'de "Part 1
opsiyonel Part 2" ayrımı kaldırıldı — tek doğrusal 3 zorunlu + 1 opsiyonel (haftalık
e-posta) adım. **Bu birleşik script canlıda uçtan uca hiç TEK SEFERDE test edilmedi**
(parçaları ayrı ayrı, kullanıcının elle aralıklarla çalıştırmasıyla test edildi ve
düzeltildi — bkz. aşağıdaki riskler).

### 5. Gerçek, canlı testlerle bulunan ve düzeltilen buglar
- **README'de `<RESOURCE_GROUP>` gibi köşeli parantez placeholder'ları** — kullanıcı
  parantezleri de komuta dahil edip yapıştırınca bash `<` karakterini redirection sanıp
  syntax error verdi. **Düzeltme:** tüm komutlar artık `RESOURCE_GROUP="..."` şeklinde
  ÖNCE tanımlanan shell değişkenlerini kullanıyor, hiçbir yerde `< >` yok.
- **Cloud Shell ~20dk boşta kalınca session'ı sıfırlıyor** (dosyalar kalıyor, shell
  değişkenleri uçuyor) — script'ler artık boş parametre geldiğinde bunu açıkça söylüyor
  ("Cloud Shell'i bir süre boş bıraktıysanız..." mesajı).
- **`az functionapp identity show` bazı Cloud Shell/az CLI sürümlerinde gerçek bir
  `InvalidApiVersionParameter` hatası veriyor** (bizim kodumuzdan bağımsız, canlıda
  gözlemlendi). Tüm script'ler ve README artık daha sağlam olan
  `az resource show --resource-type "Microsoft.Web/sites" --query identity.principalId`
  komutunu kullanıyor + Portal'dan elle alma fallback'i dokümante edildi.
- **`docs/sample-report.html`'deki dashboard-arası link statik önizlemede kırıktı**
  (yukarıda #3'te anlatıldı).

### 6. Git geçmişi temizliği (Claude contributor olarak görünmesin istendi)
İki kez `git filter-branch --msg-filter` ile tüm commit mesajlarından
`Co-Authored-By: Claude...` satırı temizlendi + `--force-with-lease` ile push edildi.
**ÖNEMLİ — YENİ OTURUMDA UNUTMA:** Bundan sonra bu repo'ya yapılan commit'lere
**"Co-Authored-By: Claude" trailer'ı EKLEME** (kullanıcının açık isteği). GitHub API ile
doğrulandı: `gh api repos/MSalikoc/ai-spm-shadow-ai/contributors` → yalnızca `MSalikoc`.
(Not: GitHub'ın sidebar'daki "Contributors" widget'ı `/stats/contributors` adlı ayrı,
önbellekli bir endpoint kullanıyor — güncellenmesi birkaç dakika/saat sürebilir, panik
yapma, gerçek veri zaten doğru.)

### 7. README tamamen yeniden yazıldı (birkaç kez)
Son hâli: ~180 satır, TEK doğrusal akış (Step 1-3 zorunlu: deploy → postdeploy.sh (her
şeyi yapar) → dashboard'ları gör; Step 4 opsiyonel: haftalık e-posta). Eski "Part 1 /
Part 2 opsiyonel" çerçevesi ve uzun mimari/rasyonel paragrafları kaldırıldı (kullanıcı
"bilgiye gerek yok, toparla" dedi). `docs/sample-report.html`'e link var (gerçek kodla,
zengin mock veriyle üretilmiş — 10 Agent 365 paketi, 10 Entra Agent Identity, 18 Shadow
AI uygulaması, 33 Purview etkileşimi). Sample'ı yeniden üretme script'i:
`/private/tmp/claude-501/.../scratchpad/gen_rich_demo.py` — **bu scratchpad'te, yeni
oturumda YOK olacak**, gerekirse yeniden yazılmalı (mantığı: `pipeline.run_connectors()`'ı
sahte ama zengin bir Graph client ile çalıştırıp `connectors_report.html_string()`
çıktısını `docs/sample-report.html`'e yazmak).

### 8. Word dokümanı
`/Users/cyberwise/Desktop/AI-SPM-Kurulum-Rehberi.docx` — Türkçe, basit dilde, adım adım
müşteri kurulum rehberi. **README'nin en son (< > parantez / birleşik postdeploy.sh)
haliyle ARTIK TUTARSIZ OLABİLİR** — README birkaç kez daha değişti ama Word dokümanı
o değişikliklerden sonra güncellenmedi. Yeni oturumda kullanıcı isterse bunu güncel
README ile senkronize et.

## KANITLANMAMIŞ / açık riskler (yeni oturumun bilmesi gereken en önemli kısım)

Bunlar "muhtemelen çalışır" ama **hiç canlıda uçtan uca doğrulanmadı**:

1. **Birleştirilmiş `postdeploy.sh`** (deploy+tüm izinler+connector açma tek script) hiç
   TEK ÇALIŞTIRMADA test edilmedi. Teorik risk: `func publish` bitince hemen
   `az resource show` ile principalId çekmeye çalışıyoruz — Managed Identity henüz Azure'da
   tam oturmamış olabilir (elle yapılan testlerde adımlar arası doğal gecikme bu riski
   gizlemiş olabilir).
2. **Agent 365 ve Purview Audit connector'larının gerçekten `CONNECTED` olduğu HİÇ
   görülmedi.** İki ayrı Function App'te de (`aispm-xdwdwjyegx6kc` ve
   `aispm-tfx7osuzcajgo`), izinler atandığı halde (terminal'de "✓ atandı" görüldü)
   `PERMISSION_MISSING` kaldı. Güçlü hipotez: bu test tenant'ında Microsoft 365 Copilot
   lisansı ve/veya Purview Audit (Standard/Premium) kaydı açık değil — ama bu KANITLANMADI,
   Copilot/Purview Audit gerçekten açık bir tenant'ta hiç denenmedi.
3. **Dashboard'lar arası link (§3) canlı bir Function App'te hiç tıklanmadı** — sadece
   syntax + statik dosya üzerinde doğrulandı.
4. **`connectors_drift.py` (Adım 8, değişiklik takibi) canlı veriyle hiç çalıştırılmadı**
   — yalnızca mock/unit test edildi. Art arda iki gerçek taramada doğru "değişiklik"
   üretip üretmediği bilinmiyor.
5. **Haftalık e-posta özeti (`notify.py`) Part 2 (connector) bulgularını hiç içermiyor**
   — sadece klasik Entra bulguları. Bilinçli bir kapsam dışı bırakma, ama entegre etmek
   istenirse bir sonraki iş.

## Önerilen sıradaki adım

Kullanıcı zaten bunu biliyor ve planlıyor: **sıfırdan bir tenant'ta, GÜNCEL (birleştirilmiş)
`postdeploy.sh` ile tam bir deploy denemesi** — hem madde 1'i hem mümkünse (Copilot/Purview
lisansı olan bir tenant bulunabilirse) madde 2'yi doğrulamak için.

## Hızlı referans komutları

```bash
# Test çalıştırma (yeni oturumda venv yeniden kurulmalı):
cd /Users/cyberwise/Desktop/CLAUDEPRO/AISPM
pip install -r requirements.txt pytest
pytest                                    # 159 test bekleniyor

# Python 3.9 uyumluluk kontrolü (CI'ın 3.11'inden bile daha katı, f-string bug'larını yakalar):
/usr/bin/python3 -m py_compile <değiştirilen_dosya.py>

# Git durumu / son commit'ler:
git -C /Users/cyberwise/Desktop/CLAUDEPRO/AISPM log --oneline -10
git -C /Users/cyberwise/Desktop/CLAUDEPRO/AISPM status --short   # temiz olmalı

# CI durumu:
gh -R MSalikoc/ai-spm-shadow-ai run list --limit 3

# Sample report'u yeniden üretmek gerekirse (script scratchpad'te kayıp olabilir):
# pipeline.run_connectors(fake_graph) -> connectors_report.html_string(result, tenant_id) -> docs/sample-report.html
```

## Mevcut (faz öncesi + faz sonrası) mimari — kısaca

```
function_app.py              Azure Function entry points (timers + HTTP routes)
pipeline.py                  core scan flow + AI Data Sources entry point (run_connectors)
collectors.py, scoring.py    OAuth-consent discovery + transparent risk scoring
report.py, executive.py      core HTML dashboard + executive KPIs (bugün 1 link eklendi)
findings.py, drift.py        managed findings + change-tracking (klasik)
notify.py                    weekly email digest (yalnızca klasik bulgular)

connectors/                  4 AI Data Sources connector + correlation engine
connectors_report.py         AI Data Sources dashboard (6-tab, /api/connectors)
connectors_drift.py          AI Data Sources change-tracking (paralel, drift.py'ye dokunmaz)

auth.py, graph_client.py, config.py   shared: auth, Graph client, tunable AI catalog
deploy/                      ARM template (Deploy to Azure)
scripts/                     postdeploy.sh (artık her şeyi yapar) + çağırdıkları
docs/sample-report.html      mock veriyle üretilmiş örnek rapor (GitHub'da, README'den link)
.github/workflows/deploy.yml CI: test her zaman, deploy yalnızca hedef tanımlıysa
```
