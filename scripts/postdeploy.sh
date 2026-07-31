#!/usr/bin/env bash
# AI-SPM tek-adım post-deploy (Azure Cloud Shell / Bash).
# "Deploy to Azure" altyapıyı kurar; bu script kodu yükler, TÜM Graph rollerini atar
# (çekirdek tarama + 4 Microsoft AI Data Sources connector'ı) ve connector'ları açar.
# Tek script, tek çalıştırma — ayrı "opsiyonel adım" yok (haftalık e-posta özeti hariç,
# bkz. README).
#
# Kullanım:
#   git clone https://github.com/MSalikoc/ai-spm-shadow-ai.git
#   cd ai-spm-shadow-ai
#   ./scripts/postdeploy.sh <RESOURCE_GROUP> <FUNCTION_APP_NAME>
#
# Not: Linux Consumption URL-tabanlı RUN_FROM_PACKAGE desteklemediği için kod
# 'func azure functionapp publish' (remote build) ile yüklenir.
set -euo pipefail

if [[ -z "${1:-}" || -z "${2:-}" ]]; then
  echo "HATA: Resource group veya Function App adı boş geldi." >&2
  echo "Kullanım: $0 <RESOURCE_GROUP> <FUNCTION_APP_NAME>" >&2
  echo "(README'deki gibi: önce RESOURCE_GROUP=\"...\" ve FUNCTION_APP=\"...\" tanımlayıp" >&2
  echo " sonra ./scripts/postdeploy.sh \"\$RESOURCE_GROUP\" \"\$FUNCTION_APP\" çalıştırın —" >&2
  echo " köşeli parantezleri < > komuta dahil ETMEYİN.)" >&2
  exit 1
fi
RG="$1"
FUNC="$2"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> 1/4 Kod deploy ediliyor (func publish, remote build)..."
cd "$ROOT"
# Varsa desteklenmeyen URL ayarını temizle
az functionapp config appsettings delete -g "$RG" -n "$FUNC" \
  --setting-names WEBSITE_RUN_FROM_PACKAGE -o none 2>/dev/null || true

if command -v func >/dev/null 2>&1; then
  func azure functionapp publish "$FUNC" --python
else
  echo "    func bulunamadı, config-zip ile deploy ediliyor..."
  az functionapp config appsettings set -g "$RG" -n "$FUNC" \
    --settings SCM_DO_BUILD_DURING_DEPLOYMENT=true ENABLE_ORYX_BUILD=true -o none
  TMP="$(mktemp -d)"
  # Tüm kök .py dosyaları + host.json + requirements.txt (notify.py dahil, yeni
  # modül eklendiğinde manuel liste güncellemeye gerek kalmasın diye).
  zip -qr "$TMP/src.zip" ./*.py host.json requirements.txt -x demo.py
  az functionapp deployment source config-zip -g "$RG" -n "$FUNC" --src "$TMP/src.zip"
fi

echo "==> 2/4 Managed Identity Graph rolleri atanıyor (çekirdek + 4 connector)..."
# 'az functionapp identity show' bazı Cloud Shell sürümlerinde bilinen bir api-version
# hatası verebiliyor (InvalidApiVersionParameter) — daha sağlam olan generic resource
# show komutunu kullanıyoruz (aynı sonucu verir).
MI="$(az resource show -g "$RG" -n "$FUNC" --resource-type "Microsoft.Web/sites" --query identity.principalId -o tsv)"
if [[ -z "$MI" ]]; then
  echo "    ! Managed Identity object ID alınamadı." >&2
  echo "    Portal'dan elle alın: Function App → Identity → System assigned →" >&2
  echo "    'Object (principal) ID', sonra: ./scripts/grant_graph_roles.sh <O_ID>" >&2
  exit 1
fi
echo "    Managed Identity: $MI"
"$ROOT/scripts/grant_graph_roles.sh" "$MI"
"$ROOT/scripts/grant_connector_roles.sh" "$MI"

echo "==> 3/4 Microsoft AI Data Sources connector'ları açılıyor..."
"$ROOT/scripts/enable_connectors.sh" "$RG" "$FUNC"

KEY="$(az functionapp keys list -g "$RG" -n "$FUNC" --query functionKeys.default -o tsv 2>/dev/null || true)"
echo "==> 4/4 Tamam."
echo "    İlk taramayı tetikle          :  curl -s \"https://$FUNC.azurewebsites.net/api/scan?code=$KEY\""
echo "    AI Data Sources dashboard     :  https://$FUNC.azurewebsites.net/api/connectors?code=$KEY&format=html"
echo "    Çekirdek dashboard (buradan başlayın) :  https://$FUNC.azurewebsites.net/api/report?code=$KEY"
echo "    (Rol yayılması + Function App yeniden başlaması birkaç dakika sürebilir —"
echo "     bu sürede AI Data Sources dashboard'u bazı kaynakları PERMISSION_MISSING"
echo "     gösterebilir; birkaç dakika sonra sayfayı yenileyin. LICENSE_MISSING ise"
echo "     tenant'ta o Microsoft özelliğinin lisansı yok demektir, script hatası değildir.)"
