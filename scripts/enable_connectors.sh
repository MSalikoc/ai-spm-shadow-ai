#!/usr/bin/env bash
# Microsoft AI Data Sources connector'larını (Agent 365, Entra Agent ID, Defender for
# Cloud Apps, Purview Audit) Function App Configuration'da açar (ENABLE_* app settings).
#
# Ön koşul: grant_connector_roles.sh zaten çalıştırılmış olmalı (Graph izinleri).
# Bu ayarlar olmadan framework'ün runtime etkisi sıfırdır (bkz. README).
#
# Kullanım:
#   ./enable_connectors.sh <RESOURCE_GROUP> <FUNCTION_APP_NAME>
set -euo pipefail

if [[ -z "${1:-}" || -z "${2:-}" ]]; then
  echo "HATA: Resource group veya Function App adı boş geldi." >&2
  echo "Kullanım: $0 <RESOURCE_GROUP> <FUNCTION_APP_NAME>" >&2
  echo "" >&2
  echo "Cloud Shell'i bir süre boş bıraktıysanız değişkenleriniz sıfırlanmış olabilir —" >&2
  echo "README'nin Step 2'sindeki RESOURCE_GROUP=/FUNCTION_APP= satırlarını tekrar" >&2
  echo "çalıştırıp bu komutu yeniden deneyin." >&2
  exit 1
fi
RG="$1"
FUNC="$2"

echo "[*] ENABLE_* connector flag'leri '$FUNC' üzerinde açılıyor..."
az functionapp config appsettings set -g "$RG" -n "$FUNC" --settings \
  ENABLE_AGENT365=true \
  ENABLE_ENTRA_AGENT_ID=true \
  ENABLE_DEFENDER_CLOUD_APPS=true \
  ENABLE_PREVIEW_CONNECTORS=true \
  ENABLE_PURVIEW_AUDIT=true \
  -o none

echo "[✓] Açıldı. Function App birkaç dakika içinde yeniden başlayıp yeni ayarları alır."
echo "    Doğrulamak için (KEY'i az functionapp keys list ile alın):"
echo "      curl \"https://$FUNC.azurewebsites.net/api/connectors?code=\$KEY\""
echo "    Görsel (HTML) için sonuna &format=html ekleyin."
echo
echo "Not: Purview DSPM (dosya import) opsiyoneldir ve ayrıca gerekir:"
echo "  az functionapp config appsettings set -g $RG -n $FUNC \\"
echo "    --settings PURVIEW_DSPM_IMPORT_PATH=/home/data/export-dosyanizin-adi"
