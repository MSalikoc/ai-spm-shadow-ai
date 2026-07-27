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

RG="${1:?Kullanim: $0 <RESOURCE_GROUP> <FUNCTION_APP_NAME>}"
FUNC="${2:?Kullanim: $0 <RESOURCE_GROUP> <FUNCTION_APP_NAME>}"

echo "[*] ENABLE_* connector flag'leri '$FUNC' üzerinde açılıyor..."
az functionapp config appsettings set -g "$RG" -n "$FUNC" --settings \
  ENABLE_AGENT365=true \
  ENABLE_ENTRA_AGENT_ID=true \
  ENABLE_DEFENDER_CLOUD_APPS=true \
  ENABLE_PREVIEW_CONNECTORS=true \
  ENABLE_PURVIEW_AUDIT=true \
  -o none

echo "[✓] Açıldı. Function App birkaç dakika içinde yeniden başlayıp yeni ayarları alır."
echo "    Doğrulamak için: curl \"https://$FUNC.azurewebsites.net/api/connectors?code=<KEY>\""
echo "    Görsel (HTML) için: .../api/connectors?code=<KEY>&format=html"
echo
echo "Not: Purview DSPM (dosya import) opsiyoneldir ve ayrıca gerekir:"
echo "  az functionapp config appsettings set -g $RG -n $FUNC \\"
echo "    --settings PURVIEW_DSPM_IMPORT_PATH=<export-dosyasının-yolu>"
