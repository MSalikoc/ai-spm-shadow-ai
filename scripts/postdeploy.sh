#!/usr/bin/env bash
# AI-SPM tek-adım post-deploy (Azure Cloud Shell / Bash).
# "Deploy to Azure" altyapıyı kurar; bu script kodu yükler ve Graph rollerini atar.
#
# Kullanım:
#   git clone https://github.com/MSalikoc/ai-spm-shadow-ai.git
#   cd ai-spm-shadow-ai
#   ./scripts/postdeploy.sh <RESOURCE_GROUP> <FUNCTION_APP_NAME>
#
# Not: Linux Consumption URL-tabanlı RUN_FROM_PACKAGE desteklemediği için kod
# 'func azure functionapp publish' (remote build) ile yüklenir.
set -euo pipefail

RG="${1:?Kullanim: $0 <RESOURCE_GROUP> <FUNCTION_APP_NAME>}"
FUNC="${2:?Kullanim: $0 <RESOURCE_GROUP> <FUNCTION_APP_NAME>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> 1/3 Kod deploy ediliyor (func publish, remote build)..."
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
  zip -qr "$TMP/src.zip" function_app.py host.json requirements.txt \
    auth.py collectors.py config.py graph_client.py pipeline.py report.py scoring.py storage.py
  az functionapp deployment source config-zip -g "$RG" -n "$FUNC" --src "$TMP/src.zip"
fi

echo "==> 2/3 Managed Identity Graph rolleri atanıyor..."
MI="$(az functionapp identity show -g "$RG" -n "$FUNC" --query principalId -o tsv)"
echo "    Managed Identity: $MI"
"$ROOT/scripts/grant_graph_roles.sh" "$MI"

KEY="$(az functionapp keys list -g "$RG" -n "$FUNC" --query functionKeys.default -o tsv 2>/dev/null || true)"
echo "==> 3/3 Tamam."
echo "    İlk taramayı tetikle:  curl -s \"https://$FUNC.azurewebsites.net/api/scan?code=$KEY\""
echo "    Dashboard'u aç      :  https://$FUNC.azurewebsites.net/api/report?code=$KEY"
