#!/usr/bin/env bash
# Managed Identity'ye Microsoft AI Data Sources connector'ları (Agent 365, Entra Agent ID,
# Defender for Cloud Apps, Purview Audit) için gereken Graph *application* rollerini atar.
#
# Bu, temel AI-SPM deploy'unun bir PARÇASI DEĞİL — 8 adımlık "Microsoft AI Data Sources"
# fazının connector'larını gerçekten çalıştırmak isteyenler için OPSİYONEL bir ek adımdır.
# grant_graph_roles.sh'ı (temel scan) DEĞİŞTİRMEZ; ayrı, idempotent bir script'tir — zaten
# atanmış roller (Directory.Read.All, Application.Read.All) sessizce atlanır.
#
# Kullanım:
#   ./grant_connector_roles.sh <MANAGED_IDENTITY_OBJECT_ID>
#
# MI object id'yi bulmak için:
#   az resource show -g <RG> -n <FUNC_NAME> --resource-type "Microsoft.Web/sites" \
#     --query identity.principalId -o tsv
# (Bu komut hata verirse: Portal → Function App → Identity → System assigned →
#  "Object (principal) ID" değerini elle kopyalayın.)
set -euo pipefail

if [[ -z "${1:-}" ]]; then
  echo "HATA: Managed Identity object ID boş geldi." >&2
  echo "Kullanım: $0 <MANAGED_IDENTITY_OBJECT_ID>" >&2
  echo "" >&2
  echo "Cloud Shell'i bir süre boş bıraktıysanız değişkenleriniz sıfırlanmış olabilir —" >&2
  echo "README'nin Step 2'sindeki RESOURCE_GROUP=/FUNCTION_APP= satırlarını tekrar" >&2
  echo "çalıştırıp MI=\$(az resource show ...) komutunu yeniden deneyin." >&2
  exit 1
fi
MI_OBJECT_ID="$1"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"   # Microsoft Graph

# Application.Read.All / Directory.Read.All temel scan'de zaten atanmış olabilir —
# script idempotent olduğu için tekrar denemek güvenli (README'deki 4 connector'ın
# ihtiyacı olan TAM izin seti burada, tek script'te toplanıyor).
ROLES=(
  "CopilotPackages.Read.All"          # Agent 365 — paket/agent envanteri
  "Application.Read.All"              # Entra Agent ID — identity/blueprint
  "Directory.Read.All"                # Entra Agent ID — owner/sponsor/grup
  "CloudApp-Discovery.Read.All"       # Defender for Cloud Apps — Shadow AI keşfi (PREVIEW)
  "AuditLogsQuery.Read.All"           # Purview Audit — hassas AI etkileşimleri
)

echo "[*] Microsoft Graph service principal bulunuyor..."
GRAPH_SP_ID=$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)
echo "    Graph SP objectId: $GRAPH_SP_ID"

for ROLE in "${ROLES[@]}"; do
  echo "[*] '$ROLE' app role id çözülüyor..."
  ROLE_ID=$(az ad sp show --id "$GRAPH_APP_ID" \
    --query "appRoles[?value=='$ROLE' && contains(allowedMemberTypes,'Application')].id | [0]" -o tsv)
  if [[ -z "$ROLE_ID" || "$ROLE_ID" == "None" ]]; then
    echo "    ! '$ROLE' bu tenant'ta bulunamadı (lisans/preview eksik olabilir), atlanıyor." >&2
    continue
  fi
  echo "    $ROLE -> $ROLE_ID ; atanıyor..."
  az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${MI_OBJECT_ID}/appRoleAssignments" \
    --headers "Content-Type=application/json" \
    --body "{\"principalId\":\"${MI_OBJECT_ID}\",\"resourceId\":\"${GRAPH_SP_ID}\",\"appRoleId\":\"${ROLE_ID}\"}" \
    >/dev/null 2>&1 && echo "    ✓ atandı" \
    || echo "    (zaten atanmış olabilir)"
done

echo "[✓] Bitti. Rol atamalarının yayılması birkaç dakika sürebilir."
echo "    Not: 'CloudApp-Discovery.Read.All' PREVIEW bir izindir — tenant'ta Defender for"
echo "    Cloud Apps lisansı yoksa bu connector LICENSE_MISSING/PERMISSION_MISSING gösterir"
echo "    (dürüstçe; sahte envanter üretilmez)."
