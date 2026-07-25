#!/usr/bin/env bash
# Managed Identity'ye AI-SPM için gereken Microsoft Graph *application* rollerini atar.
# Bu adım portal UI'dan yapılamaz — az CLI / Graph gerekir.
#
# Kullanım:
#   ./grant_graph_roles.sh <MANAGED_IDENTITY_OBJECT_ID>
#
# MI object id'yi bulmak için (Function'ın system-assigned identity'si):
#   az functionapp identity show -g <RG> -n <FUNC_NAME> --query principalId -o tsv
set -euo pipefail

MI_OBJECT_ID="${1:?Kullanim: $0 <MANAGED_IDENTITY_OBJECT_ID>}"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"   # Microsoft Graph
# Mail.Send: haftalık özet e-postası için (güvenlik: Exchange Application Access
# Policy ile yalnızca gönderen mailbox'a kısıtla — README'ye bak).
ROLES=("Directory.Read.All" "Application.Read.All" "AuditLog.Read.All" "Mail.Send")

echo "[*] Microsoft Graph service principal bulunuyor..."
GRAPH_SP_ID=$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)
echo "    Graph SP objectId: $GRAPH_SP_ID"

for ROLE in "${ROLES[@]}"; do
  echo "[*] '$ROLE' app role id çözülüyor..."
  ROLE_ID=$(az ad sp show --id "$GRAPH_APP_ID" \
    --query "appRoles[?value=='$ROLE' && contains(allowedMemberTypes,'Application')].id | [0]" -o tsv)
  if [[ -z "$ROLE_ID" || "$ROLE_ID" == "None" ]]; then
    echo "    ! '$ROLE' bulunamadı, atlanıyor." >&2
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
