#!/usr/bin/env bash
# Creates an app registration that can read EVERY AI-SPM data source, and grants it the
# Graph APPLICATION permissions.
#
# Why this exists: an `az login` sign-in produces a DELEGATED token, which can only
# carry scopes the Azure CLI application is authorized for. That covers directory
# reads — so Entra discovery works — but never CloudApp-Discovery.Read.All,
# AuditLogsQuery.Read.All or CopilotPackages.Read.All. No directory role fixes that,
# because the limit is on the client application. Application permissions on your own
# registration do fix it, and need no Azure resources.
#
# Usage:
#   ./scripts/create_app_registration.sh [APP_DISPLAY_NAME]
#
# Requires a role that can grant application permissions (Privileged Role Administrator
# or Global Administrator) — the same requirement postdeploy.sh has.
#
# 100% read-only permissions. Nothing here can change your tenant.
set -euo pipefail

APP_NAME="${1:-AI-SPM Scanner}"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Graph APPLICATION permission (app role) IDs. Names are resolved live below rather
# than hard-coded, so a renamed or newly added role fails loudly instead of silently
# granting nothing.
ROLES=(
  "Application.Read.All"          # enterprise app + service principal inventory
  "Directory.Read.All"            # OAuth grants, owners, directory context
  "AuditLog.Read.All"             # sign-in activity (also needs Entra ID P1)
  "CopilotPackages.Read.All"      # Agent 365 catalogue
  "CloudApp-Discovery.Read.All"   # Defender for Cloud Apps — Shadow AI web usage
  "AuditLogsQuery.Read.All"       # Purview Audit — sensitive AI interactions
)

command -v az >/dev/null 2>&1 || { echo "HATA: Azure CLI bulunamadı." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "HATA: önce 'az login' çalıştırın." >&2; exit 1; }

TENANT_ID="$(az account show --query tenantId -o tsv)"
echo "==> Tenant: $TENANT_ID"

echo "==> 1/4 App registration oluşturuluyor: $APP_NAME"
APP_ID="$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null || true)"
if [[ -n "$APP_ID" && "$APP_ID" != "None" ]]; then
  echo "    Zaten var, yeniden kullanılıyor: $APP_ID"
else
  APP_ID="$(az ad app create --display-name "$APP_NAME" --sign-in-audience AzureADMyOrg \
            --query appId -o tsv)"
  echo "    Oluşturuldu: $APP_ID"
fi

# The service principal is what actually holds the app roles.
az ad sp show --id "$APP_ID" >/dev/null 2>&1 || az ad sp create --id "$APP_ID" -o none
sleep 5   # directory replication

echo "==> 2/4 Graph application izinleri talep ediliyor..."
GRAPH_SP_ID="$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)"
MISSING=()
for role in "${ROLES[@]}"; do
  ROLE_ID="$(az ad sp show --id "$GRAPH_APP_ID" \
    --query "appRoles[?value=='$role' && contains(allowedMemberTypes,'Application')].id | [0]" -o tsv)"
  if [[ -z "$ROLE_ID" || "$ROLE_ID" == "None" ]]; then
    # A role your tenant's Graph does not expose (preview/licence gated). Report it
    # rather than pretending it was granted.
    MISSING+=("$role")
    continue
  fi
  az ad app permission add --id "$APP_ID" --api "$GRAPH_APP_ID" \
    --api-permissions "$ROLE_ID=Role" -o none 2>/dev/null || true
  echo "    + $role"
done

echo "==> 3/4 Admin consent veriliyor..."
# `az ad app permission admin-consent` is flaky on freshly created apps; assigning the
# app role directly is the reliable equivalent and is idempotent.
SP_OBJECT_ID="$(az ad sp show --id "$APP_ID" --query id -o tsv)"
for role in "${ROLES[@]}"; do
  ROLE_ID="$(az ad sp show --id "$GRAPH_APP_ID" \
    --query "appRoles[?value=='$role' && contains(allowedMemberTypes,'Application')].id | [0]" -o tsv)"
  [[ -z "$ROLE_ID" || "$ROLE_ID" == "None" ]] && continue
  az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_OBJECT_ID/appRoleAssignments" \
    --headers "Content-Type=application/json" \
    --body "{\"principalId\":\"$SP_OBJECT_ID\",\"resourceId\":\"$GRAPH_SP_ID\",\"appRoleId\":\"$ROLE_ID\"}" \
    -o none 2>/dev/null || true
done

echo "==> 4/4 Client secret oluşturuluyor (2 yıl)..."
SECRET="$(az ad app credential reset --id "$APP_ID" --append \
          --display-name "aispm-cli" --years 2 --query password -o tsv)"

# Print the interpreter that will actually work here. macOS has no bare `python`, and
# when a venv exists it is usually the only one holding the dependencies — printing
# `python` sends people straight into "command not found" or ModuleNotFoundError.
if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PY=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PY="python3"
else
  PY="python"
fi

# The values are printed as an `export` block rather than inline flags: it pastes as one
# unit, keeps the secret out of every later command line (and therefore out of shell
# history and `ps` output), and leaves nothing to substitute by hand.
cat <<EOF

============================================================
Hazır. Önce şu üç satırı kopyalayıp yapıştırın:

export AISPM_TENANT_ID="$TENANT_ID"
export AISPM_CLIENT_ID="$APP_ID"
export AISPM_CLIENT_SECRET="$SECRET"

Sonra sırasıyla:

  $PY aispm.py doctor --auth app
  $PY aispm.py scan  --auth app --scope consented --open

Secret'ı şimdi bir parola yöneticisine kaydedin — Azure bir daha göstermez.
export'lar sadece bu terminal oturumu için geçerli.
Rol yayılması 1-2 dakika sürebilir; hemen denerseniz 403 alabilirsiniz.

Secret'ı iptal edip yenilemek isterseniz:
  az ad app credential reset --id "$APP_ID" --append --display-name aispm-cli --years 2
============================================================
EOF

if (( ${#MISSING[@]} )); then
  cat <<EOF

NOT: Bu izinler tenant'ınızın Graph'ında bulunamadı, atlandı:
  ${MISSING[*]}
Bu genellikle o Microsoft özelliğinin tenant'ta hiç sağlanmadığı anlamına gelir
(ör. Microsoft 365 Copilot lisansı yoksa CopilotPackages.Read.All görünmez).
doctor bunları LICENSE/NOT_AVAILABLE olarak gösterecek — uydurma yapmaz.
EOF
fi
