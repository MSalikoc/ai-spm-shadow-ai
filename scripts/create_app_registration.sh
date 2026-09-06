#!/usr/bin/env bash
# Creates an app registration for AI-SPM endpoint access checks, and grants it the
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
# or Global Administrator, or an appropriately scoped custom role).
# Cloud Application Administrator cannot grant Microsoft Graph application roles.
#
# Read-only data permissions; setup itself creates registrations, grants and credentials.
set -euo pipefail

APP_NAME="${1:-AI-SPM Scanner}"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/permission_helpers.sh"

# Graph APPLICATION permission (app role) IDs. Names are resolved live below rather
# than hard-coded, so a renamed or newly added role fails loudly instead of silently
# granting nothing.
ROLES=(
  "Application.Read.All"          # enterprise app + service principal inventory
  "Directory.Read.All"            # OAuth grants, owners, directory context
  "AuditLog.Read.All"             # sign-in activity (also needs Entra ID P1)
  "AgentIdentity.Read.All"
  "AgentIdentityBlueprint.Read.All"
  "CopilotPackages.Read.All"      # Agent 365 catalogue
  "CloudApp-Discovery.Read.All"   # Defender for Cloud Apps — Shadow AI web usage
  "AuditLogsQuery.Read.All"       # Purview Audit — sensitive AI interactions
)

command -v az >/dev/null 2>&1 || { echo "HATA: Azure CLI bulunamadı." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "HATA: önce 'az login' çalıştırın." >&2; exit 1; }

TENANT_ID="$(az account show --query tenantId -o tsv)"
echo "==> Tenant: $TENANT_ID"

echo "==> 1/4 App registration oluşturuluyor: $APP_NAME"
APP_ID="$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)"
if [[ -n "$APP_ID" && "$APP_ID" != "None" ]]; then
  echo "    Zaten var, yeniden kullanılıyor: $APP_ID"
else
  APP_ID="$(az ad app create --display-name "$APP_NAME" --sign-in-audience AzureADMyOrg \
            --query appId -o tsv)"
  echo "    Oluşturuldu: $APP_ID"
fi

# The service principal is what actually holds the app roles.
[[ -n "$APP_ID" && "$APP_ID" != "None" ]] || { echo "ERROR: No application ID returned." >&2; exit 1; }
SP_OBJECT_ID="$(az ad sp list --filter "appId eq '$APP_ID'" --query "[0].id" -o tsv)"
if [[ -z "$SP_OBJECT_ID" || "$SP_OBJECT_ID" == "None" ]]; then
  SP_OBJECT_ID="$(az ad sp create --id "$APP_ID" --query id -o tsv)"
fi
[[ -n "$SP_OBJECT_ID" && "$SP_OBJECT_ID" != "None" ]] || { echo "ERROR: No service principal ID returned." >&2; exit 1; }

echo "==> 2/4 Graph application izinleri talep ediliyor..."
GRAPH_SP_ID="$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)"
[[ -n "$GRAPH_SP_ID" && "$GRAPH_SP_ID" != "None" ]] || { echo "ERROR: No Graph service principal ID returned." >&2; exit 1; }
MISSING=()
ROLE_IDS=()
GRANTED_ROLES=()
for role in "${ROLES[@]}"; do
  ROLE_ID="$(resolve_graph_role "$role")"
  if [[ -z "$ROLE_ID" || "$ROLE_ID" == "None" ]]; then
    case "$role" in
      Application.Read.All|Directory.Read.All|AuditLog.Read.All)
        echo "ERROR: required Graph application role '$role' is unavailable." >&2; exit 1 ;;
    esac
    MISSING+=("$role")
    continue
  fi
  ROLE_IDS+=("$ROLE_ID")
  GRANTED_ROLES+=("$role")
done

for ROLE_ID in "${ROLE_IDS[@]}"; do
  az ad app permission add --id "$APP_ID" --api "$GRAPH_APP_ID" --api-permissions "$ROLE_ID=Role" -o none
done
echo "==> 3/4 Admin consent veriliyor..."
# `az ad app permission admin-consent` is flaky on freshly created apps; assigning the
# app role directly is the reliable equivalent and is idempotent.
for ((i=0; i<${#ROLE_IDS[@]}; i++)); do
  grant_graph_role "$SP_OBJECT_ID" "$GRAPH_SP_ID" "${ROLE_IDS[$i]}"
  echo "    Verified grant: ${GRANTED_ROLES[$i]}"
done

echo "==> 4/4 Client secret oluşturuluyor (2 yıl)..."
SECRET="$(az ad app credential reset --id "$APP_ID" --append \
          --display-name "aispm-cli" --years 2 --query password -o tsv)"
[[ -n "$SECRET" && "$SECRET" != "None" ]] || { echo "ERROR: No client secret returned." >&2; exit 1; }

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
Available grants verified; endpoint access and licensing still need doctor/scan checks.
Önce şu üç satırı kopyalayıp yapıştırın:

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
These roles were NOT GRANTED. Role availability does not establish license status.
Agent 365 requires Microsoft Agent 365 licensing; MDCA also needs discovery ingestion.
EOF
fi
