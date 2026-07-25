#!/usr/bin/env bash
# AI-SPM Entra kimlik doğrulama kurulumu (bir kere).
# Yapar:
#   1) App registration + 4 app-role oluşturur
#   2) Identifier URI (api://<appId>) ve Easy Auth redirect URI ekler
#   3) Service principal oluşturur (rol ataması için)
#   4) Function App'te Easy Auth'u (AllowAnonymous + Entra) etkinleştirir
#   5) Rol atama adımlarını yazdırır
#
# Kullanım:
#   ./scripts/setup_entra_auth.sh <RESOURCE_GROUP> <FUNCTION_APP_NAME>
set -euo pipefail

RG="${1:?Kullanim: $0 <RG> <FUNC>}"
FUNC="${2:?Kullanim: $0 <RG> <FUNC>}"

HOST="$(az functionapp show -g "$RG" -n "$FUNC" --query defaultHostName -o tsv)"
TENANT="$(az account show --query tenantId -o tsv)"
ISSUER="https://login.microsoftonline.com/${TENANT}/v2.0"

echo "[*] App registration oluşturuluyor..."
APP_ID="$(az ad app create --display-name "AI-SPM (${FUNC})" --query appId -o tsv)"
echo "    App (client) ID: $APP_ID"

echo "[*] App roller tanımlanıyor (Report.Reader / Assessment.Operator / Notification.Operator / Administrator)..."
ROLES="$(cat <<JSON
[
 {"allowedMemberTypes":["User","Application"],"description":"AI-SPM raporunu/dashboard'unu okur","displayName":"AI-SPM Report Reader","isEnabled":true,"value":"AI-SPM.Report.Reader","id":"$(uuidgen)"},
 {"allowedMemberTypes":["User","Application"],"description":"Tarama başlatır","displayName":"AI-SPM Assessment Operator","isEnabled":true,"value":"AI-SPM.Assessment.Operator","id":"$(uuidgen)"},
 {"allowedMemberTypes":["User","Application"],"description":"Digest/bildirim tetikler","displayName":"AI-SPM Notification Operator","isEnabled":true,"value":"AI-SPM.Notification.Operator","id":"$(uuidgen)"},
 {"allowedMemberTypes":["User","Application"],"description":"Tüm AI-SPM işlemleri","displayName":"AI-SPM Administrator","isEnabled":true,"value":"AI-SPM.Administrator","id":"$(uuidgen)"}
]
JSON
)"
az ad app update --id "$APP_ID" --app-roles "$ROLES"
az ad app update --id "$APP_ID" --identifier-uris "api://${APP_ID}"
az ad app update --id "$APP_ID" --web-redirect-uris "https://${HOST}/.auth/login/aad/callback"

echo "[*] Service principal oluşturuluyor (rol ataması için)..."
az ad sp create --id "$APP_ID" >/dev/null 2>&1 || echo "    (SP zaten var)"

echo "[*] Function App'te Easy Auth etkinleştiriliyor (AllowAnonymous — 401/403 kod tarafında)..."
az webapp auth microsoft update -g "$RG" -n "$FUNC" \
  --client-id "$APP_ID" --issuer "$ISSUER" --allowed-audiences "api://${APP_ID}" >/dev/null
az webapp auth update -g "$RG" -n "$FUNC" \
  --enabled true --unauthenticated-client-action AllowAnonymous >/dev/null

# Auth artık aktif: enforcement kapısını aç + temiz dashboard URL'i (function key yok)
az functionapp config appsettings set -g "$RG" -n "$FUNC" \
  --settings "AISPM_AUTH_ENFORCED=true" "AISPM_REPORT_URL=https://${HOST}/api/report" -o none

cat <<EOF

[✓] Entra auth kuruldu.
    Client ID : $APP_ID
    Dashboard : https://${HOST}/api/report   (Entra ile korunuyor, key yok)

Sıradaki adım — kullanıcı/uygulamalara ROL ata:
  Portal → Entra ID → Enterprise applications → "AI-SPM (${FUNC})"
         → Users and groups → Add user/group → rol seç:
           AI-SPM.Report.Reader | AI-SPM.Assessment.Operator |
           AI-SPM.Notification.Operator | AI-SPM.Administrator

  (App-to-app erişim için: çağıran uygulamanın SP'sine yukarıdaki app-role'ü ata.)
EOF
