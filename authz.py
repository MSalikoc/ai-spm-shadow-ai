"""
Merkezi Entra kimlik + app-role yetkilendirme katmanı.

Azure App Service Authentication (Easy Auth) doğrulanmış kullanıcı/uygulama kimliğini
`X-MS-CLIENT-PRINCIPAL` header'ında base64 JSON olarak enjekte eder. Easy Auth açıkken
platform, istemcinin gönderdiği bu header'ı siler/yeniden yazar — yani header sahte
üretilemez. Bu katman o header'dan `roles` claim'lerini çıkarır ve endpoint'in
gerektirdiği app-role'lerle karşılaştırır.

Sonuç sözleşmesi:
  401 → kimlik yok / doğrulanmadı (principal header yok)
  403 → kimlik var ama gerekli app-role yok

Rol modeli (Administrator her şeyi kapsar):
  AI-SPM.Report.Reader        → /api/report
  AI-SPM.Assessment.Operator  → /api/scan
  AI-SPM.Notification.Operator→ /api/digest
  AI-SPM.Administrator        → hepsi
"""
import base64
import binascii
import json
import os

ROLE_READER = "AI-SPM.Report.Reader"
ROLE_ASSESSMENT = "AI-SPM.Assessment.Operator"
ROLE_NOTIFICATION = "AI-SPM.Notification.Operator"
ROLE_ADMIN = "AI-SPM.Administrator"

_ROLE_CLAIM_TYPES = {"roles", "role",
                     "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"}
_NAME_CLAIM_TYPES = {"name", "preferred_username",
                     "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"}
_OID_CLAIM_TYPES = {"oid",
                    "http://schemas.microsoft.com/identity/claims/objectidentifier"}


def _is_azure_runtime() -> bool:
    """App Service / Functions üzerinde çalışıyor muyuz? (production göstergesi)"""
    return bool(os.environ.get("WEBSITE_INSTANCE_ID"))


def dev_bypass_enabled() -> bool:
    """
    Development auth bypass — YALNIZCA açıkça etkinleştirildiğinde VE Azure
    runtime'da DEĞİLKEN geçerli. Production'da (WEBSITE_INSTANCE_ID set) env-var
    'true' olsa bile otomatik reddedilir.
    """
    return (os.environ.get("AISPM_AUTH_DEV_BYPASS", "").lower() == "true"
            and not _is_azure_runtime())


def parse_principal(header_val):
    """X-MS-CLIENT-PRINCIPAL (base64 JSON) → {id, name, roles:set} veya None."""
    if not header_val:
        return None
    try:
        data = json.loads(base64.b64decode(header_val))
    except (binascii.Error, ValueError, TypeError):
        return None
    roles, name, pid = set(), None, None
    for c in data.get("claims", []):
        typ, val = c.get("typ", ""), c.get("val", "")
        if typ in _ROLE_CLAIM_TYPES:
            roles.add(val)
        elif typ in _NAME_CLAIM_TYPES and not name:
            name = val
        elif typ in _OID_CLAIM_TYPES and not pid:
            pid = val
    return {"id": pid, "name": name, "roles": roles}


def get_principal(headers):
    """headers: .get destekleyen (case-insensitive) mapping. Dev bypass → sanal admin."""
    if dev_bypass_enabled():
        return {"id": "dev", "name": "dev-bypass", "roles": {ROLE_ADMIN}, "bypass": True}
    val = headers.get("x-ms-client-principal") if hasattr(headers, "get") else None
    return parse_principal(val)


def auth_configured() -> bool:
    """
    Easy Auth kurulduğunu doğrulayan güvenlik kapısı. setup_entra_auth.sh, Easy Auth'u
    etkinleştirdikten SONRA `AISPM_AUTH_ENFORCED=true` yazar. Bu bayrak yoksa, platform
    henüz sahte X-MS-CLIENT-PRINCIPAL header'larını silmiyor olabilir — bu yüzden hiçbir
    header'a güvenmez, her isteği reddederiz (safe-by-default).
    """
    return os.environ.get("AISPM_AUTH_ENFORCED", "").lower() == "true"


def authorize(headers, allowed_roles):
    """
    None döner (yetkili) ya da (status_code, message) döner (401/403).
    Administrator her allowed_roles kümesini kapsar.
    """
    if dev_bypass_enabled():
        return None
    if not auth_configured():
        return (401, "Kimlik doğrulama yapılandırılmamış "
                     "(scripts/setup_entra_auth.sh çalıştırın).")
    principal = get_principal(headers)
    if principal is None:
        return (401, "Kimlik doğrulanmadı. Entra ile oturum açın.")
    roles = principal.get("roles", set())
    if ROLE_ADMIN in roles or roles & set(allowed_roles):
        return None
    return (403, "Bu işlem için gerekli role sahip değilsiniz.")
