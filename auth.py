"""
Entra ID kimlik doğrulama. İki mod:

  delegated : cihaz kodu (device code) akışı — analistin kendi izinleriyle,
              app registration'a client secret gerekmez. Demo/hackathon için ideal.
  app       : client credentials — otomasyon/CI için. Client secret gerekir.

Gerekli Graph izinleri (en az):
  Directory.Read.All, Application.Read.All, AuditLog.Read.All
"""
import sys
import msal

GRAPH_SCOPES_DELEGATED = ["https://graph.microsoft.com/.default"]
GRAPH_SCOPE_APP = ["https://graph.microsoft.com/.default"]


def get_token_device_code(tenant_id: str, client_id: str) -> str:
    """Cihaz kodu akışı: kullanıcı tarayıcıda kod girerek onaylar."""
    app = msal.PublicClientApplication(
        client_id, authority=f"https://login.microsoftonline.com/{tenant_id}"
    )
    flow = app.initiate_device_flow(scopes=["https://graph.microsoft.com/.default"])
    if "user_code" not in flow:
        raise RuntimeError(f"Device flow başlatılamadı: {flow.get('error_description')}")
    print("\n" + "=" * 60)
    print(flow["message"])  # "Go to https://microsoft.com/devicelogin and enter CODE"
    print("=" * 60 + "\n", flush=True)
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise RuntimeError(f"Token alınamadı: {result.get('error_description')}")
    return result["access_token"]


def get_token_managed_identity() -> str:
    """
    Azure içinde çalışırken (Function/VM/Container) Managed Identity ile token alır.
    Secret yok. Lokal geliştirmede `az login` veya env-var'lara da düşer
    (DefaultAzureCredential zinciri).

    Ön koşul: MI'ın service principal'ına Graph app role'leri atanmış olmalı
    (Directory.Read.All, Application.Read.All, AuditLog.Read.All). README'ye bak.
    """
    from azure.identity import DefaultAzureCredential
    cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    token = cred.get_token("https://graph.microsoft.com/.default")
    return token.token


def get_token_client_credentials(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Client credentials akışı: uygulama kimliğiyle (kullanıcısız)."""
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )
    result = app.acquire_token_for_client(scopes=GRAPH_SCOPE_APP)
    if "access_token" not in result:
        raise RuntimeError(f"Token alınamadı: {result.get('error_description')}")
    return result["access_token"]
