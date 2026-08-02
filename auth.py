"""
Entra ID authentication. Two modes:

  delegated : device code flow — under the analyst's own permissions, no client
              secret needed on the app registration. Ideal for demos/hackathons.
  app       : client credentials — for automation/CI. Requires a client secret.

Required Graph permissions (at minimum):
  Directory.Read.All, Application.Read.All, AuditLog.Read.All
"""
import msal

GRAPH_SCOPES_DELEGATED = ["https://graph.microsoft.com/.default"]
GRAPH_SCOPE_APP = ["https://graph.microsoft.com/.default"]


def get_token_azure_cli(tenant_id: str | None = None) -> str:
    """
    Reuses the sign-in the operator already has from `az login`.

    This is the path that removes setup entirely for a first look: no app registration
    to create, no client secret to store, no Function App to deploy. The token carries
    the operator's own delegated permissions, so a Global Reader or Security Reader can
    run a scan against their tenant from a laptop and get the same dashboards the
    deployed version produces.
    """
    from azure.identity import AzureCliCredential
    cred = AzureCliCredential(tenant_id=tenant_id) if tenant_id else AzureCliCredential()
    return cred.get_token("https://graph.microsoft.com/.default").token


def tenant_id_from_cli() -> str | None:
    """The tenant `az login` is currently pointed at, so it need not be typed out."""
    import json
    import subprocess
    try:
        out = subprocess.run(["az", "account", "show", "-o", "json"],
                             capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return None
        return (json.loads(out.stdout) or {}).get("tenantId")
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def get_token_device_code(tenant_id: str, client_id: str) -> str:
    """Device code flow: the user confirms by entering the code in a browser."""
    app = msal.PublicClientApplication(
        client_id, authority=f"https://login.microsoftonline.com/{tenant_id}"
    )
    flow = app.initiate_device_flow(scopes=["https://graph.microsoft.com/.default"])
    if "user_code" not in flow:
        raise RuntimeError(f"Could not start device flow: {flow.get('error_description')}")
    print("\n" + "=" * 60)
    print(flow["message"])  # "Go to https://microsoft.com/devicelogin and enter CODE"
    print("=" * 60 + "\n", flush=True)
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise RuntimeError(f"Could not obtain token: {result.get('error_description')}")
    return result["access_token"]


def get_token_managed_identity() -> str:
    """
    Gets a token via Managed Identity when running inside Azure (Function/VM/Container).
    No secret. Falls back to `az login` or env-vars in local development
    (DefaultAzureCredential chain).

    Prerequisite: the MI's service principal must have the Graph app roles granted
    (Directory.Read.All, Application.Read.All, AuditLog.Read.All). See README.
    """
    from azure.identity import DefaultAzureCredential
    cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    token = cred.get_token("https://graph.microsoft.com/.default")
    return token.token


def get_token_client_credentials(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Client credentials flow: as the application identity (no user)."""
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )
    result = app.acquire_token_for_client(scopes=GRAPH_SCOPE_APP)
    if "access_token" not in result:
        raise RuntimeError(f"Could not obtain token: {result.get('error_description')}")
    return result["access_token"]
