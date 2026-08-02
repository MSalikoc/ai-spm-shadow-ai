"""
AI-SPM command line — run a scan and get both dashboards, without deploying anything.

    az login
    python aispm.py doctor          # what can this identity actually read?
    python aispm.py scan            # writes out/report.html + out/connectors.html

Deploying to Azure is still the right answer for continuous scanning (a timer, drift
history, the weekly digest). It is a heavy way to answer "is this tool worth it?",
though, so the same engine runs locally against the sign-in `az login` already gave
you: no app registration, no client secret, no Function App.

Other auth modes are there for automation:

    python aispm.py scan --auth device-code --client-id <APP_ID>
    python aispm.py scan --auth app --client-id <ID> --client-secret <SECRET>
    python aispm.py scan --auth managed
"""
import argparse
import logging
import os
import sys
import time
import webbrowser

import auth
from graph_client import GraphClient

DEFAULT_OUT = "out"


# --- shared plumbing --------------------------------------------------------
def _graph(args):
    """Builds a Graph client for the requested auth mode, plus the resolved tenant."""
    tenant, token = _token(args)
    if not tenant:
        raise SystemExit(
            "Could not determine the tenant. Run `az login`, or pass --tenant <ID>.")
    return GraphClient(token), tenant


def _token(args):
    tenant = args.tenant
    if args.auth == "azure-cli":
        tenant = tenant or auth.tenant_id_from_cli()
        return tenant, auth.get_token_azure_cli(tenant)
    if args.auth == "device-code":
        if not (args.client_id and tenant):
            raise SystemExit("--auth device-code needs --tenant and --client-id")
        return tenant, auth.get_token_device_code(tenant, args.client_id)
    if args.auth == "app":
        if not (args.client_id and args.client_secret and tenant):
            raise SystemExit("--auth app needs --tenant, --client-id and --client-secret")
        return tenant, auth.get_token_client_credentials(tenant, args.client_id,
                                                         args.client_secret)
    return tenant, auth.get_token_managed_identity()


def _graph_and_scopes(args):
    """Graph client plus what the token actually carries — see preflight.run."""
    tenant, token = _token(args)
    if not tenant:
        raise SystemExit(
            "Could not determine the tenant. Run `az login`, or pass --tenant <ID>.")
    scopes, kind = auth.token_scopes(token)
    return GraphClient(token), tenant, scopes, kind


_INSTALL_HINT = ("Azure CLI is not installed. Install it, then sign in:\n\n"
                 "    brew install azure-cli      # macOS\n"
                 "    az login\n\n"
                 "  Other platforms: https://aka.ms/InstallAzureCLI\n"
                 "  Or skip the CLI entirely with an app registration:\n"
                 "    python aispm.py doctor --auth app --tenant <ID> "
                 "--client-id <ID> --client-secret <SECRET>")

_LOGIN_HINT = ("Not signed in to Azure CLI. Run:\n\n"
               "    az login\n\n"
               "  Sign in with an account holding a read-only directory role\n"
               "  (Global Reader or Security Reader is enough).\n"
               "  Wrong tenant? Use:  az login --tenant <TENANT_ID>")


def _auth_hint(e: Exception) -> str:
    """Turns a credential failure into the command that fixes it."""
    text = str(e)
    low = text.lower()
    if "not found on path" in low or "cli not found" in low or "installed" in low:
        return _INSTALL_HINT
    if "azureclicredential" in low or "az login" in low or "az account" in low:
        return _LOGIN_HINT
    return text


# --- commands ---------------------------------------------------------------
def cmd_doctor(args) -> int:
    import preflight
    graph, tenant, scopes, kind = _graph_and_scopes(args)
    print(f"Tenant    : {tenant}")
    print(f"Auth      : {args.auth} ({kind} token)")
    print(f"Graph scopes carried ({len(scopes)}): "
          + (", ".join(sorted(scopes)) if scopes else "none readable from the token"))
    rows = preflight.run(graph, scopes, kind)
    print(preflight.format_text(rows))
    return 1 if preflight.blocking(rows) else 0


def cmd_scan(args) -> int:
    import collectors
    import connectors_report
    import pipeline
    import preflight
    import report

    os.environ["AISPM_SCAN_SCOPE"] = args.scope
    if args.activity_days:
        os.environ["AISPM_ACTIVITY_DAYS"] = str(args.activity_days)

    graph, tenant, token_scopes, token_kind = _graph_and_scopes(args)
    started = time.time()

    print(f"Tenant : {tenant}")
    print(f"Scope  : {args.scope} ({_SCOPE_HELP[args.scope]})")

    rows = preflight.run(graph, token_scopes, token_kind)
    blocking = preflight.blocking(rows)
    if blocking:
        print(preflight.format_text(rows))
        print("Stopping: the core scan needs the permissions above.")
        return 1

    # Only enable a connector this identity can actually read, so the dashboard reports
    # "not available" honestly instead of an unexplained empty section.
    if args.connectors:
        for flag, enabled in preflight.connector_flags(rows).items():
            os.environ[flag] = "true" if enabled else "false"
        usable = [r["label"] for r in rows if not r["required"] and r["status"] == preflight.OK]
        print(f"Sources: {', '.join(usable) if usable else 'core Entra/OAuth only'}")

    print("\nScanning (discovery -> permissions -> activity -> scoring)...", flush=True)
    scored = pipeline.run(graph, tenant)

    connectors_result = None
    if args.connectors and pipeline.connectors_enabled():
        print("Correlating Microsoft AI data sources...", flush=True)
        try:
            connectors_result = pipeline.run_connectors(graph)
        except Exception as e:
            print(f"  ! AI data sources step failed, continuing: {e}")

    os.makedirs(args.out, exist_ok=True)

    conn_path = None
    if connectors_result is not None:
        conn_path = os.path.join(args.out, "connectors.html")
        with open(conn_path, "w", encoding="utf-8") as f:
            f.write(connectors_report.html_string(connectors_result, tenant))
        with open(os.path.join(args.out, "connectors.json"), "w", encoding="utf-8") as f:
            f.write(connectors_report.json_string(connectors_result))

    # Written after the connectors run so the core dashboard can report their real
    # status, and link to the sibling file rather than to an /api/ route that does not
    # exist for a page opened off disk.
    core_path = os.path.join(args.out, "report.html")
    with open(core_path, "w", encoding="utf-8") as f:
        f.write(report.html_string(
            scored, tenant,
            connector_health=(connectors_result or {}).get("health"),
            connectors_href="connectors.html" if conn_path else None))
    report.write_json(scored, os.path.join(args.out, "report.json"))

    summary = pipeline.summary(scored)
    ai_matched = sum(1 for a in scored if a.get("ai_match"))
    telemetry = graph.telemetry()

    print(f"\nDone in {time.time() - started:.0f}s — {summary['total']} applications assessed "
          f"({ai_matched} matched the AI catalog)")
    print(f"  {summary['critical']} critical · {summary['high']} high · "
          f"{summary['medium']} medium · {summary['low']} low")
    if not summary["activity_available"]:
        print("  usage metrics unavailable (needs AuditLog.Read.All and Entra ID P1)")
    print(f"  {telemetry['requests']} Graph requests"
          f" · {telemetry['batch_calls']} batched calls"
          f" · {telemetry['throttled']} throttled")
    print(f"\n  {core_path}")
    if conn_path:
        print(f"  {conn_path}")

    for a in scored[:5]:
        print(f"    [{a['risk_score']:>3} {a['risk_level']:<8}] {a['display_name']}")

    if args.open:
        webbrowser.open(f"file://{os.path.abspath(core_path)}")
    return 0


def cmd_sample(args) -> int:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))
    import make_sample
    make_sample.main()
    return 0


_SCOPE_HELP = {
    "ai": "only apps matching the AI catalog",
    "consented": "every app holding a real OAuth grant — the full consent surface",
    "all": "every third-party app in the tenant",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aispm", description="AI-SPM — Shadow AI posture management (read-only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Start with:  az login  &&  python aispm.py doctor")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        # Credentials fall back to the environment so they need not be typed on the
        # command line, where they end up in shell history and in `ps` output.
        sp.add_argument("--tenant", default=os.environ.get("AISPM_TENANT_ID"),
                        help="Entra tenant ID (env: AISPM_TENANT_ID; "
                             "default: whatever az login points at)")
        sp.add_argument("--auth", default="azure-cli",
                        choices=["azure-cli", "device-code", "app", "managed"],
                        help="how to authenticate (default: reuse `az login`)")
        sp.add_argument("--client-id", default=os.environ.get("AISPM_CLIENT_ID"),
                        help="app registration ID (env: AISPM_CLIENT_ID)")
        sp.add_argument("--client-secret", default=os.environ.get("AISPM_CLIENT_SECRET"),
                        help="client secret (env: AISPM_CLIENT_SECRET)")
        return sp

    common(sub.add_parser("doctor", help="check what this identity can read, and why not"))

    scan = common(sub.add_parser("scan", help="run a scan and write the dashboards"))
    scan.add_argument("--out", default=DEFAULT_OUT, help=f"output folder (default: {DEFAULT_OUT})")
    scan.add_argument("--scope", default="ai", choices=list(_SCOPE_HELP),
                      help="which applications to assess: "
                           + " | ".join(f"{k} = {v}" for k, v in _SCOPE_HELP.items()))
    scan.add_argument("--activity-days", type=int,
                      help="sign-in history window, 7-90 (default 90; lower is faster)")
    scan.add_argument("--no-connectors", dest="connectors", action="store_false",
                      help="skip the Microsoft AI data sources step")
    scan.add_argument("--open", action="store_true", help="open the dashboard when done")

    sub.add_parser("sample", help="write sample dashboards to docs/ (no tenant needed)")
    return p


def _reject_placeholders(args) -> None:
    """
    Catches an unsubstituted placeholder before it becomes a confusing failure.

    Documentation writes `--tenant <TENANT>`; pasted into zsh, `<TENANT>` is an input
    redirection and the shell dies with "no such file or directory: TENANT", which
    names neither the flag nor the real problem. Quoted, it reaches us verbatim
    instead. Either way, say what actually needs doing.
    """
    for flag, value in (("--tenant", args.tenant), ("--client-id", getattr(args, "client_id", None)),
                        ("--client-secret", getattr(args, "client_secret", None))):
        text = (value or "").strip()
        if text.startswith("<") and text.endswith(">"):
            raise SystemExit(
                f"{flag} is still the placeholder {text} — replace it with the real value.\n"
                "  Tip: export the values once instead of typing them each run:\n"
                "    export AISPM_TENANT_ID=... AISPM_CLIENT_ID=... AISPM_CLIENT_SECRET=...\n"
                "    python aispm.py scan --auth app --scope consented --open")


def main(argv=None) -> int:
    # azure-identity logs its own credential failure at WARNING before we get the
    # exception, which prints a raw SDK line above the actionable message below it.
    logging.getLogger("azure").setLevel(logging.ERROR)
    logging.getLogger("azure.identity").setLevel(logging.ERROR)

    args = build_parser().parse_args(argv)
    _reject_placeholders(args)
    handler = {"doctor": cmd_doctor, "scan": cmd_scan, "sample": cmd_sample}[args.command]
    try:
        return handler(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as e:
        print(f"\nError: {_auth_hint(e)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
