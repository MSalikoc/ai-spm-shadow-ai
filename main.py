"""
AI-SPM v0 — Shadow AI Discovery (Entra/Graph, read-only).

Usage (device code, no secret required):
  python main.py --tenant <TENANT_ID> --client-id <APP_ID>

Usage (automation, client secret):
  python main.py --mode app --tenant <T> --client-id <C> --client-secret <S>

Output: out/shadow_ai.html + out/shadow_ai.json
"""
import argparse
import os
import sys

import auth
import pipeline
import report
from graph_client import GraphClient


def main() -> int:
    p = argparse.ArgumentParser(description="AI-SPM Shadow AI Discovery (read-only)")
    p.add_argument("--tenant", required=True, help="Entra tenant ID")
    p.add_argument("--client-id", help="App registration (client) ID (delegated/app mode)")
    p.add_argument("--mode", choices=["delegated", "app", "managed"], default="delegated")
    p.add_argument("--client-secret", help="required for app mode")
    p.add_argument("--out", default="out", help="output folder")
    args = p.parse_args()

    if args.mode == "app":
        if not (args.client_id and args.client_secret):
            p.error("--mode app requires --client-id and --client-secret")
        token = auth.get_token_client_credentials(args.tenant, args.client_id, args.client_secret)
    elif args.mode == "managed":
        token = auth.get_token_managed_identity()
    else:
        if not args.client_id:
            p.error("--mode delegated requires --client-id")
        token = auth.get_token_device_code(args.tenant, args.client_id)

    graph = GraphClient(token)

    print("[*] scan running (discovery → permission mapping → scoring)...", flush=True)
    scored = pipeline.run(graph, args.tenant)

    os.makedirs(args.out, exist_ok=True)
    json_path = os.path.join(args.out, "shadow_ai.json")
    html_path = os.path.join(args.out, "shadow_ai.html")
    report.write_json(scored, json_path)
    report.write_html(scored, html_path, args.tenant)

    crit = sum(1 for a in scored if a["risk_level"] == "Critical")
    high = sum(1 for a in scored if a["risk_level"] == "High")
    print(f"\n[✓] Done: {len(scored)} findings ({crit} critical, {high} high)")
    print(f"    HTML: {html_path}\n    JSON: {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
