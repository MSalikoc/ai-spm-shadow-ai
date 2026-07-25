"""
AI-SPM v0 — Shadow AI Discovery (Entra/Graph, read-only).

Kullanım (cihaz kodu, secret gerekmez):
  python main.py --tenant <TENANT_ID> --client-id <APP_ID>

Kullanım (otomasyon, client secret):
  python main.py --mode app --tenant <T> --client-id <C> --client-secret <S>

Çıktı: out/shadow_ai.html + out/shadow_ai.json
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
    p.add_argument("--client-id", help="App registration (client) ID (delegated/app modu)")
    p.add_argument("--mode", choices=["delegated", "app", "managed"], default="delegated")
    p.add_argument("--client-secret", help="app modu için gerekli")
    p.add_argument("--out", default="out", help="çıktı klasörü")
    args = p.parse_args()

    if args.mode == "app":
        if not (args.client_id and args.client_secret):
            p.error("--mode app için --client-id ve --client-secret gerekli")
        token = auth.get_token_client_credentials(args.tenant, args.client_id, args.client_secret)
    elif args.mode == "managed":
        token = auth.get_token_managed_identity()
    else:
        if not args.client_id:
            p.error("--mode delegated için --client-id gerekli")
        token = auth.get_token_device_code(args.tenant, args.client_id)

    graph = GraphClient(token)

    print("[*] tarama çalışıyor (keşif → izin eşleme → skorlama)...", flush=True)
    scored = pipeline.run(graph, args.tenant)

    os.makedirs(args.out, exist_ok=True)
    json_path = os.path.join(args.out, "shadow_ai.json")
    html_path = os.path.join(args.out, "shadow_ai.html")
    report.write_json(scored, json_path)
    report.write_html(scored, html_path, args.tenant)

    crit = sum(1 for a in scored if a["risk_level"] == "Kritik")
    high = sum(1 for a in scored if a["risk_level"] == "Yüksek")
    print(f"\n[✓] Tamamlandı: {len(scored)} bulgu ({crit} kritik, {high} yüksek)")
    print(f"    HTML: {html_path}\n    JSON: {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
