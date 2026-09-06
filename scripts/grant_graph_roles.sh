#!/usr/bin/env bash
# Usage: ./scripts/grant_graph_roles.sh <MANAGED_IDENTITY_OBJECT_ID>
# Requires Privileged Role Administrator / Global Administrator or an appropriately
# scoped custom role. Cloud Application Administrator cannot grant Graph app roles.
set -euo pipefail
if [[ -z "${1:-}" ]]; then
  echo "ERROR: Managed Identity object ID required. Usage: $0 <MANAGED_IDENTITY_OBJECT_ID>" >&2
  exit 1
fi
source "$(dirname "$0")/permission_helpers.sh"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"
# Mail.Send is for the weekly digest; restrict mailbox access in Exchange.
REQUIRED_ROLES=("Directory.Read.All" "Application.Read.All" "AuditLog.Read.All" "Mail.Send")
OPTIONAL_ROLES=()
grant_graph_roles "$1"
