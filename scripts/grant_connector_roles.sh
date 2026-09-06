#!/usr/bin/env bash
# Usage: ./scripts/grant_connector_roles.sh <MANAGED_IDENTITY_OBJECT_ID>
# Requires Privileged Role Administrator / Global Administrator or an appropriately
# scoped custom role. Cloud Application Administrator cannot grant Graph app roles.
# Agent 365 requires Microsoft Agent 365 licensing; MDCA needs ingested discovery data.
set -euo pipefail
if [[ -z "${1:-}" ]]; then
  echo "ERROR: Managed Identity object ID required. Usage: $0 <MANAGED_IDENTITY_OBJECT_ID>" >&2
  exit 1
fi
source "$(dirname "$0")/permission_helpers.sh"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"
REQUIRED_ROLES=("Application.Read.All" "Directory.Read.All")
# Sponsor listing documents a write permission; never auto-grant it.
OPTIONAL_ROLES=("AgentIdentity.Read.All" "AgentIdentityBlueprint.Read.All"
  "CopilotPackages.Read.All" "CloudApp-Discovery.Read.All" "AuditLogsQuery.Read.All")
grant_graph_roles "$1"
