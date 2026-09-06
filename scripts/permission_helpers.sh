#!/usr/bin/env bash
# Sourced by setup scripts running with set -euo pipefail.
# Graph application consent requires Privileged Role Administrator / Global Administrator
# or an appropriately scoped custom role, not Cloud Application Administrator.

has_graph_role() {
  local principal="$1" resource="$2" role="$3" uri ids
  uri="https://graph.microsoft.com/v1.0/servicePrincipals/$principal/appRoleAssignments"
  while [[ -n "$uri" && "$uri" != "None" ]]; do
    ids="$(az rest --method GET --uri "$uri" \
      --query "value[?resourceId=='$resource' && appRoleId=='$role'].id" -o tsv)" || return 2
    if [[ -n "$ids" && "$ids" != "None" ]]; then return 0; fi
    uri="$(az rest --method GET --uri "$uri" --query '"@odata.nextLink"' -o tsv)" || return 2
  done
  return 1
}

grant_graph_role() {
  local principal="$1" resource="$2" role="$3" status attempt
  if has_graph_role "$principal" "$resource" "$role"; then return 0; else status=$?; fi
  if [[ "$status" != 1 ]]; then echo "ERROR: cannot read existing role assignments." >&2; return "$status"; fi
  az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principal/appRoleAssignments" \
    --headers "Content-Type=application/json" \
    --body "{\"principalId\":\"$principal\",\"resourceId\":\"$resource\",\"appRoleId\":\"$role\"}" \
    -o none || return $?
  for attempt in 1 2 3; do
    if has_graph_role "$principal" "$resource" "$role"; then return 0; else status=$?; fi
    if [[ "$status" != 1 ]]; then echo "ERROR: cannot verify role assignment." >&2; return "$status"; fi
    if [[ "$attempt" != 3 ]]; then sleep 2 || return $?; fi
  done
  echo "ERROR: Graph role $role was not visible after assignment; retry setup." >&2
  return 1
}

resolve_graph_role() {
  az ad sp show --id "$GRAPH_APP_ID" \
    --query "appRoles[?value=='$1' && isEnabled && contains(allowedMemberTypes,'Application')].id | [0]" -o tsv
}

grant_graph_roles() {
  local principal="$1" resource role role_id i
  local names=() ids=()
  resource="$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)" || return $?
  if [[ -z "$resource" || "$resource" == "None" ]]; then echo "ERROR: Graph service principal not found." >&2; return 1; fi
  # Resolve the entire plan before changing any grants.
  for role in "${REQUIRED_ROLES[@]}"; do
    role_id="$(resolve_graph_role "$role")" || return $?
    if [[ -z "$role_id" || "$role_id" == "None" ]]; then
      echo "ERROR: required Graph application role '$role' is unavailable." >&2
      return 1
    fi
    names+=("$role"); ids+=("$role_id")
  done
  for role in "${OPTIONAL_ROLES[@]}"; do
    role_id="$(resolve_graph_role "$role")" || return $?
    if [[ -z "$role_id" || "$role_id" == "None" ]]; then
      echo "WARNING: optional role '$role' is unavailable and NOT GRANTED. This does not establish license status." >&2
      continue
    fi
    names+=("$role"); ids+=("$role_id")
  done
  for ((i=0; i<${#ids[@]}; i++)); do
    grant_graph_role "$principal" "$resource" "${ids[$i]}" || return $?
    echo "    Verified grant: ${names[$i]}"
  done
  echo "Available grants verified; unavailable optional roles were NOT granted."
  echo "Run doctor and scan to check endpoint access, licensing and data ingestion prerequisites."
}
