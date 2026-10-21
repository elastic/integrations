#!/usr/bin/env bash
# PROTOTYPE: demo nginx + loadgen + an Elastic Agent enrolled in the elastic-package stack.
#
#   ./demo.sh [up]   create/pin the "Nginx demo" agent policy, enroll the agent, start compose
#   ./demo.sh down   unenroll the demo agents (best effort), remove containers + logs volume
#   ./demo.sh logs   follow compose logs
#
# Needs: the elastic-package stack up (profile nginx-proto), dev Kibana on :5602/kyle, jq, openssl.
# Then add Nginx through the wizard (ECS or OTel) on the existing agent policy "Nginx demo"
# with default values.
#
# The demo policy is pinned to its own output (https://elasticsearch:9200) and Fleet Server
# host (https://fleet-server:8220) on the stack network. The defaults from dev Kibana's
# kibana.dev.yml point at host.docker.internal, which is http-only for ES and not in the
# stack certs' SANs.
set -euo pipefail

cd "$(dirname "$0")"

PROFILE=${STACK_PROFILE:-nginx-proto}
KIBANA_URL=${KIBANA_URL:-http://localhost:5602/kyle}
KIBANA_AUTH=${KIBANA_AUTH:-elastic:changeme}
POLICY_NAME=${POLICY_NAME:-Nginx demo}
NEW_POLICY_ID=nginx-demo
OUTPUT_ID=nginx-demo-stack-es
FLEET_HOST_ID=nginx-demo-stack-fleet-server

if [[ $PROFILE == default ]]; then STACK_PROJECT=elastic-package-stack; else STACK_PROJECT=elastic-package-stack-$PROFILE; fi
export STACK_NETWORK=${STACK_PROJECT}_default
export STACK_CA=$HOME/.elastic-package/profiles/$PROFILE/certs/ca-cert.pem

die() { echo "demo.sh: $*" >&2; exit 1; }

kbn() { # kbn METHOD PATH [JSON]
  local args=(-sS --fail-with-body -u "$KIBANA_AUTH" -H 'kbn-xsrf: true'
    -H 'elastic-api-version: 2023-10-31' -H 'content-type: application/json' -X "$1" "$KIBANA_URL$2")
  if [[ $# -ge 3 ]]; then args+=(-d "$3"); fi
  curl "${args[@]}"
}

kbn_status() { # kbn_status PATH -> HTTP status code
  curl -s -o /dev/null -w '%{http_code}' -u "$KIBANA_AUTH" "$KIBANA_URL$1"
}

find_policy() { # -> "<id> <namespace>" of the policy named $POLICY_NAME, or nothing
  kbn GET '/api/fleet/agent_policies?perPage=1000' |
    jq -r --arg n "$POLICY_NAME" '[.items[] | select(.name == $n)][0] // empty | "\(.id) \(.namespace)"'
}

up() {
  command -v jq >/dev/null || die "jq not found"
  docker info >/dev/null 2>&1 || die "docker daemon not running"
  docker network inspect "$STACK_NETWORK" >/dev/null 2>&1 ||
    die "network $STACK_NETWORK not found, start the stack (elastic-package stack up -p $PROFILE)"
  [[ -f $STACK_CA ]] || die "CA not found: $STACK_CA"

  local setup
  setup=$(kbn GET /api/fleet/agents/setup) || die "Kibana not reachable at $KIBANA_URL"
  [[ $(jq -r .isReady <<<"$setup") == true ]] ||
    die "Fleet not ready: $(jq -c .missing_requirements <<<"$setup") (is fleet-server healthy?)"

  # Same image as the stack's Fleet Server: matching version, already pulled.
  AGENT_IMAGE=$(docker inspect --format '{{.Config.Image}}' "$STACK_PROJECT-fleet-server-1" 2>/dev/null ||
    echo "docker.elastic.co/elastic-agent/elastic-agent-wolfi:9.6.0-SNAPSHOT")
  export AGENT_IMAGE

  if [[ $(kbn_status "/api/fleet/outputs/$OUTPUT_ID") == 404 ]]; then
    local fingerprint
    fingerprint=$(openssl x509 -in "$STACK_CA" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d :)
    echo "Creating output $OUTPUT_ID"
    kbn POST /api/fleet/outputs "$(jq -n --arg id "$OUTPUT_ID" --arg fp "$fingerprint" '{
      id: $id, name: "Nginx demo - stack Elasticsearch", type: "elasticsearch",
      hosts: ["https://elasticsearch:9200"], ca_trusted_fingerprint: $fp,
      is_default: false, is_default_monitoring: false}')" >/dev/null
  fi

  if [[ $(kbn_status "/api/fleet/fleet_server_hosts/$FLEET_HOST_ID") == 404 ]]; then
    echo "Creating Fleet Server host $FLEET_HOST_ID"
    kbn POST /api/fleet/fleet_server_hosts "$(jq -n --arg id "$FLEET_HOST_ID" '{
      id: $id, name: "Nginx demo - stack Fleet Server",
      host_urls: ["https://fleet-server:8220"], is_default: false}')" >/dev/null
  fi

  local found policy_id namespace
  found=$(find_policy)
  local pin
  pin=$(jq -n --arg o "$OUTPUT_ID" --arg f "$FLEET_HOST_ID" \
    '{data_output_id: $o, monitoring_output_id: $o, fleet_server_host_id: $f}')
  if [[ -z $found ]]; then
    echo "Creating agent policy \"$POLICY_NAME\" (no system integration, no agent monitoring)"
    policy_id=$NEW_POLICY_ID
    kbn POST '/api/fleet/agent_policies?sys_monitoring=false' "$(jq -n \
      --arg id "$policy_id" --arg n "$POLICY_NAME" --argjson pin "$pin" '{
      id: $id, name: $n, namespace: "default",
      description: "PROTOTYPE: integration group demo (packages/nginx_group/_dev/shared/demo)",
      monitoring_enabled: []} + $pin')" >/dev/null
  else
    read -r policy_id namespace <<<"$found"
    echo "Using agent policy \"$POLICY_NAME\" ($policy_id), pinning output + Fleet Server host"
    kbn PUT "/api/fleet/agent_policies/$policy_id" "$(jq -n \
      --arg n "$POLICY_NAME" --arg ns "$namespace" --argjson pin "$pin" \
      '{name: $n, namespace: $ns} + $pin')" >/dev/null
  fi

  FLEET_ENROLLMENT_TOKEN=$(kbn GET '/api/fleet/enrollment_api_keys?perPage=1000' |
    jq -r --arg p "$policy_id" '[.items[] | select(.policy_id == $p and .active)][0].api_key // empty')
  if [[ -z $FLEET_ENROLLMENT_TOKEN ]]; then
    FLEET_ENROLLMENT_TOKEN=$(kbn POST /api/fleet/enrollment_api_keys \
      "$(jq -n --arg p "$policy_id" '{policy_id: $p}')" | jq -r .item.api_key)
  fi
  export FLEET_ENROLLMENT_TOKEN

  docker compose up -d

  cat <<EOF

nginx:   http://localhost:8090/nginx_status
agent:   docker logs -f nginx-demo-agent  (enrolls as "nginx-demo" in Fleet > Agents)
next:    add Nginx (ECS or OTel) via the wizard on existing agent policy "$POLICY_NAME"
         with default values. Data shows up ~30s after the policy reaches the agent.
EOF
}

down() {
  local found policy_id _ns
  if found=$(find_policy 2>/dev/null) && [[ -n $found ]]; then
    read -r policy_id _ns <<<"$found"
    echo "Unenrolling agents on policy $policy_id"
    kbn POST /api/fleet/agents/bulk_unenroll "$(jq -n --arg p "$policy_id" \
      '{agents: "policy_id:\"\($p)\"", revoke: true}')" >/dev/null ||
      echo "demo.sh: unenroll failed, remove the agent in Fleet by hand" >&2
  else
    echo "demo.sh: Kibana not reachable or no \"$POLICY_NAME\" policy, skipping unenroll" >&2
  fi
  docker compose down -v
}

case ${1:-up} in
  up) up ;;
  down) down ;;
  logs) docker compose logs -f ;;
  *) die "usage: $0 [up|down|logs]" ;;
esac
