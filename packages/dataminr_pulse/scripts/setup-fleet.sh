#!/bin/bash
set -euo pipefail

# Configuration
ES_URL="${ES_URL:-http://localhost:9200}"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-changeme}"
KIBANA_PASSWORD="${KIBANA_PASSWORD:-changeme}"
PACKAGE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Dataminr Pulse Integration - Fleet Setup ==="
echo ""

# Step 1: Wait for Elasticsearch
echo "[1/6] Waiting for Elasticsearch..."
until curl -s -u "elastic:${ELASTIC_PASSWORD}" "${ES_URL}/_cluster/health" | grep -qE '"status":"(green|yellow)"'; do
  sleep 5
done
echo "  Elasticsearch is ready."

# Step 2: Set kibana_system password
echo "[2/6] Setting kibana_system password..."
curl -s -u "elastic:${ELASTIC_PASSWORD}" \
  -X POST "${ES_URL}/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}" > /dev/null
echo "  kibana_system password set."

# Step 3: Wait for Kibana
echo "[3/6] Waiting for Kibana..."
until curl -s -u "elastic:${ELASTIC_PASSWORD}" "${KIBANA_URL}/api/status" | grep -q '"overall"'; do
  sleep 5
done
echo "  Kibana is ready."

# Step 4: Wait for Fleet Server
echo "[4/6] Waiting for Fleet Server..."
until curl -s -u "elastic:${ELASTIC_PASSWORD}" \
  "${KIBANA_URL}/api/fleet/agents" \
  -H "kbn-xsrf: true" 2>/dev/null | grep -q '"total"'; do
  sleep 5
done
echo "  Fleet is ready."

# Step 5: Install the custom integration package
echo "[5/6] Installing Dataminr Pulse integration package..."

if command -v elastic-package &> /dev/null; then
  echo "  Building package with elastic-package..."
  cd "${PACKAGE_DIR}"
  elastic-package build

  PACKAGE_ZIP=$(find build -name "*.zip" -type f 2>/dev/null | head -1)

  if [ -n "${PACKAGE_ZIP}" ]; then
    echo "  Uploading package: ${PACKAGE_ZIP}"
    UPLOAD_RESULT=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
      -X POST "${KIBANA_URL}/api/fleet/epm/packages" \
      -H "kbn-xsrf: true" \
      -H "Content-Type: application/zip" \
      --data-binary "@${PACKAGE_ZIP}")
    echo "  ${UPLOAD_RESULT}" | python3 -m json.tool 2>/dev/null || echo "  ${UPLOAD_RESULT}"
  else
    echo "  Warning: No package zip found in build/ directory."
  fi
else
  echo "  elastic-package CLI not found. Install the package manually:"
  echo "    Option A: Install elastic-package and re-run this script"
  echo "    Option B: Upload via Kibana UI: Fleet > Integrations > Upload integration"
fi

# Step 6: List enrollment tokens
echo ""
echo "[6/6] Enrollment tokens:"
TOKENS=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
  "${KIBANA_URL}/api/fleet/enrollment_api_keys" \
  -H "kbn-xsrf: true")
echo "${TOKENS}" | python3 -m json.tool 2>/dev/null || echo "${TOKENS}"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Kibana:  ${KIBANA_URL}"
echo "Login:   elastic / ${ELASTIC_PASSWORD}"
echo ""
echo "To configure the Dataminr Pulse integration:"
echo "  1. Go to Fleet > Agent Policies"
echo "  2. Select the default policy (or create a new one)"
echo "  3. Add integration > Dataminr Pulse"
echo ""
echo "For testing with mock API (start with: docker compose --profile mock up -d):"
echo "  URL:           http://mock-dataminr-api:8080"
echo "  Base URL:      /pulse/v1"
echo "  Auth URL:      http://mock-dataminr-api:8080/auth/2/token"
echo "  Client ID:     test-client-id"
echo "  Client Secret: test-client-secret"
