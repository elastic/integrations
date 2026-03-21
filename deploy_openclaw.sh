#!/bin/bash
set -e

# Configuration
PACKAGE_DIR="/root/.openclaw/workspace/integrations/packages/openclaw"
ZIP_FILE="/root/.openclaw/workspace/integrations/build/packages/openclaw-1.0.2.zip"
ES_URL="https://lex-demo.es.ap-east-1.aws.elastic-cloud.com"
KB_URL="https://lex-demo.kb.ap-east-1.aws.elastic-cloud.com:9243"
AUTH="elastic:h81ah8kYqVlCfbbUetRWVq09"

echo "========================================"
echo "🚀 Starting OpenClaw Integration Deployment"
echo "========================================"

echo "[1/3] Building the package..."
cd "$PACKAGE_DIR"
elastic-package build
echo "✅ Build successful."

echo ""
echo "[2/3] Deleting existing data stream from Elasticsearch..."
# Ignore errors on deletion if the data stream doesn't exist
curl -s -X DELETE "${ES_URL}/_data_stream/logs-openclaw.sessions-default" -u "${AUTH}" | grep -q '"acknowledged":true' && echo "✅ Data stream deleted." || echo "⚠️ Data stream not found or could not be deleted."

echo ""
echo "[3/3] Uploading and installing the package to Kibana Fleet..."
# Use application/zip and --data-binary instead of multipart/form-data
UPLOAD_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}\n" -X POST "${KB_URL}/api/fleet/epm/packages" \
  -u "${AUTH}" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/zip" \
  --data-binary "@${ZIP_FILE}")

if echo "$UPLOAD_RESPONSE" | grep -q 'items'; then
  echo "✅ Package uploaded and installed successfully!"
else
  echo "❌ Upload failed or returned unexpected response:"
  echo "$UPLOAD_RESPONSE"
  exit 1
fi

echo ""
echo "🎉 Deployment complete! You can now generate some new chats to test."
