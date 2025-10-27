#!/bin/bash
# System test runner with data inspection capability
# This script runs system tests and provides time to inspect data before cleanup

set -e

echo "🧪 Running system tests with deferred cleanup..."
echo "⏰ Data will be kept for 5 minutes after tests complete"
echo ""

# Run tests with 5-minute cleanup delay
elastic-package test system -v --defer-cleanup 5m

echo ""
echo "📊 Test complete! Data is still available for inspection."
echo ""
echo "🔍 To view indexed documents, run:"
echo ""
echo "  # View all indexed documents"
echo "  curl -sk -u elastic:changeme 'https://127.0.0.1:9200/logs-projectdiscovery_cloud.vulnerability*/_search?size=10&pretty'"
echo ""
echo "  # View just the source of latest document"
echo "  curl -sk -u elastic:changeme 'https://127.0.0.1:9200/logs-projectdiscovery_cloud.vulnerability*/_search?size=1&sort=@timestamp:desc' | jq '.hits.hits[0]._source'"
echo ""
echo "  # Count documents"
echo "  curl -sk -u elastic:changeme 'https://127.0.0.1:9200/logs-projectdiscovery_cloud.vulnerability*/_count' | jq"
echo ""
echo "  # View specific fields"
echo "  curl -sk -u elastic:changeme 'https://127.0.0.1:9200/logs-projectdiscovery_cloud.vulnerability*/_search?size=1' | jq '.hits.hits[0]._source | {input, message, event, vulnerability}'"
echo ""
echo "⏰ Cleanup will happen automatically in 5 minutes..."
echo "   Or press Ctrl+C now to cancel cleanup and keep data"
