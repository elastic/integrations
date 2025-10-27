#!/bin/bash
# View ingested data from system tests

echo "📊 Querying ingested vulnerability data..."
echo ""

# Get all documents
echo "=== All Documents ==="
curl -sk -u elastic:changeme \
  "https://127.0.0.1:9200/logs-projectdiscovery_cloud.vulnerability*/_search?size=10&pretty" \
  | jq '.hits.hits[] | {
      index: ._index,
      timestamp: ._source["@timestamp"],
      vulnerability_id: ._source.vulnerability.id,
      vulnerability_status: ._source.vulnerability.status,
      input_type: ._source.input.type,
      message: ._source.message,
      event_module: ._source.event.module
    }'

echo ""
echo "=== Full Document Example ==="
curl -sk -u elastic:changeme \
  "https://127.0.0.1:9200/logs-projectdiscovery_cloud.vulnerability*/_search?size=1&sort=@timestamp:desc" \
  | jq '.hits.hits[0]._source' > /tmp/ingested-sample.json

cat /tmp/ingested-sample.json | jq

echo ""
echo "✅ Full document saved to: /tmp/ingested-sample.json"
echo ""
echo "=== Document Count ==="
curl -sk -u elastic:changeme \
  "https://127.0.0.1:9200/logs-projectdiscovery_cloud.vulnerability*/_count" \
  | jq
