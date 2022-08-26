#!/bin/sh

# Sends queries to the elasticsearch service configured in _dev/deploy in order
# to generate all existing log types. `server` and `gc` logs will be generated
# without external trigger.

set -e

elasticsearch_host=http://elasticsearch:9200
username=elastic
password=changeme

# create an index that will trace every indexing/searching operations
echo Creating foo-* index template with 0ms slowlog threshold
curl -s -S -u $username:$password -X PUT $elasticsearch_host/_template/foo-template \
  -H "Content-Type: application/json" \
  -d "{\"index_patterns\": [\"foo-*\"], \"settings\": { \"index.indexing.slowlog.threshold.index.trace\": \"0ms\", \"index.search.slowlog.threshold.query.trace\": \"0ms\" } }"

echo Creating foo-bar index
curl -s -S -u $username:$password -X PUT $elasticsearch_host/foo-bar

while true
do
  echo Generating audit, deprecation and slowlogs

  # audit logs will be generated automatically on requests

  # generates deprecation log and index_search slowlog
  curl -s -S -u $username:$password -X POST $elasticsearch_host/foo-bar/_search \
    -H "Content-Type: application/json" \
    -d "{\"_source\": { \"exclude\": [\"bar\"] } }"

  # generates index_indexing slowlog
  curl -s -S -u $username:$password -X POST $elasticsearch_host/foo-bar/_doc \
    -H "Content-Type: application/json" \
    -d "{ \"foo\": \"bar\" }"

  sleep 5
done
