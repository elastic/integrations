#!/bin/bash

# Sends queries to the elasticsearch service configured in _dev/deploy in order
# to generate all existing log types. `server` and `gc` logs will be generated
# without external trigger.

set -e

# the host started by `elastic-package service up`
elasticsearch_host=http://localhost:9201
username=elastic
password=changeme

# create an index that will trace every indexing/searching operations
curl -u $username:$password -X PUT $elasticsearch_host/_template/foo-template \
  -H "Content-Type: application/json" \
  -d "{\"index_patterns\": [\"foo-*\"], \"settings\": { \"index.indexing.slowlog.threshold.index.trace\": \"0ms\", \"index.search.slowlog.threshold.query.trace\": \"0ms\" } }" &> /dev/null

curl -u $username:$password -X PUT $elasticsearch_host/foo-bar &> /dev/null

while true
do
  # generates deprecation log and index_search slowlog
  curl -u $username:$password -X POST $elasticsearch_host/foo-bar/_search \
    -H "Content-Type: application/json" \
    -d "{\"_source\": { \"exclude\": [\"bar\"] } }" &> /dev/null

  # generates index_indexing slowlog
  curl -u $username:$password -X POST $elasticsearch_host/foo-bar/_doc \
    -H "Content-Type: application/json" \
    -d "{ \"foo\": \"bar\" }" &> /dev/null

  sleep 5
done
