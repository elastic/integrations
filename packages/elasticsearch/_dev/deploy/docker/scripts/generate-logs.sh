#!/bin/sh

# Sends queries to the elasticsearch service configured in _dev/deploy in order
# to generate all existing log types. `server` and `gc` logs will be generated
# without external trigger.

set -e

auth=$(echo -n $ES_SERVICE_USERNAME:$ES_SERVICE_PASSWORD | base64)

# create an index that will trace every indexing/searching operations
curl --request PUT \
  --url $ES_SERVICE_HOST/test_1 \
  --header "Authorization: Basic $auth" \
  --header 'Content-Type: application/json' \
  --header 'X-Opaque-ID: myApp1' \
  --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'

# set index settings
curl --request PUT \
  --url $ES_SERVICE_HOST/test_1/_settings \
  --header "Authorization: Basic $auth" \
  --header 'Content-Type: application/json' \
  --header 'X-Opaque-ID: myApp1' \
  --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' \
  --data '{"settings": {
	"index.search.slowlog.threshold.query.warn": "100ms",
	"index.search.slowlog.threshold.query.info": "100ms",
        "index.search.slowlog.threshold.query.debug": "0ms",
	"index.search.slowlog.threshold.query.trace": 0,
	"index.indexing.slowlog.threshold.index.trace": 0
}
}'

while true
do
  echo Generating slowlogs, audit and deprecation

  ## INDEXING SLOW LOG
  # index document
  curl --request POST \
    --url $ES_SERVICE_HOST/test_1/_doc \
    --header "Authorization: Basic $auth" \
    --header 'Content-Type: application/json' \
    --header 'X-Opaque-ID: myApp1' \
    --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' \
    --data '{
  "a":"b"
  }'

  ## SEARCH SLOW LOG
  # search with xopaqueid and trace.id
  curl --request GET \
    --url $ES_SERVICE_HOST/test_1/_search \
    --header "Authorization: Basic $auth" \
    --header 'Content-Type: application/json' \
    --header 'X-Opaque-ID: myApp1' \
    --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'

  # search with trace.id only
  curl --request GET \
    --url $ES_SERVICE_HOST/test_1/_search \
    --header "Authorization: Basic $auth" \
    --header 'Content-Type: application/json' \
    --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'

  # search without trace.id nor xopaqueid
  curl --request GET \
    --url $ES_SERVICE_HOST/test_1/_search \
    --header "Authorization: Basic $auth" \
    --header 'Content-Type: application/json'


  ## AUDIT LOG
  # access granted new index with ids
  curl --request PUT \
    --url $ES_SERVICE_HOST/test_1 \
    --header "Authorization: Basic $auth" \
    --header 'X-Opaque-ID: myApp1' \
    --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'

  # access granted new index no ids
  curl --request PUT \
    --url $ES_SERVICE_HOST/test_2 \
    --header "Authorization: Basic $auth" \

  # anonymous access denied
  curl -s --request PUT \
    --url $ES_SERVICE_HOST/test_3 \
    --header 'X-Opaque-ID: myApp1' \
    --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'

  ## DEPRECATION LOGS
  # data path deprecation warning
  curl --request PUT \
    --url $ES_SERVICE_HOST/testindex2/ \
    --header "Authorization: Basic $auth" \
    --header 'Content-Type: application/json' \
    --header 'X-Opaque-Id: myAppId' \
    --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' \
    --data '{
      "settings" : {
          "index" : {
              "number_of_shards" : 3,
              "number_of_replicas" : 1,
              "data_path": "/tmp/dummy"
          }
      }
  }'

  # merge at once deprecation critical
  curl --request PUT \
    --url $ES_SERVICE_HOST/testindex2/ \
    --header "Authorization: Basic $auth" \
    --header 'Content-Type: application/json' \
    --header 'X-Opaque-Id: myAppId' \
    --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' \
    --data '{
      "settings" : {
          "index" : {
              "number_of_shards" : 3,
              "number_of_replicas" : 1,
              "merge.policy.max_merge_at_once_explicit": 20
          }
      }
  }'

  sleep 5
done
