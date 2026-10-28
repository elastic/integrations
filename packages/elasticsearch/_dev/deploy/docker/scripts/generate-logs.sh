#!/bin/sh

# Sends queries to the elasticsearch service configured in _dev/deploy in order
# to generate all existing log types. `server` and `gc` logs will be generated
# without external trigger.
set -e

auth=$(echo -n $ES_SERVICE_USERNAME:$ES_SERVICE_PASSWORD | base64)

# Copy the log files content from this container to /var/log/ which is a bind mounted to ${SERVICE_LOGS_DIR}
# This sh must be executed by a root user in order to have permission to write in the ${SERVICE_LOGS_DIR} folder
copy_log_files () {
  for f in /es_logs/*;
  do
    echo "Copy ${f##*/} file..."

    if [[ ! -e /var/log/${f##*/} ]]; then
      touch /var/log/${f##*/}
    fi

    ## appends only new lines
    comm -23 "$f" /var/log/${f##*/} >> /var/log/${f##*/}
  done
}

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

# set machine learning job
curl --request PUT \
  --url $ES_SERVICE_HOST/_ml/anomaly_detectors/test-job1?pretty \
  --header "Authorization: Basic $auth" \
  --header 'Content-Type: application/json' \
  --header 'X-Opaque-ID: myApp1' \
  --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' \
  --data '{
            "analysis_config": {
              "bucket_span": "15m",
              "detectors": [
                {
                  "detector_description": "Sum of bytes",
                  "function": "sum",
                  "field_name": "bytes"
                }
              ]
            },
            "data_description": {
              "time_field": "timestamp",
              "time_format": "epoch_ms"
            },
            "analysis_limits": {
              "model_memory_limit": "11MB"
            },
            "model_plot_config": {
              "enabled": true,
              "annotations_enabled": true
            },
            "results_index_name": "test-job1",
            "datafeed_config":
            {
              "indices": [
                "kibana_sample_data_logs"
              ],
              "query": {
                "bool": {
                  "must": [
                    {
                      "match_all": {}
                    }
                  ]
                }
              },
              "runtime_mappings": {
                "hour_of_day": {
                  "type": "long",
                  "script": {
                    "source": "emit(doc['timestamp'].value.getHour());"
                  }
                }
              },
              "datafeed_id": "datafeed-test-job1"
            }
          }'

## Open ML job
curl --request POST \
  --url $ES_SERVICE_HOST/_ml/anomaly_detectors/test-job1/_open \
  --header "Authorization: Basic $auth" \
  --header 'Content-Type: application/json' \
  --header 'X-Opaque-ID: myApp1' \
  --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'

## Ingest pipeline monitoring

## Create a pipeline
curl --request PUT \
  --url $ES_SERVICE_HOST/_ingest/pipeline/test-pipeline \
  --header "Authorization: Basic $auth" \
  --header 'Content-Type: application/json' \
  --header 'X-Opaque-ID: myApp1' \
  --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' \
  --data '{
  "processors" : [
    {
      "set" : {
        "field": "my-keyword-field",
        "value": "foo"
      }
    }
  ]
}'

## Create an index that uses the ingest pipeline
curl --request PUT \
  --url $ES_SERVICE_HOST/test_ip \
  --header "Authorization: Basic $auth" \
  --header 'Content-Type: application/json' \
  --header 'X-Opaque-ID: myApp1' \
  --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'

curl --request PUT \
  --url $ES_SERVICE_HOST/test_ip/_settings \
  --header "Authorization: Basic $auth" \
  --header 'Content-Type: application/json' \
  --header 'X-Opaque-ID: myApp1' \
  --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' \
  --data '{"settings": {
	"index.default_pipeline": "test-pipeline"
}}'

# Query activity logs (elasticsearch.querylog) are not written by Elasticsearch 8.x default
# log4j2; append ECS JSON lines so the logfile system test can ingest them.
CLUSTER_NAME=$(curl -s --request GET \
  --url "$ES_SERVICE_HOST/" \
  --header "Authorization: Basic $auth" | tr ',' '\n' | grep '"cluster_name"' | head -1 | cut -d'"' -f4)
if [ -z "$CLUSTER_NAME" ]; then CLUSTER_NAME=elasticsearch; fi

CLUSTER_UUID=$(curl -s --request GET \
  --url "$ES_SERVICE_HOST/" \
  --header "Authorization: Basic $auth" | tr ',' '\n' | grep '"cluster_uuid"' | head -1 | cut -d'"' -f4)
if [ -z "$CLUSTER_UUID" ]; then CLUSTER_UUID=unknown-cluster-uuid; fi

NODE_INFO=$(curl -s --request GET \
  --url "$ES_SERVICE_HOST/_cat/nodes?h=id,name" \
  --header "Authorization: Basic $auth" | head -1)
NODE_ID=$(echo "$NODE_INFO" | awk '{print $1}')
NODE_NAME=$(echo "$NODE_INFO" | awk '{print $2}')
if [ -z "$NODE_ID" ]; then NODE_ID=unknown-node-id; fi
if [ -z "$NODE_NAME" ]; then NODE_NAME=unknown-node-name; fi

touch /var/log/integration_querylog.json

append_querylog_fixture() {
  ts=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
  printf '%s\n' "{\"@timestamp\":\"${ts}\",\"log.level\":\"INFO\",\"auth.type\":\"REALM\",\"elasticsearch.querylog.dsl.total_count\":3,\"elasticsearch.querylog.indices\":[\"query_log_test_index\"],\"elasticsearch.querylog.query\":\"{\\\"size\\\":10,\\\"query\\\":{\\\"match_all\\\":{\\\"boost\\\":1.0}}}\",\"elasticsearch.querylog.result_count\":3,\"elasticsearch.querylog.shards.successful\":1,\"elasticsearch.querylog.took\":1577209,\"elasticsearch.querylog.took_millis\":1,\"elasticsearch.querylog.type\":\"dsl\",\"elasticsearch.task.id\":16285,\"event.duration\":1577209,\"event.outcome\":\"success\",\"http.request.headers.x_opaque_id\":\"myApp1\",\"trace.id\":\"0af7651916cd43dd8448eb211c80319c\",\"user.name\":\"elastic\",\"user.realm\":\"reserved\",\"ecs.version\":\"1.2.0\",\"service.name\":\"ES_ECS\",\"event.dataset\":\"elasticsearch.querylog\",\"process.thread.name\":\"elasticsearch[integration-test][search][T#1]\",\"log.logger\":\"elasticsearch.querylog\",\"elasticsearch.cluster.uuid\":\"${CLUSTER_UUID}\",\"elasticsearch.node.id\":\"${NODE_ID}\",\"elasticsearch.node.name\":\"${NODE_NAME}\",\"elasticsearch.cluster.name\":\"${CLUSTER_NAME}\"}" >> /var/log/integration_querylog.json
}

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

  copy_log_files

  append_querylog_fixture

  echo Generating ingest pipeline load
  curl --request POST \
    --url $ES_SERVICE_HOST/test_ip/_bulk \
    --header "Authorization: Basic $auth" \
    --header 'Content-Type: application/json' \
    --header 'X-Opaque-ID: myApp1' \
    --header 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' \
    --data '{ "create": {} }
{ "a":1 }
{ "create": {} }
{ "a":2 }
{ "create": {} }
{ "a":3 }
{ "create": {} }
{ "a":4 }
'

  sleep 10
done
