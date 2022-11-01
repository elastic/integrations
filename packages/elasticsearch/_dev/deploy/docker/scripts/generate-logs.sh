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

  sleep 10
done
