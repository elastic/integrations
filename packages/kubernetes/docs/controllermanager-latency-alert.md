## Controller Manager Request Latency alert

In order to install the Controller Manager Request Latency alert run the following:
```bash
curl -X PUT "https://elastic:changeme@localhost:9200/_watcher/watch/Controller-Manager-Request-Latency?pretty" -k -H 'Content-Type: application/json' -d'
{
  "trigger": {
    "schedule": {
      "interval": "10m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "query": {
            "bool": {
              "must": [
                {
                  "range": {
                    "@timestamp": {
                      "gte": "now-10m",
                      "lte": "now",
                      "format": "strict_date_optional_time"
                    }
                  }
                },
                {
                  "bool": {
                    "must": [
                      {
                        "query_string": {
                          "query": "data_stream.dataset: kubernetes.controllermanager",
                          "analyze_wildcard": true
                        }
                      },
                      {
                        "exists": {
                          "field": "kubernetes.controllermanager.client.request.duration"
                        }
                      }
                    ],
                    "filter": [],
                    "should": [],
                    "must_not": []
                  }
                }
              ],
              "filter": [],
              "should": [],
              "must_not": []
            }
          },
          "size": 0,
          "runtime_mappings": {
            "avg_duration": {
              "type": "double",
              "script": {
                "source": "emit(doc['kubernetes.controllermanager.client.request.duration.us.sum'].value / doc['kubernetes.controllermanager.client.request.duration.us.count'].value / 1000 )"
              }
            }
          },
          "aggs": {
            "avg_duration": {
              "avg": {
                "field": "avg_duration"
              }
            }
          }
        },
        "indices": [
          "*"
        ]
      }
    }
  },
  "condition": {
    "script": {
      "source": "return ctx.payload.aggregations.avg_duration.value > params.threshold",
      "params": {
        "threshold": 10
      }
    }
  },
  "actions": {
    "my-logging-action": {
      "logging": {
        "text": "The average request duration for k8s Controller Manager is {{ctx.payload.aggregations.avg_duration}} ms. Threshold is 10."
      }
    }
  },
  "metadata": {
    "xpack": {
      "type": "json"
    },
    "name": "Controller Manager Request Latency"
  }
}
'
```