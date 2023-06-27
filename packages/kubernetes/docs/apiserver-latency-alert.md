## Kubernetes API Latency alert

In order to install the API Latency alert run the following:
```bash
curl -X PUT "https://elastic:changeme@localhost:9200/_watcher/watch/apiserver-latency?pretty" -k -H 'Content-Type: application/json' -d'
{
  "trigger": {
    "schedule": {
      "interval": "10m"
    }
  },
  "input": {
    "search": {
      "request": {
        "search_type": "query_then_fetch",
        "indices": [
          "*"
        ],
        "rest_total_hits_as_int": true,
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
                          "query": "data_stream.dataset: kubernetes.apiserver AND NOT (kubernetes.apiserver.request.verb: WATCH or kubernetes.apiserver.request.verb: CONNECT)",
                          "analyze_wildcard": true
                        }
                      },
                      {
                        "exists": {
                          "field": "kubernetes.apiserver.request.duration"
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
                "source": "emit(doc['kubernetes.apiserver.request.duration.us.sum'].value / doc['kubernetes.apiserver.request.duration.us.count'].value / 1000 )"
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
        }
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
        "level": "error",
        "text": "The average request duration for k8s API Server is {{ctx.payload.aggregations.avg_duration}} ms. Threshold is 10 ms."
      }
    }
  },
  "metadata": {
    "xpack": {
      "type": "json"
    },
    "name": "API Server Request Latency"
  }
}
'
```