## Kubernetes Pod RX Error Rate alert

In order to install the Pod RX Error Rate alert run the following:
```bash
curl -X PUT "https://elastic:changeme@localhost:9200/_watcher/watch/Pod-RX-Error-Rate?pretty" -k -H 'Content-Type: application/json' -d'
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
          "size": 0,
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
                          "query": "data_stream.dataset: kubernetes.pod",
                          "analyze_wildcard": true
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
          "aggs": {
            "rx_error_rates": {
              "terms": {
                "field": "kubernetes.pod.name",
                "size": "10000",
                "order": {
                  "_key": "asc"
                }
              },
              "aggs": {
                "by_minute": {
                  "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "minute"
                  },
                  "aggs": {
                    "my_rate": {
                      "rate": {
                        "field": "kubernetes.pod.network.rx.errors",
                        "unit": "minute"
                      }
                    }
                  }
                },
                "avg_minute_rate": {
                  "avg_bucket": {
                    "buckets_path": "by_minute>my_rate",
                    "gap_policy": "skip"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "metrics-kubernetes.pod-default"
        ]
      }
    }
  },
  "condition": {
    "array_compare": {
      "ctx.payload.aggregations.rx_error_rates.buckets": {
        "path": "avg_minute_rate.value",
        "gt": {
          "value": 1
        }
      }
    }
  },
  "actions": {
    "log_hits": {
      "foreach": "ctx.payload.aggregations.rx_error_rates.buckets",
      "max_iterations": 500,
      "logging": {
        "text": "Kubernetes Pod found with high rx error rate: {{ctx.payload.key}} -> {{ctx.payload.avg_minute_rate.value}}"
      }
    }
  },
  "metadata": {
    "xpack": {
      "type": "json"
    },
    "name": "Pod RX Error Rate"
  }
}
'
```