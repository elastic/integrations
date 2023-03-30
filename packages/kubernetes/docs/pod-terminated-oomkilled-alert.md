## Kubernetes Pod Terminated with OOMKilled alert

In order to install the Pod Terminated with OOMKilled ((Out of Memory) alert run the following:
```bash
curl -X PUT "https://elastic:changeme@localhost:9200/_watcher/watch/Pod-Terminated-OOMKilled?pretty" -k -H 'Content-Type: application/json' -d'
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
                          "query": "data_stream.dataset: kubernetes.state_container",
                          "analyze_wildcard": true
                        }
                      },
                      {
                        "exists": {
                          "field": "kubernetes.container.status.last_terminated_reason"
                        }
                      },
                      {
                        "query_string": {
                          "query": "kubernetes.container.status.last_terminated_reason: OOMKilled",
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
            "pods": {
              "terms": {
                "field": "kubernetes.pod.name",
                "order": {
                  "_key": "asc"
                }
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
    "array_compare": {
      "ctx.payload.aggregations.pods.buckets": {
        "path": "doc_count",
        "gte": {
          "value": 1
        }
      }
    }
  },
  "actions": {
    "log_hits": {
      "foreach": "ctx.payload.aggregations.pods.buckets",
      "max_iterations": 500,
      "logging": {
        "text": "Pod {{ctx.payload.key}} was terminated with status OOMKilled"
      }
    }
  },
  "metadata": {
    "xpack": {
      "type": "json"
    },
    "name": "Pod Terminated OOMKilled"
  }
}
'
```