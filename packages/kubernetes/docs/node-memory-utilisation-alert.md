## Kubernetes Node Memory Usage alert

In order to install the Node Memory Usage alert run the following:
```bash
curl -X PUT "https://elastic:changeme@localhost:9200/_watcher/watch/Node-Memory-Usage?pretty" -k -H 'Content-Type: application/json' -d'
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
                          "query": "data_stream.dataset: kubernetes.node OR data_stream.dataset: kubernetes.state_node",
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
            "nodes": {
              "terms": {
                "field": "kubernetes.node.name",
                "size": "10000",
                "order": {
                  "_key": "asc"
                }
              },
              "aggs": {
                "nodeUsage": {
                  "max": {
                    "field": "kubernetes.node.memory.usage.bytes"
                  }
                },
                "nodeCap": {
                  "max": {
                    "field": "kubernetes.node.memory.capacity.bytes"
                  }
                },
                "nodeMemoryUsagePCT": {
                  "bucket_script": {
                    "buckets_path": {
                      "nodeUsage": "nodeUsage",
                      "nodeCap": "nodeCap"
                    },
                    "script": {
                      "source": "( params.nodeUsage ) / params.nodeCap",
                      "lang": "painless",
                      "params": {
                        "_interval": 10000
                      }
                    },
                    "gap_policy": "skip"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "metrics-kubernetes*"
        ]
      }
    }
  },
  "condition": {
    "array_compare": {
      "ctx.payload.aggregations.nodes.buckets": {
        "path": "nodeMemoryUsagePCT.value",
        "gte": {
          "value": 80
        }
      }
    }
  },
  "actions": {
    "log_hits": {
      "foreach": "ctx.payload.aggregations.nodes.buckets",
      "max_iterations": 500,
      "logging": {
        "text": "Kubernetes node found with high memory usage: {{ctx.payload.key}} -> {{ctx.payload.nodeMemoryUsagePCT.value}}"
      }
    }
  },
  "metadata": {
    "xpack": {
      "type": "json"
    },
    "name": "Node Memory Usage"
  }
}
'
```