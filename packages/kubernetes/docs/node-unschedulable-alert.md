## Unschedulable Kubernetes Node alert

In order to install the [Unschedulable Node](https://kubernetes.io/docs/concepts/architecture/nodes/#manual-node-administration) alert run the following:
```bash
curl -X PUT "https://elastic:changeme@localhost:9200/_watcher/watch/Node-Unschedulable?pretty" -k -H 'Content-Type: application/json' -d'
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
                          "query": "data_stream.dataset: kubernetes.state_node",
                          "analyze_wildcard": true
                        }
                      },
                      {
                        "exists": {
                          "field": "kubernetes.node.status.unschedulable"
                        }
                      },
                      {
                        "query_string": {
                          "query": "kubernetes.node.status.unschedulable: true",
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
                "order": {
                  "_key": "asc"
                }
              }
            }
          }
        },
        "indices": [
          "metrics-kubernetes.state_node-default"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "gte": 1
      }
    }
  },
  "actions": {
    "log_hits": {
      "foreach": "ctx.payload.aggregations.nodes.buckets",
      "max_iterations": 500,
      "logging": {
        "text": "Kubernetes node found unschedulable: {{ctx.payload.key}}"
      }
    }
  },
  "metadata": {
    "xpack": {
      "type": "json"
    },
    "name": "Node Unschedulable"
  }
}
'
```