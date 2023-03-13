## Kubernetes Node Out Of Disk alert

In order to install the Node Out Of Disk alert run the following:
```bash
curl -X PUT "https://elastic:changeme@localhost:9200/_watcher/watch/Node-Out-Of-Disk?pretty" -k -H 'Content-Type: application/json' -d'
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
                          "field": "kubernetes.node.status.out_of_disk"
                        }
                      },
                      {
                        "query_string": {
                          "query": "kubernetes.node.status.out_of_disk: true",
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
        "text": "Kubernetes node found out of disk: {{ctx.payload.key}}"
      }
    }
  },
  "metadata": {
    "xpack": {
      "type": "json"
    },
    "name": "Node Out Of Disk"
  }
}
'
```