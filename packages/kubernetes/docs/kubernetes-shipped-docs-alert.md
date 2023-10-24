## Kubernetes Kubernetes Shipped Docs alert

One useful information is if Elastic Agent is shipping any Kubernetes related data to Elastic.
For this we can check every minute if docs are stored in ES. The threshold here is 10 docs per 1 minute.
If we find less the watcher will be triggered.
In order to install the Kubernetes Shipped Docs alert run the following:
```bash
curl -X PUT "https://elastic:changeme@localhost:9200/_watcher/watch/Kubernetes-Shipped-Docs?pretty" -k -H 'Content-Type: application/json' -d'
{
  "trigger": {
    "schedule": {
      "interval": "1m"
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
                      "gte": "now-1m",
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
                          "query": "event.module:kubernetes",
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
          }
        },
        "indices": [
          "metrics-kubernetes*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "lte": 10
      }
    }
  },
  "actions": {
    "my-logging-action": {
      "logging": {
        "text": "{{ctx.payload.hits.total}} documents were shipped in your Kubernetes indexes during the last minute. Threshold is at least 10."
      }
    }
  },
  "metadata": {
    "xpack": {
      "type": "json"
    },
    "name": "Kubernetes Shipped Docs"
  }
}
'
```