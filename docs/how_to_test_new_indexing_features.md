Elasticsearch has been adding new indexing modes and features that allow optimization of storage size and query performance.

We'd like to enable integration developers to start testing the ingest and query performance of enabling these features before we start making any changes in the integrations themselves or allowing end users to enable these from the Fleet UI.

Today, each of these can already be enabled by leveraging the `*@custom` component templates that Fleet installs for each integration data stream, to varying degrees of ease of use (details below). We could improve the UX around this for integration developers by adding an explicit API in Fleet to enable this, however it may not be necessary. See https://github.com/elastic/kibana/issues/132818 for discussion around how a feature flag API could be added to ease this a bit more.

## How to do this today

### Synthetic source

- Background: https://github.com/elastic/elasticsearch/pull/85649
- Integrations support: https://github.com/elastic/package-spec/issues/340

This one is quite easy to enable on an integration using the component template. Here's how to do this for the nginx substatus metrics for example:

1. Install the nginx package
2. Run this dev tools command:
```
PUT /_component_template/metrics-nginx.substatus@custom
{
  "template": {
    "settings": {},
    "mappings": {
      "_source": {
        "mode": "synthetic"
      }
    }
  },
  "_meta": {
    "package": {
      "name": "nginx"
    }
  }
}
```
3. If a data stream already existed, rollover the data stream to get the new mappings: `POST metrics-nginx.substatus-default/_rollover`

One challenge with leveraging synthetic source is that it doesn't support `keyword` fields that have a `ignore_above` configured. It may be worth removing this setting for testing on those fields. This can be done by editing the package in dev and installing it via `elastic-package` or overriding it via the custom component template, similar to the doc-value-only example below.

### doc-value-only fields

- Background: https://www.elastic.co/blog/whats-new-elasticsearch-kibana-cloud-8-1-0
- Integrations support: https://github.com/elastic/integrations/issues/3419

This one is the most painful w/ component templates because it required adding `index: false` to every long and double field. Providing an API in Fleet would make this a bit easier. Here's how to do this manually:

1. Install the nginx package
2. Get the mappings included with the package: `GET /_component_template/logs-nginx.access@package`
3. Copy the output into your favorite text editor, search for each `"type": "long"` and `"type": "double"` and add `"index": false`
5. Update the custom component template with the new mappings. For example, here's how to set the long fields to `index: false`
```
PUT /_component_template/merics-nginx.substatus@custom
{
  "template": {
    "settings": {},
    "mappings": {
      "properties": {
        "nginx": {
          "properties": {
            "stubstatus": {
              "properties": {
                "hostname": {
                  "ignore_above": 1024,
                  "type": "keyword"
                },
                "current": {
                  "type": "long",
                  "index": false
                },
                "waiting": {
                  "type": "long",
                  "index": false
                },
                "accepts": {
                  "type": "long",
                  "index": false
                },
                "handled": {
                  "type": "long",
                  "index": false
                },
                "writing": {
                  "type": "long",
                  "index": false
                },
                "dropped": {
                  "type": "long",
                  "index": false
                },
                "active": {
                  "type": "long",
                  "index": false
                },
                "reading": {
                  "type": "long",
                  "index": false
                },
                "requests": {
                  "type": "long",
                  "index": false
                }
              }
            }
          }
        }
      }
    }
  },
  "_meta": {
    "package": {
      "name": "nginx"
    }
  }
}
```
6. If a data stream already existed, rollover the data stream to get the new mappings: `POST metrics-nginx.substatus-default/_rollover`

### Time-series indexing (TSDB) - not GA

- Background: https://github.com/elastic/elasticsearch/issues/74660
- Integrations support: https://github.com/elastic/package-spec/issues/311

Usage of TSDB indexing requires the following:
- Mapping parameters must be added for `time_series_dimension` and `time_series_metric` on appropriate fields. This is already supported by the package ecosystem and Fleet, so packages can already define these options.
- The `mode: time_series` and `routing_path` index settings must be added, this can be done by editing the custom component template.

Note that the `routing_path` setting should correspond to fields with `time_series_dimension` specified. In the future, ES may automate this setting.

1. Install the kubernetes package (already has TSDB mappings set up)
2. Run this dev tools command:
```
PUT /_component_template/metrics-kubernetes.pod@custom
{
  "template": {
    "settings": {
      "index.mode": "time_series",
      "index.routing_path": ["kubernetes.pod.uid"]
    },
    "mappings": {}
  },
  "_meta": {
    "package": {
      "name": "kubernetes"
    }
  }
}
```
3. If a data stream already existed, rollover the data stream to get the new mappings: `POST metrics-kubernetes.pod-default/_rollover`
