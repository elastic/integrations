# Prometheus Input Package

This input package can collect metrics from:
- [Prometheus Exporters (Collectors)](#prometheus-exporters-collectors).
It gives users the flexibility to add custom mappings and ingest pipelines.

## Metrics


### Prometheus Exporters (Collectors)

The Prometheus input package connects to the Prometheus server and pulls metrics using the `/metrics` endpoint.

#### Scraping from a Prometheus exporter

To scrape metrics from a Prometheus exporter, configure the `hosts` setting to it. The path
to retrieve the metrics from (`/metrics` by default) can be configured with metrics_path.

#### Histograms and types

`Use Types` parameter (default: `true`) enables a different layout for metrics storage, leveraging Elasticsearch
types, including {{ url "elasticsearch-histograms" "histograms" }}.

`Rate Counters` parameter (default: `true`) enables calculating a rate out of Prometheus counters. When enabled, integration stores
the counter increment since the last collection. This metric should make some aggregations easier and with better
performance. This parameter can only be enabled in combination with `Use Types`.

When `Use Types` and `Rate Counters` are enabled, metrics are stored like this:

```json
{
    "prometheus": {
        "labels": {
            "instance": "172.27.0.2:9090",
            "job": "prometheus"
        },
        "prometheus_target_interval_length_seconds_count": {
            "counter": 1,
            "rate": 0
        },
        "prometheus_target_interval_length_seconds_sum": {
            "counter": 15.000401344,
            "rate": 0
        },
        "prometheus_tsdb_compaction_chunk_range_seconds": {
            "histogram": {
                "values": [50, 300, 1000, 4000, 16000],
                "counts": [10, 2, 34, 7]
            }
        }
    },
}

```

#### Filtering metrics

In order to filter out/in metrics one can make use of `Metrics Filters Include`, `Metrics Filters Exclude` settings:

```yml
Metrics Filters Include: ["node_filesystem_*"]
Metrics Filters Exclude: ["node_filesystem_device_*"]
```

The configuration above will include only metrics that match `node_filesystem_*` pattern and do not match `node_filesystem_device_*`.


To keep only specific metrics, anchor the start and the end of the regexp of each metric:

- the caret ^ matches the beginning of a text
- the dollar $ matches the end of a text

```yml
Metrics Filters Include: ["^node_network_net_dev_group$", "^node_network_up$"]
```

### Datastream Dataset Name
The users of the Prometheus Input Package have the option of adding their own dataset name, to which the events get added. Prometheus Metrics from different services can be collected by adding multiple instances of Input package. The metrics can be filtered on the basis of dataset name.
