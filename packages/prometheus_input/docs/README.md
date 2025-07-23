# Prometheus Input Package

The Prometheus Input package allows you to collect metrics from [Prometheus Exporters (Collectors)](https://prometheus.io/docs/instrumenting/exporters/) and gives you the flexibility to add custom mappings and ingest pipelines.

## Metrics

#### Collect metrics from a Prometheus exporter

To collect metrics from a Prometheus exporter, configure the `hosts` setting to it and append the <metrics_path> from which you are collecting your metrics, using the following format: 
- `http[s]://<hostname>:<port>/<metrics_path>`

This is an example of host configuration: `http://localhost:9090/metrics`

#### Histograms and types

The parameter `Use Types` (default: `true`) enables a different layout for metrics storage, leveraging Elasticsearch types, including [histograms](https://www.elastic.co/guide/en/elasticsearch/reference/current/histogram.html).

The parameter `Rate Counters` (default: `true`) allows you to calculate a rate out of Prometheus counters. When enabled, integration stores the counter increment since the last collection. This metric provides better aggregation. This parameter can only be enabled in combination with the parameter `Use Types`.

When `Use Types` and `Rate Counters` are enabled, metrics are stored as follows:

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

To filter out/in metrics, you can use the following settings:

```yml
Metrics Filters Include: ["node_filesystem_*"]
Metrics Filters Exclude: ["node_filesystem_device_*"]
```

The configuration above will include only metrics that match `node_filesystem_*` pattern and do not match `node_filesystem_device_*`.

To keep only specific metrics, anchor the start and the end of the regexp of each metric:

- the caret sign `^` matches the beginning of a text
- the dollar sign `$` matches the end of a text

```yml
Metrics Filters Include: ["^node_network_net_dev_group$", "^node_network_up$"]
```

### Datastream dataset name

By using the Prometheus Input Package, you can add your own dataset name, to which the events get added. You can collect Prometheus metrics from different services by adding multiple instances of the Input package. Metrics can be filtered based on the dataset name.
