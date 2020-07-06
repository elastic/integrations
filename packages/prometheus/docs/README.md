# Prometheus Integration

This integration periodically fetches metrics from [Prometheus](https://prometheus.io/) servers.
This integration can collect metrics from Prometheus Exporters, receive metrics from Prometheus using Remote Write
and execute specific Prometheus queries against Promethes Query API.

## Metrics

### Collector Metrics

The Prometheus `collector` dataset scrapes data from [prometheus exporters](https://prometheus.io/docs/instrumenting/exporters/).

#### Scraping from a Prometheus exporter

To scrape metrics from a Prometheus exporter, configure the `hosts` setting to it. The path
to retrieve the metrics from (`/metrics` by default) can be configured with Metrics Path.

#### Histograms and types [x-pack]

`Use Types` paramater (default: false) enables a different layout for metrics storage, leveraging Elasticsearch
types, including [histograms](https://www.elastic.co/guide/en/elasticsearch/reference/current/histogram.html).

`Rate Counters` paramater (default: false) enables calculating a rate out of Prometheus counters. When enabled, Metricbeat stores
the counter increment since the last collection. This metric should make some aggregations easier and with better
performance. This parameter can only be enabled in combination with `Use Types`.

When `Use Types` and `Rate Counters` are enabled, metrics are stored like this:

```$json
{
  "_index": ".ds-metrics-prometheus.collector-default-000001",
  "_id": "JlK9AHMBeyDc0b9rCwVA",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-29T15:40:55.028Z",
    "prometheus": {
      "labels": {
        "slice": "inner_eval",
        "instance": "localhost:9090",
        "job": "prometheus"
      },
      "prometheus_engine_query_duration_seconds_sum": {
        "counter": 0.002697546,
        "rate": 0.00006945900000000001
      },
      "prometheus_engine_query_duration_seconds_count": {
        "rate": 1,
        "counter": 37
      }
    },
    "dataset": {
      "type": "metrics",
      "name": "prometheus.collector",
      "namespace": "default"
    },
    "agent": {
      "ephemeral_id": "98420e91-ee6d-4883-8ad3-02fa8d47f5c1",
      "id": "9fc3e975-6789-4738-a11a-ba7108b0a92c",
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "module": "prometheus",
      "duration": 15397122,
      "dataset": "prometheus.collector"
    },
    "metricset": {
      "period": 10000,
      "name": "collector"
    },
    "service": {
      "address": "localhost:9090",
      "type": "prometheus"
    },
    "stream": {
      "namespace": "default",
      "type": "metrics",
      "dataset": "prometheus.collector"
    },
    "host": {},
  },
  "fields": {
    "@timestamp": [
      "2020-06-29T15:40:55.028Z"
    ]
  },
  "highlight": {
    "event.dataset": [
      "@kibana-highlighted-field@prometheus.collector@/kibana-highlighted-field@"
    ]
  },
  "sort": [
    1593445255028
  ]
}
```

#### Scraping all metrics from a Prometheus server

We recommend using the Remote Write dataset for this, and make Prometheus push metrics to Agent.


#### Filtering metrics

In order to filter out/in metrics one can make use of `Metrics Filters Include`, `Metrics Filters Exclude` settings:

```$yml
Metrics Filters Include: ["node_filesystem_*"]
Metrics Filters Exclude: ["node_filesystem_device_*"]
```

The configuration above will include only metrics that match `node_filesystem_*` pattern and do not match `node_filesystem_device_*`.


To keep only specific metrics, anchor the start and the end of the regexp of each metric:

- the caret ^ matches the beginning of a text or line,
- the dollar sign $ matches the end of a text.

```$yml
Metrics Filters Include: ["^node_network_net_dev_group$", "^node_network_up$"]
```

An example event for `collector` looks as following:

```$json
{
  "_id": "xhalI3MBp-HYgBGo7zEW",
  "_index": ".ds-metrics-prometheus.collector-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-07-06T10:22:23.034Z",
    "agent": {},
    "dataset": {
      "name": "prometheus.collector",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "prometheus.collector",
      "duration": 13290705,
      "module": "prometheus"
    },
    "host": {},
    "metricset": {
      "name": "collector",
      "period": 10000
    },
    "prometheus": {
      "labels": {
        "consumer": "ee9cb2",
        "instance": "localhost:9090",
        "job": "prometheus",
        "type": "series"
      },
      "metrics": {
        "prometheus_wal_watcher_records_read_total": 74
      }
    },
    "service": {
      "address": "localhost:9090",
      "type": "prometheus"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-07-06T10:22:23.034Z"
    ]
  },
  "highlight": {
    "event.dataset": [
      "@kibana-highlighted-field@prometheus.collector@/kibana-highlighted-field@"
    ]
  },
  "sort": [
    1594030943034
  ]
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| prometheus.labels.* | Prometheus metric labels | object |
| prometheus.metrics.* | Prometheus metric | object |



### Remote Write Metrics

The Prometheus `remote_write` can receive metrics from a Prometheus server that
has configured [remote_write](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#remote_write)
setting accordingly, for instance:

```$yml
remote_write:
  - url: "http://localhost:9201/write"
```


> TIP: In order to assure the health of the whole queue, the following configuration
 [parameters](https://prometheus.io/docs/practices/remote_write/#parameters) should be considered:

- `max_shards`: Sets the maximum number of parallelism with which Prometheus will try to send samples to Metricbeat.
It is recommended that this setting should be equal to the number of cores of the machine where Metricbeat runs.
Metricbeat can handle connections in parallel and hence setting `max_shards` to the number of parallelism that
Metricbeat can actually achieve is the optimal queue configuration.
- `max_samples_per_send`: Sets the number of samples to batch together for each send. Recommended values are
between 100 (default) and 1000. Having a bigger batch can lead to improved throughput and in more efficient
storage since Metricbeat groups metrics with the same labels into same event documents.
However this will increase the memory usage of Metricbeat.
- `capacity`: It is recommended to set capacity to 3-5 times `max_samples_per_send`.
Capacity sets the number of samples that are queued in memory per shard, and hence capacity should be high enough so as to
be able to cover `max_samples_per_send`.


Metrics sent to the http endpoint will be put by default under the `prometheus.metrics` prefix with their labels under `prometheus.labels`.
A basic configuration would look like:

```$yml
host: "localhost"
port: "9201"
```


Also consider using secure settings for the server, configuring the module with TLS/SSL as shown:

```$yml
host: "localhost"
ssl.certificate: "/etc/pki/server/cert.pem"
ssl.key: "/etc/pki/server/cert.key"
port: "9201"
```

and on Prometheus side:

```$yml
remote_write:
  - url: "https://localhost:9201/write"
    tls_config:
        cert_file: "/etc/prometheus/my_key.pem"
        key_file: "/etc/prometheus/my_key.key"
        # Disable validation of the server certificate.
        #insecure_skip_verify: true
```

An example event for `remote_write` looks as following:

```$json
{
  "_id": "dJf5AHMBA2PIMpu1O4DQ",
  "_index": ".ds-metrics-prometheus.remote_write-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-29T16:46:40.018Z",
    "agent": {
      "ephemeral_id": "cb348102-0121-4c5b-8fcd-10ea27d25f77",
      "id": "3bdc7670-9ced-4c70-bba9-00d7e183ae4b",
      "name": "Christoss-MBP",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "prometheus.remote_write",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "prometheus.remote_write",
      "module": "prometheus"
    },
    "host": {},
    "metricset": {
      "name": "remote_write"
    },
    "prometheus": {
      "labels": {
        "id": "/systemreserved/acpid",
        "instance": "cadvisor:8080",
        "job": "cadvisor"
      },
      "metrics": {
        "container_fs_reads_bytes_total": 1196032,
        "container_fs_reads_total": 27
      }
    },
    "service": {
      "type": "prometheus"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-29T16:46:40.018Z"
    ]
  },
  "sort": [
    1593449200018
  ]
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| prometheus.labels.* | Prometheus metric labels | object |
| prometheus.metrics.* | Prometheus metric | object |



### Query Metrics

The Prometheus `query` dataset to query from [querying API of Prometheus](https://prometheus.io/docs/prometheus/latest/querying/api/#expression-queries).

#### Instant queries

The following configuration performs an instant query for `up` metric at a single point in time:
```$yml
queries:
- name: 'up'
  path: '/api/v1/query'
  params:
    query: "up"
```


More complex PromQL expressions can also be used like the following one which calculates the per-second rate of HTTP
requests as measured over the last 5 minutes.
```$yml
queries:
- name: "rate_http_requests_total"
  path: "/api/v1/query"
  params:
    query: "rate(prometheus_http_requests_total[5m])"
```

#### Range queries


The following example evaluates the expression `up` over a 30-second range with a query resolution of 15 seconds:
```$yml
queries:
- name: "up_master"
  path: "/api/v1/query_range"
  params:
    query: "up{node='master01'}"
    start: "2019-12-20T23:30:30.000Z"
    end: "2019-12-21T23:31:00.000Z"
    step: 15s
```

An example event for `query` looks as following:

```$json
{
  "_id": "IlG5AHMBeyDc0b9rYc28",
  "_index": ".ds-metrics-prometheus.query-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-29T15:36:54.000Z",
    "agent": {
      "ephemeral_id": "98420e91-ee6d-4883-8ad3-02fa8d47f5c1",
      "id": "9fc3e975-6789-4738-a11a-ba7108b0a92c",
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "prometheus.query",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "prometheus.query",
      "duration": 2123733,
      "module": "prometheus"
    },
    "host": {},
    "metricset": {
      "name": "query",
      "period": 10000
    },
    "prometheus": {
      "labels": {},
      "query": {
        "prometheus_http_requests_total_rate": 0.3818181818181818
      }
    },
    "service": {
      "address": "localhost:9090",
      "type": "prometheus"
    },
    "stream": {
      "dataset": "prometheus.query",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-29T15:36:54.000Z"
    ]
  },
  "highlight": {
    "event.dataset": [
      "@kibana-highlighted-field@prometheus.query@/kibana-highlighted-field@"
    ]
  },
  "sort": [
    1593445014000
  ]
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| prometheus.labels.* | Prometheus metric labels | object |
| prometheus.query.* | Prometheus value resulted from PromQL | object |
