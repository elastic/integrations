# Prometheus Integration

This integration periodically fetches metrics from [Prometheus](https://prometheus.io/) servers.
This integration can collect metrics from Prometheus Exporters, receive metrics from Prometheus using Remote Write
and execute specific Prometheus queries again Promethes Query API.

## Metrics

### Collector Metrics

The Prometheus `collector` dataset scrapes data from [prometheus exporters](https://prometheus.io/docs/instrumenting/exporters/).

#### Scraping from a Prometheus exporter

To scrape metrics from a Prometheus exporter, configure the `hosts` field to it. The path
to retrieve the metrics from (`/metrics` by default) can be configured with `metrics_path`.

```$yml
period: 10s
hosts: ["node:9100"]
metrics_path: /metrics

#username: "user"
#password: "secret"

# This can be used for service account based authorization:
#bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
#ssl.certificate_authorities:
#  - /var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt
```


#### Histograms and types [x-pack]


```$yml
period: 10s
hosts: ["localhost:9090"]
use_types: true
rate_counters: true
```

`use_types` paramater (default: false) enables a different layout for metrics storage, leveraging Elasticsearch
types, including [histograms](https://www.elastic.co/guide/en/elasticsearch/reference/current/histogram.html).

`rate_counters` paramater (default: false) enables calculating a rate out of Prometheus counters. When enabled, Metricbeat stores
the counter increment since the last collection. This metric should make some aggregations easier and with better
performance. This parameter can only be enabled in combination with `use_types`.

When `use_types` and `rate_counters` are enabled, metrics are stored like this:

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
    "host": {
      "name": "minikube",
      "hostname": "minikube",
      "architecture": "x86_64",
      "os": {
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
      "ip": [
        "192.168.64.10",
        "fe80::a883:2fff:fe7f:6b12",
        "172.17.0.1"
      ],
      "mac": [
        "aa:83:2f:7f:6b:12",
        "02:42:14:e3:dc:1d"
      ]
    }
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

> ⚠️
Depending on your scale this method may not be suitable. We recommend using the
remote_write dataset for this, and make Prometheus push metrics to Agent.

This module can scrape all metrics stored in a Prometheus server, by using the
[federation API](https://prometheus.io/docs/prometheus/latest/federation/). By pointing this
config to the Prometheus server:

```$yml
  period: 10s
  hosts: ["localhost:9090"]
  metrics_path: '/federate'
  query:
    'match[]': '{__name__!=""}'
```


#### Filtering metrics

In order to filter out/in metrics one can make use of `metrics_filters.include` `metrics_filters.exclude` settings:

```$yml
hosts: ["localhost:9090"]
metrics_path: /metrics
metrics_filters:
    include: ["node_filesystem_*"]
    exclude: ["node_filesystem_device_*"]
```

The configuration above will include only metrics that match `node_filesystem_*` pattern and do not match `node_filesystem_device_*`.


To keep only specific metrics, anchor the start and the end of the regexp of each metric:

- the caret ^ matches the beginning of a text or line,
- the dollar sign $ matches the end of a text.

```$yml
hosts: ["localhost:9090"]
metrics_path: /metrics
metrics_filters:
    include: ["^node_network_net_dev_group$", "^node_network_up$"]
```


An example event for `collector` looks as following:

```$json
{
    "@timestamp": "2019-03-01T08:05:34.853Z",
    "event": {
        "dataset": "prometheus.collector",
        "duration": 115000,
        "module": "prometheus"
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "prometheus": {
        "labels": {
            "job": "prometheus",
            "listener_name": "http"
        },
        "metrics": {
            "net_conntrack_listener_conn_accepted_total": 3,
            "net_conntrack_listener_conn_closed_total": 0
        }
    },
    "service": {
        "address": "127.0.0.1:55555",
        "type": "prometheus"
    }
}
```

The fields reported are:

{{fields "collector"}}


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
  "_index": ".ds-metrics-prometheus.remote_write-default-000001",
  "_id": "dJf5AHMBA2PIMpu1O4DQ",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-29T16:46:40.018Z",
    "ecs": {
      "version": "1.5.0"
    },
    "host": {
      "architecture": "x86_64",
      "os": {
        "name": "Mac OS X",
        "kernel": "18.7.0",
        "build": "18G95",
        "platform": "darwin",
        "version": "10.14.6",
        "family": "darwin"
      },
      "id": "883134FF-0EC4-5E1B-9F9E-FD06FB681D84",
      "ip": [
        "fe80::aede:48ff:fe00:1122",
        "fe80::cce:4e5b:69eb:892b",
        "2a02:587:a035:997d:14bc:cf14:23aa:e402",
        "2a02:587:a035:997d:e85f:6b25:8c74:f991",
        "192.168.1.7",
        "fe80::24b8:6bff:fe93:e156",
        "fe80::cc22:c485:38b6:5929",
        "192.168.64.1"
      ],
      "mac": [
        "ac:de:48:00:11:22",
        "a6:83:e7:8c:c8:7b",
        "a4:83:e7:8c:c8:7b",
        "06:83:e7:8c:c8:7b",
        "26:b8:6b:93:e1:56",
        "ca:00:5c:62:81:01",
        "ca:00:5c:62:81:00",
        "ca:00:5c:62:81:05",
        "ca:00:5c:62:81:04",
        "ca:00:5c:62:81:01",
        "0a:00:27:00:00:00",
        "3a:76:9f:5d:69:a5",
        "ae:de:48:00:33:64"
      ],
      "hostname": "Christoss-MBP",
      "name": "Christoss-MBP"
    },
    "agent": {
      "version": "8.0.0",
      "ephemeral_id": "cb348102-0121-4c5b-8fcd-10ea27d25f77",
      "id": "3bdc7670-9ced-4c70-bba9-00d7e183ae4b",
      "name": "Christoss-MBP",
      "type": "metricbeat"
    },
    "metricset": {
      "name": "remote_write"
    },
    "prometheus": {
      "metrics": {
        "container_fs_reads_bytes_total": 1196032,
        "container_fs_reads_total": 27
      },
      "labels": {
        "instance": "cadvisor:8080",
        "job": "cadvisor",
        "id": "/systemreserved/acpid"
      }
    },
    "service": {
      "type": "prometheus"
    },
    "event": {
      "dataset": "prometheus.remote_write",
      "module": "prometheus"
    },
    "dataset": {
      "type": "metrics",
      "name": "prometheus.remote_write",
      "namespace": "default"
    }
  },
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

{{fields "remote_write"}}


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
  "_index": ".ds-metrics-prometheus.query-default-000001",
  "_id": "IlG5AHMBeyDc0b9rYc28",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-29T15:36:54.000Z",
    "host": {
      "os": {
        "kernel": "4.19.81",
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
      "ip": [
        "192.168.64.10",
        "fe80::b8dd:15ff:feb0:528d",
        "172.18.0.1",
      ],
      "mac": [
        "aa:83:2f:7f:6b:12",
        "02:42:14:e3:dc:1d",
      ],
      "hostname": "minikube",
      "architecture": "x86_64",
      "name": "minikube"
    },
    "agent": {
      "type": "metricbeat",
      "version": "8.0.0",
      "ephemeral_id": "98420e91-ee6d-4883-8ad3-02fa8d47f5c1",
      "id": "9fc3e975-6789-4738-a11a-ba7108b0a92c",
      "name": "minikube"
    },
    "event": {
      "module": "prometheus",
      "duration": 2123733,
      "dataset": "prometheus.query"
    },
    "metricset": {
      "name": "query",
      "period": 10000
    },
    "dataset": {
      "type": "metrics",
      "name": "prometheus.query",
      "namespace": "default"
    },
    "stream": {
      "dataset": "prometheus.query",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "service": {
      "address": "localhost:9090",
      "type": "prometheus"
    },
    "prometheus": {
      "labels": {},
      "query": {
        "prometheus_http_requests_total_rate": 0.3818181818181818
      }
    }
  },
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

{{fields "query"}}