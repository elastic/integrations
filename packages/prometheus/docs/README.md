# Prometheus Integration

This integration can collect metrics from:
  - [Prometheus Exporters (Collectors)](#prometheus-exporters-collectors)
  - [Prometheus Server Remote-Write](#prometheus-server-remote-write)
  - [Prometheus Queries (PromQL)](#prometheus-queries-promql)

## Metrics

### Prometheus Exporters (Collectors)

The Prometheus integration `collector` dataset connects to the Prometheus server and pulls metrics using either the `/metrics` endpoint or the [Prometheus Federation API](https://prometheus.io/docs/prometheus/latest/federation/).

#### Scraping from a Prometheus exporter

To scrape metrics from a Prometheus exporter, configure the `hosts` setting to it. The path
to retrieve the metrics from (`/metrics` by default) can be configured with Metrics Path.

#### Histograms and types

`Use Types` parameter (default: true) enables a different layout for metrics storage, leveraging Elasticsearch
types, including [histograms](https://www.elastic.co/guide/en/elasticsearch/reference/current/histogram.html).

`Rate Counters` parameter (default: true) enables calculating a rate out of Prometheus counters. When enabled, Metricbeat stores
the counter increment since the last collection. This metric should make some aggregations easier and with better
performance. This parameter can only be enabled in combination with `Use Types`.

When `Use Types` and `Rate Counters` are enabled, metrics are stored like this:

```json
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

```yml
Metrics Filters Include: ["node_filesystem_*"]
Metrics Filters Exclude: ["node_filesystem_device_*"]
```

The configuration above will include only metrics that match `node_filesystem_*` pattern and do not match `node_filesystem_device_*`.


To keep only specific metrics, anchor the start and the end of the regexp of each metric:

- the caret ^ matches the beginning of a text or line,
- the dollar sign $ matches the end of a text.

```yml
Metrics Filters Include: ["^node_network_net_dev_group$", "^node_network_up$"]
```

An example event for `collector` looks as following:

```json
{
    "@timestamp": "2022-09-21T13:53:53.737Z",
    "ecs": {
        "version": "8.0.0"
    },
    "service": {
        "address": "http://prometheus-server-server:80/metrics",
        "type": "prometheus"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "prometheus.collector"
    },
    "elastic_agent": {
        "id": "68e3d23a-08cd-4477-924b-25f491194aba",
        "version": "8.4.0",
        "snapshot": true
    },
    "host": {},
    "metricset": {
        "period": 10000,
        "name": "collector"
    },
    "prometheus": {
        "prometheus_target_sync_length_seconds": {
            "value": 0.000103602
        },
        "labels": {
            "scrape_job": "kubernetes-services",
            "instance": "prometheus-server-server:80",
            "quantile": "0.5",
            "job": "prometheus"
        }
    },
    "event": {
        "duration": 10509824,
        "agent_id_status": "verified",
        "ingested": "2022-09-21T13:53:54Z",
        "module": "prometheus",
        "dataset": "prometheus.collector"
    }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.labels | Image labels. | object |  |
| container.name | Container name. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.mac | Host mac addresses. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |
| prometheus.\*.counter | Prometheus counter metric | object | counter |
| prometheus.\*.histogram | Prometheus histogram metric | object |  |
| prometheus.\*.rate | Prometheus rated counter metric | object | gauge |
| prometheus.\*.value | Prometheus gauge metric | object | gauge |
| prometheus.labels.\* | Prometheus metric labels | object |  |
| prometheus.labels_fingerprint | Autogenerated ID representing the fingerprint of labels object | keyword |  |
| prometheus.metrics.\* | Prometheus metric | object | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |



### Prometheus Server Remote-Write

The Prometheus `remote_write` can receive metrics from a Prometheus server that
has configured [remote_write](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#remote_write)
setting accordingly, for instance:
```yml
remote_write:
  - url: "http://localhost:9201/write"
```

In Kuberneter additionally should be created a Service resource:
```yml
---
apiVersion: v1
kind: Service
metadata:
  name: elastic-agent
  namespace: kube-system
  labels:
    app: elastic-agent
spec:
  ports:
    - port: 9201
      protocol: TCP
      targetPort: 9201
  selector:
    app: elastic-agent
  sessionAffinity: None
  type: ClusterIP
```
This Service can be used as a `remote_write.url` in Prometheus configuration:
```yml
remote_write:
  - url: "http://elastic-agent.kube-system:9201/write"
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

> TIP: To limit amount of samples that are sent by the Prometheus Server can be used [`write_relabel_configs`](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#remote_write)
configuration. It is a relabeling, that applies to samples before sending them to the remote endpoint. Example:
```
remote_write:
  - url: "http://localhost:9201/write"
    write_relabel_configs:
      - source_labels: [job]
        regex: 'prometheus'
        action: keep
```

Metrics sent to the http endpoint will be put by default under the `prometheus.` prefix with their labels under `prometheus.labels`.
A basic configuration would look like:

```yml
host: "localhost"
port: "9201"
```


Also consider using secure settings for the server, configuring the module with TLS/SSL as shown:

```yml
host: "localhost"
ssl.certificate: "/etc/pki/server/cert.pem"
ssl.key: "/etc/pki/server/cert.key"
port: "9201"
```

and on Prometheus side:

```yml
remote_write:
  - url: "https://localhost:9201/write"
    tls_config:
        cert_file: "/etc/prometheus/my_key.pem"
        key_file: "/etc/prometheus/my_key.key"
        # Disable validation of the server certificate.
        #insecure_skip_verify: true
```

An example event for `remote_write` looks as following:

```json
{
    "agent": {
        "name": "kind-control-plane",
        "id": "af0df4c2-33b7-41fd-8eb5-573376996db2",
        "ephemeral_id": "5c3d912b-9bf3-4747-b784-1f7c275a5979",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "@timestamp": "2022-09-22T12:23:35.757Z",
    "ecs": {
        "version": "8.0.0"
    },
    "service": {
        "type": "prometheus"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "prometheus.remote_write"
    },
    "elastic_agent": {
        "id": "af0df4c2-33b7-41fd-8eb5-573376996db2",
        "version": "8.4.0",
        "snapshot": true
    },
    "host": {},
    "metricset": {
        "name": "remote_write"
    },
    "prometheus": {
        "node_cpu_guest_seconds_total": {
            "rate": 0,
            "counter": 0
        },
        "node_cpu_seconds_total": {
            "rate": 0,
            "counter": 2284.68
        },
        "labels": {
            "app": "prometheus",
            "app_kubernetes_io_managed_by": "Helm",
            "instance": "172.19.0.2:9100",
            "release": "prometheus-server",
            "cpu": "5",
            "heritage": "Helm",
            "mode": "user",
            "node": "kind-control-plane",
            "component": "node-exporter",
            "service": "prometheus-server-node-exporter",
            "namespace": "kube-system",
            "job": "kubernetes-service-endpoints",
            "chart": "prometheus-15.10.1"
        }
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2022-09-22T12:24:16Z",
        "module": "prometheus",
        "dataset": "prometheus.remote_write"
    }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.labels | Image labels. | object |  |
| container.name | Container name. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.mac | Host mac addresses. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |
| prometheus.\*.counter | Prometheus counter metric | object | counter |
| prometheus.\*.histogram | Prometheus histogram metric | object |  |
| prometheus.\*.rate | Prometheus rated counter metric | object | gauge |
| prometheus.\*.value | Prometheus gauge metric | object | gauge |
| prometheus.labels.\* | Prometheus metric labels | object |  |
| prometheus.labels_fingerprint | Autogenerated ID representing the fingerprint of all labels and the list of metrics names | keyword |  |
| prometheus.metrics.\* | Prometheus metric | object | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


#### Histograms and types

`use_types` parameter (default: true) enables a different layout for metrics storage, leveraging Elasticsearch
types, including [histograms](https://www.elastic.co/guide/en/elasticsearch/reference/current/histogram.html).

`rate_counters` parameter (default: true) enables calculating a rate out of Prometheus counters. When enabled, Metricbeat stores
the counter increment since the last collection. This metric should make some aggregations easier and with better
performance. This parameter can only be enabled in combination with `use_types`.

`period` parameter (default: 60s) configures the timeout of internal cache, which stores counter values in order to calculate rates between consecutive fetches. The parameter will be validated and all values lower than 60sec will be reset to the default value.

Note that by default prometheus pushes data with the interval of 60s (in remote write). In case that prometheus push rate is changed, the `period` parameter needs to be configured accordingly.

When `use_types` and `rate_counters` are enabled, metrics are stored like this:

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
        }
        "prometheus_tsdb_compaction_chunk_range_seconds_bucket": {
            "histogram": {
                "values": [50, 300, 1000, 4000, 16000],
                "counts": [10, 2, 34, 7]
            }
        }
    },
}
```

#### Types' patterns

Unlike `collector` metricset, `remote_write` receives metrics in raw format from the prometheus server.
In this, the module has to internally use a heuristic in order to identify efficiently the type of each raw metric.
For these purpose some name patterns are used in order to identify the type of each metric.
The default patterns are the following:

. `_total` suffix: the metric is of Counter type
. `_sum` suffix: the metric is of Counter type
. `_count` suffix: the metric is of Counter type
. `_bucket` suffix and `le` in labels: the metric is of Histogram type

Everything else is handled as a Gauge. In addition there is no special handling for Summaries so it is expected that
Summary's quantiles are handled as Gauges and Summary's sum and count as Counters.

Users have the flexibility to add their own patterns using the following configuration:

```yml
types_patterns:
    counter_patterns: ["_my_counter_suffix"]
    histogram_patterns: ["_my_histogram_suffix"]
```

The configuration above will consider metrics with names that match `_my_counter_suffix` as Counters
and those that match `_my_histogram_suffix` (and have `le` in their labels) as Histograms.


To match only specific metrics, anchor the start and the end of the regexp of each metric:

- the caret `^` matches the beginning of a text or line,
- the dollar sign `$` matches the end of a text.

```yml
types_patterns:
    histogram_patterns: ["^my_histogram_metric$"]
```

Note that when using `types_patterns`, the provided patterns have higher priority than the default patterns.
For instance if `_histogram_total` is a defined histogram pattern, then a metric like `network_bytes_histogram_total`
will be handled as a histogram, even if it has the suffix `_total` which is a default pattern for counters.

### Prometheus Queries (PromQL)

The Prometheus `query` dataset executes specific Prometheus queries against [Promethes Query API](https://prometheus.io/docs/prometheus/latest/querying/api/#expression-queries).

#### Instant queries

The following configuration performs an instant query for `up` metric at a single point in time:
```yml
queries:
- name: 'up'
  path: '/api/v1/query'
  params:
    query: "up"
```


More complex PromQL expressions can also be used like the following one which calculates the per-second rate of HTTP
requests as measured over the last 5 minutes.
```yml
queries:
- name: "rate_http_requests_total"
  path: "/api/v1/query"
  params:
    query: "rate(prometheus_http_requests_total[5m])"
```

#### Range queries


The following example evaluates the expression `up` over a 30-second range with a query resolution of 15 seconds:
```yml
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

```json
{
    "agent": {
        "name": "kind-control-plane",
        "id": "68e3d23a-08cd-4477-924b-25f491194aba",
        "type": "metricbeat",
        "ephemeral_id": "63ab98c3-c4ae-4a30-84f9-9a2d7f459728",
        "version": "8.4.0"
    },
    "@timestamp": "2022-09-21T14:06:49.000Z",
    "ecs": {
        "version": "8.0.0"
    },
    "service": {
        "address": "http://prometheus-server-server:80",
        "type": "prometheus"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "prometheus.query"
    },
    "elastic_agent": {
        "id": "68e3d23a-08cd-4477-924b-25f491194aba",
        "version": "8.4.0",
        "snapshot": true
    },
    "host": {},
    "metricset": {
        "period": 10000,
        "name": "query"
    },
    "prometheus": {
        "query": {
            "instant_vector": 0.7838951248394681
        },
        "labels": {}
    },
    "event": {
        "duration": 1153570,
        "agent_id_status": "verified",
        "ingested": "2022-09-21T14:06:50Z",
        "module": "prometheus",
        "dataset": "prometheus.query"
    }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.labels | Image labels. | object |  |
| container.name | Container name. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.mac | Host mac addresses. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |
| prometheus.labels.\* | Prometheus metric labels | object |  |
| prometheus.labels_fingerprint | Autogenerated ID representing the fingerprint of labels object and includes query name | keyword |  |
| prometheus.query.\* | Prometheus value resulted from PromQL | object | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


## Dashboard

Prometheus integration is shipped including default overview dashboard.
Default dashboard works only for `remote_write` datastream and `collector` datastream, if metrics are scraped from the Prometheus server metrics endpoint.
