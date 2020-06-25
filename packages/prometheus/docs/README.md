# Prometheus Integration

This integration periodically fetches metrics from [Prometheus](https://prometheus.io/) servers.
This integration can collect metrics from Prometheus Exporters, receive metrics from Prometheus using Remote Write
and execute specific Prometheus queries again Promethes Query API.

## Metrics

### Collector Metrics

The Prometheus `collector` dataset scrapes data from [prometheus exporters](https://prometheus.io/docs/instrumenting/exporters/).

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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| prometheus. |  | keyword |
| prometheus.labels.* | Prometheus metric labels | object |
| prometheus.metrics.* | Prometheus metric | object |
| prometheus.query.* | Prometheus value resulted from PromQL | object |



### Remote Write Metrics

The Prometheus `remote_write` can receive metrics from a Prometheus server that
has configured [remote_write](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#remote_write)
setting accordingly.

An example event for `remote_write` looks as following:

```$json
{
    "@timestamp": "2020-02-28T13:55:37.221Z",
    "@metadata": {
        "beat": "metricbeat",
        "type": "_doc",
        "version": "8.0.0"
    },
    "service": {
        "type": "prometheus"
    },
    "agent": {
        "version": "8.0.0",
        "type": "metricbeat",
        "ephemeral_id": "ead09243-0aa0-4fd2-8732-1e09a6d36338",
        "hostname": "host1",
        "id": "bd12ee45-881f-48e4-af20-13b139548607"
    },
    "ecs": {
        "version": "1.4.0"
    },
    "host": {},
    "event": {
        "dataset": "prometheus.remote_write",
        "module": "prometheus"
    },
    "metricset": {
        "name": "remote_write"
    },
    "prometheus": {
        "metrics": {
            "container_tasks_state": 0
        },
        "labels": {
            "name": "nodeexporter",
            "id": "/docker/1d6ec1931c9b527d4fe8e28d9c798f6ec612f48af51949f3219b5ca77e120b10",
            "container_label_com_docker_compose_oneoff": "False",
            "instance": "cadvisor:8080",
            "container_label_com_docker_compose_service": "nodeexporter",
            "state": "iowaiting",
            "monitor": "docker-host-alpha",
            "container_label_com_docker_compose_project": "dockprom",
            "job": "cadvisor",
            "image": "prom/node-exporter:v0.18.1",
            "container_label_maintainer": "The Prometheus Authors <prometheus-developers@googlegroups.com>",
            "container_label_com_docker_compose_config_hash": "2cc2fedf6da5ff0996a209d9801fb74962a8f4c21e44be03ed82659817d9e7f9",
            "container_label_com_docker_compose_version": "1.24.1",
            "container_label_com_docker_compose_container_number": "1",
            "container_label_org_label_schema_group": "monitoring"
        }
    }
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
| prometheus.query.* | Prometheus value resulted from PromQL | object |



### Query Metrics

The Prometheus `query` dataset to query from [querying API of Prometheus](https://prometheus.io/docs/prometheus/latest/querying/api/#expression-queries).

An example event for `query` looks as following:

```$json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "event": {
        "dataset": "prometheus.query",
        "duration": 115000,
        "module": "prometheus"
    },
    "metricset": {
        "name": "query",
        "period": 10000
    },
    "prometheus": {
        "labels": {
            "__name__": "go_threads",
            "instance": "localhost:9090",
            "job": "prometheus"
        },
        "query": {
            "go_threads": 18
        }
    },
    "service": {
        "address": "localhost:32769",
        "type": "prometheus"
    }
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
| prometheus.query.* | Prometheus value resulted from PromQL | object |
