# Couchbase Integration

## Overview

The Couchbase integration allows you to monitor your Couchbase instance. Couchbase Server is an open-source, distributed multi-model NoSQL document-oriented database software package optimized for interactive applications.

Use the Couchbase integration to collect metrics related to the bucket, cluster, node, and sync gateway. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

For example, you could use the data from this integration to know when there are more than some number of failed authentication requests for a single piece of content in a given time period. You could also use the data to troubleshoot the underlying issue by looking at the documents ingested in Elasticsearch.

## Data streams

The Couchbase integration collects metrics data.

Metrics give you insight into the state of the Couchbase. Metrics data streams collected by the Couchbase integration include [Bucket](https://docs.couchbase.com/server/current/rest-api/rest-buckets-summary.html), [Cluster](https://docs.couchbase.com/server/current/rest-api/rest-cluster-details.html), [Cache](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#cache), [Couchbase Lite Replication](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#cbl_replication_pull), [Database](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#database), [Delta Sync](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#delta_sync), [Eventing](https://developer.couchbase.com/tutorial-monitoring-eventing-service?learningPath=learn/couchbase-monitoring-guide#get-cluster-eventing-service-stats), [GSI views](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#gsi_views), [Import](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#shared_bucket_import), [Index](https://developer.couchbase.com/tutorial-monitoring-index-service#get-cluster-index-service-stats), [Node](https://docs.couchbase.com/server/current/rest-api/rest-cluster-details.html), [Query](https://developer.couchbase.com/tutorial-monitoring-query-service?learningPath=learn/couchbase-monitoring-guide#get-cluster-query-service-stats), [Resource Utilization](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#resource_utilization), [Security](https://docs.couchbase.com/sync-gateway/current/stats-monitoring.html#security), and [XDCR](https://docs.couchbase.com/server/current/rest-api/rest-bucket-stats.html) metrics from [Couchbase](https://www.couchbase.com/) so that the user could monitor and troubleshoot the performance of the Couchbase instances.

This integration uses:
- `http` metricbeat module to collect `bucket`, `cluster`, `eventing`, `index`, `query`, and `xdcr` metrics.
- `httpjson` filebeat input to collect `node` metrics.
- `prometheus` metricbeat module to collect `cache`, `cbl_replication`, `database_stats`, `delta_sync`, `gsi_views`, `import`, `resource`, and `security` metrics.

Note: 
- For Couchbase cluster setup, there is an ideal scenario of a single host with administrator access for the entire cluster to collect metrics. Providing multiple hosts from the same cluster might lead to data duplication. In the case of multiple clusters, adding a new integration to collect data from different cluster hosts is a good option.
- For Couchbase `node` metrics, the metrics would be fetched from the first host only and the rest of the hosts will be ignored.

## Compatibility

This integration has been tested against Couchbase `v6.6`, `v7.0`, and `v7.1`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from Couchbase, you must know the host(s) and the administrator credentials for the Couchbase instance(s).

Host Configuration Format: `http[s]://username:password@host:port`

Example Host Configuration: `http://Administrator:password@localhost:8091`

## Setup

In order to collect data using [Sync Gateway](https://www.couchbase.com/products/sync-gateway), follow the steps given below:
- Download and configure [Sync Gateway](https://docs.couchbase.com/sync-gateway/current/get-started-install.html)
- Download and configure [Sync Gateway Promethus Exporter](https://github.com/couchbaselabs/couchbase-sync-gateway-exporter.git) and provide Sync Gateway Host using --sgw.url flag while running the Exporter App
- Example configuration: `--sgw.url=http://sgw:4985`

## Limitation

For Couchbase `node` metrics, the metrics would be fetched from the first host only and the rest of the hosts will be ignored.

## Metrics reference

### Bucket

This is the `bucket` data stream. A bucket is a logical container for a related set of items such as key-value pairs or documents.

An example event for `bucket` looks as following:

```json
{
    "@timestamp": "2022-09-22T09:52:54.159Z",
    "agent": {
        "ephemeral_id": "7a05dbed-39c2-48ba-a54c-9c08ad6d571a",
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.1"
    },
    "couchbase": {
        "bucket": {
            "data": {
                "used": {
                    "bytes": 103804
                }
            },
            "disk": {
                "fetches": 0,
                "used": {
                    "bytes": 2005443
                }
            },
            "item": {
                "count": 0
            },
            "memory": {
                "used": {
                    "bytes": 28202560
                }
            },
            "name": "beer-sample",
            "operations_per_sec": 0,
            "ram": {
                "quota": {
                    "bytes": 209715200,
                    "used": {
                        "pct": 13.44802856445312
                    }
                }
            },
            "type": "membase"
        }
    },
    "data_stream": {
        "dataset": "couchbase.bucket",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.bucket",
        "duration": 205027230,
        "ingested": "2022-09-22T09:52:57Z",
        "kind": "metric",
        "module": "couchbase",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "51511c1493f34922b559a964798246ec",
        "ip": [
            "192.168.128.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-126-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "json",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_couchbase_1:8091/pools/default/buckets",
        "type": "http"
    },
    "tags": [
        "couchbase-bucket"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| couchbase.bucket.data.used.bytes | Size of user data within buckets of the specified state that are resident in RAM. | long | byte | gauge |
| couchbase.bucket.disk.fetches | Number of disk fetches. | long |  | gauge |
| couchbase.bucket.disk.used.bytes | Amount of disk used (bytes). | long | byte | gauge |
| couchbase.bucket.item.count | Number of items associated with the bucket. | long |  | counter |
| couchbase.bucket.memory.used.bytes | Amount of memory used by the bucket (bytes). | long | byte | gauge |
| couchbase.bucket.name | Name of the bucket. | keyword |  |  |
| couchbase.bucket.operations_per_sec | Number of operations per second. | long |  | gauge |
| couchbase.bucket.ram.quota.bytes | Amount of RAM used by the bucket (bytes). | long | byte | gauge |
| couchbase.bucket.ram.quota.used.pct | Percentage of RAM used (for active objects) against the configured bucket size (%). | scaled_float | percent | gauge |
| couchbase.bucket.type | Type of the bucket. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |


### Cache

This is the `cache` data stream. The cache is hardware or software that is used to store something, usually data, temporarily in a computing environment. These metrics are related to caching in Couchbase.

An example event for `cache` looks as following:

```json
{
    "@timestamp": "2022-09-22T09:57:04.471Z",
    "agent": {
        "ephemeral_id": "21cbbba2-0fd7-4a33-aa1f-b5c9a1d2806f",
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.1"
    },
    "couchbase": {
        "cache": {
            "channel": {
                "count": 0,
                "entries": {
                    "max": 0
                },
                "hits": 0,
                "misses": 0,
                "revisions": {
                    "active": 0,
                    "removal": 0,
                    "tombstone": 0
                }
            },
            "database": {
                "name": "beer-sample"
            },
            "revision": {
                "hits": 0,
                "misses": 0
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.cache",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.cache",
        "duration": 166393581,
        "ingested": "2022-09-22T09:57:06Z",
        "kind": "metric",
        "module": "couchbase",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "51511c1493f34922b559a964798246ec",
        "ip": [
            "192.168.128.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-126-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "server": {
        "address": "elastic-package-service_exporter_1:9421"
    },
    "service": {
        "address": "http://elastic-package-service_exporter_1:9421/metrics",
        "type": "prometheus"
    },
    "tags": [
        "couchbase-cache",
        "prometheus"
    ]
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| container.id | Unique container id. | keyword |  |
| couchbase.cache.channel.count | The total number of channels being cached. | long | gauge |
| couchbase.cache.channel.entries.max | The total size of the largest channel cache. | long | gauge |
| couchbase.cache.channel.hits | The total number of channel cache requests fully served by the cache. | long | counter |
| couchbase.cache.channel.misses | The total number of channel cache requests not fully served by the cache. | long | counter |
| couchbase.cache.channel.revisions.active | The total number of active revisions in the channel cache. | long | gauge |
| couchbase.cache.channel.revisions.removal | The total number of removal revisions in the channel cache. | long | gauge |
| couchbase.cache.channel.revisions.tombstone | The total number of tombstone revisions in the channel cache. | long | gauge |
| couchbase.cache.database.name | The database for which the data is being extracted. | keyword |  |
| couchbase.cache.revision.hits | The total number of revision cache hits. | long | counter |
| couchbase.cache.revision.misses | The total number of revision cache misses. | long | counter |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### Cluster

This is the `cluster` data stream. A cluster is a collection of nodes that are accessed and managed as a single group. Each node is an equal partner in orchestrating the cluster to provide facilities such as operational information (monitoring) or managing cluster membership of nodes and the health of nodes.

An example event for `cluster` looks as following:

```json
{
    "@timestamp": "2022-09-22T10:01:46.548Z",
    "agent": {
        "ephemeral_id": "f85d7474-76e3-4c32-91ea-9697b5c5616c",
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.1"
    },
    "couchbase": {
        "cluster": {
            "buckets": {
                "max": {
                    "count": 30
                }
            },
            "hdd": {
                "free": {
                    "bytes": 29240784815
                },
                "quota": {
                    "total": {
                        "bytes": 104431374336
                    }
                },
                "total": {
                    "bytes": 104431374336
                },
                "used": {
                    "data": {
                        "bytes": 29005976
                    },
                    "value": {
                        "bytes": 75190589521
                    }
                }
            },
            "memory": {
                "quota": {
                    "index": {
                        "mb": 512
                    },
                    "mb": 512
                }
            },
            "ram": {
                "quota": {
                    "total": {
                        "per_node": {
                            "bytes": 536870912
                        },
                        "value": {
                            "bytes": 536870912
                        }
                    },
                    "used": {
                        "per_node": {
                            "bytes": 419430400
                        },
                        "value": {
                            "bytes": 419430400
                        }
                    }
                },
                "total": {
                    "bytes": 12527394816
                },
                "used": {
                    "data": {
                        "bytes": 88818480
                    },
                    "value": {
                        "bytes": 9708548096
                    }
                }
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.cluster",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.cluster",
        "duration": 11570551,
        "ingested": "2022-09-22T10:01:50Z",
        "kind": "metric",
        "module": "couchbase",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "51511c1493f34922b559a964798246ec",
        "ip": [
            "192.168.128.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-126-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "json",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_couchbase_1:8091/pools/default",
        "type": "http"
    },
    "tags": [
        "couchbase-cluster"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| couchbase.cluster.buckets.max.count | Maximum number of buckets. | long |  |  |
| couchbase.cluster.hdd.free.bytes | Free hard drive space in the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.hdd.quota.total.bytes | Hard drive quota total for the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.hdd.total.bytes | Total hard drive space available to the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.hdd.used.data.bytes | Hard drive space used by the data in the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.hdd.used.value.bytes | Hard drive space used by the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.memory.quota.index.mb | Memory quota setting for the Index service (Mbyte). | long | byte | gauge |
| couchbase.cluster.memory.quota.mb | Memory quota setting for the cluster (Mbyte). | long | byte | gauge |
| couchbase.cluster.ram.quota.total.per_node.bytes | RAM quota used by the current node in the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.ram.quota.total.value.bytes | RAM quota total for the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.ram.quota.used.per_node.bytes | Ram quota used by the current node in the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.ram.quota.used.value.bytes | RAM quota used by the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.ram.total.bytes | Total RAM available to cluster (bytes). | long | byte | gauge |
| couchbase.cluster.ram.used.data.bytes | RAM used by the data in the cluster (bytes). | long | byte | gauge |
| couchbase.cluster.ram.used.value.bytes | RAM used by the cluster (bytes). | long | byte | gauge |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |


### Couchbase Lite Replication

This is the `cbl_replication` data stream.

CBL Replication push is a process by which clients upload database changes from the local source database to the remote (server) target database.

CBL Replication pull is a process by which clients download database changes from the remote (server) source database to the local target database.

An example event for `cbl_replication` looks as following:

```json
{
    "@timestamp": "2022-09-22T09:59:52.208Z",
    "agent": {
        "ephemeral_id": "e0442987-7962-4d01-bacb-8c407327e0fd",
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.1"
    },
    "couchbase": {
        "cbl_replication": {
            "database": {
                "name": "beer-sample"
            },
            "pull": {
                "attachment": {
                    "bytes": 0,
                    "count": 0
                },
                "num": {
                    "caught_up": 0,
                    "continuous": {
                        "active": 0,
                        "total": 0
                    },
                    "one_shot": {
                        "active": 0,
                        "total": 0
                    },
                    "since_zero": 0
                },
                "request": {
                    "changes": {
                        "time": 0
                    }
                },
                "rev": {
                    "latency": {
                        "send": 0
                    }
                }
            },
            "push": {
                "attachment": {
                    "bytes": 0,
                    "count": 0
                },
                "conflict": {
                    "write": {
                        "count": 0
                    }
                },
                "doc": {
                    "count": 0
                },
                "propose": {
                    "change": {
                        "count": 0,
                        "time": 0
                    }
                },
                "sync": {
                    "function": {
                        "time": 0
                    }
                },
                "write": {
                    "processing": {
                        "time": 0
                    }
                }
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.cbl_replication",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.cbl_replication",
        "duration": 16495401,
        "ingested": "2022-09-22T09:59:54Z",
        "kind": "metric",
        "module": "couchbase",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "51511c1493f34922b559a964798246ec",
        "ip": [
            "192.168.128.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-126-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "server": {
        "address": "elastic-package-service_exporter_1:9421"
    },
    "service": {
        "address": "http://elastic-package-service_exporter_1:9421/metrics",
        "type": "prometheus"
    },
    "tags": [
        "couchbase-cbl_replication",
        "prometheus"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| couchbase.cbl_replication.database.name | The database for which the data is being extracted. | keyword |  |  |
| couchbase.cbl_replication.pull.attachment.bytes | The total size of attachments pulled. This is the pre-compressed size. | long | byte | counter |
| couchbase.cbl_replication.pull.attachment.count | The total number of attachments pulled. | long |  | counter |
| couchbase.cbl_replication.pull.num.caught_up | The total number of replications which have caught up to the latest changes. | long |  | gauge |
| couchbase.cbl_replication.pull.num.continuous.active | The total number of continuous pull replications in the active state. | long |  | gauge |
| couchbase.cbl_replication.pull.num.continuous.total | The total number of continuous pull replications. | long |  | gauge |
| couchbase.cbl_replication.pull.num.one_shot.active | The total number of one-shot pull replications in the active state. | long |  | gauge |
| couchbase.cbl_replication.pull.num.one_shot.total | The total number of one-shot pull replications. | long |  | gauge |
| couchbase.cbl_replication.pull.num.since_zero | The total number of new replications started (/_changes?since=0). | long |  | counter |
| couchbase.cbl_replication.pull.request.changes.time | The total time taken to perform the requested changes. | scaled_float | s | counter |
| couchbase.cbl_replication.pull.rev.latency.send | The total amount of time between Sync Gateway receiving a request for a revision and that revision being sent. | scaled_float |  | counter |
| couchbase.cbl_replication.push.attachment.bytes | The total number of attachment bytes pushed. | long | byte | counter |
| couchbase.cbl_replication.push.attachment.count | The total number of attachments pushed. | long |  | counter |
| couchbase.cbl_replication.push.conflict.write.count | The total number of writes that left the document in a conflicted state. Includes new conflicts, and mutations that don’t resolve existing conflicts. | long |  | counter |
| couchbase.cbl_replication.push.doc.count | The total number of documents pushed. | long |  | gauge |
| couchbase.cbl_replication.push.propose.change.count | The total number of changes and-or proposeChanges messages processed since node start-up. | long |  | counter |
| couchbase.cbl_replication.push.propose.change.time | The total time spent processing changes and/or proposeChanges messages. | scaled_float | s | counter |
| couchbase.cbl_replication.push.sync.function.time | The total time spent evaluating the sync_function. | scaled_float | s | counter |
| couchbase.cbl_replication.push.write.processing.time | Total time spent processing writes. Measures complete request-to-response time for a write. | scaled_float | s | gauge |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |


### Database Stats

This is the `database_stats` data stream. Database statistics provides stats relative to the database like document writes, read and received.

An example event for `database_stats` looks as following:

```json
{
    "@timestamp": "2022-09-22T10:04:29.529Z",
    "agent": {
        "ephemeral_id": "48f54b0c-9383-4c54-b6e5-569eb9cf91c8",
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.1"
    },
    "couchbase": {
        "database_stats": {
            "database": {
                "name": "beer-sample"
            },
            "dcp": {
                "received": {
                    "time": 565344894604
                }
            },
            "document": {
                "reads": {
                    "blip": 0,
                    "rest": 0
                },
                "writes": 1090
            },
            "replications": {
                "active": 0,
                "total": 0
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.database_stats",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.database_stats",
        "duration": 43035902,
        "ingested": "2022-09-22T10:04:32Z",
        "kind": "metric",
        "module": "couchbase",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "51511c1493f34922b559a964798246ec",
        "ip": [
            "192.168.128.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-126-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "server": {
        "address": "elastic-package-service_exporter_1:9421"
    },
    "service": {
        "address": "http://elastic-package-service_exporter_1:9421/metrics",
        "type": "prometheus"
    },
    "tags": [
        "couchbase-database_stats",
        "prometheus"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| couchbase.database_stats.database.name | The database for which the data is being extracted. | keyword |  |  |
| couchbase.database_stats.dcp.received.time | The time between a document write and that document being received by Sync Gateway over DCP. | long | s | gauge |
| couchbase.database_stats.document.reads.blip | The total number of documents read via Couchbase Lite 2.x replication since Sync Gateway node startup. | long |  | counter |
| couchbase.database_stats.document.reads.rest | The total number of documents read via the REST API since Sync Gateway node startup. | long |  | counter |
| couchbase.database_stats.document.writes | The total number of documents written by any means (replication, rest API interaction or imports) since Sync Gateway node startup. | long |  | counter |
| couchbase.database_stats.replications.active | The total number of active replications. | long |  | gauge |
| couchbase.database_stats.replications.total | The total number of replications created since Sync Gateway node startup. | long |  | counter |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |


### Delta Sync, Import, Security and GSI views

This is the `miscellaneous` data stream.

The Delta Sync provides the ability to replicate only those parts of a Couchbase Mobile document that have changed. 

The import is processed with an admin user context in the Sync Function, similar to writes made through the Sync Gateway Admin API.

The Security metrics give the metrics related to authentication requests such as number of authentication failures and number of access errors.

Global Secondary Indexes (GSI) support queries made by the Query Service.

An example event for `miscellaneous` looks as following:

```json
{
    "@timestamp": "2022-09-22T10:09:47.340Z",
    "agent": {
        "ephemeral_id": "83776be2-5f6a-4a29-a52c-496ade27a500",
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.1"
    },
    "couchbase": {
        "miscellaneous": {
            "database": {
                "name": "beer-sample"
            },
            "delta_sync": {
                "cache": {
                    "hits": 0
                },
                "pull": {
                    "replications": 0
                },
                "push": {
                    "documents": 0
                },
                "requested": 0,
                "sent": 0
            },
            "gsi_views": {
                "access": {
                    "count": 0
                },
                "all_docs": {
                    "count": 0
                },
                "channels": {
                    "count": 0
                },
                "role_access": {
                    "count": 0
                }
            },
            "security": {
                "access": {
                    "errors": {
                        "count": 0
                    }
                },
                "authentications": {
                    "failed": {
                        "count": 0
                    }
                },
                "documents": {
                    "rejected": {
                        "count": 0
                    }
                }
            },
            "shared_bucket": {
                "import": {
                    "documents": {
                        "count": 2215,
                        "errors": {
                            "count": 0
                        }
                    }
                }
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.miscellaneous",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.miscellaneous",
        "duration": 46202229,
        "ingested": "2022-09-22T10:09:50Z",
        "kind": "metric",
        "module": "couchbase",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "51511c1493f34922b559a964798246ec",
        "ip": [
            "192.168.128.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-126-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "server": {
        "address": "elastic-package-service_exporter_1:9421"
    },
    "service": {
        "address": "http://elastic-package-service_exporter_1:9421/metrics",
        "type": "prometheus"
    },
    "tags": [
        "couchbase-miscellaneous",
        "prometheus"
    ]
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| container.id | Unique container id. | keyword |  |
| couchbase.miscellaneous.database.name | The database for which the data is being extracted. | keyword |  |
| couchbase.miscellaneous.delta_sync.cache.hits | The total number of requested deltas that were available in the revision cache. | long | counter |
| couchbase.miscellaneous.delta_sync.pull.replications | The number of delta replications that have been run. | long | counter |
| couchbase.miscellaneous.delta_sync.push.documents | The total number of documents pushed as a delta from a previous revision. | long | counter |
| couchbase.miscellaneous.delta_sync.requested | The total number of times a revision is sent as delta from a previous revision. | long | counter |
| couchbase.miscellaneous.delta_sync.sent | The total number of revisions sent to clients as deltas. | long | counter |
| couchbase.miscellaneous.gsi_views.access.count | The total number of 'access' queries performed. | long | counter |
| couchbase.miscellaneous.gsi_views.all_docs.count | The total number of 'allDocs' queries performed. | long | counter |
| couchbase.miscellaneous.gsi_views.channels.count | The total number of 'channels' queries performed. | long | counter |
| couchbase.miscellaneous.gsi_views.role_access.count | The total number of 'roleAccess' queries performed. | long | counter |
| couchbase.miscellaneous.security.access.errors.count | The total number of documents rejected by write access functions (requireAccess, requireRole, requireUser). | long | counter |
| couchbase.miscellaneous.security.authentications.failed.count | The total number of unsuccessful authentications. | long | counter |
| couchbase.miscellaneous.security.documents.rejected.count | The total number of documents rejected by the sync_function. | long | counter |
| couchbase.miscellaneous.shared_bucket.import.documents.count | The total number of documents imported. | long | counter |
| couchbase.miscellaneous.shared_bucket.import.documents.errors.count | The total number of errors arising as a result of a document import. | long | counter |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### Resource Utilization

This is the `resource` data stream. The Resource Utilization metrics are related to [MemStats](https://golang.org/pkg/runtime/#MemStats) records statistics about the memory allocator.

An example event for `resource` looks as following:

```json
{
    "@timestamp": "2022-09-22T10:23:05.191Z",
    "agent": {
        "ephemeral_id": "b2613a7a-186f-44ff-9a25-ddc0a5ad8e7f",
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.1"
    },
    "couchbase": {
        "resource": {
            "admin_net": {
                "bytes": {
                    "received": 0,
                    "sent": 0
                }
            },
            "error": {
                "count": 0
            },
            "go_memstats": {
                "heap": {
                    "alloc": 0,
                    "idle": 0,
                    "in_use": 0,
                    "released": 0
                },
                "stack": {
                    "in_use": 0
                }
            },
            "last_gc": 1.66,
            "process": {
                "cpu": {
                    "pct": 0
                },
                "memory": {
                    "resident": 0
                }
            },
            "warn": {
                "count": 13
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.resource",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.resource",
        "duration": 8430124,
        "ingested": "2022-09-22T10:23:07Z",
        "kind": "metric",
        "module": "couchbase",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "51511c1493f34922b559a964798246ec",
        "ip": [
            "192.168.128.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-126-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "server": {
        "address": "elastic-package-service_exporter_1:9421"
    },
    "service": {
        "address": "http://elastic-package-service_exporter_1:9421/metrics",
        "type": "prometheus"
    },
    "tags": [
        "couchbase-resource",
        "prometheus"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| couchbase.resource.admin_net.bytes.received | The total number of bytes received (since node start-up) on the network interface to which the Sync Gateway api.admin_interface is bound. | scaled_float | byte | gauge |
| couchbase.resource.admin_net.bytes.sent | The total number of bytes sent (since node start-up) on the network interface to which the Sync Gateway api.admin_interface is bound. | scaled_float | byte | gauge |
| couchbase.resource.error.count | The total number of errors logged. | long |  | counter |
| couchbase.resource.go_memstats.heap.alloc | Bytes of allocated heap objects. | scaled_float | byte | gauge |
| couchbase.resource.go_memstats.heap.idle | Bytes in idle (unused) spans. | scaled_float | byte | gauge |
| couchbase.resource.go_memstats.heap.in_use | Bytes in in-use spans. | scaled_float | byte | gauge |
| couchbase.resource.go_memstats.heap.released | Bytes of physical memory returned to the OS. | scaled_float | byte | gauge |
| couchbase.resource.go_memstats.stack.in_use | Bytes in stack spans. | scaled_float | byte | gauge |
| couchbase.resource.last_gc | The time the last garbage collection finished, as nanoseconds since 1970 (the UNIX epoch). | scaled_float | nanos | gauge |
| couchbase.resource.process.cpu.pct | The CPU’s utilization as percentage value. | scaled_float | percent | gauge |
| couchbase.resource.process.memory.resident | The memory utilization (Resident Set Size) for the process, in bytes. | scaled_float | byte | gauge |
| couchbase.resource.warn.count | The total number of warnings logged. | long |  | counter |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |


### Node

This is the `node` data stream. A Couchbase Server node is a physical or virtual machine that hosts a single instance of Couchbase Server.

An example event for `node` looks as following:

```json
{
    "@timestamp": "2022-10-10T11:34:02.041Z",
    "agent": {
        "ephemeral_id": "f455cc9f-942b-4318-9cb1-a11269a57879",
        "id": "65d42681-92be-4888-9931-ccf1d81228b8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "couchbase": {
        "node": {
            "commands": {
                "get": {
                    "count": 0
                }
            },
            "couch": {
                "docs": {
                    "data_size": {
                        "bytes": 52241687
                    },
                    "disk_size": {
                        "bytes": 80882701
                    }
                },
                "spatial": {
                    "data_size": {
                        "bytes": 0
                    },
                    "disk_size": {
                        "bytes": 0
                    }
                },
                "views": {
                    "data_size": {
                        "bytes": 0
                    },
                    "disk_size": {
                        "bytes": 769568
                    }
                }
            },
            "cpu_utilization_rate": {
                "pct": 74.35661764705883
            },
            "current_items": {
                "total": 70591,
                "value": 70591
            },
            "ep_bg_fetched": 0,
            "get": {
                "hits": 0
            },
            "hostname": "172.29.0.7:8091",
            "memcached": {
                "allocated": {
                    "bytes": 9557
                },
                "reserved": {
                    "bytes": 9557
                }
            },
            "memory": {
                "free": {
                    "bytes": 5373763584
                },
                "total": {
                    "bytes": 12527394816
                },
                "used": {
                    "bytes": 137197744
                }
            },
            "operations": {
                "count": 0
            },
            "swap": {
                "total": {
                    "bytes": 4126142464
                },
                "used": {
                    "bytes": 63963136
                }
            },
            "uptime": {
                "sec": 89
            },
            "vb_replica": {
                "items": {
                    "current": 0
                }
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.node",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "65d42681-92be-4888-9931-ccf1d81228b8",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "created": "2022-10-10T11:34:02.041Z",
        "dataset": "couchbase.node",
        "ingested": "2022-10-10T11:34:05Z",
        "kind": "metric",
        "module": "couchbase",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "couchbase-node"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| couchbase.node.commands.get.count | Number of get commands. | long |  | counter |
| couchbase.node.couch.docs.data_size.bytes | Data size of Couch docs associated with a node (bytes). | long | byte | gauge |
| couchbase.node.couch.docs.disk_size.bytes | Amount of disk space used by Couch docs (bytes). | long | byte | gauge |
| couchbase.node.couch.spatial.data_size.bytes | Size of object data for spatial views (bytes). | long | byte | gauge |
| couchbase.node.couch.spatial.disk_size.bytes | Amount of disk space used by spatial views (bytes). | long | byte | gauge |
| couchbase.node.couch.views.data_size.bytes | Size of object data for Couch views (bytes). | long | byte | gauge |
| couchbase.node.couch.views.disk_size.bytes | Amount of disk space used by Couch views (bytes). | long | byte | gauge |
| couchbase.node.cpu_utilization_rate.pct | The CPU utilization rate (%). | float | percent | gauge |
| couchbase.node.current_items.total | Total number of items associated with the node. | long |  | counter |
| couchbase.node.current_items.value | Number of current items. | long |  | gauge |
| couchbase.node.ep_bg_fetched | Number of disk fetches performed since the server was started. | long |  | counter |
| couchbase.node.get.hits | Number of hits get. | long |  | gauge |
| couchbase.node.hostname | The hostname of the node. | keyword |  |  |
| couchbase.node.memcached.allocated.bytes | Amount of memcached memory allocated (bytes). | long | byte | gauge |
| couchbase.node.memcached.reserved.bytes | Amount of memcached memory reserved (bytes). | long | byte | gauge |
| couchbase.node.memory.free.bytes | Amount of memory free for the node (bytes). | long | byte | gauge |
| couchbase.node.memory.total.bytes | Total memory available to the node (bytes). | long | byte | gauge |
| couchbase.node.memory.used.bytes | Memory used by the node (bytes). | long | byte | gauge |
| couchbase.node.operations.count | Number of operations performed on Couchbase. | long |  | counter |
| couchbase.node.swap.total.bytes | Total swap size allocated (bytes). | long | byte | gauge |
| couchbase.node.swap.used.bytes | Amount of swap space used (bytes). | long | byte | gauge |
| couchbase.node.uptime.sec | Time during which the node was in operation (sec). | long | s | gauge |
| couchbase.node.vb_replica.items.current | Number of items/documents that are replicas. | long |  | gauge |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| input.type | Input type. | keyword |  |  |


### Query Index

This is the `query_index` data stream. The Query service enables you to issue queries to extract data from the Couchbase server. The Index collects statistics provided by the Index service.

An example event for `query_index` looks as following:

```json
{
    "@timestamp": "2022-09-22T10:19:52.007Z",
    "agent": {
        "ephemeral_id": "5028ac11-4e9b-4b17-a5bc-94ed9769b952",
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.1"
    },
    "couchbase": {
        "query_index": {
            "query": {
                "request_time": {
                    "avg": 0.0178967996
                },
                "requests": 2.5,
                "result": {
                    "count": 1.3
                }
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.query_index",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.query_index",
        "duration": 2678413,
        "ingested": "2022-09-22T10:19:52Z",
        "kind": "metric",
        "module": "couchbase",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "51511c1493f34922b559a964798246ec",
        "ip": [
            "192.168.128.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-126-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "json",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_couchbase_1:8091/pools/default/buckets/@eventing/stats",
        "type": "http"
    },
    "tags": [
        "couchbase-query_index"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| couchbase.query_index.eventing.failed.count | Total number of failed eventing function operations. | float |  | gauge |
| couchbase.query_index.query.request_time.avg | Average total request time. | float | s | gauge |
| couchbase.query_index.query.requests | Current number of requests per second. | float |  | gauge |
| couchbase.query_index.query.result.count | Number of results returned. | float |  | gauge |
| couchbase.query_index.ram.pct | The percentage of index entries in ram. | float |  | gauge |
| couchbase.query_index.ram.remaining | The amount of memory remaining. | float |  | gauge |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |


### XDCR

This is the `xdcr` data stream. Cross Data Center Replication (XDCR) replicates data between a source bucket and a target bucket. XDCR collects metrics related to statistics of XDCR. Metrics can be fetched from multiple buckets.

Note: It is preferable to add a new integration if user requires to fetch metrics from multiple hosts for XDCR data stream.

An example event for `xdcr` looks as following:

```json
{
    "@timestamp": "2022-09-22T10:25:44.885Z",
    "agent": {
        "ephemeral_id": "d0773541-caa0-44fc-ae34-779a20df5ccb",
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.1"
    },
    "couchbase": {
        "xdcr": {
            "backoff": 0,
            "bytes": {
                "total": 0
            },
            "count": 2,
            "errors": {
                "out_of_memory": 0
            },
            "items": {
                "remaining": 0,
                "sent": 0
            },
            "producer": {
                "count": 2
            }
        }
    },
    "data_stream": {
        "dataset": "couchbase.xdcr",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e9b62dba-64d7-428d-8d75-88f57c77d423",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "couchbase.xdcr",
        "duration": 3367774988,
        "ingested": "2022-09-22T10:25:49Z",
        "kind": "metric",
        "module": "couchbase",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "51511c1493f34922b559a964798246ec",
        "ip": [
            "192.168.128.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-126-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "json",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_couchbase_1:8091/pools/default/buckets/beer-sample/stats",
        "type": "http"
    },
    "tags": [
        "couchbase-xdcr"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| couchbase.xdcr.backoff | Number of backoffs for XDCR DCP connections. | float |  | gauge |
| couchbase.xdcr.bytes.total | Number of bytes being sent for XDCR DCP connections. | float | byte | gauge |
| couchbase.xdcr.count | Number of internal XDCR DCP connections in specified bucket. | float |  | gauge |
| couchbase.xdcr.errors.out_of_memory | Number of times unrecoverable OOMs(Out Of Memory) happened while processing operations. | float |  | gauge |
| couchbase.xdcr.items.remaining | Number of XDCR items remaining to be sent to consumer in specified bucket. | float |  | gauge |
| couchbase.xdcr.items.sent | Number of XDCR items being sent for a producer for specified bucket. | float |  | gauge |
| couchbase.xdcr.producer.count | Number of XDCR senders for specified bucket. | float |  | gauge |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |

