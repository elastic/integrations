# Compute

## Metrics

The `compute` dataset is designed to fetch metrics for [Compute Engine](https://cloud.google.com/compute/) Virtual Machines in Google Cloud Platform. It contains all metrics exported from the [GCP Cloud Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-compute).

Extra labels and metadata are also extracted using the [Compute API](https://cloud.google.com/compute/docs/reference/rest/v1/instances/get). This is enough to get most of the info associated with a metric like Compute labels and metadata and metric specific Labels.

## Sample Event

An example event for `compute` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev",
            "name": "elastic-obs-integrations-dev"
        },
        "instance": {
            "id": "4751091017865185079",
            "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
        },
        "machine": {
            "type": "e2-medium"
        },
        "provider": "gcp",
        "availability_zone": "us-central1-c",
        "region": "us-central1"
    },
    "event": {
        "dataset": "gcp.compute",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "compute": {
            "firewall": {
                "dropped": {
                    "bytes": 421
                },
                "dropped_packets_count": {
                    "value": 4
                }
            },
            "instance": {
                "cpu": {
                    "reserved_cores": {
                        "value": 1
                    },
                    "usage": {
                        "pct": 0.07259952346383708
                    },
                    "usage_time": {
                        "sec": 4.355971407830225
                    }
                },
                "memory": {
                    "balloon": {
                        "ram_size": {
                            "value": 4128378880
                        },
                        "ram_used": {
                            "value": 2190848000
                        },
                        "swap_in": {
                            "bytes": 0
                        },
                        "swap_out": {
                            "bytes": 0
                        }
                    }
                },
                "uptime": {
                    "sec": 60.00000000000091
                }
            }
        },
        "labels": {
            "user": {
                "goog-gke-node": ""
            }
        }
    },
    "host": {
        "id": "4751091017865185079",
        "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
    },
    "metricset": {
        "name": "compute",
        "period": 10000
    },
    "service": {
        "type": "gcp"
    }
}
```

## Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |
| error.message | Error message. | match_only_text |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gcp.compute.firewall.dropped.bytes | Incoming bytes dropped by the firewall | long |
| gcp.compute.firewall.dropped_packets_count.value | Incoming packets dropped by the firewall | long |
| gcp.compute.instance.cpu.reserved_cores.value | Number of cores reserved on the host of the instance | double |
| gcp.compute.instance.cpu.usage.pct | The fraction of the allocated CPU that is currently in use on the instance | double |
| gcp.compute.instance.cpu.usage_time.sec | Usage for all cores in seconds | double |
| gcp.compute.instance.disk.read.bytes | Count of bytes read from disk | long |
| gcp.compute.instance.disk.read_ops_count.value | Count of disk read IO operations | long |
| gcp.compute.instance.disk.write.bytes | Count of bytes written to disk | long |
| gcp.compute.instance.disk.write_ops_count.value | Count of disk write IO operations | long |
| gcp.compute.instance.memory.balloon.ram_size.value | The total amount of memory in the VM. This metric is only available for VMs that belong to the e2 family. | long |
| gcp.compute.instance.memory.balloon.ram_used.value | Memory currently used in the VM. This metric is only available for VMs that belong to the e2 family. | long |
| gcp.compute.instance.memory.balloon.swap_in.bytes | The amount of memory read into the guest from its own swap space. This metric is only available for VMs that belong to the e2 family. | long |
| gcp.compute.instance.memory.balloon.swap_out.bytes | The amount of memory written from the guest to its own swap space. This metric is only available for VMs that belong to the e2 family. | long |
| gcp.compute.instance.network.egress.bytes | Count of bytes sent over the network | long |
| gcp.compute.instance.network.egress.packets.count | Count of packets sent over the network | long |
| gcp.compute.instance.network.ingress.bytes | Count of bytes received from the network | long |
| gcp.compute.instance.network.ingress.packets.count | Count of packets received from the network | long |
| gcp.compute.instance.uptime.sec | Number of seconds the VM has been running. | long |
| gcp.compute.instance.uptime_total.sec | Elapsed time since the VM was started, in seconds. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | long |
| gcp.labels.metadata.\* |  | object |
| gcp.labels.metrics.\* |  | object |
| gcp.labels.resource.\* |  | object |
| gcp.labels.system.\* |  | object |
| gcp.labels.user.\* |  | object |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
