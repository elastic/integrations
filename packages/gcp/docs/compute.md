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

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| gcp.compute.firewall.dropped.bytes | Delta of incoming bytes dropped by the firewall | long | gauge |
| gcp.compute.firewall.dropped_packets_count.value | Delta of incoming packets dropped by the firewall | long | gauge |
| gcp.compute.instance.cpu.reserved_cores.value | Number of cores reserved on the host of the instance | double | gauge |
| gcp.compute.instance.cpu.usage.pct | The fraction of the allocated CPU that is currently in use on the instance | double | gauge |
| gcp.compute.instance.cpu.usage_time.sec | Delta of usage for all cores in seconds | double | gauge |
| gcp.compute.instance.disk.read.bytes | Delta of count of bytes read from disk | long | gauge |
| gcp.compute.instance.disk.read_ops_count.value | Delta of count of disk read IO operations | long | gauge |
| gcp.compute.instance.disk.write.bytes | Delta of count of bytes written to disk | long | gauge |
| gcp.compute.instance.disk.write_ops_count.value | Delta of count of disk write IO operations | long | gauge |
| gcp.compute.instance.memory.balloon.ram_size.value | The total amount of memory in the VM. This metric is only available for VMs that belong to the e2 family. | long | gauge |
| gcp.compute.instance.memory.balloon.ram_used.value | Memory currently used in the VM. This metric is only available for VMs that belong to the e2 family. | long | gauge |
| gcp.compute.instance.memory.balloon.swap_in.bytes | Delta of the amount of memory read into the guest from its own swap space. This metric is only available for VMs that belong to the e2 family. | long | gauge |
| gcp.compute.instance.memory.balloon.swap_out.bytes | Delta of the amount of memory written from the guest to its own swap space. This metric is only available for VMs that belong to the e2 family. | long | gauge |
| gcp.compute.instance.network.egress.bytes | Delta of count of bytes sent over the network | long | gauge |
| gcp.compute.instance.network.egress.packets.count | Delta of count of packets sent over the network | long | gauge |
| gcp.compute.instance.network.ingress.bytes | Delta of count of bytes received from the network | long | gauge |
| gcp.compute.instance.network.ingress.packets.count | Delta of count of packets received from the network | long | gauge |
| gcp.compute.instance.uptime.sec | Delta of number of seconds the VM has been running. | long | gauge |
| gcp.compute.instance.uptime_total.sec | Elapsed time since the VM was started, in seconds. Sampled every 60 seconds. After sampling, data is not visible for up to 120 seconds. | long | gauge |
| gcp.labels.metadata.\* |  | object |  |
| gcp.labels.metrics.\* |  | object |  |
| gcp.labels.resource.\* |  | object |  |
| gcp.labels.system.\* |  | object |  |
| gcp.labels.user.\* |  | object |  |
| gcp.labels_fingerprint | Hashed value of the labels field. | keyword |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
