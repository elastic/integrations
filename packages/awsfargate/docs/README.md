# AWS Fargate Integration

This integration is used to fetch metrics from [AWS Fargate](https://aws.amazon.com/fargate/).

## AWS Credentials

No AWS credentials are required for this integration.

### Why there are no credentials required?

## AWS Permissions

??

## Metrics

### Task Stats

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| awsfargate.task_stats.cpu.kernel.norm.pct | Percentage of time in kernel space normalized by the number of CPU cores. | scaled_float |
| awsfargate.task_stats.cpu.kernel.pct | Percentage of time in kernel space. | scaled_float |
| awsfargate.task_stats.cpu.kernel.ticks | CPU ticks in kernel space. | long |
| awsfargate.task_stats.cpu.system.norm.pct | Percentage of total CPU time in the system normalized by the number of CPU cores. | scaled_float |
| awsfargate.task_stats.cpu.system.pct | Percentage of total CPU time in the system. | scaled_float |
| awsfargate.task_stats.cpu.system.ticks | CPU system ticks. | long |
| awsfargate.task_stats.cpu.total.norm.pct | Total CPU usage normalized by the number of CPU cores. | scaled_float |
| awsfargate.task_stats.cpu.total.pct | Total CPU usage. | scaled_float |
| awsfargate.task_stats.cpu.user.norm.pct | Percentage of time in user space normalized by the number of CPU cores. | scaled_float |
| awsfargate.task_stats.cpu.user.pct | Percentage of time in user space. | scaled_float |
| awsfargate.task_stats.cpu.user.ticks | CPU ticks in user space. | long |
| awsfargate.task_stats.diskio.read.bytes | Bytes read during the life of the container | long |
| awsfargate.task_stats.diskio.read.ops | Number of reads during the life of the container | long |
| awsfargate.task_stats.diskio.read.queued | Total number of queued requests | long |
| awsfargate.task_stats.diskio.read.rate | Number of current reads per second | long |
| awsfargate.task_stats.diskio.read.reads | Number of current reads per second | scaled_float |
| awsfargate.task_stats.diskio.read.service_time | Total time to service IO requests, in nanoseconds | long |
| awsfargate.task_stats.diskio.read.summary.bytes | Bytes read and written during the life of the container | long |
| awsfargate.task_stats.diskio.read.summary.ops | Number of I/O operations during the life of the container | long |
| awsfargate.task_stats.diskio.read.summary.queued | Total number of queued requests | long |
| awsfargate.task_stats.diskio.read.summary.rate | Number of current operations per second | long |
| awsfargate.task_stats.diskio.read.summary.service_time | Total time to service IO requests, in nanoseconds | long |
| awsfargate.task_stats.diskio.read.summary.wait_time | Total time requests spent waiting in queues for service, in nanoseconds | long |
| awsfargate.task_stats.diskio.read.total | Number of reads and writes per second | scaled_float |
| awsfargate.task_stats.diskio.read.wait_time | Total time requests spent waiting in queues for service, in nanoseconds | long |
| awsfargate.task_stats.diskio.read.write.bytes | Bytes written during the life of the container | long |
| awsfargate.task_stats.diskio.read.write.ops | Number of writes during the life of the container | long |
| awsfargate.task_stats.diskio.read.write.queued | Total number of queued requests | long |
| awsfargate.task_stats.diskio.read.write.rate | Number of current writes per second | long |
| awsfargate.task_stats.diskio.read.write.service_time | Total time to service IO requests, in nanoseconds | long |
| awsfargate.task_stats.diskio.read.write.wait_time | Total time requests spent waiting in queues for service, in nanoseconds | long |
| awsfargate.task_stats.diskio.read.writes | Number of current writes per second | scaled_float |
| awsfargate.task_stats.identifier | Container identifier across tasks and clusters, which equals to container.name + '/' + container.id. | keyword |
| awsfargate.task_stats.memory.stats.\*.commit.peak | Peak committed bytes on Windows | long |
| awsfargate.task_stats.memory.stats.\*.commit.total | Total bytes | long |
| awsfargate.task_stats.memory.stats.\*.fail.count | Fail counter. | scaled_float |
| awsfargate.task_stats.memory.stats.\*.limit | Memory limit. | long |
| awsfargate.task_stats.memory.stats.\*.private_working_set.total | private working sets on Windows | long |
| awsfargate.task_stats.memory.stats.\*.rss.pct | Memory resident set size percentage. | scaled_float |
| awsfargate.task_stats.memory.stats.\*.rss.total | Total memory resident set size. | long |
| awsfargate.task_stats.memory.stats.\*.rss.usage.max | Max memory usage. | long |
| awsfargate.task_stats.memory.stats.\*.rss.usage.pct | Memory usage percentage. | scaled_float |
| awsfargate.task_stats.memory.stats.\*.rss.usage.total | Total memory usage. | long |
| awsfargate.task_stats.network.inbound.bytes | Total number of incoming bytes. | long |
| awsfargate.task_stats.network.inbound.dropped | Total number of dropped incoming packets. | long |
| awsfargate.task_stats.network.inbound.errors | Total errors on incoming packets. | long |
| awsfargate.task_stats.network.inbound.packets | Total number of incoming packets. | long |
| awsfargate.task_stats.network.interface | Network interface name. | keyword |
| awsfargate.task_stats.network.outbound.bytes | Total number of outgoing bytes. | long |
| awsfargate.task_stats.network.outbound.dropped | Total number of dropped outgoing packets. | long |
| awsfargate.task_stats.network.outbound.errors | Total errors on outgoing packets. | long |
| awsfargate.task_stats.network.outbound.packets | Total number of outgoing packets. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |


An example event for `task_stats` looks as following:

```json
{
    "@timestamp": "2022-03-29T17:12:37.593Z",
    "service": {
        "type": "awsfargate"
    },
    "container": {
        "id": "c2469245446140748978d75427f2733a-947972811",
        "image": {
            "name": "docker.elastic.co/beats/metricbeat:8.0.1"
        },
        "name": "metricbeat-container",
        "labels": {
            "com_amazonaws_ecs_cluster": "arn:aws:ecs:eu-west-1:627286350134:cluster/fargate-cluster-mbranca",
            "com_amazonaws_ecs_container-name": "metricbeat-container",
            "com_amazonaws_ecs_task-arn": "arn:aws:ecs:eu-west-1:627286350134:task/fargate-cluster-mbranca/c2469245446140748978d75427f2733a",
            "com_amazonaws_ecs_task-definition-family": "metricbeat-mbranca",
            "com_amazonaws_ecs_task-definition-version": "5"
        }
    },
    "host": {
        "name": "ip-172-31-4-254.eu-west-1.compute.internal"
    },
    "agent": {
        "ephemeral_id": "9f822bc1-6406-487d-8a2c-d93da8fb90ff",
        "id": "a241110c-d125-4129-84c8-dc7b6aad2a02",
        "name": "ip-172-31-4-254.eu-west-1.compute.internal",
        "type": "metricbeat",
        "version": "8.0.1"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "awsfargate": {
        "task_stats": {
            "diskio": {
                "write": {
                    "wait_time": 0,
                    "queued": 0,
                    "ops": 3,
                    "bytes": 12288,
                    "rate": 0,
                    "service_time": 0
                },
                "summary": {
                    "queued": 0,
                    "ops": 3,
                    "bytes": 12288,
                    "rate": 0,
                    "service_time": 0,
                    "wait_time": 0
                },
                "reads": 0,
                "writes": 0,
                "total": 0,
                "read": {
                    "service_time": 0,
                    "wait_time": 0,
                    "queued": 0,
                    "ops": 0,
                    "bytes": 0,
                    "rate": 0
                }
            },
            "cluster_name": "fargate-cluster-mbranca",
            "task_name": "metricbeat-mbranca",
            "identifier": "metricbeat-container/c2469245446140748978d75427f2733a-947972811",
            "cpu": {
                "user": {
                    "ticks": 2610000000,
                    "pct": 0,
                    "norm": {
                        "pct": 0
                    }
                },
                "system": {
                    "norm": {
                        "pct": 1
                    },
                    "ticks": 6944980000000,
                    "pct": 2
                },
                "core": {},
                "total": {
                    "pct": 0.0003370733935742972,
                    "norm": {
                        "pct": 0.0001685366967871486
                    }
                },
                "kernel": {
                    "ticks": 720000000,
                    "pct": 0.001004016064257028,
                    "norm": {
                        "pct": 0.000502008032128514
                    }
                }
            },
            "memory": {
                "limit": 0,
                "rss": {
                    "total": 56008704,
                    "pct": 6.072475855489759e-12
                },
                "usage": {
                    "total": 59355136,
                    "pct": 6.435296739937261e-12,
                    "max": 86831104
                },
                "stats": {
                    "hierarchical_memory_limit": 536870912,
                    "pgfault": 82038,
                    "total_pgfault": 82038,
                    "inactive_anon": 0,
                    "pgmajfault": 0,
                    "rss_huge": 0,
                    "writeback": 0,
                    "dirty": 0,
                    "total_active_anon": 56160256,
                    "total_dirty": 0,
                    "total_inactive_file": 28672,
                    "total_mapped_file": 0,
                    "total_pgmajfault": 0,
                    "pgpgout": 56172,
                    "active_file": 36864,
                    "cache": 0,
                    "rss": 56008704,
                    "total_unevictable": 0,
                    "total_writeback": 0,
                    "active_anon": 56160256,
                    "mapped_file": 0,
                    "pgpgin": 69927,
                    "total_cache": 0,
                    "total_inactive_anon": 0,
                    "total_pgpgout": 56172,
                    "inactive_file": 28672,
                    "total_pgpgin": 69927,
                    "total_rss": 56008704,
                    "total_rss_huge": 0,
                    "unevictable": 0,
                    "hierarchical_memsw_limit": 9223372036854772000,
                    "total_active_file": 36864
                },
                "fail": {
                    "count": 0
                }
            },
            "network": {
                "eth1": {
                    "inbound": {
                        "packets": 86949,
                        "bytes": 120475632,
                        "dropped": 0,
                        "errors": 0
                    },
                    "outbound": {
                        "bytes": 6726350,
                        "dropped": 0,
                        "errors": 0,
                        "packets": 17857
                    }
                }
            }
        }
    },
    "cloud": {
        "region": "eu-west-1"
    },
    "event": {
        "dataset": "awsfargate.task_stats",
        "module": "awsfargate",
        "duration": 2110532
    },
    "metricset": {
        "name": "task_stats",
        "period": 10000
    }
}
```
