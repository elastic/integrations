# IBM MQ integration

## Overview

[IBM MQ](https://www.ibm.com/docs/en/ibm-mq) is a message-oriented middleware for secure and reliable communication between distributed systems. It supports messaging patterns like queuing, publish/subscribe, and assures message delivery without a direct connection between sender and receiver.

Use the IBM MQ integration to:

- Collect Queue Manager performance metrics and error logs, providing insights into messages, topics, subscriptions, and operational events.
- Streamline observability by ingesting IBM MQ metrics and logs into Elasticsearch, enabling centralized monitoring and analysis of IBM MQ environments.
- Enhance system reliability through real-time analysis and proactive alerting based on collected metrics and logs.

## Data streams

The IBM MQ integration collects logs and metrics data.

Logs provide insights into operations and events within the IBM MQ environment. The errorlog data stream collected by the IBM MQ integration enables users to track errors and warnings, understand their causes, and address issues related to message handling and processing.

Metrics provide statistics on the performance and health of IBM MQ. The qmgr data stream collected by the IBM MQ integration covers Queue Manager performance metrics, including message throughput, topics, subscriptions, and other operational statistics. This allows users to monitor and optimize the performance and reliability of their IBM MQ instances.

Data streams:

- `errorlog`: Collects error and warning messages from the IBM MQ Queue Manager, providing details like error descriptions, actions, explanations, and error codes.
- `qmgr`: Collects performance metrics from the Queue Manager, including message throughput, topics, subscriptions, and other vital operational statistics.

NOTE: 
You can monitor and view logs within the ingested documents for IBM MQ using the logs-* index pattern in Discover. For metrics, the corresponding index pattern is metrics-*.

## Compatibility

This integration has been tested against IBM MQ v9.1, IBM MQ v9.2 and IBM MQ v9.4. Currently, the `ibmmq qmgr` data stream is only compatible with the containerized versions of IBM MQ, such as those available from [IBM Cloud Container Registry](https://icr.io/) or [Docker Hub](https://hub.docker.com/r/ibmcom/mq). 

## What do I need to use this integration?

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

To ingest data from IBM MQ:

- You should specify Hostname and Port (example: localhost:9157) of Prometheus endpoint (/metrics).
- You should specify the path of IBM MQ Queue Manager Error logs. (default paths: `/var/mqm/errors/*.LOG` and `/var/mqm/qmgrs/*/errors/*.LOG`)

## Setup

For step-by-step instructions on how to set up an integration, check the [Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

## Steps to setup Prometheus

Enable Metrics in IBM MQ: Ensure that the `MQ_ENABLE_METRICS` environment variable is set to true for user's IBM MQ service to expose the metrics endpoint.

The Docker image starts the runmqserver process, which spawns the HTTP server exposing metrics in Prometheus format on port `9157`.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the IBM MQ Integration should display a list of available dashboards. Click on the dashboard available for user's configured data stream. It should be populated with the required data.

## Troubleshooting

- In version 1.3.0 of this integration, the field type of `ibmmq.errorlog.error.description` has been changed from `text` to `keyword `. It is therefore recommended to update the `ibmmq.errorlog.error.description` field to use the `keyword` type wherever it is being used. This can be achieved by using the [Update By Query API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-update-by-query.html#docs-update-by-query-api-ingest-pipeline), allowing for a seamless transition of the field type from  `text` to `keyword` facross all relevant documents.

## Metrics reference

### Queue Manager performance metrics

The `qmgr` data stream collects [performance metrics of Queue Manager](https://www.ibm.com/docs/en/ibm-mq/9.4.x?topic=operator-metrics-published-by-mq-container) like messages, topics, subscriptions, and calls.

An example event for `qmgr` looks as following:

```json
{
    "@timestamp": "2026-03-19T22:40:01.042Z",
    "agent": {
        "ephemeral_id": "d15b5676-526a-4e87-81d3-2a74f42e5a5a",
        "id": "bcbcbee4-c185-49d6-963d-4df9cd2c5dfa",
        "name": "elastic-agent-86864",
        "type": "metricbeat",
        "version": "9.3.2"
    },
    "data_stream": {
        "dataset": "ibmmq.qmgr",
        "namespace": "55431",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "bcbcbee4-c185-49d6-963d-4df9cd2c5dfa",
        "snapshot": true,
        "version": "9.3.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "ibmmq.qmgr",
        "duration": 12723400,
        "ingested": "2026-03-19T22:40:04Z",
        "kind": "metric",
        "module": "ibmmq",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-86864",
        "ip": [
            "172.18.0.7",
            "172.25.0.2"
        ],
        "mac": [
            "02-42-AC-12-00-07",
            "02-42-AC-19-00-02"
        ],
        "name": "elastic-agent-86864",
        "os": {
            "kernel": "6.8.0-106-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "ibmmq": {
        "labels": {
            "job": "ibmmq",
            "qmgr": "QM1"
        },
        "qmgr": {
            "calls": {
                "failed": {
                    "callback": {
                        "count": 0
                    },
                    "close": {
                        "count": 0
                    },
                    "connections": {
                        "count": 0
                    },
                    "get": {
                        "count": 6
                    },
                    "inquire": {
                        "count": 0
                    },
                    "open": {
                        "count": 0
                    },
                    "set": {
                        "count": 0
                    },
                    "subscription_request": {
                        "count": 0
                    }
                },
                "succeeded": {
                    "callback": {
                        "count": 0
                    },
                    "close": {
                        "count": 19
                    },
                    "connections": {
                        "count": 11
                    },
                    "control": {
                        "count": 0
                    },
                    "disconnect": {
                        "count": 1
                    },
                    "inquire": {
                        "count": 7
                    },
                    "open": {
                        "count": 30
                    },
                    "set": {
                        "count": 0
                    },
                    "status": {
                        "count": 0
                    },
                    "subscription_request": {
                        "count": 1
                    }
                }
            },
            "cpu": {
                "load": {
                    "fifteen_minute": {
                        "average": {
                            "percentage": 1.86
                        }
                    },
                    "five_minute": {
                        "average": {
                            "percentage": 2.18
                        }
                    },
                    "one_minute": {
                        "average": {
                            "percentage": 2.67
                        }
                    }
                }
            },
            "destructive": {
                "get": {
                    "bytes": 10749,
                    "count": 27
                }
            },
            "errors": {
                "file_system": {
                    "free_space": {
                        "percentage": 49.79
                    },
                    "in_use": {
                        "bytes": 505299337216
                    }
                }
            },
            "fdc": {
                "files": 0
            },
            "log": {
                "file_system": {
                    "in_use": {
                        "bytes": 505299300352
                    },
                    "max": {
                        "bytes": 1006450962432
                    }
                },
                "in_use": {
                    "bytes": 50331648
                },
                "max": {
                    "bytes": 83886080
                },
                "primary_space": {
                    "in_use": {
                        "percentage": 1.89
                    }
                },
                "slowest_write": {
                    "since_restart": {
                        "seconds": 0.004807
                    }
                },
                "workload": {
                    "primary_space": {
                        "utilization": {
                            "percentage": 1.89
                        }
                    }
                },
                "write": {
                    "latency": {
                        "seconds": 0.002068
                    },
                    "size": {
                        "bytes": 5719
                    }
                },
                "written": {
                    "bytes": {
                        "logical": 26659,
                        "physical": 126976
                    }
                }
            },
            "messages": {
                "commit": {
                    "count": 9
                },
                "expired": {
                    "count": 0
                },
                "failed": {
                    "browse": {
                        "count": 6
                    },
                    "mq": {
                        "put": {
                            "count": 0
                        },
                        "put1": {
                            "count": 0
                        }
                    }
                },
                "mq": {
                    "put": {
                        "bytes": 7817,
                        "count": 20
                    }
                },
                "non_persistent": {
                    "browse": {
                        "bytes": 0,
                        "count": 0
                    },
                    "destructive": {
                        "get": {
                            "count": 12
                        }
                    },
                    "get": {
                        "bytes": 4444
                    },
                    "mq": {
                        "put": {
                            "count": 6
                        },
                        "put1": {
                            "count": 0
                        }
                    },
                    "put": {
                        "bytes": 1956
                    }
                },
                "persistent": {
                    "browse": {
                        "bytes": 2908,
                        "count": 5
                    },
                    "destructive": {
                        "get": {
                            "count": 10
                        }
                    },
                    "get": {
                        "bytes": 3397
                    },
                    "mq": {
                        "put": {
                            "count": 10
                        },
                        "put1": {
                            "count": 4
                        }
                    },
                    "put": {
                        "bytes": 5861
                    }
                },
                "published": {
                    "subscribers": {
                        "bytes": 1320,
                        "count": 6
                    }
                },
                "purged": {
                    "queue": {
                        "count": 0
                    }
                }
            },
            "queue_manager": {
                "file_system": {
                    "free_space": {
                        "percentage": 49.79
                    },
                    "in_use": {
                        "bytes": 505299337216
                    }
                }
            },
            "ram": {
                "free": {
                    "percentage": 12.97
                },
                "usage": {
                    "estimate": {
                        "queue_manager": {
                            "bytes": 197132288
                        }
                    }
                }
            },
            "rollback": {
                "count": 0
            },
            "subscription": {
                "durable": {
                    "alter": {
                        "count": 0
                    },
                    "create": {
                        "count": 1
                    },
                    "delete": {
                        "count": 0
                    },
                    "resume": {
                        "count": 0
                    }
                },
                "failed": {
                    "create_alter_resume": {
                        "count": 0
                    },
                    "delete": {
                        "count": 0
                    }
                },
                "non_durable": {
                    "create": {
                        "count": 0
                    },
                    "delete": {
                        "count": 0
                    }
                }
            },
            "system": {
                "cpu": {
                    "time": {
                        "estimate": {
                            "queue_manager": {
                                "percentage": 0.08
                            }
                        },
                        "percentage": 2.63
                    }
                }
            },
            "topic": {
                "mq": {
                    "put": {
                        "count": 9,
                        "failed": {
                            "count": 0
                        },
                        "non_persistent": {
                            "count": 6
                        },
                        "persistent": {
                            "count": 3
                        }
                    }
                },
                "put": {
                    "bytes": 14560
                }
            },
            "trace": {
                "file_system": {
                    "free_space": {
                        "percentage": 49.79
                    },
                    "in_use": {
                        "bytes": 505299337216
                    }
                }
            },
            "user": {
                "cpu": {
                    "time": {
                        "estimate": {
                            "queue_manager": {
                                "percentage": 0.09
                            }
                        },
                        "percentage": 8.2
                    }
                }
            }
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "service": {
        "address": "http://svc-ibmmq:9157/metrics",
        "type": "ibmmq"
    },
    "tags": [
        "ibmmq-qmgr"
    ]
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| ibmmq.labels.job | Prometheus label job. | keyword |  |
| ibmmq.labels.qmgr | Name of Queue Manager. | keyword |  |
| ibmmq.qmgr.calls.failed.callback.count | Failed MQCB count. | long | counter |
| ibmmq.qmgr.calls.failed.close.count | Failed MQCLOSE count. | long | counter |
| ibmmq.qmgr.calls.failed.connections.count | Failed MQCONN/MQCONNX count. | long | counter |
| ibmmq.qmgr.calls.failed.get.count | Failed MQGET - count. | long | counter |
| ibmmq.qmgr.calls.failed.inquire.count | Failed MQINQ count. | long | counter |
| ibmmq.qmgr.calls.failed.open.count | Failed MQOPEN count. | long | counter |
| ibmmq.qmgr.calls.failed.set.count | Failed MQSET count. | long | counter |
| ibmmq.qmgr.calls.failed.subscription_request.count | Failed MQSUBRQ count. | long | counter |
| ibmmq.qmgr.calls.succeeded.callback.count | MQCB count. | long | counter |
| ibmmq.qmgr.calls.succeeded.close.count | MQCLOSE count. | long | counter |
| ibmmq.qmgr.calls.succeeded.connections.count | MQCONN/MQCONNX count. | long | counter |
| ibmmq.qmgr.calls.succeeded.control.count | MQCTL count. | long | counter |
| ibmmq.qmgr.calls.succeeded.disconnect.count | MQDISC count. | long | counter |
| ibmmq.qmgr.calls.succeeded.inquire.count | MQINQ count. | long | counter |
| ibmmq.qmgr.calls.succeeded.open.count | MQOPEN count. | long | counter |
| ibmmq.qmgr.calls.succeeded.set.count | MQSET count. | long | counter |
| ibmmq.qmgr.calls.succeeded.status.count | MQSTAT count. | long | counter |
| ibmmq.qmgr.calls.succeeded.subscription_request.count | MQSUBRQ count. | long | counter |
| ibmmq.qmgr.cpu.load.fifteen_minute.average.percentage | CPU load - fifteen minute average. | float | gauge |
| ibmmq.qmgr.cpu.load.five_minute.average.percentage | CPU load - five minute average. | float | gauge |
| ibmmq.qmgr.cpu.load.one_minute.average.percentage | CPU load - one minute average. | float | gauge |
| ibmmq.qmgr.destructive.get.bytes | Interval total destructive get - byte count. | long | counter |
| ibmmq.qmgr.destructive.get.count | Interval total destructive get - count. | long | counter |
| ibmmq.qmgr.errors.file_system.free_space.percentage | MQ errors file system - free space. | float | gauge |
| ibmmq.qmgr.errors.file_system.in_use.bytes | MQ errors file system - bytes in use. | long | gauge |
| ibmmq.qmgr.fdc.files | MQ FDC file count. | long | gauge |
| ibmmq.qmgr.log.file_system.free_space.percentage | Log file system - free space. | float | gauge |
| ibmmq.qmgr.log.file_system.in_use.bytes | Log file system - bytes in use. | long | gauge |
| ibmmq.qmgr.log.file_system.max.bytes | Log file system - bytes max. | long | gauge |
| ibmmq.qmgr.log.in_use.bytes | Log - bytes in use. | long | gauge |
| ibmmq.qmgr.log.max.bytes | Log - bytes max. | long | gauge |
| ibmmq.qmgr.log.occupied.extents.waiting_to_be_archived.bytes | Log - occupied by extents waiting to be archived. | long | gauge |
| ibmmq.qmgr.log.occupied.reusable_extents.bytes | Log - bytes occupied by reusable extents. | long | gauge |
| ibmmq.qmgr.log.primary_space.in_use.percentage | Log - current primary space in use. | float | gauge |
| ibmmq.qmgr.log.required_for_media_recovery.bytes | Log - bytes required for media recovery. | long | gauge |
| ibmmq.qmgr.log.sequence_number.disk | Log - disk written log sequence number. | long | gauge |
| ibmmq.qmgr.log.sequence_number.quorum | Log - quorum log sequence number. | long | gauge |
| ibmmq.qmgr.log.slowest_write.since_restart.seconds | Log - slowest write since restart. | float | gauge |
| ibmmq.qmgr.log.workload.primary_space.utilization.percentage | Log - workload primary space utilization. | float | gauge |
| ibmmq.qmgr.log.write.latency.seconds | Log - write latency. | float | gauge |
| ibmmq.qmgr.log.write.size.bytes | Log - write size. | long | gauge |
| ibmmq.qmgr.log.written.bytes.logical | Log - logical bytes written. | long | counter |
| ibmmq.qmgr.log.written.bytes.physical | Log - physical bytes written. | long | counter |
| ibmmq.qmgr.messages.commit.count | Commit count. | long | counter |
| ibmmq.qmgr.messages.expired.count | Expired message count. | long | counter |
| ibmmq.qmgr.messages.failed.browse.count | Failed browse count. | long | counter |
| ibmmq.qmgr.messages.failed.mq.put.count | Failed MQPUT count. | long | counter |
| ibmmq.qmgr.messages.failed.mq.put1.count | Failed MQPUT1 count. | long | counter |
| ibmmq.qmgr.messages.mq.put.bytes | Interval total MQPUT/MQPUT1 byte count. | long | counter |
| ibmmq.qmgr.messages.mq.put.count | Interval total MQPUT/MQPUT1 count. | long | counter |
| ibmmq.qmgr.messages.non_persistent.browse.bytes | Non-persistent message browse - byte count. | long | counter |
| ibmmq.qmgr.messages.non_persistent.browse.count | Non-persistent message browse - count. | long | counter |
| ibmmq.qmgr.messages.non_persistent.destructive.get.count | Non-persistent message destructive get - count. | long | counter |
| ibmmq.qmgr.messages.non_persistent.get.bytes | Got non-persistent messages - byte count. | long | counter |
| ibmmq.qmgr.messages.non_persistent.mq.put.count | Non-persistent message MQPUT count. | long | counter |
| ibmmq.qmgr.messages.non_persistent.mq.put1.count | Non-persistent message MQPUT1 count. | long | counter |
| ibmmq.qmgr.messages.non_persistent.put.bytes | Put non-persistent messages - byte count. | long | counter |
| ibmmq.qmgr.messages.persistent.browse.bytes | Persistent message browse - byte count. | long | counter |
| ibmmq.qmgr.messages.persistent.browse.count | Persistent message browse - count. | long | counter |
| ibmmq.qmgr.messages.persistent.destructive.get.count | Persistent message destructive get - count. | long | counter |
| ibmmq.qmgr.messages.persistent.get.bytes | Get persistent messages - byte count. | long | counter |
| ibmmq.qmgr.messages.persistent.mq.put.count | Persistent message MQPUT count. | long | counter |
| ibmmq.qmgr.messages.persistent.mq.put1.count | Persistent message MQPUT1 count. | long | counter |
| ibmmq.qmgr.messages.persistent.put.bytes | Put persistent messages - byte count. | long | counter |
| ibmmq.qmgr.messages.published.subscribers.bytes | Published to subscribers - byte count. | long | counter |
| ibmmq.qmgr.messages.published.subscribers.count | Published to subscribers - message count. | long | counter |
| ibmmq.qmgr.messages.purged.queue.count | Purged queue count. | long | counter |
| ibmmq.qmgr.nha.recovery.average.network_round_trip.time.seconds | Average network round trip time. | float | gauge |
| ibmmq.qmgr.nha.recovery.backlog.average.bytes | Backlog average bytes. | long | gauge |
| ibmmq.qmgr.nha.recovery.backlog.bytes | Backlog bytes. | long | gauge |
| ibmmq.qmgr.nha.recovery.log.data.average.compression.time.seconds | Log data average compression time. | float | gauge |
| ibmmq.qmgr.nha.recovery.log.data.average.decompression.time.seconds | Log data average decompression time. | float | gauge |
| ibmmq.qmgr.nha.recovery.log.decompressed.bytes | Log bytes decompressed. | long | gauge |
| ibmmq.qmgr.nha.recovery.log.sent.bytes | Log bytes sent. | long | counter |
| ibmmq.qmgr.nha.recovery.log.sent.compressed.bytes | Compressed log bytes sent. | long | gauge |
| ibmmq.qmgr.nha.recovery.log.sequence_number.recovery | Recovery log sequence number. | long | gauge |
| ibmmq.qmgr.nha.recovery.rebase.count | Rebase count. | long | gauge |
| ibmmq.qmgr.nha.replication.average.network_round_trip.time.seconds | Average network round trip time. | float | gauge |
| ibmmq.qmgr.nha.replication.backlog.average.bytes | Backlog average bytes. | long | gauge |
| ibmmq.qmgr.nha.replication.backlog.bytes | Backlog bytes. | long | gauge |
| ibmmq.qmgr.nha.replication.catch_up.log.data.average.compression.time.seconds | Catch-up log data average compression time. | float | gauge |
| ibmmq.qmgr.nha.replication.catch_up.log.data.average.decompression.time.seconds | Catch-up log data average decompression time. | float | gauge |
| ibmmq.qmgr.nha.replication.catch_up.log.decompressed.bytes | Catch-up log bytes decompressed. | long | gauge |
| ibmmq.qmgr.nha.replication.catch_up.log.sent.bytes | Catch-up log bytes sent. | long | counter |
| ibmmq.qmgr.nha.replication.catch_up.log.sent.compressed.bytes | Catch-up compressed log bytes sent. | long | counter |
| ibmmq.qmgr.nha.replication.catch_up.log.sent.uncompressed.bytes | Catch-up uncompressed log bytes sent. | long | counter |
| ibmmq.qmgr.nha.replication.log.file_system.free_space.percentage | Log file system - free space. | float | gauge |
| ibmmq.qmgr.nha.replication.log.file_system.in_use.bytes | Log file system - bytes in use. | long | gauge |
| ibmmq.qmgr.nha.replication.log.sequence_number.acknowledged | Acknowledged log sequence number. | long | gauge |
| ibmmq.qmgr.nha.replication.log.write.average.acknowledgement.latency.seconds | Log write average acknowledgement latency. | float | gauge |
| ibmmq.qmgr.nha.replication.log.write.average.acknowledgement.size.bytes | Log write average acknowledgement size. | long | gauge |
| ibmmq.qmgr.nha.replication.mq.fdc.file.count | MQ FDC file count. | long | gauge |
| ibmmq.qmgr.nha.replication.queue_manager.file_system.free_space.percentage | Queue Manager file system - free space. | float | gauge |
| ibmmq.qmgr.nha.replication.queue_manager.file_system.in_use.bytes | Queue Manager file system - bytes in use. | long | gauge |
| ibmmq.qmgr.nha.replication.synchronous.log.data.average.compression.time.seconds | Synchronous log data average compression time. | float | gauge |
| ibmmq.qmgr.nha.replication.synchronous.log.data.average.decompression.time.seconds | Synchronous log data average decompression time. | float | gauge |
| ibmmq.qmgr.nha.replication.synchronous.log.decompressed.bytes | Synchronous log bytes decompressed. | long | gauge |
| ibmmq.qmgr.nha.replication.synchronous.log.sent.bytes | Synchronous log bytes sent. | long | counter |
| ibmmq.qmgr.nha.replication.synchronous.log.sent.compressed.bytes | Synchronous compressed log bytes sent. | long | counter |
| ibmmq.qmgr.nha.replication.synchronous.log.sent.uncompressed.bytes | Synchronous uncompressed log bytes sent. | long | counter |
| ibmmq.qmgr.queue_manager.file_system.free_space.percentage | Queue Manager file system - free space. | float | gauge |
| ibmmq.qmgr.queue_manager.file_system.in_use.bytes | Queue Manager file system - bytes in use. | long | gauge |
| ibmmq.qmgr.ram.free.percentage | RAM free percentage. | float | gauge |
| ibmmq.qmgr.ram.usage.estimate.queue_manager.bytes | RAM total bytes - estimate for queue manager. | long | gauge |
| ibmmq.qmgr.rollback.count | Rollback count. | long | counter |
| ibmmq.qmgr.subscription.durable.alter.count | Alter durable subscription count. | long | counter |
| ibmmq.qmgr.subscription.durable.create.count | Create durable subscription count. | long | counter |
| ibmmq.qmgr.subscription.durable.delete.count | Delete durable subscription count. | long | counter |
| ibmmq.qmgr.subscription.durable.resume.count | Resume durable subscription count. | long | counter |
| ibmmq.qmgr.subscription.failed.create_alter_resume.count | Failed create/alter/resume subscription count. | long | counter |
| ibmmq.qmgr.subscription.failed.delete.count | Subscription delete failure count. | long | counter |
| ibmmq.qmgr.subscription.non_durable.create.count | Create non-durable subscription count. | long | counter |
| ibmmq.qmgr.subscription.non_durable.delete.count | Delete non-durable subscription count. | long | counter |
| ibmmq.qmgr.system.cpu.time.estimate.queue_manager.percentage | System CPU time - percentage estimate for queue manager. | float | gauge |
| ibmmq.qmgr.system.cpu.time.percentage | System CPU time percentage. | float | gauge |
| ibmmq.qmgr.topic.mq.put.count | Topic MQPUT/MQPUT1 interval total. | long | counter |
| ibmmq.qmgr.topic.mq.put.failed.count | Failed topic MQPUT/MQPUT1 count. | long | counter |
| ibmmq.qmgr.topic.mq.put.non_persistent.count | Non-persistent - topic MQPUT/MQPUT1 count. | long | counter |
| ibmmq.qmgr.topic.mq.put.persistent.count | Persistent - topic MQPUT/MQPUT1 count. | long | counter |
| ibmmq.qmgr.topic.put.bytes | Interval total topic bytes put. | long | counter |
| ibmmq.qmgr.trace.file_system.free_space.percentage | MQ trace file system - free space. | float | gauge |
| ibmmq.qmgr.trace.file_system.in_use.bytes | MQ trace file system - bytes in use. | long | gauge |
| ibmmq.qmgr.user.cpu.time.estimate.queue_manager.percentage | User CPU time - percentage estimate for queue manager. | float | gauge |
| ibmmq.qmgr.user.cpu.time.percentage | User CPU time percentage. | float | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


## Logs reference

### Queue Manager Error logs

The `errorlog` data stream collects [Error logs of Queue Manager](https://www.site24x7.com/help/log-management/ibm-mq-error-logs.html) which include the description, action, explanation and code of the error.

An example event for `errorlog` looks as following:

```json
{
    "@timestamp": "2026-04-21T15:00:39.503Z",
    "agent": {
        "ephemeral_id": "a2bda129-5568-4c2f-b346-0b37d19e4bdf",
        "id": "8403f38c-7819-48a6-a78f-c14ab29dd711",
        "name": "elastic-agent-31767",
        "type": "filebeat",
        "version": "9.3.2"
    },
    "data_stream": {
        "dataset": "ibmmq.errorlog",
        "namespace": "68766",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8403f38c-7819-48a6-a78f-c14ab29dd711",
        "snapshot": true,
        "version": "9.3.2"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2026-04-21T15:01:06.194Z",
        "dataset": "ibmmq.errorlog",
        "ingested": "2026-04-21T15:01:09Z",
        "kind": "event",
        "module": "ibmmq",
        "type": [
            "error"
        ]
    },
    "host": {
        "hostname": "8aecb22657e3",
        "name": "elastic-agent-31767"
    },
    "ibmmq": {
        "errorlog": {
            "error": {
                "action": "None.",
                "code": "AMQ6287I",
                "description": "IBM MQ V9.4.0.20 (p940-020-260211).",
                "explanation": "IBM MQ system information: Host Info :- Linux 6.8.0-110-generic (MQ Linux (x86-64 platform) 64-bit) Installation :- /opt/mqm (Installation1) Version :- 9.4.0.20 (p940-020-260211)"
            },
            "insert": {
                "comment": [
                    "Linux 6.8.0-110-generic (MQ Linux (x86-64 platform) 64-bit)",
                    "/opt/mqm (Installation1)",
                    "9.4.0.20 (p940-020-260211)"
                ]
            },
            "installation": "Installation1"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/AMQERR01.LOG"
        },
        "flags": "multiline",
        "offset": 0
    },
    "process": {
        "pid": 457.1,
        "title": "crtmqm"
    },
    "service": {
        "version": "9.4.0.20"
    },
    "tags": [
        "forwarded",
        "ibmmq-errorlog"
    ],
    "user": {
        "name": "root"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ibmmq.errorlog.error.action | Defines what to do when the error occurs. | keyword |
| ibmmq.errorlog.error.code | Error code. | keyword |
| ibmmq.errorlog.error.description | Error description. | keyword |
| ibmmq.errorlog.error.explanation | Explains the error in more detail. | keyword |
| ibmmq.errorlog.insert.arith | Changing content based on error.id. | keyword |
| ibmmq.errorlog.insert.comment | Changing content based on error.id. | keyword |
| ibmmq.errorlog.installation | This is the installation name which can be given at installation time. Each installation of IBM MQ on UNIX, Linux, and Windows, has a unique identifier known as an installation name. The installation name is used to associate things such as queue managers and configuration files with an installation. | keyword |
| ibmmq.errorlog.queue_manager | Name of the queue manager. Queue managers provide queuing services to applications, and manages the queues that belong to them. | keyword |
| input.type | The input type from which the event was generated. This field is set to the value specified for the type option in the input section of the Filebeat config file. | keyword |
| log.flags | This field contains the flags of the event. | keyword |
| log.offset | The file offset the reported line starts at. | long |

