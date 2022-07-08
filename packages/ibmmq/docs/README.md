# IBM MQ integration

The IBM MQ Integration is used to fetch observability data from [IBM MQ web endpoints](https://www.ibm.com/docs/en/ibm-mq) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `IBM MQ v9.1` and `IBM MQ v9.2`.

## Requirements

In order to ingest data from IBM MQ:

- User must provide Hostname and Port (example: localhost:9157) of Prometheus endpoint (/metrics).

## Metrics

### Queue Manager performance metrics

The `qmgr` data stream collects [performance metrics of Queue Manager](https://www.ibm.com/docs/en/ibm-mq/9.2?topic=operator-metrics-published-when-using-mq) like messages, topics, subscriptions and calls.

An example event for `qmgr` looks as following:

```json
{
    "@timestamp": "2022-07-04T07:29:32.808Z",
    "agent": {
        "ephemeral_id": "b74cf2bf-29aa-46f0-8eec-ed48244675f2",
        "id": "0402a600-6a5e-443e-a57e-10f6f91ff35e",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "ibmmq.qmgr",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "0402a600-6a5e-443e-a57e-10f6f91ff35e",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "ibmmq.qmgr",
        "duration": 4639837,
        "ingested": "2022-07-04T07:29:36Z",
        "kind": "metric",
        "module": "ibmmq",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.18.0.7"
        ],
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
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
                        "count": 2
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
                        "count": 0
                    },
                    "connections": {
                        "count": 0
                    },
                    "control": {
                        "count": 0
                    },
                    "disconnect": {
                        "count": 0
                    },
                    "inquire": {
                        "count": 4
                    },
                    "open": {
                        "count": 0
                    },
                    "set": {
                        "count": 0
                    },
                    "status": {
                        "count": 0
                    },
                    "subscription_request": {
                        "count": 0
                    }
                }
            },
            "destructive": {
                "get": {
                    "bytes": 4868,
                    "count": 13
                }
            },
            "log": {
                "written": {
                    "bytes": {
                        "logical": 0,
                        "physical": 0
                    }
                }
            },
            "messages": {
                "commit": {
                    "count": 0
                },
                "expired": {
                    "count": 0
                },
                "failed": {
                    "browse": {
                        "count": 0
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
                        "bytes": 4868,
                        "count": 13
                    }
                },
                "non_persistent": {
                    "browse": {
                        "bytes": 0,
                        "count": 0
                    },
                    "destructive": {
                        "get": {
                            "count": 13
                        }
                    },
                    "get": {
                        "bytes": 4868
                    },
                    "mq": {
                        "put": {
                            "count": 13
                        },
                        "put1": {
                            "count": 0
                        }
                    },
                    "put": {
                        "bytes": 4868
                    }
                },
                "persistent": {
                    "browse": {
                        "bytes": 0,
                        "count": 0
                    },
                    "destructive": {
                        "get": {
                            "count": 0
                        }
                    },
                    "get": {
                        "bytes": 0
                    },
                    "mq": {
                        "put": {
                            "count": 0
                        },
                        "put1": {
                            "count": 0
                        }
                    },
                    "put": {
                        "bytes": 0
                    }
                },
                "published": {
                    "subscribers": {
                        "bytes": 3500,
                        "count": 13
                    }
                },
                "purged": {
                    "queue": {
                        "count": 0
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
                        "count": 0
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
            "topic": {
                "mq": {
                    "put": {
                        "count": 13,
                        "failed": {
                            "count": 0
                        },
                        "non_persistent": {
                            "count": 13
                        },
                        "persistent": {
                            "count": 0
                        }
                    }
                },
                "put": {
                    "bytes": 3500
                }
            }
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_ibmmq_1:9157/metrics",
        "type": "ibmmq"
    },
    "tags": [
        "forwarded",
        "ibmmq-qmgr"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| ibmmq.labels.job | Prometheus label job. | keyword |
| ibmmq.labels.qmgr | Name of Queue Manager. | keyword |
| ibmmq.qmgr.calls.failed.callback.count | Failed MQCB count. | long |
| ibmmq.qmgr.calls.failed.close.count | Failed MQCLOSE count. | long |
| ibmmq.qmgr.calls.failed.connections.count | Failed MQCONN/MQCONNX count. | long |
| ibmmq.qmgr.calls.failed.get.count | Failed MQGET count. | long |
| ibmmq.qmgr.calls.failed.inquire.count | Failed MQINQ count. | long |
| ibmmq.qmgr.calls.failed.open.count | Failed MQOPEN count. | long |
| ibmmq.qmgr.calls.failed.set.count | Failed MQSET count. | long |
| ibmmq.qmgr.calls.failed.subscription_request.count | Failed MQSUBRQ count. | long |
| ibmmq.qmgr.calls.succeeded.callback.count | MQCB count. | long |
| ibmmq.qmgr.calls.succeeded.close.count | MQCLOSE count. | long |
| ibmmq.qmgr.calls.succeeded.connections.count | MQCONN/MQCONNX count. | long |
| ibmmq.qmgr.calls.succeeded.control.count | MQCTL count. | long |
| ibmmq.qmgr.calls.succeeded.disconnect.count | MQDISC count. | long |
| ibmmq.qmgr.calls.succeeded.inquire.count | MQINQ count. | long |
| ibmmq.qmgr.calls.succeeded.open.count | MQOPEN count. | long |
| ibmmq.qmgr.calls.succeeded.set.count | MQSET count. | long |
| ibmmq.qmgr.calls.succeeded.status.count | MQSTAT count. | long |
| ibmmq.qmgr.calls.succeeded.subscription_request.count | MQSUBRQ count. | long |
| ibmmq.qmgr.destructive.get.bytes | Interval total destructive get byte count. | long |
| ibmmq.qmgr.destructive.get.count | Interval total destructive get count. | long |
| ibmmq.qmgr.log.written.bytes.logical | Log - logical bytes written. | long |
| ibmmq.qmgr.log.written.bytes.physical | Log - physical bytes written. | long |
| ibmmq.qmgr.messages.commit.count | Commit count. | long |
| ibmmq.qmgr.messages.expired.count | Expired message count. | long |
| ibmmq.qmgr.messages.failed.browse.count | Failed browse count. | long |
| ibmmq.qmgr.messages.failed.mq.put.count | Failed MQPUT count. | long |
| ibmmq.qmgr.messages.failed.mq.put1.count | Failed MQPUT1 count. | long |
| ibmmq.qmgr.messages.mq.put.bytes | Interval total MQPUT/MQPUT1 byte count. | long |
| ibmmq.qmgr.messages.mq.put.count | Interval total MQPUT/MQPUT1 count. | long |
| ibmmq.qmgr.messages.non_persistent.browse.bytes | Non-persistent message browse byte count. | long |
| ibmmq.qmgr.messages.non_persistent.browse.count | Non-persistent message destructive get count. | long |
| ibmmq.qmgr.messages.non_persistent.destructive.get.count | Non-persistent message destructive get count. | long |
| ibmmq.qmgr.messages.non_persistent.get.bytes | Get non-persistent messages byte count. | long |
| ibmmq.qmgr.messages.non_persistent.mq.put.count | Non-persistent message MQPUT count. | long |
| ibmmq.qmgr.messages.non_persistent.mq.put1.count | Non-persistent message MQPUT1 count. | long |
| ibmmq.qmgr.messages.non_persistent.put.bytes | Put non-persistent messages byte count. | long |
| ibmmq.qmgr.messages.persistent.browse.bytes | Persistent message browse byte count. | long |
| ibmmq.qmgr.messages.persistent.browse.count | Persistent message browse count. | long |
| ibmmq.qmgr.messages.persistent.destructive.get.count | Persistent message destructive get count. | long |
| ibmmq.qmgr.messages.persistent.get.bytes | Get persistent messages byte count. | long |
| ibmmq.qmgr.messages.persistent.mq.put.count | Persistent message MQPUT count. | long |
| ibmmq.qmgr.messages.persistent.mq.put1.count | Persistent message MQPUT1 count. | long |
| ibmmq.qmgr.messages.persistent.put.bytes | Put persistent messages byte count. | long |
| ibmmq.qmgr.messages.published.subscribers.bytes | Published to subscribers byte count. | long |
| ibmmq.qmgr.messages.published.subscribers.count | Published to subscribers byte count. | long |
| ibmmq.qmgr.messages.purged.queue.count | Purged queue count. | long |
| ibmmq.qmgr.rollback.count | Rollback count. | long |
| ibmmq.qmgr.subscription.durable.alter.count | Alter durable subscription count. | long |
| ibmmq.qmgr.subscription.durable.create.count | Create durable subscription count. | long |
| ibmmq.qmgr.subscription.durable.delete.count | Delete durable subscription count. | long |
| ibmmq.qmgr.subscription.durable.resume.count | Alter durable subscription count. | long |
| ibmmq.qmgr.subscription.failed.create_alter_resume.count | Failed create/alter/resume subscription count. | long |
| ibmmq.qmgr.subscription.failed.delete.count | Subscription delete failure count. | long |
| ibmmq.qmgr.subscription.non_durable.create.count | Create non-durable subscription count. | long |
| ibmmq.qmgr.subscription.non_durable.delete.count | Delete non-durable subscription count. | long |
| ibmmq.qmgr.topic.mq.put.count | Topic MQPUT/MQPUT1 interval total. | long |
| ibmmq.qmgr.topic.mq.put.failed.count | Failed topic MQPUT/MQPUT1 count. | long |
| ibmmq.qmgr.topic.mq.put.non_persistent.count | Non-persistent topic MQPUT/MQPUT1 count. | long |
| ibmmq.qmgr.topic.mq.put.persistent.count | Persistent topic MQPUT/MQPUT1 count. | long |
| ibmmq.qmgr.topic.put.bytes | Interval total topic bytes put. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |

