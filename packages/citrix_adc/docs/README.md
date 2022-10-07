# Citrix ADC Integration

## Overview

The Citrix ADC integration allows you to monitor your Citrix ADC instance. Citrix ADC is an application delivery controller that performs application-specific traffic analysis to intelligently distribute, optimize, and secure Layer 4 - Layer 7 (L4–L7) network traffic for web applications.

Use the Citrix ADC integration to collect metrics related to the lbvserver. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

## Data streams

The Citrix ADC integration collects metrics data.

Metrics give you insight into the statistics of the Citrix ADC. Metrics data streams collected by the Citrix ADC integration include [lbvserver](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/lb/lbvserver/), so that the user could monitor and troubleshoot the performance of the Citrix ADC instances.

This integration uses:
- `httpjson` filebeat module to collect `lbvserver` metrics.

## Compatibility

This integration has been tested against Citrix ADC `v13.0` and `v13.1`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from Citrix ADC, you must know the host(s) and the administrator credentials for the Citrix ADC instance.

Host Configuration Format: `http[s]://host[:port]`

Example Host Configuration: `http://localhost:9080`

## Metrics reference

### Load Balancing Virtual Server

This is the `lbvserver` data stream. lbvserver stands for Load Balancing Virtual Server. The load balancing server is logically located between the client and the server farm, and manages traffic flow to the servers in the server farm. 

An example event for `lbvserver` looks as following:

```json
{
    "@timestamp": "2022-10-07T06:25:28.550Z",
    "agent": {
        "ephemeral_id": "5d00842d-a4ee-4502-9a8c-16100e326dc0",
        "id": "6713ae74-2a36-4e79-bc7b-954d6b48d5bd",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "citrix_adc": {
        "lbvserver": {
            "client": {
                "connections": {
                    "current": {
                        "count": 8
                    },
                    "established": {
                        "count": 6
                    }
                },
                "response_time": {
                    "application_performance_index": 1
                }
            },
            "connections": {
                "actual": {
                    "count": 8
                }
            },
            "down": {
                "backup": {
                    "hits": 13
                }
            },
            "health": 67,
            "hit": {
                "count": 10,
                "rate": 5
            },
            "name": "elastic",
            "packets": {
                "received": {
                    "count": 7
                },
                "sent": {
                    "count": 8,
                    "rate": 8
                }
            },
            "protocol": "HTTP",
            "request": {
                "deferred": {
                    "count": 13,
                    "rate": 13
                },
                "received": {
                    "bytes": {
                        "rate": 7,
                        "value": 7
                    },
                    "count": 5,
                    "rate": 5
                },
                "surge_queue": {
                    "count": 8
                },
                "waiting": {
                    "count": 6
                }
            },
            "requests_responses": {
                "dropped": {
                    "count": 13
                },
                "invalid": {
                    "count": 13
                }
            },
            "response": {
                "received": {
                    "bytes": {
                        "rate": 7,
                        "value": 7
                    },
                    "count": 5,
                    "rate": 5
                }
            },
            "service": {
                "active": {
                    "count": 10
                },
                "inactive": {
                    "count": 6
                }
            },
            "spillover": {
                "count": 8
            },
            "state": "DOWN",
            "threshold": {
                "spillover": 8
            },
            "time_to_last_byte": {
                "avg": 6
            },
            "transaction": {
                "frustrating": {
                    "count": 1
                },
                "tolerable": {
                    "count": 3
                }
            }
        }
    },
    "data_stream": {
        "dataset": "citrix_adc.lbvserver",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "6713ae74-2a36-4e79-bc7b-954d6b48d5bd",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "created": "2022-10-07T06:25:28.550Z",
        "dataset": "citrix_adc.lbvserver",
        "ingested": "2022-10-07T06:25:32Z",
        "kind": "event",
        "module": "citrix_adc",
        "original": "{\"actsvcs\":\"10\",\"avgcltttlb\":\"6\",\"cltresponsetimeapdex\":1,\"cltttlbtransactionsrate\":3,\"cpuusagepm\":\"10\",\"curbackuppersistencesessions\":\"8\",\"curclntconnections\":\"8\",\"curmptcpsessions\":\"13\",\"curpersistencesessions\":\"8\",\"cursrvrconnections\":\"8\",\"cursubflowconn\":\"13\",\"deferredreq\":\"13\",\"deferredreqrate\":13,\"establishedconn\":\"6\",\"frustratingttlbtransactions\":\"1\",\"frustratingttlbtransactionsrate\":1,\"h2requestsrate\":7,\"h2responsesrate\":7,\"hitsrate\":5,\"httpmaxhdrfldlenpkts\":\"3\",\"httpmaxhdrszpkts\":\"3\",\"inactsvcs\":\"6\",\"invalidrequestresponse\":\"13\",\"invalidrequestresponsedropped\":\"13\",\"labelledconn\":\"8\",\"name\":\"elastic\",\"pktsrecvdrate\":8,\"pktssentrate\":8,\"primaryipaddress\":\"8.8.8.8\",\"primaryport\":80,\"pushlabel\":\"8\",\"reqretrycount\":\"3\",\"reqretrycountexceeded\":\"3\",\"requestbytesrate\":7,\"requestsrate\":5,\"responsebytesrate\":7,\"responsesrate\":5,\"sothreshold\":\"8\",\"state\":\"DOWN\",\"surgecount\":\"8\",\"svcsurgecount\":\"8\",\"svrbusyerrrate\":3,\"tcpmaxooopkts\":\"3\",\"toleratingttlbtransactions\":\"3\",\"toleratingttlbtransactionsrate\":1,\"totalconnreassemblyqueue75\":\"13\",\"totalconnreassemblyqueueflush\":\"3\",\"totalh2requests\":\"7\",\"totalh2responses\":\"7\",\"totalpktsrecvd\":\"7\",\"totalpktssent\":\"8\",\"totalrequestbytes\":\"7\",\"totalrequests\":\"5\",\"totalresponsebytes\":\"7\",\"totalresponses\":\"5\",\"totalsvrbusyerr\":\"3\",\"totcltttlbtransactions\":\"3\",\"tothits\":\"10\",\"totspillovers\":\"8\",\"totvserverdownbackuphits\":\"13\",\"type\":\"HTTP\",\"vslbhealth\":\"67\",\"vsvrsurgecount\":\"6\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "ip": [
            "8.8.8.8"
        ]
    },
    "server": {
        "ip": "8.8.8.8",
        "port": 80
    },
    "tags": [
        "preserve_original_event",
        "citrix_adc-lbvserver",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| citrix_adc.lbvserver.client.connections.current.count | Number of current client connections. | float |  | gauge |
| citrix_adc.lbvserver.client.connections.established.count | Number of client connections in ESTABLISHED state. | float |  | gauge |
| citrix_adc.lbvserver.client.response_time.application_performance_index | Vserver APDEX (Application Performance Index) index based on client response times. | float |  |  |
| citrix_adc.lbvserver.connections.actual.count | Number of current connections to the actual servers behind the virtual server. | float |  | gauge |
| citrix_adc.lbvserver.down.backup.hits | Number of times traffic was diverted to the backup vserver since the primary vserver was DOWN. | float |  | counter |
| citrix_adc.lbvserver.health | Health of the vserver. | float |  |  |
| citrix_adc.lbvserver.hit.count | Total vserver hits. | float |  | counter |
| citrix_adc.lbvserver.hit.rate | Rate (/s) counter for tothits. | float |  | gauge |
| citrix_adc.lbvserver.name | Name of the virtual server. | keyword |  |  |
| citrix_adc.lbvserver.packets.received.count | Total number of packets received by the service or virtual server. | float |  | counter |
| citrix_adc.lbvserver.packets.sent.count | Total number of packets sent. | float |  | counter |
| citrix_adc.lbvserver.packets.sent.rate | Rate (/s) counter for totalpktssent. | float |  | gauge |
| citrix_adc.lbvserver.protocol | Protocol associated with the vserver. | keyword |  |  |
| citrix_adc.lbvserver.request.deferred.count | Number of deferred requests on specific vserver. | float |  | counter |
| citrix_adc.lbvserver.request.deferred.rate | Rate (/s) counter for deferredreq. | float |  | gauge |
| citrix_adc.lbvserver.request.received.bytes.rate | Rate (/s) counter for totalrequestbytes. | float |  | gauge |
| citrix_adc.lbvserver.request.received.bytes.value | Total number of request bytes received on the service or virtual server. | float | byte | counter |
| citrix_adc.lbvserver.request.received.count | Total number of requests received on the service or virtual server. | float |  | counter |
| citrix_adc.lbvserver.request.received.rate | Rate (/s) counter for totalrequests. | float |  | gauge |
| citrix_adc.lbvserver.request.surge_queue.count | Number of requests in the surge queue. | float |  | gauge |
| citrix_adc.lbvserver.request.waiting.count | Number of requests waiting on specific vserver. | float |  | gauge |
| citrix_adc.lbvserver.requests_responses.dropped.count | Number invalid requests/responses dropped on the vserver. | float |  | counter |
| citrix_adc.lbvserver.requests_responses.invalid.count | Number invalid requests/responses on the vserver. | float |  | counter |
| citrix_adc.lbvserver.response.received.bytes.rate | Rate (/s) counter for totalresponsebytes. | float |  | gauge |
| citrix_adc.lbvserver.response.received.bytes.value | Number of response bytes received by the service or virtual server. | float | byte | counter |
| citrix_adc.lbvserver.response.received.count | Number of responses received on the service or virtual server. | float |  | counter |
| citrix_adc.lbvserver.response.received.rate | Rate (/s) counter for totalresponses. | float |  | gauge |
| citrix_adc.lbvserver.service.active.count | Number of ACTIVE services bound to a vserver. | float |  | gauge |
| citrix_adc.lbvserver.service.inactive.count | Number of INACTIVE services bound to a vserver. | float |  | gauge |
| citrix_adc.lbvserver.spillover.count | Number of times vserver experienced spill over. | float |  | counter |
| citrix_adc.lbvserver.state | Current state of the server. | keyword |  |  |
| citrix_adc.lbvserver.threshold.spillover | Spill Over Threshold set on the vserver. | float |  | gauge |
| citrix_adc.lbvserver.time_to_last_byte.avg | Average TTLB (Time To Last Byte) between the client and the server. | float |  | gauge |
| citrix_adc.lbvserver.transaction.frustrating.count | Frustrating transactions based on APDEX (Application Performance Index) threshold. | float |  | gauge |
| citrix_adc.lbvserver.transaction.tolerable.count | Tolerable transactions based on APDEX (Application Performance Index) threshold. | float |  | gauge |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |  |
| input.type | Type of Filebeat input. | keyword |  |  |
| related.ip | All of the IPs seen on your event. | ip |  |  |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |  |  |
| server.port | Port of the server. | long |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
