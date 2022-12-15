# Citrix ADC Integration

## Overview

The Citrix ADC integration allows you to monitor your Citrix ADC instance. Citrix ADC is an application delivery controller that performs application-specific traffic analysis to intelligently distribute, optimize, and secure Layer 4 - Layer 7 (L4–L7) network traffic for web applications.

Use the Citrix ADC integration to collect metrics related to the interface, lbvserver, and service. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

## Data streams

The Citrix ADC integration collects metrics data.

Metrics give you insight into the statistics of the Citrix ADC. Metrics data streams collected by the Citrix ADC integration include [interface](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/network/interface/), [lbvserver](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/lb/lbvserver/), and [service](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/basic/service/), so that the user could monitor and troubleshoot the performance of the Citrix ADC instances.

Note:
- Users can monitor and see the metrics inside the ingested documents for Citrix ADC in the logs-* index pattern from `Discover`.

## Compatibility

This integration has been tested against Citrix ADC `v13.0` and `v13.1`.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from Citrix ADC, you must know the host(s) and the administrator credentials for the Citrix ADC instance.

Host Configuration Format: `http[s]://host[:port]`

Example Host Configuration: `http://localhost:9080`

## Metrics reference

### Interface

This is the `interface` data stream. The Citrix ADC interfaces are numbered in slot/port notation. In addition to modifying the characteristics of individual interfaces, you can configure virtual LANs to restrict traffic to specific groups of hosts. `interface` data stream collects metrics related to id, state, inbound packets, outbound packets, and received packets.

An example event for `interface` looks as following:

```json
{
    "@timestamp": "2022-10-07T06:24:46.588Z",
    "agent": {
        "ephemeral_id": "6bbf5dd0-e14b-4006-ac77-ee175a9e81b8",
        "id": "6713ae74-2a36-4e79-bc7b-954d6b48d5bd",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "citrix_adc": {
        "interface": {
            "disabled": {
                "count": 0
            },
            "link": {
                "down_time": "00:00:11",
                "up_time": "4.06:45:16"
            },
            "mac": {
                "moved": {
                    "count": 0,
                    "rate": 0
                }
            },
            "packets": {
                "inbound": {
                    "dropped": {
                        "count": 2797172,
                        "rate": 32
                    },
                    "dropped_by_hardware": {
                        "count": 0,
                        "rate": 0
                    },
                    "error_free": {
                        "discarded": {
                            "count": 0,
                            "rate": 0
                        }
                    }
                },
                "outbound": {
                    "dropped_by_hardware": {
                        "count": 0,
                        "rate": 0
                    },
                    "error_free": {
                        "discarded": {
                            "count": 0,
                            "rate": 0
                        }
                    }
                },
                "received": {
                    "count": 5396347,
                    "jumbo": {
                        "count": 0,
                        "rate": 0
                    },
                    "multicast": {
                        "count": 278537,
                        "rate": 0
                    },
                    "rate": 38,
                    "tagged": {
                        "count": 0,
                        "rate": 0
                    }
                },
                "transmission": {
                    "dropped": {
                        "count": 0,
                        "rate": 0
                    }
                },
                "transmitted": {
                    "count": 2511171,
                    "jumbo": {
                        "count": 0,
                        "rate": 0
                    },
                    "rate": 5,
                    "tagged": {
                        "count": 0,
                        "rate": 0
                    }
                }
            },
            "received": {
                "bytes": {
                    "rate": 4603,
                    "value": 1103884030
                }
            },
            "stalled": {
                "count": 0
            },
            "state": "UP",
            "transmitted": {
                "bytes": {
                    "rate": 1924,
                    "value": 776571650
                }
            }
        }
    },
    "data_stream": {
        "dataset": "citrix_adc.interface",
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
        "created": "2022-10-07T06:24:46.588Z",
        "dataset": "citrix_adc.interface",
        "ingested": "2022-10-07T06:24:50Z",
        "kind": "event",
        "module": "citrix_adc",
        "original": "{\"curintfstate\":\"UP\",\"curlinkdowntime\":\"00:00:11\",\"curlinkstate\":\"DOWN\",\"curlinkuptime\":\"4.06:45:16\",\"errdroppedrxpkts\":\"2797172\",\"errdroppedrxpktsrate\":32,\"errdroppedtxpkts\":\"0\",\"errdroppedtxpktsrate\":0,\"errifindiscards\":\"0\",\"errifindiscardsrate\":0,\"errlinkhangs\":\"0\",\"errnicmuted\":\"0\",\"errpktrx\":\"0\",\"errpktrxrate\":0,\"errpkttx\":\"0\",\"errpkttxrate\":0,\"id\":\"0/1\",\"interfacealias\":\"\",\"jumbopktsreceived\":\"0\",\"jumbopktsreceivedrate\":0,\"jumbopktstransmitted\":\"0\",\"jumbopktstransmittedrate\":0,\"linkreinits\":\"0\",\"macmovedrate\":0,\"netscalerpktsrate\":6,\"nicerrdisables\":\"0\",\"nicerrifoutdiscards\":\"0\",\"nicerrifoutdiscardsrate\":0,\"nicmulticastpktsrate\":0,\"nicrxstalls\":\"0\",\"nicstsstalls\":\"0\",\"nictotmulticastpkts\":\"278537\",\"nictxstalls\":\"0\",\"rxbytesrate\":4603,\"rxcrcerrors\":\"0\",\"rxcrcerrorsrate\":0,\"rxlacpdu\":\"0\",\"rxlacpdurate\":0,\"rxpktsrate\":38,\"totmacmoved\":\"0\",\"totnetscalerpkts\":\"2493179\",\"totrxbytes\":\"1103884064\",\"totrxpkts\":\"5396347\",\"tottxbytes\":\"776571619\",\"tottxpkts\":\"2511171\",\"trunkpktsreceived\":\"0\",\"trunkpktsreceivedrate\":0,\"trunkpktstransmitted\":\"0\",\"trunkpktstransmittedrate\":0,\"txbytesrate\":1924,\"txlacpdu\":\"0\",\"txlacpdurate\":0,\"txpktsrate\":5}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "interface": {
        "id": "0/1"
    },
    "tags": [
        "preserve_original_event",
        "citrix_adc-interface",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| citrix_adc.interface.disabled.count | Number of times the specified interface is disabled by the NetScaler. | float |  | counter |
| citrix_adc.interface.link.down_time | Duration for which the link is DOWN. | keyword |  |  |
| citrix_adc.interface.link.up_time | Duration for which the link is UP. | keyword |  |  |
| citrix_adc.interface.mac.moved.count | Number of MAC moves between ports. | float |  | counter |
| citrix_adc.interface.mac.moved.rate | Rate (/s) counter for totmacmoved. | float |  | gauge |
| citrix_adc.interface.packets.inbound.dropped.count | Number of inbound packets dropped by the specified interface. | float |  | counter |
| citrix_adc.interface.packets.inbound.dropped.rate | Rate (/s) counter for errdroppedrxpkts. | float |  | gauge |
| citrix_adc.interface.packets.inbound.dropped_by_hardware.count | Number of inbound packets dropped by the hardware on a specified interface once the NetScaler appliance starts or the interface statistics are cleared. | float |  | counter |
| citrix_adc.interface.packets.inbound.dropped_by_hardware.rate | Rate (/s) counter for errpktrx. | float |  | gauge |
| citrix_adc.interface.packets.inbound.error_free.discarded.count | Number of error-free inbound packets discarded by the specified interface due to a lack of resources. | float |  | counter |
| citrix_adc.interface.packets.inbound.error_free.discarded.rate | Rate (/s) counter for errifindiscards. | float |  | gauge |
| citrix_adc.interface.packets.outbound.dropped_by_hardware.count | Number of outbound packets dropped by the hardware on a specified interface since the NetScaler appliance was started or the interface statistics were cleared. | float |  | counter |
| citrix_adc.interface.packets.outbound.dropped_by_hardware.rate | Rate (/s) counter for errpkttx. | float |  | gauge |
| citrix_adc.interface.packets.outbound.error_free.discarded.count | Number of error-free outbound packets discarded by the specified interface due to a lack of resources. | float |  | counter |
| citrix_adc.interface.packets.outbound.error_free.discarded.rate | Rate (/s) counter for nicerrifoutdiscards. | float |  | gauge |
| citrix_adc.interface.packets.received.count | Number of packets received by an interface since the NetScaler appliance was started or the interface statistics were cleared. | float |  | counter |
| citrix_adc.interface.packets.received.jumbo.count | Number of Jumbo Packets received on specified interface. | float |  | counter |
| citrix_adc.interface.packets.received.jumbo.rate | Rate (/s) counter for jumbopktsreceived. | float |  | gauge |
| citrix_adc.interface.packets.received.multicast.count | Number of multicast packets received by the specified interface since the NetScaler appliance was started or the interface statistics were cleared. | float |  | counter |
| citrix_adc.interface.packets.received.multicast.rate | Rate (/s) counter for nictotmulticastpkts. | float |  | gauge |
| citrix_adc.interface.packets.received.rate | Rate (/s) counter for totrxpkts. | float |  | gauge |
| citrix_adc.interface.packets.received.tagged.count | Number of Tagged Packets received on specified Trunk interface through Allowed VLan List. | float |  | counter |
| citrix_adc.interface.packets.received.tagged.rate | Rate (/s) counter for trunkpktsreceived. | float |  | gauge |
| citrix_adc.interface.packets.transmission.dropped.count | Number of packets dropped in transmission by the specified interface due to one of the following reasons. (1) VLAN mismatch. (2) Oversized packets. (3) Interface congestion. (4) Loopback packets sent on non loopback interface. | float |  |  |
| citrix_adc.interface.packets.transmission.dropped.rate | Rate (/s) counter for errdroppedtxpkts. | float |  |  |
| citrix_adc.interface.packets.transmitted.count | Number of packets transmitted by an interface since the NetScaler appliance was started or the interface statistics were cleared. | float |  | counter |
| citrix_adc.interface.packets.transmitted.jumbo.count | Number of Jumbo packets transmitted on specified interface by upper layer, with TSO enabled actual trasmission size could be non Jumbo. | float |  | counter |
| citrix_adc.interface.packets.transmitted.jumbo.rate | Rate (/s) counter for jumbopktstransmitted. | float |  | gauge |
| citrix_adc.interface.packets.transmitted.rate | Rate (/s) counter for tottxpkts. | float |  | gauge |
| citrix_adc.interface.packets.transmitted.tagged.count | Number of Tagged Packets transmitted on specified Trunk interface through Allowed VLan List. | float |  | counter |
| citrix_adc.interface.packets.transmitted.tagged.rate | Rate (/s) counter for trunkpktstransmitted. | float |  | gauge |
| citrix_adc.interface.received.bytes.rate | Rate (/s) counter for totrxbytes. | float |  | gauge |
| citrix_adc.interface.received.bytes.value | Number of bytes received by an interface since the NetScaler appliance was started or the interface statistics were cleared. | float | byte | counter |
| citrix_adc.interface.stalled.count | Number of times the interface stalled, when receiving packets, since the NetScaler appliance was started or the interface statistics were cleared. | float |  | counter |
| citrix_adc.interface.state | Current state of the specified interface. | keyword |  |  |
| citrix_adc.interface.transmitted.bytes.rate | Rate (/s) counter for tottxbytes. | float |  | gauge |
| citrix_adc.interface.transmitted.bytes.value | Number of bytes transmitted by an interface since the NetScaler appliance was started or the interface statistics were cleared. | float | byte | counter |
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
| interface.id | Interface ID as reported by an observer (typically SNMP interface ID). | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |


### Load Balancing Virtual Server

This is the `lbvserver` data stream. The load balancing server is logically located between the client and the server farm, and manages traffic flow to the servers in the server farm. `lbvserver` data stream collects metrics related to name, state, client connections, requests, and responses.

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
| citrix_adc.lbvserver.health | Health of the vserver. This gives percentage of UP services bound to the vserver. | float |  |  |
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


### Service

This is the `service` data stream. With the help of the service endpoint, metrics like throughput, client-server connections, request bytes can be collected along with other statistics for Service resources. `service` data stream collects metrics related to name, IP address, port, throughput, and transactions.

An example event for `service` looks as following:

```json
{
    "@timestamp": "2022-10-07T06:26:11.339Z",
    "agent": {
        "ephemeral_id": "2fa2a685-d35a-40a6-8212-7a9dd581d647",
        "id": "6713ae74-2a36-4e79-bc7b-954d6b48d5bd",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "citrix_adc": {
        "service": {
            "client_connection": {
                "count": 8
            },
            "primary": {
                "ip_address": "127.0.0.1",
                "port": 80
            },
            "request": {
                "bytes": {
                    "rate": 139,
                    "value": 8334520
                },
                "count": 15133,
                "rate": 0
            },
            "response": {
                "bytes": {
                    "rate": 316,
                    "value": 26482988
                },
                "count": 15133,
                "rate": 0
            },
            "reuse_pool": 2,
            "server": {
                "connection": {
                    "count": 2,
                    "established": {
                        "count": 2
                    }
                },
                "time_to_first_byte": {
                    "avg": 34
                }
            },
            "surge_queue": {
                "count": 0
            },
            "throughput": {
                "rate": 0,
                "value": 0
            },
            "transaction": {
                "active": {
                    "count": 0
                },
                "frustrating": {
                    "count": 0
                },
                "time_to_last_byte": {
                    "count": 0
                },
                "tolerable": {
                    "count": 0
                }
            }
        }
    },
    "data_stream": {
        "dataset": "citrix_adc.service",
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
        "created": "2022-10-07T06:26:11.339Z",
        "dataset": "citrix_adc.service",
        "ingested": "2022-10-07T06:26:14Z",
        "kind": "event",
        "module": "citrix_adc",
        "original": "{\"activetransactions\":\"0\",\"avgsvrttfb\":\"34\",\"curclntconnections\":\"8\",\"curload\":\"0\",\"curreusepool\":\"2\",\"cursrvrconnections\":\"2\",\"curtflags\":\"0\",\"frustratingttlbtransactions\":\"0\",\"httpmaxhdrfldlenpkts\":\"0\",\"httpmaxhdrszpkts\":\"0\",\"maxclients\":\"0\",\"name\":\"nshttpd-gui-127.0.0.1-80\",\"primaryipaddress\":\"127.0.0.1\",\"primaryport\":80,\"requestbytesrate\":139,\"requestsrate\":0,\"responsebytesrate\":316,\"responsesrate\":0,\"serviceorder\":\"0\",\"servicetype\":\"HTTP\",\"state\":\"UP\",\"surgecount\":\"0\",\"svrestablishedconn\":\"2\",\"tcpmaxooopkts\":\"0\",\"throughput\":\"0\",\"throughputrate\":0,\"toleratingttlbtransactions\":\"0\",\"totalconnreassemblyqueue75\":\"0\",\"totalconnreassemblyqueueflush\":\"0\",\"totalrequestbytes\":\"8334520\",\"totalrequests\":\"15133\",\"totalresponsebytes\":\"26482988\",\"totalresponses\":\"15133\",\"totsvrttlbtransactions\":\"0\",\"vsvrservicehits\":\"0\",\"vsvrservicehitsrate\":0}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "service": {
        "name": "nshttpd-gui-127.0.0.1-80",
        "state": "UP",
        "type": "HTTP"
    },
    "tags": [
        "preserve_original_event",
        "citrix_adc-service",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| citrix_adc.service.client_connection.count | Number of current client connections. | float |  | counter |
| citrix_adc.service.primary.ip_address | The IP address on which specific service is running. | ip |  |  |
| citrix_adc.service.primary.port | The port on which the service is running. | long |  |  |
| citrix_adc.service.request.bytes.rate | Rate (/s) counter for totalrequestbytes. | float |  | gauge |
| citrix_adc.service.request.bytes.value | Total number of request bytes received on specific service or virtual server. | float | byte | counter |
| citrix_adc.service.request.count | Total number of requests received on specific service or virtual server. | float |  | counter |
| citrix_adc.service.request.rate | Rate (/s) counter for totalrequests. | float |  | gauge |
| citrix_adc.service.response.bytes.rate | Rate (/s) counter for totalresponsebytes. | float |  | gauge |
| citrix_adc.service.response.bytes.value | Number of response bytes received by specific service or virtual server. | float | byte | counter |
| citrix_adc.service.response.count | Number of responses received on specific service or virtual server. | float |  | counter |
| citrix_adc.service.response.rate | Rate (/s) counter for totalresponses. | float |  | gauge |
| citrix_adc.service.reuse_pool | Number of requests in the idle queue/reuse pool. | float |  |  |
| citrix_adc.service.server.connection.count | Number of current connections to the actual servers behind the virtual server. | float |  | counter |
| citrix_adc.service.server.connection.established.count | Number of server connections in ESTABLISHED state. | float |  | counter |
| citrix_adc.service.server.time_to_first_byte.avg | Average TTFB (Time To First Byte) between the NetScaler appliance and the server. | float |  | gauge |
| citrix_adc.service.surge_queue.count | Number of requests in the surge queue. | float |  | counter |
| citrix_adc.service.throughput.rate | Rate (/s) counter for throughput. | float |  | gauge |
| citrix_adc.service.throughput.value | Number of bytes received or sent by specific service (Mbps). | float |  | counter |
| citrix_adc.service.transaction.active.count | Number of active transactions handled by specific service. | float |  | counter |
| citrix_adc.service.transaction.frustrating.count | Frustrating transactions based on APDEX (Application Performance Index) threshold (\>4T). | float |  | gauge |
| citrix_adc.service.transaction.time_to_last_byte.count | Total transactions where server TTLB (Time To Last Byte) is calculated. | float |  | counter |
| citrix_adc.service.transaction.tolerable.count | Tolerable transactions based on APDEX (Application Performance Index) threshold (\>T ;; \<4T). | float |  | counter |
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
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |  |  |
| service.state | Current state of the service. | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |

