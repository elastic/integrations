# Citrix ADC Integration

## Overview

The Citrix ADC integration allows you to monitor your Citrix ADC instance. Citrix ADC is an application delivery controller that performs application-specific traffic analysis to intelligently distribute, optimize, and secure Layer 4 - Layer 7 (L4–L7) network traffic for web applications.

Use the Citrix ADC integration to collect metrics related to the vpn. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

## Data streams

The Citrix ADC integration collects metrics data.

Metrics give you insight into the statistics of the Citrix ADC. Metrics data streams collected by the Citrix ADC integration include [vpn](https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/12.0/statistics/vpn/vpn/), so that the user could monitor and troubleshoot the performance of the Citrix ADC instances.

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

### VPN

This is the `vpn` data stream. Citrix VPN is the add-on that provides full Secure Sockets Layer (SSL) virtual private network (VPN) capabilities to Citrix Gateway, allowing users to access remote applications on internal networks securely.

An example event for `vpn` looks as following:

```json
{
    "@timestamp": "2022-10-10T11:42:13.787Z",
    "agent": {
        "ephemeral_id": "8fd05f47-0933-4b28-8412-6d4b6f365dff",
        "id": "98ae8a23-ea52-4679-b111-33a6d6e8db77",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "citrix_adc": {
        "vpn": {
            "client_server": {
                "request": {
                    "hit": {
                        "count": 16,
                        "rate": 16
                    }
                }
            },
            "configuration_request_served": {
                "count": 8,
                "rate": 8
            },
            "cps": {
                "failure": {
                    "count": 11,
                    "rate": 11
                },
                "success": {
                    "count": 4,
                    "rate": 11
                }
            },
            "file_system": {
                "request": {
                    "received": {
                        "count": 16,
                        "rate": 16
                    }
                }
            },
            "ica": {
                "license_failure": {
                    "count": 7,
                    "rate": 7
                }
            },
            "login_failed": {
                "license_unavailable": {
                    "count": 16
                }
            },
            "login_page": {
                "hits": 8
            },
            "socks": {
                "client_error": {
                    "count": 8,
                    "rate": 8
                },
                "connection": {
                    "request": {
                        "received": {
                            "count": 3,
                            "rate": 2
                        },
                        "sent": {
                            "count": 2,
                            "rate": 2
                        }
                    },
                    "response": {
                        "received": {
                            "count": 2,
                            "rate": 2
                        },
                        "sent": {
                            "count": 8,
                            "rate": 8
                        }
                    }
                },
                "method": {
                    "request": {
                        "received": {
                            "count": 17,
                            "rate": 17
                        },
                        "sent": {
                            "count": 17,
                            "rate": 17
                        }
                    },
                    "response": {
                        "received": {
                            "count": 3,
                            "rate": 3
                        },
                        "sent": {
                            "count": 3,
                            "rate": 3
                        }
                    }
                },
                "server_error": {
                    "count": 8,
                    "rate": 8
                }
            },
            "sta": {
                "connection": {
                    "failure": {
                        "count": 4,
                        "rate": 4
                    },
                    "success": {
                        "count": 4,
                        "rate": 4
                    }
                },
                "request": {
                    "sent": {
                        "count": 11,
                        "rate": 11
                    }
                },
                "response": {
                    "received": {
                        "count": 7,
                        "rate": 7
                    }
                }
            }
        }
    },
    "data_stream": {
        "dataset": "citrix_adc.vpn",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "98ae8a23-ea52-4679-b111-33a6d6e8db77",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "created": "2022-10-10T11:42:13.787Z",
        "dataset": "citrix_adc.vpn",
        "ingested": "2022-10-10T11:42:17Z",
        "kind": "event",
        "module": "citrix_adc",
        "original": "{\"errorcode\":0,\"message\":\"Done\",\"severity\":\"NONE\",\"vpn\":{\"cfghtmlserved\":\"8\",\"cfghtmlservedrate\":8,\"cpsconnfailure\":\"11\",\"cpsconnfailurerate\":11,\"cpsconnsuccess\":\"4\",\"cpsconnsuccessrate\":11,\"csconnsuccrate\":16,\"csgconnectedusersrate\":17,\"csgptktvalidatenotstarted\":\"5\",\"csgptktvalidatenotstartedrate\":5,\"csgrtktvalidatenotstarted\":\"9\",\"csgrtktvalidatenotstartedrate\":9,\"csgtotalconnectedusers\":\"9\",\"cshttpprobehit\":\"16\",\"cshttpprobehitrate\":16,\"csnonhttpprobehit\":\"16\",\"csnonhttpprobehitrate\":16,\"csrequesthit\":\"16\",\"csrequesthitrate\":16,\"dnsreqhit\":\"8\",\"dnsreqhitrate\":8,\"fsrequestrate\":16,\"icalicensefailure\":\"7\",\"icalicensefailurerate\":7,\"iipdisabledmipdisabled\":\"9\",\"iipdisabledmipdisabledrate\":9,\"iipdisabledmipused\":\"16\",\"iipdisabledmipusedrate\":12,\"iipfailedmipdisabled\":\"9\",\"iipfailedmipdisabledrate\":9,\"iipfailedmipused\":\"12\",\"iipfailedmipusedrate\":12,\"iipspillovermipused\":\"12\",\"iipspillovermipusedrate\":12,\"indexhtmlhit\":\"8\",\"indexhtmlnoserved\":\"8\",\"socksclienterror\":\"8\",\"socksclienterrorrate\":8,\"socksconnreqrcvd\":\"3\",\"socksconnreqrcvdrate\":2,\"socksconnreqsent\":\"2\",\"socksconnreqsentrate\":2,\"socksconnresprcvd\":\"2\",\"socksconnresprcvdrate\":2,\"socksconnrespsent\":\"8\",\"socksconnrespsentrate\":8,\"socksmethreqrcvd\":\"17\",\"socksmethreqrcvdrate\":17,\"socksmethreqsent\":\"17\",\"socksmethreqsentrate\":17,\"socksmethresprcvd\":\"3\",\"socksmethresprcvdrate\":3,\"socksmethrespsent\":\"3\",\"socksmethrespsentrate\":3,\"socksservererror\":\"8\",\"socksservererrorrate\":8,\"staconnfailure\":\"4\",\"staconnfailurerate\":4,\"staconnsuccess\":\"4\",\"staconnsuccessrate\":4,\"stamonfail\":\"5\",\"stamonfailrate\":5,\"stamonrcvd\":\"7\",\"stamonrcvdrate\":5,\"stamonsent\":\"7\",\"stamonsentrate\":7,\"stamonsucc\":\"5\",\"stamonsuccrate\":5,\"starequestsent\":\"11\",\"starequestsentrate\":11,\"staresponserecvd\":\"7\",\"staresponserecvdrate\":7,\"totalcsconnsucc\":\"16\",\"totalfsrequest\":\"16\",\"vpnlicensefail\":\"16\",\"winsrequesthit\":\"16\",\"winsrequesthitrate\":16}}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "citrix_adc-vpn",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| citrix_adc.vpn.client_server.request.hit.count | Number of SSL VPN tunnels formed between VPN server and client. | float | counter |
| citrix_adc.vpn.client_server.request.hit.rate | Rate (/s) counter for cpsconnsuccess. | float | gauge |
| citrix_adc.vpn.configuration_request_served.count | Number of client configuration requests received by VPN server. | float | counter |
| citrix_adc.vpn.configuration_request_served.rate | Rate (/s) counter for cfghtmlserved. | float | gauge |
| citrix_adc.vpn.cps.failure.count | Number of CPS connection failures. | float | counter |
| citrix_adc.vpn.cps.failure.rate | Rate (/s) counter for cpsconnfailure. | float | gauge |
| citrix_adc.vpn.cps.success.count | Number of CPS connection success. | float | counter |
| citrix_adc.vpn.cps.success.rate | Rate (/s) counter for cpsconnsuccess. | float | gauge |
| citrix_adc.vpn.file_system.request.received.count | Number of file system requests received by VPN server. | float | counter |
| citrix_adc.vpn.file_system.request.received.rate | Rate (/s) counter for totalfsrequest. | float | gauge |
| citrix_adc.vpn.ica.license_failure.count | Number of ICA (Independent Computing Architecture) license failures. | float | counter |
| citrix_adc.vpn.ica.license_failure.rate | Rate (/s) counter for icalicensefailure. | float | gauge |
| citrix_adc.vpn.login_failed.license_unavailable.count | Number of users not able to login because of license unavailability. | float | counter |
| citrix_adc.vpn.login_page.hits | Number of requests for VPN login page. | float | counter |
| citrix_adc.vpn.socks.client_error.count | Number of SOCKS client errors. | float | counter |
| citrix_adc.vpn.socks.client_error.rate | Rate (/s) counter for socksclienterror. | float | gauge |
| citrix_adc.vpn.socks.connection.request.received.count | Number of received SOCKS connect requests. | float | counter |
| citrix_adc.vpn.socks.connection.request.received.rate | Rate (/s) counter for socksconnreqrcvd. | float | gauge |
| citrix_adc.vpn.socks.connection.request.sent.count | Number of sent SOCKS connect requests. | float | counter |
| citrix_adc.vpn.socks.connection.request.sent.rate | Rate (/s) counter for socksconnreqsent. | float | gauge |
| citrix_adc.vpn.socks.connection.response.received.count | Number of received SOCKS connect responses. | float | counter |
| citrix_adc.vpn.socks.connection.response.received.rate | Rate (/s) counter for socksconnresprcvd. | float | gauge |
| citrix_adc.vpn.socks.connection.response.sent.count | Number of sent SOCKS connect responses. | float | counter |
| citrix_adc.vpn.socks.connection.response.sent.rate | Rate (/s) counter for socksconnrespsent. | float | gauge |
| citrix_adc.vpn.socks.method.request.received.count | Number of received SOCKS method requests. | float | counter |
| citrix_adc.vpn.socks.method.request.received.rate | Rate (/s) counter for socksmethreqrcvd. | float | gauge |
| citrix_adc.vpn.socks.method.request.sent.count | Number of sent SOCKS method requests. | float | counter |
| citrix_adc.vpn.socks.method.request.sent.rate | Rate (/s) counter for socksmethreqsent. | float | gauge |
| citrix_adc.vpn.socks.method.response.received.count | Number of received SOCKS method responses. | float | counter |
| citrix_adc.vpn.socks.method.response.received.rate | Rate (/s) counter for socksmethresprcvd. | float | gauge |
| citrix_adc.vpn.socks.method.response.sent.count | Number of sent SOCKS method responses. | float | counter |
| citrix_adc.vpn.socks.method.response.sent.rate | Rate (/s) counter for socksmethrespsent. | float | gauge |
| citrix_adc.vpn.socks.server_error.count | Number of SOCKS server errors. | float | counter |
| citrix_adc.vpn.socks.server_error.rate | Rate (/s) counter for socksservererror. | float | gauge |
| citrix_adc.vpn.sta.connection.failure.count | Number of STA (Secure Ticket Authority) connection failures. | float | counter |
| citrix_adc.vpn.sta.connection.failure.rate | Rate (/s) counter for staconnfailure. | float | gauge |
| citrix_adc.vpn.sta.connection.success.count | Number of STA (Secure Ticket Authority) connection success. | float | counter |
| citrix_adc.vpn.sta.connection.success.rate | Rate (/s) counter for staconnsuccess. | float | gauge |
| citrix_adc.vpn.sta.request.sent.count | Number of STA (Secure Ticket Authority) requests sent. | float | counter |
| citrix_adc.vpn.sta.request.sent.rate | Rate (/s) counter for starequestsent. | float | gauge |
| citrix_adc.vpn.sta.response.received.count | Number of STA (Secure Ticket Authority) responses received. | float | counter |
| citrix_adc.vpn.sta.response.received.rate | Rate (/s) counter for staresponserecvd. | float | gauge |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |
| input.type | Type of Filebeat input. | keyword |  |
| tags | List of keywords used to tag each event. | keyword |  |
