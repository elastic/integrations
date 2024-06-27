# Cybereason

## Overview

[Cybereason](https://www.cybereason.com/) is a cybersecurity company that specializes in endpoint detection and response (EDR) solutions to help organizations detect and respond to cyber threats. Cybereason's goal is to provide a comprehensive cybersecurity solution that helps organizations defend against a wide range of cyber threats, including malware, ransomware, and advanced persistent threats (APTs).

Use the Cybereason integration to collect and parse data from the REST APIs. Then visualize that data in Kibana.

## Compatibility

This module has been tested against the latest Cybereason On-Premises version **23.2**.

## Data streams

The Cybereason integration collects six types of logs: Logon Session, Malop Connection, Malop Process, Malware, Poll Malop and Suspicions Process.

**[Logon Session](https://api-doc.cybereason.com/en/latest/APIReference/QueryAPI/queryElementFeatures.html#logon-session-edr)** - This data stream helps security teams monitor and analyze logon sessions within their network, identifying potential threats and taking appropriate action to mitigate risks.

**[Malop Connection](https://api-doc.cybereason.com/en/latest/APIReference/QueryAPI/queryElementFeatures.html#connection-edr-and-xdr)** - This data stream provides detailed insights into network connections observed by the endpoint detection and response (EDR) system.

**[Malop Process](https://api-doc.cybereason.com/en/latest/APIReference/QueryAPI/queryElementFeatures.html#malop-process-edr)** - This data stream provides details about malicious processes detected within their environment, aiding in the detection and mitigation of security threats.

**[Malware](https://api-doc.cybereason.com/en/latest/APIReference/MalwareAPI/queryMalwareTypes.html#querymalware)** - This data stream provides detailed information about a malware detection event, including the detected file, its type, detection method, and additional metadata for analysis and response.

**[Poll Malop](https://api-doc.cybereason.com/en/latest/APIReference/MalopAPI/getMalopsMalware.html#getmalopsmalware)** - This data stream provides comprehensive information about Malops detected by Cybereason's EDR system, enabling security teams to analyze and respond to potential threats effectively.

**[Suspicions Process]()** - This data stream provides detailed information about processes that are suspected or deemed malicious within the endpoint detection and response (EDR) system.

**NOTE**: Suspicions Process has the same endpoint as the first three data streams, we have added a filter - `hasSuspicions : true` and some custom fields to get the logs related to suspicions.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.12.0**.

## Setup

### To collect logs through REST API, follow the below steps:

- Visit [this page](https://www.cybereason.com/platform/bundles) to deploy a Cybereason instance in your environment.
- Once deployed, you'll obtain the parameters such as host, port, username and password for configuring Cybereason integration within your Elasticsearch environment.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Cybereason.
3. Click on the "Cybereason" integration from the search results.
4. Click on the Add Cybereason Integration button to add the integration.
5. While adding the integration, please enter the following details to collect logs via REST API:
   - Host
   - Port
   - Username
   - Password
   - Initial Interval
   - Interval
   - Batch Size

## Logs Reference

### Logon Session

This is the `Logon Session` dataset.

#### Example

An example event for `logon_session` looks as following:

```json
{
    "@timestamp": "2024-03-13T12:20:35.086Z",
    "cybereason": {
        "logon_session": {
            "element_values": {
                "owner_machine": {
                    "element_values": [
                        {
                            "element_type": "Machine",
                            "guid": "_MlzCxCi55eyTiwX",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "desktop-f2nf4st",
                            "object": {
                                "ownermachine": "myd"
                            },
                            "simple_values": {
                                "machinesimple": "value"
                            }
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                },
                "processes": {
                    "element_values": [
                        {
                            "element_type": "MachineProcess",
                            "guid": "_MlzCxCi55eyTiwXYX",
                            "has_malops": true,
                            "has_suspicions": true,
                            "name": "desktop-f2nf4stgy",
                            "object": {
                                "process": "myd"
                            },
                            "simple_values": {
                                "processsimple": "value"
                            }
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 320
                },
                "remote_machine": {
                    "element_values": [
                        {
                            "element_type": "Remote",
                            "guid": "AAAAGKxw2bFBmcGUssss",
                            "has_malops": false,
                            "has_suspicions": true,
                            "name": "desktop-f2nf4stmjremote",
                            "object": {
                                "remote": "myd"
                            },
                            "simple_values": {
                                "remotesimple": "value"
                            }
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                },
                "user": {
                    "element_values": [
                        {
                            "element_type": "User",
                            "guid": "AAAAGKxw2bFBmcGU",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "desktop-f2nf4st\\eden",
                            "object": {
                                "user": "myd"
                            },
                            "simple_values": {
                                "usersimple": "value"
                            }
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                }
            },
            "evidence_map": {
                "evidence": "map"
            },
            "filter_data": {
                "group_by_value": "{guid=AAAAGKxw2bFBmcGU, __typename=User, elementDisplayName=desktop-f2nf4st\\eden, group=7af5074f-ab26-43b3-b0f1-acc962920615, hasSuspicions=false, hasMalops=false}",
                "sort_in_group_value": "hyefilter"
            },
            "guid_string": "_MlzC6rnLebZ2aBh",
            "is_malicious": false,
            "labels_ids": "l1",
            "malicious": false,
            "malop_priority": "HIGH",
            "simple_values": {
                "creation_time": {
                    "total_values": 1,
                    "values": [
                        "2024-03-13T12:20:35.086Z"
                    ]
                },
                "element_display_name": {
                    "total_values": 1,
                    "values": [
                        "Unknown host > desktop-f2nf4st"
                    ]
                },
                "group": {
                    "total_values": 1,
                    "values": [
                        "00000000-0000-0000-0000-000000000000"
                    ]
                },
                "logon_type": {
                    "total_values": 1,
                    "values": [
                        "SLT_RemoteInteractive"
                    ]
                }
            },
            "suspect": false,
            "suspicion_count": 0,
            "suspicions": {
                "xyz": "dhyg"
            },
            "suspicions_map": {
                "suspicions": "map"
            }
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "malware"
        ],
        "id": "_MlzC6rnLebZ2aBh",
        "kind": "alert",
        "original": "[{\"simpleValues\":{\"logonType\":{\"totalValues\":1,\"values\":[\"SLT_RemoteInteractive\"]},\"creationTime\":{\"totalValues\":1,\"values\":[\"1710332435086\"]},\"group\":{\"totalValues\":1,\"values\":[\"00000000-0000-0000-0000-000000000000\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"Unknown host > desktop-f2nf4st\"]}},\"elementValues\":{\"user\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"User\",\"guid\":\"AAAAGKxw2bFBmcGU\",\"name\":\"desktop-f2nf4st\\\\eden\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{\"user\":\"myd\"},\"simpleValues\":{\"usersimple\":\"value\"}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"remoteMachine\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"Remote\",\"guid\":\"AAAAGKxw2bFBmcGUssss\",\"name\":\"desktop-f2nf4stmjremote\",\"hasSuspicions\":true,\"hasMalops\":false,\"elementValues\":{\"remote\":\"myd\"},\"simpleValues\":{\"remotesimple\":\"value\"}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"ownerMachine\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"Machine\",\"guid\":\"_MlzCxCi55eyTiwX\",\"name\":\"desktop-f2nf4st\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{\"ownermachine\":\"myd\"},\"simpleValues\":{\"machinesimple\":\"value\"}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"processes\":{\"totalValues\":320,\"elementValues\":[{\"elementType\":\"MachineProcess\",\"guid\":\"_MlzCxCi55eyTiwXYX\",\"name\":\"desktop-f2nf4stgy\",\"hasSuspicions\":true,\"hasMalops\":true,\"elementValues\":{\"process\":\"myd\"},\"simpleValues\":{\"processsimple\":\"value\"}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0}},\"suspicions\":{\"xyz\":\"dhyg\"},\"filterData\":{\"sortInGroupValue\":\"hyefilter\",\"groupByValue\":\"{guid=AAAAGKxw2bFBmcGU, __typename=User, elementDisplayName=desktop-f2nf4st\\\\eden, group=7af5074f-ab26-43b3-b0f1-acc962920615, hasSuspicions=false, hasMalops=false}\"},\"isMalicious\":false,\"suspicionCount\":0,\"guidString\":\"_MlzC6rnLebZ2aBh\",\"labelsIds\":\"l1\",\"malopPriority\":\"HIGH\",\"suspect\":false,\"malicious\":false}, {\"suspicions\":\"map\"}, {\"evidence\":\"map\"}]",
        "type": [
            "info"
        ]
    },
    "related": {
        "user": [
            "AAAAGKxw2bFBmcGU",
            "desktop-f2nf4st\\eden"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields"
    ],
    "user": {
        "id": [
            "AAAAGKxw2bFBmcGU"
        ],
        "name": [
            "desktop-f2nf4st\\eden"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cybereason.logon_session.element_values.owner_machine.element_values.element_type |  | keyword |
| cybereason.logon_session.element_values.owner_machine.element_values.guid |  | keyword |
| cybereason.logon_session.element_values.owner_machine.element_values.has_malops |  | boolean |
| cybereason.logon_session.element_values.owner_machine.element_values.has_suspicions |  | boolean |
| cybereason.logon_session.element_values.owner_machine.element_values.name |  | keyword |
| cybereason.logon_session.element_values.owner_machine.element_values.object |  | flattened |
| cybereason.logon_session.element_values.owner_machine.element_values.simple_values |  | flattened |
| cybereason.logon_session.element_values.owner_machine.guessed_total |  | long |
| cybereason.logon_session.element_values.owner_machine.total_malicious |  | long |
| cybereason.logon_session.element_values.owner_machine.total_suspicious |  | long |
| cybereason.logon_session.element_values.owner_machine.total_values |  | long |
| cybereason.logon_session.element_values.processes.element_values.element_type |  | keyword |
| cybereason.logon_session.element_values.processes.element_values.guid |  | keyword |
| cybereason.logon_session.element_values.processes.element_values.has_malops |  | boolean |
| cybereason.logon_session.element_values.processes.element_values.has_suspicions |  | boolean |
| cybereason.logon_session.element_values.processes.element_values.name |  | keyword |
| cybereason.logon_session.element_values.processes.element_values.object |  | flattened |
| cybereason.logon_session.element_values.processes.element_values.simple_values |  | flattened |
| cybereason.logon_session.element_values.processes.guessed_total |  | long |
| cybereason.logon_session.element_values.processes.total_malicious |  | long |
| cybereason.logon_session.element_values.processes.total_suspicious |  | long |
| cybereason.logon_session.element_values.processes.total_values |  | long |
| cybereason.logon_session.element_values.remote_machine.element_values.element_type |  | keyword |
| cybereason.logon_session.element_values.remote_machine.element_values.guid |  | keyword |
| cybereason.logon_session.element_values.remote_machine.element_values.has_malops |  | boolean |
| cybereason.logon_session.element_values.remote_machine.element_values.has_suspicions |  | boolean |
| cybereason.logon_session.element_values.remote_machine.element_values.name |  | keyword |
| cybereason.logon_session.element_values.remote_machine.element_values.object |  | flattened |
| cybereason.logon_session.element_values.remote_machine.element_values.simple_values |  | flattened |
| cybereason.logon_session.element_values.remote_machine.guessed_total |  | long |
| cybereason.logon_session.element_values.remote_machine.total_malicious |  | long |
| cybereason.logon_session.element_values.remote_machine.total_suspicious |  | long |
| cybereason.logon_session.element_values.remote_machine.total_values |  | long |
| cybereason.logon_session.element_values.user.element_values.element_type |  | keyword |
| cybereason.logon_session.element_values.user.element_values.guid |  | keyword |
| cybereason.logon_session.element_values.user.element_values.has_malops |  | boolean |
| cybereason.logon_session.element_values.user.element_values.has_suspicions |  | boolean |
| cybereason.logon_session.element_values.user.element_values.name |  | keyword |
| cybereason.logon_session.element_values.user.element_values.object |  | flattened |
| cybereason.logon_session.element_values.user.element_values.simple_values |  | flattened |
| cybereason.logon_session.element_values.user.guessed_total |  | long |
| cybereason.logon_session.element_values.user.total_malicious |  | long |
| cybereason.logon_session.element_values.user.total_suspicious |  | long |
| cybereason.logon_session.element_values.user.total_values |  | long |
| cybereason.logon_session.evidence_map |  | flattened |
| cybereason.logon_session.filter_data.group_by_value |  | keyword |
| cybereason.logon_session.filter_data.sort_in_group_value |  | keyword |
| cybereason.logon_session.guid_string |  | keyword |
| cybereason.logon_session.is_malicious |  | boolean |
| cybereason.logon_session.labels_ids |  | keyword |
| cybereason.logon_session.malicious |  | boolean |
| cybereason.logon_session.malop_priority |  | keyword |
| cybereason.logon_session.simple_values.creation_time.total_values |  | long |
| cybereason.logon_session.simple_values.creation_time.values |  | date |
| cybereason.logon_session.simple_values.element_display_name.total_values |  | long |
| cybereason.logon_session.simple_values.element_display_name.values |  | keyword |
| cybereason.logon_session.simple_values.group.total_values |  | long |
| cybereason.logon_session.simple_values.group.values |  | keyword |
| cybereason.logon_session.simple_values.logon_type.total_values |  | long |
| cybereason.logon_session.simple_values.logon_type.values |  | keyword |
| cybereason.logon_session.suspect |  | boolean |
| cybereason.logon_session.suspicion_count |  | long |
| cybereason.logon_session.suspicions |  | flattened |
| cybereason.logon_session.suspicions_map |  | flattened |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Malop Connection

This is the `Malop Connection` dataset.

#### Example

An example event for `malop_connection` looks as following:

```json
{
    "@timestamp": "2024-03-13T11:54:39.973Z",
    "cybereason": {
        "malop_connection": {
            "element_values": {
                "dns_query": {
                    "element_values": [
                        {
                            "element_type": "Machine",
                            "guid": "7vCmFBCi55eyTiwX",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "dim-win10"
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                },
                "owner_machine": {
                    "element_values": [
                        {
                            "element_type": "Machine",
                            "guid": "7vCmFBCi55eyTiwX",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "dim-win10",
                            "object": {
                                "pole": "bye"
                            }
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                },
                "owner_process": {
                    "element_values": [
                        {
                            "element_type": "Process",
                            "guid": "7vCmFPstj36nuaBO",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "backgroundtaskhost.exe",
                            "object": {
                                "user": {
                                    "elementValues": [
                                        {
                                            "elementType": "User",
                                            "guid": "AAAAGGZ3xLXVm27e",
                                            "hasMalops": false,
                                            "hasSuspicions": false,
                                            "name": "cy\\cymulator",
                                            "simpleValues": {
                                                "ok": "lope"
                                            }
                                        }
                                    ],
                                    "guessedTotal": 0,
                                    "totalMalicious": 0,
                                    "totalSuspicious": 0,
                                    "totalValues": 1
                                }
                            }
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                },
                "owner_process_user": {
                    "element_values": [
                        {
                            "element_type": "User",
                            "guid": "AAAAGGZ3xLXVm27e",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "cy\\cymulator"
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                }
            },
            "evidence_map": {
                "evidence": "map"
            },
            "filter_data": {
                "group_by_value": "81.2.69.192:50394 > 81.2.69.142:443",
                "sort_in_group_value": "filter"
            },
            "guid_string": "7vCmFD3khy-bwG9X",
            "is_malicious": false,
            "labels_ids": "labelids",
            "malicious": false,
            "malop_priority": "MEDIUM",
            "simple_values": {
                "accessed_by_malware_evidence": {
                    "total_values": 1,
                    "values": [
                        false
                    ]
                },
                "aggregated_received_bytes_count": {
                    "total_values": 1,
                    "values": [
                        6811
                    ]
                },
                "aggregated_transmitted_bytes_count": {
                    "total_values": 1,
                    "values": [
                        4098
                    ]
                },
                "calculated_creation_time": {
                    "total_values": 1,
                    "values": [
                        "2024-03-13T11:54:39.973Z"
                    ]
                },
                "direction": {
                    "total_values": 1,
                    "values": [
                        "OUTGOING"
                    ]
                },
                "element_display_name": {
                    "total_values": 1,
                    "values": [
                        "81.2.69.192:50394 > 81.2.69.142:443"
                    ]
                },
                "end_time": {
                    "total_values": 1,
                    "values": [
                        "2024-03-13T11:55:40.803Z"
                    ]
                },
                "group": {
                    "total_values": 1,
                    "values": [
                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                    ]
                },
                "local_port": {
                    "total_values": 1,
                    "values": [
                        50394
                    ]
                },
                "port_type": {
                    "total_values": 1,
                    "values": [
                        "SERVICE_HTTP"
                    ]
                },
                "remote_address_country_name": {
                    "total_values": 1,
                    "values": [
                        "United States"
                    ]
                },
                "remote_port": {
                    "total_values": 1,
                    "values": [
                        443
                    ]
                },
                "server_address": {
                    "total_values": 1,
                    "values": [
                        "0.0.0.0"
                    ]
                },
                "server_port": {
                    "total_values": 1,
                    "values": [
                        443
                    ]
                },
                "state": {
                    "total_values": 1,
                    "values": [
                        "CONNECTION_OPEN"
                    ]
                },
                "transport_protocol": {
                    "total_values": 1,
                    "values": [
                        "TCP"
                    ]
                }
            },
            "suspect": false,
            "suspicion_count": 0,
            "suspicions": {
                "malop": "connection"
            },
            "suspicions_map": {
                "suspicions": "map"
            }
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "network"
        ],
        "end": "2024-03-13T11:55:40.803Z",
        "id": "7vCmFD3khy-bwG9X",
        "kind": "alert",
        "original": "[{\"simpleValues\":{\"remoteAddressCountryName\":{\"totalValues\":1,\"values\":[\"United States\"]},\"aggregatedReceivedBytesCount\":{\"totalValues\":1,\"values\":[\"6811\"]},\"endTime\":{\"totalValues\":1,\"values\":[\"1710330940803\"]},\"state\":{\"totalValues\":1,\"values\":[\"CONNECTION_OPEN\"]},\"portType\":{\"totalValues\":1,\"values\":[\"SERVICE_HTTP\"]},\"transportProtocol\":{\"totalValues\":1,\"values\":[\"TCP\"]},\"accessedByMalwareEvidence\":{\"totalValues\":1,\"values\":[\"false\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"81.2.69.192:50394 > 81.2.69.142:443\"]},\"aggregatedTransmittedBytesCount\":{\"totalValues\":1,\"values\":[\"4098\"]},\"localPort\":{\"totalValues\":1,\"values\":[\"50394\"]},\"serverAddress\":{\"totalValues\":1,\"values\":[\"0.0.0.0\"]},\"serverPort\":{\"totalValues\":1,\"values\":[\"443\"]},\"calculatedCreationTime\":{\"totalValues\":1,\"values\":[\"1710330879973\"]},\"remotePort\":{\"totalValues\":1,\"values\":[\"443\"]},\"direction\":{\"totalValues\":1,\"values\":[\"OUTGOING\"]}},\"elementValues\":{\"ownerMachine\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"Machine\",\"guid\":\"7vCmFBCi55eyTiwX\",\"name\":\"dim-win10\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{\"pole\":\"bye\"},\"simpleValues\":{}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"dnsQuery\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"Machine\",\"guid\":\"7vCmFBCi55eyTiwX\",\"name\":\"dim-win10\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"ownerProcess\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"Process\",\"guid\":\"7vCmFPstj36nuaBO\",\"name\":\"backgroundtaskhost.exe\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{\"user\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"User\",\"guid\":\"AAAAGGZ3xLXVm27e\",\"name\":\"cy\\\\cymulator\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"ok\":\"lope\"}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0}},\"simpleValues\":{}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"ownerProcess.user\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"User\",\"guid\":\"AAAAGGZ3xLXVm27e\",\"name\":\"cy\\\\cymulator\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0}},\"suspicions\":{\"malop\":\"connection\"},\"filterData\":{\"sortInGroupValue\":\"filter\",\"groupByValue\":\"81.2.69.192:50394 > 81.2.69.142:443\"},\"isMalicious\":false,\"suspicionCount\":0,\"guidString\":\"7vCmFD3khy-bwG9X\",\"labelsIds\":\"labelids\",\"malopPriority\":\"MEDIUM\",\"suspect\":false,\"malicious\":false}, {\"suspicions\":\"map\"}, {\"evidence\":\"map\"}]",
        "type": [
            "connection"
        ]
    },
    "network": {
        "transport": "TCP"
    },
    "process": {
        "real_user": {
            "id": [
                "7vCmFBCi55eyTiwX"
            ],
            "name": [
                "dim-win10"
            ]
        }
    },
    "related": {
        "ip": [
            "0.0.0.0"
        ],
        "user": [
            "7vCmFBCi55eyTiwX",
            "dim-win10"
        ]
    },
    "server": {
        "address": [
            "0.0.0.0"
        ],
        "ip": "0.0.0.0",
        "port": 443
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cybereason.malop_connection.element_values.dns_query.element_values.element_type |  | keyword |
| cybereason.malop_connection.element_values.dns_query.element_values.guid |  | keyword |
| cybereason.malop_connection.element_values.dns_query.element_values.has_malops | Indicates whether or not the connection is associated with any Malops. | boolean |
| cybereason.malop_connection.element_values.dns_query.element_values.has_suspicions | Indicates whether or not the connection is associated with any suspicions. | boolean |
| cybereason.malop_connection.element_values.dns_query.element_values.name |  | keyword |
| cybereason.malop_connection.element_values.dns_query.element_values.object |  | flattened |
| cybereason.malop_connection.element_values.dns_query.element_values.simple_values |  | flattened |
| cybereason.malop_connection.element_values.dns_query.guessed_total |  | long |
| cybereason.malop_connection.element_values.dns_query.total_malicious |  | long |
| cybereason.malop_connection.element_values.dns_query.total_suspicious |  | long |
| cybereason.malop_connection.element_values.dns_query.total_values |  | long |
| cybereason.malop_connection.element_values.owner_machine.element_values.element_type |  | keyword |
| cybereason.malop_connection.element_values.owner_machine.element_values.guid |  | keyword |
| cybereason.malop_connection.element_values.owner_machine.element_values.has_malops |  | boolean |
| cybereason.malop_connection.element_values.owner_machine.element_values.has_suspicions |  | boolean |
| cybereason.malop_connection.element_values.owner_machine.element_values.name |  | keyword |
| cybereason.malop_connection.element_values.owner_machine.element_values.object |  | flattened |
| cybereason.malop_connection.element_values.owner_machine.element_values.simple_values |  | flattened |
| cybereason.malop_connection.element_values.owner_machine.guessed_total |  | long |
| cybereason.malop_connection.element_values.owner_machine.total_malicious |  | long |
| cybereason.malop_connection.element_values.owner_machine.total_suspicious |  | long |
| cybereason.malop_connection.element_values.owner_machine.total_values |  | long |
| cybereason.malop_connection.element_values.owner_process.element_values.element_type |  | keyword |
| cybereason.malop_connection.element_values.owner_process.element_values.guid |  | keyword |
| cybereason.malop_connection.element_values.owner_process.element_values.has_malops |  | boolean |
| cybereason.malop_connection.element_values.owner_process.element_values.has_suspicions |  | boolean |
| cybereason.malop_connection.element_values.owner_process.element_values.name |  | keyword |
| cybereason.malop_connection.element_values.owner_process.element_values.object |  | flattened |
| cybereason.malop_connection.element_values.owner_process.element_values.simple_values |  | flattened |
| cybereason.malop_connection.element_values.owner_process.guessed_total |  | long |
| cybereason.malop_connection.element_values.owner_process.total_malicious |  | long |
| cybereason.malop_connection.element_values.owner_process.total_suspicious |  | long |
| cybereason.malop_connection.element_values.owner_process.total_values |  | long |
| cybereason.malop_connection.element_values.owner_process_user.element_values.element_type |  | keyword |
| cybereason.malop_connection.element_values.owner_process_user.element_values.guid |  | keyword |
| cybereason.malop_connection.element_values.owner_process_user.element_values.has_malops |  | boolean |
| cybereason.malop_connection.element_values.owner_process_user.element_values.has_suspicions |  | boolean |
| cybereason.malop_connection.element_values.owner_process_user.element_values.name |  | keyword |
| cybereason.malop_connection.element_values.owner_process_user.element_values.object |  | flattened |
| cybereason.malop_connection.element_values.owner_process_user.element_values.simple_values |  | flattened |
| cybereason.malop_connection.element_values.owner_process_user.guessed_total |  | long |
| cybereason.malop_connection.element_values.owner_process_user.total_malicious |  | long |
| cybereason.malop_connection.element_values.owner_process_user.total_suspicious |  | long |
| cybereason.malop_connection.element_values.owner_process_user.total_values |  | long |
| cybereason.malop_connection.evidence_map |  | flattened |
| cybereason.malop_connection.filter_data.group_by_value | The value by which the results are sorted. | keyword |
| cybereason.malop_connection.filter_data.sort_in_group_value | The unique numerical value Cybereason assigned to the results group. | keyword |
| cybereason.malop_connection.guid_string |  | keyword |
| cybereason.malop_connection.is_malicious |  | boolean |
| cybereason.malop_connection.labels_ids |  | keyword |
| cybereason.malop_connection.malicious |  | boolean |
| cybereason.malop_connection.malop_priority |  | keyword |
| cybereason.malop_connection.simple_values.accessed_by_malware_evidence.total_values |  | long |
| cybereason.malop_connection.simple_values.accessed_by_malware_evidence.values |  | boolean |
| cybereason.malop_connection.simple_values.aggregated_received_bytes_count.total_values |  | long |
| cybereason.malop_connection.simple_values.aggregated_received_bytes_count.values |  | long |
| cybereason.malop_connection.simple_values.aggregated_transmitted_bytes_count.total_values |  | long |
| cybereason.malop_connection.simple_values.aggregated_transmitted_bytes_count.values |  | long |
| cybereason.malop_connection.simple_values.calculated_creation_time.total_values |  | long |
| cybereason.malop_connection.simple_values.calculated_creation_time.values |  | date |
| cybereason.malop_connection.simple_values.direction.total_values |  | long |
| cybereason.malop_connection.simple_values.direction.values |  | keyword |
| cybereason.malop_connection.simple_values.element_display_name.total_values |  | long |
| cybereason.malop_connection.simple_values.element_display_name.values |  | keyword |
| cybereason.malop_connection.simple_values.end_time.total_values |  | long |
| cybereason.malop_connection.simple_values.end_time.values | The end time (in epoch) of the period during which to search. | date |
| cybereason.malop_connection.simple_values.group.total_values |  | long |
| cybereason.malop_connection.simple_values.group.values |  | keyword |
| cybereason.malop_connection.simple_values.local_port.total_values |  | long |
| cybereason.malop_connection.simple_values.local_port.values |  | long |
| cybereason.malop_connection.simple_values.port_type.total_values |  | long |
| cybereason.malop_connection.simple_values.port_type.values |  | keyword |
| cybereason.malop_connection.simple_values.remote_address_country_name.total_values |  | long |
| cybereason.malop_connection.simple_values.remote_address_country_name.values |  | keyword |
| cybereason.malop_connection.simple_values.remote_port.total_values |  | long |
| cybereason.malop_connection.simple_values.remote_port.values |  | long |
| cybereason.malop_connection.simple_values.server_address.total_values |  | long |
| cybereason.malop_connection.simple_values.server_address.values |  | ip |
| cybereason.malop_connection.simple_values.server_port.total_values |  | long |
| cybereason.malop_connection.simple_values.server_port.values |  | long |
| cybereason.malop_connection.simple_values.state.total_values |  | long |
| cybereason.malop_connection.simple_values.state.values |  | keyword |
| cybereason.malop_connection.simple_values.transport_protocol.total_values |  | long |
| cybereason.malop_connection.simple_values.transport_protocol.values |  | keyword |
| cybereason.malop_connection.suspect |  | boolean |
| cybereason.malop_connection.suspicion_count |  | long |
| cybereason.malop_connection.suspicions |  | flattened |
| cybereason.malop_connection.suspicions_map |  | flattened |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Malop Process

This is the `Malop Process` dataset.

#### Example

An example event for `malop_process` looks as following:

```json
{
    "@timestamp": "2023-12-28T19:03:51.785Z",
    "cybereason": {
        "malop_process": {
            "element_values": {
                "affected_machines": {
                    "element_values": [
                        {
                            "element_type": "Machine",
                            "guid": "zpP73xCi55eyTiwX",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "cybereason",
                            "object": {
                                "element": "values"
                            },
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "cybereason"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73xCi55eyTiwX"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        false
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        false
                                    ]
                                }
                            }
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                },
                "affected_users": {
                    "element_values": [
                        {
                            "element_type": "User",
                            "guid": "AAAAGAJYAICT5xYW",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "cybereason\\theavengers",
                            "object": {
                                "values": "element"
                            },
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "cybereason\\theavengers"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "AAAAGAJYAICT5xYW"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        false
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        false
                                    ]
                                }
                            }
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                },
                "files_to_remediate": {
                    "element_values": [
                        {
                            "element_type": "File",
                            "guid": "zpP7358Lbsf7z787",
                            "has_malops": false,
                            "has_suspicions": true,
                            "name": "x64cymulateprocesshider.exe",
                            "object": {
                                "files": "remediate"
                            },
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "x64cymulateprocesshider.exe"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP7358Lbsf7z787"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        false
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                }
                            }
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 1,
                    "total_values": 1
                },
                "primary_root_cause_elements": {
                    "element_values": [
                        {
                            "element_type": "Process",
                            "guid": "zpP73wfcKRFKvnZa",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73wfcKRFKvnZa"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73yUewMOXCNBN",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "object": {
                                "values": "primaryroot"
                            },
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73yUewMOXCNBN"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73wdciiw3CcZ9",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73wdciiw3CcZ9"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73zALshBfA7mQ",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73zALshBfA7mQ"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP736Yq9t-ujawF",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP736Yq9t-ujawF"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP736adtvfQP86p",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP736adtvfQP86p"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73yUHiaZd-JI6",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73yUHiaZd-JI6"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP733Hfwc2Ol2KV",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP733Hfwc2Ol2KV"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73zlRSCV3N9Si",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73zlRSCV3N9Si"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73-Mvct_YhLo2",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73-Mvct_YhLo2"
                                    ]
                                }
                            }
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 10
                },
                "root_cause_elements": {
                    "element_values": [
                        {
                            "element_type": "Process",
                            "guid": "zpP735vQl83mbAFk",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "object": {
                                "element": "root"
                            },
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP735vQl83mbAFk"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP733MJZQ5ua9PD",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP733MJZQ5ua9PD"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73wfcKRFKvnZa",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73wfcKRFKvnZa"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73yUewMOXCNBN",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73yUewMOXCNBN"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73wdciiw3CcZ9",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73wdciiw3CcZ9"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73-slLQbqr1eb",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73-slLQbqr1eb"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73xTlNawf6qox",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73xTlNawf6qox"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP736adtvfQP86p",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP736adtvfQP86p"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP732Q23xdwLJhh",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP732Q23xdwLJhh"
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73zlRSCV3N9Si",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73zlRSCV3N9Si"
                                    ]
                                }
                            }
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 10
                },
                "suspects": {
                    "element_values": [
                        {
                            "element_type": "Process",
                            "guid": "zpP735vQl83mbAFk",
                            "has_malops": true,
                            "has_suspicions": true,
                            "name": "injected (chain of injections)",
                            "object": {
                                "type": "suspects"
                            },
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP735vQl83mbAFk"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP733MJZQ5ua9PD",
                            "has_malops": true,
                            "has_suspicions": true,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP733MJZQ5ua9PD"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73wfcKRFKvnZa",
                            "has_malops": true,
                            "has_suspicions": true,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73wfcKRFKvnZa"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73yUewMOXCNBN",
                            "has_malops": true,
                            "has_suspicions": true,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73yUewMOXCNBN"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73wdciiw3CcZ9",
                            "has_malops": true,
                            "has_suspicions": true,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73wdciiw3CcZ9"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73-slLQbqr1eb",
                            "has_malops": true,
                            "has_suspicions": true,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73-slLQbqr1eb"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73xTlNawf6qox",
                            "has_malops": true,
                            "has_suspicions": true,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73xTlNawf6qox"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP736adtvfQP86p",
                            "has_malops": true,
                            "has_suspicions": true,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP736adtvfQP86p"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP732Q23xdwLJhh",
                            "has_malops": true,
                            "has_suspicions": true,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP732Q23xdwLJhh"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                }
                            }
                        },
                        {
                            "element_type": "Process",
                            "guid": "zpP73zlRSCV3N9Si",
                            "has_malops": true,
                            "has_suspicions": true,
                            "name": "injected (chain of injections)",
                            "simple_values": {
                                "element_display_name": {
                                    "total_values": 1,
                                    "values": [
                                        "injected (chain of injections)"
                                    ]
                                },
                                "group": {
                                    "total_values": 1,
                                    "values": [
                                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                                    ]
                                },
                                "guid": {
                                    "total_values": 1,
                                    "values": [
                                        "zpP73zlRSCV3N9Si"
                                    ]
                                },
                                "has_malops": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                },
                                "has_suspicions": {
                                    "total_values": 1,
                                    "values": [
                                        true
                                    ]
                                }
                            }
                        }
                    ],
                    "guessedTotal": 0,
                    "total_malicious": 10,
                    "total_suspicious": 10,
                    "total_values": 10
                }
            },
            "evidence_map": {
                "evidence": "map"
            },
            "filter_data": {
                "group_by_value": "NONE_MALOP_ACTIVITY_TYPE",
                "sort_in_group_value": "hello"
            },
            "guid_string": "AAAA0xquIk3X9oQ_",
            "is_malicious": false,
            "labels_ids": "lbl2",
            "malicious": false,
            "malop_priority": "LOW",
            "simple_values": {
                "all_ransomware_processes_suspended": {
                    "total_values": 1,
                    "values": [
                        false
                    ]
                },
                "creation_time": {
                    "total_values": 1,
                    "values": [
                        "2023-12-28T19:01:46.501Z"
                    ]
                },
                "decision_feature": {
                    "total_values": 1,
                    "values": [
                        "Process.maliciousByCodeInjection(Malop decision)"
                    ]
                },
                "decision_feature_set": {
                    "total_values": 1,
                    "values": [
                        "Process.maliciousByCodeInjection(Malop decision)"
                    ]
                },
                "detection_type": {
                    "total_values": 1,
                    "values": [
                        "PROCESS_INJECTION"
                    ]
                },
                "has_ransomware_suspended_processes": {
                    "total_values": 1,
                    "values": [
                        false
                    ]
                },
                "icon_base64": {
                    "total_values": 1,
                    "values": [
                        "base"
                    ]
                },
                "is_blocked": {
                    "total_values": 1,
                    "values": [
                        false
                    ]
                },
                "malop": {
                    "activity_types": {
                        "total_values": 2,
                        "values": [
                            "NONE_MALOP_ACTIVITY_TYPE",
                            "MALICIOUS_INFECTION"
                        ]
                    },
                    "last_update_time": {
                        "total_values": 1,
                        "values": [
                            "2023-12-28T19:03:51.785Z"
                        ]
                    },
                    "start_time": {
                        "total_values": 1,
                        "values": [
                            "2023-12-28T18:59:35.356Z"
                        ]
                    }
                },
                "root_cause_element": {
                    "company_product": {
                        "total_values": 1,
                        "values": [
                            "product"
                        ]
                    },
                    "hashes": {
                        "total_values": 1,
                        "values": [
                            "nbvgyui765tghnxxx"
                        ]
                    },
                    "names": {
                        "total_values": 1,
                        "values": [
                            "injected (chain of injections)"
                        ]
                    },
                    "types": {
                        "total_values": 1,
                        "values": [
                            "Process"
                        ]
                    }
                },
                "total": {
                    "number_of": {
                        "incoming_connections": {
                            "total_values": 1,
                            "values": [
                                768
                            ]
                        },
                        "outgoing_connections": {
                            "total_values": 1,
                            "values": [
                                23
                            ]
                        }
                    },
                    "received_bytes": {
                        "total_values": 1,
                        "values": [
                            76
                        ]
                    },
                    "transmitted_bytes": {
                        "total_values": 1,
                        "values": [
                            90
                        ]
                    }
                }
            },
            "suspect": false,
            "suspicion_count": 0,
            "suspicions": {
                "connectingToBlackListAddressSuspicion": 1710261170916
            },
            "suspicions_map": {
                "suspicions": "map"
            }
        }
    },
    "destination": {
        "bytes": 76
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "malware"
        ],
        "created": "2023-12-28T19:01:46.501Z",
        "id": "AAAA0xquIk3X9oQ_",
        "kind": "alert",
        "original": "[{\"simpleValues\":{\"hasRansomwareSuspendedProcesses\":{\"totalValues\":1,\"values\":[\"false\"]},\"decisionFeatureSet\":{\"totalValues\":1,\"values\":[\"Process.maliciousByCodeInjection(Malop decision)\"]},\"decisionFeature\":{\"totalValues\":1,\"values\":[\"Process.maliciousByCodeInjection(Malop decision)\"]},\"detectionType\":{\"totalValues\":1,\"values\":[\"PROCESS_INJECTION\"]},\"malopActivityTypes\":{\"totalValues\":2,\"values\":[\"NONE_MALOP_ACTIVITY_TYPE\",\"MALICIOUS_INFECTION\"]},\"creationTime\":{\"totalValues\":1,\"values\":[\"1703790106501\"]},\"isBlocked\":{\"totalValues\":1,\"values\":[\"false\"]},\"rootCauseElementTypes\":{\"totalValues\":1,\"values\":[\"Process\"]},\"rootCauseElementCompanyProduct\":{\"totalValues\":1,\"values\":[\"product\"]},\"rootCauseElementHashes\":{\"totalValues\":1,\"values\":[\"nbvgyui765tghnxxx\"]},\"iconBase64\":{\"totalValues\":1,\"values\":[\"base\"]},\"malopStartTime\":{\"totalValues\":1,\"values\":[\"1703789975356\"]},\"rootCauseElementNames\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]},\"totalNumberOfIncomingConnections\":{\"totalValues\":1,\"values\":[768]},\"totalNumberOfOutgoingConnections\":{\"totalValues\":1,\"values\":[23]},\"totalReceivedBytes\":{\"totalValues\":1,\"values\":[76]},\"totalTransmittedBytes\":{\"totalValues\":1,\"values\":[90]},\"malopLastUpdateTime\":{\"totalValues\":1,\"values\":[\"1703790231785\"]},\"allRansomwareProcessesSuspended\":{\"totalValues\":1,\"values\":[\"false\"]}},\"elementValues\":{\"suspects\":{\"totalValues\":10,\"elementValues\":[{\"elementType\":\"Process\",\"guid\":\"zpP735vQl83mbAFk\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":true,\"hasMalops\":true,\"elementValues\":{\"type\":\"suspects\"},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"true\"]},\"guid\":{\"totalValues\":1,\"values\":[\"zpP735vQl83mbAFk\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"true\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP733MJZQ5ua9PD\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":true,\"hasMalops\":true,\"elementValues\":{},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"true\"]},\"guid\":{\"totalValues\":1,\"values\":[\"zpP733MJZQ5ua9PD\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"true\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73wfcKRFKvnZa\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":true,\"hasMalops\":true,\"elementValues\":{},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"true\"]},\"guid\":{\"totalValues\":1,\"values\":[\"zpP73wfcKRFKvnZa\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"true\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73yUewMOXCNBN\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":true,\"hasMalops\":true,\"elementValues\":{},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"true\"]},\"guid\":{\"totalValues\":1,\"values\":[\"zpP73yUewMOXCNBN\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"true\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73wdciiw3CcZ9\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":true,\"hasMalops\":true,\"elementValues\":{},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"true\"]},\"guid\":{\"totalValues\":1,\"values\":[\"zpP73wdciiw3CcZ9\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"true\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73-slLQbqr1eb\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":true,\"hasMalops\":true,\"elementValues\":{},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"true\"]},\"guid\":{\"totalValues\":1,\"values\":[\"zpP73-slLQbqr1eb\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"true\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73xTlNawf6qox\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":true,\"hasMalops\":true,\"elementValues\":{},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"true\"]},\"guid\":{\"totalValues\":1,\"values\":[\"zpP73xTlNawf6qox\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"true\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP736adtvfQP86p\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":true,\"hasMalops\":true,\"elementValues\":{},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"true\"]},\"guid\":{\"totalValues\":1,\"values\":[\"zpP736adtvfQP86p\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"true\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP732Q23xdwLJhh\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":true,\"hasMalops\":true,\"elementValues\":{},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"true\"]},\"guid\":{\"totalValues\":1,\"values\":[\"zpP732Q23xdwLJhh\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"true\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73zlRSCV3N9Si\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":true,\"hasMalops\":true,\"elementValues\":{},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"true\"]},\"guid\":{\"totalValues\":1,\"values\":[\"zpP73zlRSCV3N9Si\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"true\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}}],\"totalSuspicious\":10,\"totalMalicious\":10,\"guessedTotal\":0},\"filesToRemediate\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"File\",\"guid\":\"zpP7358Lbsf7z787\",\"name\":\"x64cymulateprocesshider.exe\",\"hasSuspicions\":true,\"hasMalops\":false,\"elementValues\":{\"files\":\"remediate\"},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"false\"]},\"guid\":{\"totalValues\":1,\"values\":[\"zpP7358Lbsf7z787\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"true\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"x64cymulateprocesshider.exe\"]}}}],\"totalSuspicious\":1,\"totalMalicious\":0,\"guessedTotal\":0},\"primaryRootCauseElements\":{\"totalValues\":10,\"elementValues\":[{\"elementType\":\"Process\",\"guid\":\"zpP73wfcKRFKvnZa\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73wfcKRFKvnZa\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73yUewMOXCNBN\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{\"values\":\"primaryroot\"},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73yUewMOXCNBN\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73wdciiw3CcZ9\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73wdciiw3CcZ9\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73zALshBfA7mQ\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73zALshBfA7mQ\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP736Yq9t-ujawF\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP736Yq9t-ujawF\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP736adtvfQP86p\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP736adtvfQP86p\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73yUHiaZd-JI6\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73yUHiaZd-JI6\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP733Hfwc2Ol2KV\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP733Hfwc2Ol2KV\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73zlRSCV3N9Si\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73zlRSCV3N9Si\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73-Mvct_YhLo2\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73-Mvct_YhLo2\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"affectedUsers\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"User\",\"guid\":\"AAAAGAJYAICT5xYW\",\"name\":\"cybereason\\\\theavengers\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{\"values\":\"element\"},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"false\"]},\"guid\":{\"totalValues\":1,\"values\":[\"AAAAGAJYAICT5xYW\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"false\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"cybereason\\\\theavengers\"]}}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"rootCauseElements\":{\"totalValues\":10,\"elementValues\":[{\"elementType\":\"Process\",\"guid\":\"zpP735vQl83mbAFk\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{\"element\":\"root\"},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP735vQl83mbAFk\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP733MJZQ5ua9PD\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP733MJZQ5ua9PD\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73wfcKRFKvnZa\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73wfcKRFKvnZa\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73yUewMOXCNBN\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73yUewMOXCNBN\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73wdciiw3CcZ9\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73wdciiw3CcZ9\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73-slLQbqr1eb\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73-slLQbqr1eb\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73xTlNawf6qox\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73xTlNawf6qox\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP736adtvfQP86p\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP736adtvfQP86p\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP732Q23xdwLJhh\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP732Q23xdwLJhh\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}},{\"elementType\":\"Process\",\"guid\":\"zpP73zlRSCV3N9Si\",\"name\":\"injected (chain of injections)\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"guid\":{\"totalValues\":1,\"values\":[\"zpP73zlRSCV3N9Si\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"injected (chain of injections)\"]}}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"affectedMachines\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"Machine\",\"guid\":\"zpP73xCi55eyTiwX\",\"name\":\"cybereason\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{\"element\":\"values\"},\"simpleValues\":{\"hasMalops\":{\"totalValues\":1,\"values\":[\"false\"]},\"guid\":{\"totalValues\":1,\"values\":[\"zpP73xCi55eyTiwX\"]},\"hasSuspicions\":{\"totalValues\":1,\"values\":[\"false\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"cybereason\"]}}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0}},\"suspicions\":{\"connectingToBlackListAddressSuspicion\":1710261170916},\"filterData\":{\"sortInGroupValue\":\"hello\",\"groupByValue\":\"NONE_MALOP_ACTIVITY_TYPE\"},\"isMalicious\":false,\"suspicionCount\":0,\"guidString\":\"AAAA0xquIk3X9oQ_\",\"labelsIds\":\"lbl2\",\"malopPriority\":\"LOW\",\"suspect\":false,\"malicious\":false}, {\"suspicions\":\"map\"}, {\"evidence\":\"map\"}]",
        "type": [
            "info"
        ]
    },
    "related": {
        "hash": [
            "nbvgyui765tghnxxx"
        ]
    },
    "source": {
        "bytes": 90
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cybereason.malop_process.element_values.affected_machines.element_values.element_type |  | keyword |
| cybereason.malop_process.element_values.affected_machines.element_values.guid |  | keyword |
| cybereason.malop_process.element_values.affected_machines.element_values.has_malops |  | boolean |
| cybereason.malop_process.element_values.affected_machines.element_values.has_suspicions |  | boolean |
| cybereason.malop_process.element_values.affected_machines.element_values.name |  | keyword |
| cybereason.malop_process.element_values.affected_machines.element_values.object |  | flattened |
| cybereason.malop_process.element_values.affected_machines.element_values.simple_values.element_display_name.total_values |  | long |
| cybereason.malop_process.element_values.affected_machines.element_values.simple_values.element_display_name.values |  | keyword |
| cybereason.malop_process.element_values.affected_machines.element_values.simple_values.group.total_values |  | long |
| cybereason.malop_process.element_values.affected_machines.element_values.simple_values.group.values |  | keyword |
| cybereason.malop_process.element_values.affected_machines.element_values.simple_values.guid.total_values |  | long |
| cybereason.malop_process.element_values.affected_machines.element_values.simple_values.guid.values |  | keyword |
| cybereason.malop_process.element_values.affected_machines.element_values.simple_values.has_malops.total_values |  | long |
| cybereason.malop_process.element_values.affected_machines.element_values.simple_values.has_malops.values |  | boolean |
| cybereason.malop_process.element_values.affected_machines.element_values.simple_values.has_suspicions.total_values |  | long |
| cybereason.malop_process.element_values.affected_machines.element_values.simple_values.has_suspicions.values |  | boolean |
| cybereason.malop_process.element_values.affected_machines.guessed_total |  | long |
| cybereason.malop_process.element_values.affected_machines.total_malicious |  | long |
| cybereason.malop_process.element_values.affected_machines.total_suspicious |  | long |
| cybereason.malop_process.element_values.affected_machines.total_values |  | long |
| cybereason.malop_process.element_values.affected_users.element_values.element_type |  | keyword |
| cybereason.malop_process.element_values.affected_users.element_values.guid |  | keyword |
| cybereason.malop_process.element_values.affected_users.element_values.has_malops |  | boolean |
| cybereason.malop_process.element_values.affected_users.element_values.has_suspicions |  | boolean |
| cybereason.malop_process.element_values.affected_users.element_values.name |  | keyword |
| cybereason.malop_process.element_values.affected_users.element_values.object |  | flattened |
| cybereason.malop_process.element_values.affected_users.element_values.simple_values.element_display_name.total_values |  | long |
| cybereason.malop_process.element_values.affected_users.element_values.simple_values.element_display_name.values |  | keyword |
| cybereason.malop_process.element_values.affected_users.element_values.simple_values.group.total_values |  | long |
| cybereason.malop_process.element_values.affected_users.element_values.simple_values.group.values |  | keyword |
| cybereason.malop_process.element_values.affected_users.element_values.simple_values.guid.total_values |  | long |
| cybereason.malop_process.element_values.affected_users.element_values.simple_values.guid.values |  | keyword |
| cybereason.malop_process.element_values.affected_users.element_values.simple_values.has_malops.total_values |  | long |
| cybereason.malop_process.element_values.affected_users.element_values.simple_values.has_malops.values |  | boolean |
| cybereason.malop_process.element_values.affected_users.element_values.simple_values.has_suspicions.total_values |  | long |
| cybereason.malop_process.element_values.affected_users.element_values.simple_values.has_suspicions.values |  | boolean |
| cybereason.malop_process.element_values.affected_users.guessed_total |  | long |
| cybereason.malop_process.element_values.affected_users.total_malicious |  | long |
| cybereason.malop_process.element_values.affected_users.total_suspicious |  | long |
| cybereason.malop_process.element_values.affected_users.total_values |  | long |
| cybereason.malop_process.element_values.files_to_remediate.element_values.element_type |  | keyword |
| cybereason.malop_process.element_values.files_to_remediate.element_values.guid |  | keyword |
| cybereason.malop_process.element_values.files_to_remediate.element_values.has_malops |  | boolean |
| cybereason.malop_process.element_values.files_to_remediate.element_values.has_suspicions |  | boolean |
| cybereason.malop_process.element_values.files_to_remediate.element_values.name |  | keyword |
| cybereason.malop_process.element_values.files_to_remediate.element_values.object |  | flattened |
| cybereason.malop_process.element_values.files_to_remediate.element_values.simple_values.element_display_name.total_values |  | long |
| cybereason.malop_process.element_values.files_to_remediate.element_values.simple_values.element_display_name.values |  | keyword |
| cybereason.malop_process.element_values.files_to_remediate.element_values.simple_values.group.total_values |  | long |
| cybereason.malop_process.element_values.files_to_remediate.element_values.simple_values.group.values |  | keyword |
| cybereason.malop_process.element_values.files_to_remediate.element_values.simple_values.guid.total_values |  | long |
| cybereason.malop_process.element_values.files_to_remediate.element_values.simple_values.guid.values |  | keyword |
| cybereason.malop_process.element_values.files_to_remediate.element_values.simple_values.has_malops.total_values |  | long |
| cybereason.malop_process.element_values.files_to_remediate.element_values.simple_values.has_malops.values |  | boolean |
| cybereason.malop_process.element_values.files_to_remediate.element_values.simple_values.has_suspicions.total_values |  | long |
| cybereason.malop_process.element_values.files_to_remediate.element_values.simple_values.has_suspicions.values |  | boolean |
| cybereason.malop_process.element_values.files_to_remediate.guessed_total |  | long |
| cybereason.malop_process.element_values.files_to_remediate.total_malicious |  | long |
| cybereason.malop_process.element_values.files_to_remediate.total_suspicious |  | long |
| cybereason.malop_process.element_values.files_to_remediate.total_values |  | long |
| cybereason.malop_process.element_values.primary_root_cause_elements.element_values.element_type |  | keyword |
| cybereason.malop_process.element_values.primary_root_cause_elements.element_values.guid |  | keyword |
| cybereason.malop_process.element_values.primary_root_cause_elements.element_values.has_malops |  | boolean |
| cybereason.malop_process.element_values.primary_root_cause_elements.element_values.has_suspicions |  | boolean |
| cybereason.malop_process.element_values.primary_root_cause_elements.element_values.name |  | keyword |
| cybereason.malop_process.element_values.primary_root_cause_elements.element_values.object |  | flattened |
| cybereason.malop_process.element_values.primary_root_cause_elements.element_values.simple_values.element_display_name.total_values |  | long |
| cybereason.malop_process.element_values.primary_root_cause_elements.element_values.simple_values.element_display_name.values |  | keyword |
| cybereason.malop_process.element_values.primary_root_cause_elements.element_values.simple_values.group.total_values |  | long |
| cybereason.malop_process.element_values.primary_root_cause_elements.element_values.simple_values.group.values |  | keyword |
| cybereason.malop_process.element_values.primary_root_cause_elements.element_values.simple_values.guid.total_values |  | long |
| cybereason.malop_process.element_values.primary_root_cause_elements.element_values.simple_values.guid.values |  | keyword |
| cybereason.malop_process.element_values.primary_root_cause_elements.guessed_total |  | long |
| cybereason.malop_process.element_values.primary_root_cause_elements.total_malicious |  | long |
| cybereason.malop_process.element_values.primary_root_cause_elements.total_suspicious |  | long |
| cybereason.malop_process.element_values.primary_root_cause_elements.total_values |  | long |
| cybereason.malop_process.element_values.root_cause_elements.element_values.element_type |  | keyword |
| cybereason.malop_process.element_values.root_cause_elements.element_values.guid |  | keyword |
| cybereason.malop_process.element_values.root_cause_elements.element_values.has_malops |  | boolean |
| cybereason.malop_process.element_values.root_cause_elements.element_values.has_suspicions |  | boolean |
| cybereason.malop_process.element_values.root_cause_elements.element_values.name |  | keyword |
| cybereason.malop_process.element_values.root_cause_elements.element_values.object |  | flattened |
| cybereason.malop_process.element_values.root_cause_elements.element_values.simple_values.element_display_name.total_values |  | long |
| cybereason.malop_process.element_values.root_cause_elements.element_values.simple_values.element_display_name.values |  | keyword |
| cybereason.malop_process.element_values.root_cause_elements.element_values.simple_values.group.total_values |  | long |
| cybereason.malop_process.element_values.root_cause_elements.element_values.simple_values.group.values |  | keyword |
| cybereason.malop_process.element_values.root_cause_elements.element_values.simple_values.guid.total_values |  | long |
| cybereason.malop_process.element_values.root_cause_elements.element_values.simple_values.guid.values |  | keyword |
| cybereason.malop_process.element_values.root_cause_elements.guessed_total |  | long |
| cybereason.malop_process.element_values.root_cause_elements.total_malicious |  | long |
| cybereason.malop_process.element_values.root_cause_elements.total_suspicious |  | long |
| cybereason.malop_process.element_values.root_cause_elements.total_values |  | long |
| cybereason.malop_process.element_values.suspects.element_values.element_type |  | keyword |
| cybereason.malop_process.element_values.suspects.element_values.guid |  | keyword |
| cybereason.malop_process.element_values.suspects.element_values.has_malops |  | boolean |
| cybereason.malop_process.element_values.suspects.element_values.has_suspicions |  | boolean |
| cybereason.malop_process.element_values.suspects.element_values.name |  | keyword |
| cybereason.malop_process.element_values.suspects.element_values.object |  | flattened |
| cybereason.malop_process.element_values.suspects.element_values.simple_values.element_display_name.total_values |  | long |
| cybereason.malop_process.element_values.suspects.element_values.simple_values.element_display_name.values |  | keyword |
| cybereason.malop_process.element_values.suspects.element_values.simple_values.group.total_values |  | long |
| cybereason.malop_process.element_values.suspects.element_values.simple_values.group.values |  | keyword |
| cybereason.malop_process.element_values.suspects.element_values.simple_values.guid.total_values |  | long |
| cybereason.malop_process.element_values.suspects.element_values.simple_values.guid.values |  | keyword |
| cybereason.malop_process.element_values.suspects.element_values.simple_values.has_malops.total_values |  | long |
| cybereason.malop_process.element_values.suspects.element_values.simple_values.has_malops.values |  | boolean |
| cybereason.malop_process.element_values.suspects.element_values.simple_values.has_suspicions.total_values |  | long |
| cybereason.malop_process.element_values.suspects.element_values.simple_values.has_suspicions.values |  | boolean |
| cybereason.malop_process.element_values.suspects.guessedTotal |  | long |
| cybereason.malop_process.element_values.suspects.total_malicious |  | long |
| cybereason.malop_process.element_values.suspects.total_suspicious |  | long |
| cybereason.malop_process.element_values.suspects.total_values |  | long |
| cybereason.malop_process.evidence_map |  | flattened |
| cybereason.malop_process.filter_data.group_by_value |  | keyword |
| cybereason.malop_process.filter_data.sort_in_group_value |  | keyword |
| cybereason.malop_process.guid_string |  | keyword |
| cybereason.malop_process.is_malicious |  | boolean |
| cybereason.malop_process.labels_ids |  | keyword |
| cybereason.malop_process.malicious |  | boolean |
| cybereason.malop_process.malop_priority |  | keyword |
| cybereason.malop_process.simple_values.all_ransomware_processes_suspended.total_values |  | long |
| cybereason.malop_process.simple_values.all_ransomware_processes_suspended.values | Indicates whether or not the Malop has malicious processes which are suspended. | boolean |
| cybereason.malop_process.simple_values.creation_time.total_values |  | long |
| cybereason.malop_process.simple_values.creation_time.values |  | date |
| cybereason.malop_process.simple_values.decision_feature.total_values |  | long |
| cybereason.malop_process.simple_values.decision_feature.values |  | keyword |
| cybereason.malop_process.simple_values.decision_feature_set.total_values |  | long |
| cybereason.malop_process.simple_values.decision_feature_set.values |  | keyword |
| cybereason.malop_process.simple_values.detection_type.total_values |  | long |
| cybereason.malop_process.simple_values.detection_type.values | The root cause for the Malop. . | keyword |
| cybereason.malop_process.simple_values.has_ransomware_suspended_processes.total_values |  | long |
| cybereason.malop_process.simple_values.has_ransomware_suspended_processes.values | Indicates whether or not any of the Malop’s suspicious processes are currently suspended due to ransomware activity. | boolean |
| cybereason.malop_process.simple_values.icon_base64.total_values |  | long |
| cybereason.malop_process.simple_values.icon_base64.values |  | keyword |
| cybereason.malop_process.simple_values.is_blocked.total_values |  | long |
| cybereason.malop_process.simple_values.is_blocked.values | Indicates whether or not the Malop has malicious processes that are marked for prevention. | boolean |
| cybereason.malop_process.simple_values.malop.activity_types.total_values |  | long |
| cybereason.malop_process.simple_values.malop.activity_types.values | Type of activity detected. | keyword |
| cybereason.malop_process.simple_values.malop.last_update_time.total_values |  | long |
| cybereason.malop_process.simple_values.malop.last_update_time.values |  | date |
| cybereason.malop_process.simple_values.malop.start_time.total_values |  | long |
| cybereason.malop_process.simple_values.malop.start_time.values |  | date |
| cybereason.malop_process.simple_values.root_cause_element.company_product.total_values |  | long |
| cybereason.malop_process.simple_values.root_cause_element.company_product.values | The company and product associated with the Element that triggered the Malop, represented as company:product. | keyword |
| cybereason.malop_process.simple_values.root_cause_element.hashes.total_values |  | long |
| cybereason.malop_process.simple_values.root_cause_element.hashes.values | Hash value of the Element that triggered the Malop. | keyword |
| cybereason.malop_process.simple_values.root_cause_element.names.total_values |  | long |
| cybereason.malop_process.simple_values.root_cause_element.names.values | Name of the Element that triggered the Malop. | keyword |
| cybereason.malop_process.simple_values.root_cause_element.types.total_values |  | long |
| cybereason.malop_process.simple_values.root_cause_element.types.values | Type of Element that triggered the Malop. | keyword |
| cybereason.malop_process.simple_values.total.number_of.incoming_connections.total_values |  | long |
| cybereason.malop_process.simple_values.total.number_of.incoming_connections.values | Total number of incoming connections associated with the malicious process. | long |
| cybereason.malop_process.simple_values.total.number_of.outgoing_connections.total_values |  | long |
| cybereason.malop_process.simple_values.total.number_of.outgoing_connections.values | Total number of outgoing connections associated with the malicious process. | long |
| cybereason.malop_process.simple_values.total.received_bytes.total_values |  | long |
| cybereason.malop_process.simple_values.total.received_bytes.values | Total bytes received by the malicious process. | long |
| cybereason.malop_process.simple_values.total.transmitted_bytes.total_values |  | long |
| cybereason.malop_process.simple_values.total.transmitted_bytes.values | Total bytes transmitted by the malicious process. | long |
| cybereason.malop_process.suspect |  | boolean |
| cybereason.malop_process.suspicion_count |  | long |
| cybereason.malop_process.suspicions |  | flattened |
| cybereason.malop_process.suspicions_map |  | flattened |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Malware

This is the `Malware` dataset.

#### Example

An example event for `malware` looks as following:

```json
{
    "@timestamp": "2024-03-11T08:56:57.000Z",
    "cybereason": {
        "malware": {
            "data_model": {
                "class": ".BaseFileMalwareDataModel",
                "description": "EXECUTE_MALICIOUS_ACTIVITY",
                "detection": {
                    "name": "IL:Trojan.MSILZilla.30425",
                    "rule": "Formatting (1106)"
                },
                "file_path": "c:\\programdata\\cymulate\\hopper\\boot64_1da739212534cbd666bc903c25b812e0\\cymulatelm64.exe",
                "module": "Formatting (1106)",
                "process_name": "remotefxvgpudisablement.exe",
                "type": "UnknownMalware",
                "url": "https://malware_data_model"
            },
            "detection": {
                "engine": "StaticAnalysis",
                "value": {
                    "original": "62b9e0dfd0ef2cd88fdcd412523c7d9f",
                    "type": "DVT_FILE"
                }
            },
            "element_type": "File",
            "guid": "-286218732.7910817006083139531",
            "id": {
                "element_type": "File",
                "guid": "-286218732.7910817006083139531",
                "malware_type": "UnknownMalware",
                "timestamp": "2024-03-11T08:56:57.000Z"
            },
            "machine_name": "dim-win10",
            "name": "cymulatelm64.exe",
            "needs_attention": false,
            "reference": {
                "element_type": "File",
                "guid": "-286218732.7910817006083139531"
            },
            "scheduler_scan": false,
            "score": 0.7721870783056456,
            "status": "Detected",
            "timestamp": "2024-03-11T08:56:57.000Z",
            "type": "UnknownMalware"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "malware"
        ],
        "kind": "alert",
        "original": "{ \"guid\": \"-286218732.7910817006083139531\", \"timestamp\": 1710147417000, \"name\": \"cymulatelm64.exe\", \"type\": \"UnknownMalware\", \"elementType\": \"File\", \"machineName\": \"dim-win10\", \"status\": \"Detected\", \"needsAttention\": false, \"referenceGuid\": \"-286218732.7910817006083139531\", \"referenceElementType\": \"File\", \"score\": 0.7721870783056456, \"detectionValue\": \"62b9e0dfd0ef2cd88fdcd412523c7d9f\", \"detectionValueType\": \"DVT_FILE\", \"detectionEngine\": \"StaticAnalysis\", \"malwareDataModel\": { \"@class\": \".BaseFileMalwareDataModel\", \"type\": \"UnknownMalware\", \"detectionName\": \"IL:Trojan.MSILZilla.30425\", \"filePath\": \"c:\\\\programdata\\\\cymulate\\\\hopper\\\\boot64_1da739212534cbd666bc903c25b812e0\\\\cymulatelm64.exe\" , \"processName\": \"remotefxvgpudisablement.exe\", \"url\": \"https://malware_data_model\", \"detectionRule\": \"Formatting (1106)\", \"module\": \"Formatting (1106)\", \"description\": \"EXECUTE_MALICIOUS_ACTIVITY\"}, \"id\": { \"guid\": \"-286218732.7910817006083139531\", \"timestamp\": 1710147417000, \"malwareType\": \"UnknownMalware\", \"elementType\": \"File\" }, \"schedulerScan\": false }",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "dim-win10"
    },
    "related": {
        "hosts": [
            "dim-win10"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cybereason.malware.data_model.class |  | keyword |
| cybereason.malware.data_model.description |  | keyword |
| cybereason.malware.data_model.detection.name |  | keyword |
| cybereason.malware.data_model.detection.rule |  | keyword |
| cybereason.malware.data_model.file_path | The path to the file for the malware. | keyword |
| cybereason.malware.data_model.module |  | keyword |
| cybereason.malware.data_model.process_name |  | keyword |
| cybereason.malware.data_model.type |  | keyword |
| cybereason.malware.data_model.url |  | keyword |
| cybereason.malware.detection.engine |  | keyword |
| cybereason.malware.detection.value.original |  | keyword |
| cybereason.malware.detection.value.type |  | keyword |
| cybereason.malware.element_type |  | keyword |
| cybereason.malware.guid | The unique GUID the Cybereason platform uses for this specific malware instance. | keyword |
| cybereason.malware.id.element_type |  | keyword |
| cybereason.malware.id.guid |  | keyword |
| cybereason.malware.id.malware_type |  | keyword |
| cybereason.malware.id.timestamp |  | date |
| cybereason.malware.machine_name | The name of the machine on which the Cybereason platform found the malware. | keyword |
| cybereason.malware.name | The name of the process running the malware. | keyword |
| cybereason.malware.needs_attention |  | boolean |
| cybereason.malware.reference.element_type |  | keyword |
| cybereason.malware.reference.guid |  | keyword |
| cybereason.malware.scheduler_scan |  | boolean |
| cybereason.malware.score |  | double |
| cybereason.malware.status | The detection status of the malware. This should match the Anti-Malware settings you specified for your Cybereason platform. | keyword |
| cybereason.malware.timestamp | The time (in epoch) when the Cybereason platform detected this malware. | date |
| cybereason.malware.type | The type of malware as classified by the Cybereason platform. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Poll Malop

This is the `Poll Malop` dataset.

#### Example

An example event for `poll_malop` looks as following:

```json
{
    "@timestamp": "2024-03-04T19:12:56.110Z",
    "cybereason": {
        "poll_malop": {
            "class": ".MalopInboxModel",
            "closed": false,
            "closer_name": "Closer Name",
            "containers": [
                "Testing"
            ],
            "creation_time": "2023-09-15T23:52:35.604Z",
            "data": {
                "close_time": "2023-11-23T06:45:15.015Z",
                "detection_type": "CUSTOM_RULE",
                "priority": "LOW",
                "severity": "High",
                "status": "Active",
                "type": "CUSTOM_RULE"
            },
            "decision_statuses": [
                "Testing"
            ],
            "detection": {
                "engines": [
                    "EDR"
                ],
                "types": [
                    "calc_Custom_Rule"
                ]
            },
            "display_name": "register-cimprovider.exe",
            "edr": true,
            "empty": true,
            "escalated": false,
            "group": "72a61eac-6f79-4670-8607-a1334ddd2ff0",
            "guid": "AAAA05JzW7vmNhCD",
            "icon_base64": "muhk",
            "labels": [
                "IT-Pending",
                "Testing"
            ],
            "last_update_time": "2024-03-04T19:12:56.110Z",
            "machines": [
                {
                    "class": ".MachineInboxModel",
                    "connected": false,
                    "display_name": "d3dock-poc",
                    "empty": true,
                    "guid": "lbnnvBCi55eyTiwX",
                    "isolated": false,
                    "last_connected": "2024-01-07T06:23:30.725Z",
                    "os_type": "WINDOWS"
                },
                {
                    "class": ".MachineInboxModel",
                    "connected": true,
                    "display_name": "cybereason",
                    "empty": true,
                    "guid": "zpP73xCi55eyTiwX",
                    "isolated": true,
                    "last_connected": "2024-03-18T08:30:50.941Z",
                    "os_type": "linux"
                },
                {
                    "class": ".MachineInboxModel",
                    "connected": false,
                    "display_name": "dim-win10",
                    "empty": true,
                    "guid": "7vCmFBCi55eyTiwX",
                    "isolated": false,
                    "last_connected": "2024-03-17T16:21:34.714Z",
                    "os_type": "xyz"
                }
            ],
            "primary_root_cause_name": "register-cimprovider.exe",
            "priority": "HIGH",
            "root_cause_element": {
                "hashes": "f7b32703e444fdc75c09840afa3dcda8286f3b24",
                "names_count": 1,
                "type": "Process"
            },
            "severity": "High",
            "status": "Active",
            "users": [
                {
                    "admin": false,
                    "display_name": "d3dock-poc\\administrator",
                    "domain_user": false,
                    "guid": "AAAAGGHyKbMGbI4y",
                    "local_system": false
                },
                {
                    "admin": false,
                    "display_name": "cybereason\\system",
                    "domain_user": false,
                    "guid": "AAAAGK97gKTvmLc3",
                    "local_system": true
                },
                {
                    "admin": false,
                    "display_name": "cy\\cymulator",
                    "domain_user": false,
                    "guid": "AAAAGGZ3xLXVm27e",
                    "local_system": false
                }
            ]
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "malware"
        ],
        "created": "2023-09-15T23:52:35.604Z",
        "id": "AAAA05JzW7vmNhCD",
        "kind": "alert",
        "original": "{\"@class\":\".MalopInboxModel\",\"guid\":\"AAAA05JzW7vmNhCD\",\"closerName\":\"Closer Name\",\"displayName\":\"register-cimprovider.exe\",\"rootCauseElementType\":\"Process\",\"primaryRootCauseName\":\"register-cimprovider.exe\",\"rootCauseElementNamesCount\":1,\"detectionEngines\":[\"EDR\"],\"detectionTypes\":[\"calc_Custom_Rule\"],\"malopDetectionType\":\"CUSTOM_RULE\",\"creationTime\":1694821955604,\"lastUpdateTime\":1709579576110,\"iconBase64\":\"muhk\",\"priority\":\"HIGH\",\"group\":\"72a61eac-6f79-4670-8607-a1334ddd2ff0\",\"rootCauseElementHashes\": \"f7b32703e444fdc75c09840afa3dcda8286f3b24\",\"status\":\"Active\",\"severity\":\"High\",\"machines\":[{\"@class\":\".MachineInboxModel\",\"guid\":\"lbnnvBCi55eyTiwX\",\"displayName\":\"d3dock-poc\",\"osType\":\"WINDOWS\",\"connected\":false,\"isolated\":false,\"lastConnected\":1704608610725,\"empty\":true},{\"@class\":\".MachineInboxModel\",\"guid\":\"zpP73xCi55eyTiwX\",\"displayName\":\"cybereason\",\"osType\":\"linux\",\"connected\":true,\"isolated\":true,\"lastConnected\":1710750650941,\"empty\":true},{\"@class\":\".MachineInboxModel\",\"guid\":\"7vCmFBCi55eyTiwX\",\"displayName\":\"dim-win10\",\"osType\":\"xyz\",\"connected\":false,\"isolated\":false,\"lastConnected\":1710692494714,\"empty\":true}],\"users\":[{\"guid\":\"AAAAGGHyKbMGbI4y\",\"displayName\":\"d3dock-poc\\\\administrator\",\"admin\":false,\"localSystem\":false,\"domainUser\":false},{\"guid\":\"AAAAGK97gKTvmLc3\",\"displayName\":\"cybereason\\\\system\",\"admin\":false,\"localSystem\":true,\"domainUser\":false},{\"guid\":\"AAAAGGZ3xLXVm27e\",\"displayName\":\"cy\\\\cymulator\",\"admin\":false,\"localSystem\":false,\"domainUser\":false}],\"containers\":[\"Testing\"],\"labels\":[\"IT-Pending\", \"Testing\"],\"decisionStatuses\":[\"Testing\"],\"malopCloseTime\":1700721915015,\"escalated\":false,\"malopStatus\":\"Active\",\"malopSeverity\":\"High\",\"edr\":true,\"malopType\":\"CUSTOM_RULE\",\"malopPriority\":\"LOW\",\"closed\":false,\"empty\":true}",
        "type": [
            "info"
        ]
    },
    "group": {
        "id": [
            "72a61eac-6f79-4670-8607-a1334ddd2ff0"
        ]
    },
    "host": {
        "id": [
            "lbnnvBCi55eyTiwX",
            "zpP73xCi55eyTiwX",
            "7vCmFBCi55eyTiwX"
        ],
        "name": [
            "d3dock-poc",
            "cybereason",
            "dim-win10"
        ],
        "os": {
            "type": [
                "windows",
                "linux"
            ]
        }
    },
    "related": {
        "hash": [
            "f7b32703e444fdc75c09840afa3dcda8286f3b24"
        ],
        "hosts": [
            "d3dock-poc",
            "cybereason",
            "dim-win10",
            "lbnnvBCi55eyTiwX",
            "zpP73xCi55eyTiwX",
            "7vCmFBCi55eyTiwX",
            "WINDOWS",
            "linux",
            "xyz"
        ],
        "user": [
            "d3dock-poc\\administrator",
            "cybereason\\system",
            "cy\\cymulator",
            "AAAAGGHyKbMGbI4y",
            "AAAAGK97gKTvmLc3",
            "AAAAGGZ3xLXVm27e"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cybereason.poll_malop.class |  | keyword |
| cybereason.poll_malop.closed |  | boolean |
| cybereason.poll_malop.closer_name |  | keyword |
| cybereason.poll_malop.containers |  | keyword |
| cybereason.poll_malop.creation_time | The time (in epoch) when the Malop was generated. | date |
| cybereason.poll_malop.data.close_time |  | date |
| cybereason.poll_malop.data.detection_type | The type of detection for the root cause. . | keyword |
| cybereason.poll_malop.data.priority |  | keyword |
| cybereason.poll_malop.data.severity |  | keyword |
| cybereason.poll_malop.data.status |  | keyword |
| cybereason.poll_malop.data.type |  | keyword |
| cybereason.poll_malop.decision_statuses | The prevention action that the Cybereason platform used for this Malop. | keyword |
| cybereason.poll_malop.detection.engines | The method of detecting the Malop. | keyword |
| cybereason.poll_malop.detection.types | The type of detection for the root cause. | keyword |
| cybereason.poll_malop.display_name | The display name for the item. | keyword |
| cybereason.poll_malop.edr | Indicates whether the Malop is an Auto Hunt Malop or an Endpoint Protection Malop. | boolean |
| cybereason.poll_malop.empty |  | boolean |
| cybereason.poll_malop.escalated | Indicates whether someone has marked the Malop as escalated. | boolean |
| cybereason.poll_malop.files | An object containing details on files associated with the MalOp. | flattened |
| cybereason.poll_malop.group | The Group ID of the affected sensors. | keyword |
| cybereason.poll_malop.guid | The unique GUID the Cybereason platform uses for the MalOp. | keyword |
| cybereason.poll_malop.icon_base64 | The base64 value for the item that is the root cause of the Malop. | keyword |
| cybereason.poll_malop.labels | An object that contains details on the labels, such as the label name and the time the label was added. | keyword |
| cybereason.poll_malop.last_update_time | The time (in epoch) when the Malop was last updated. | date |
| cybereason.poll_malop.machines.class |  | keyword |
| cybereason.poll_malop.machines.connected | Indicates whether the machine is currently connected to the Cybereason server. | boolean |
| cybereason.poll_malop.machines.display_name |  | keyword |
| cybereason.poll_malop.machines.empty |  | boolean |
| cybereason.poll_malop.machines.guid |  | keyword |
| cybereason.poll_malop.machines.isolated | Indicates whether the machine is currently isolated. | boolean |
| cybereason.poll_malop.machines.last_connected | The time (in epoch) when the machine was last connected to a Cybereason server. | date |
| cybereason.poll_malop.machines.os_type | The operating system type of the affected machine. . | keyword |
| cybereason.poll_malop.primary_root_cause_name |  | keyword |
| cybereason.poll_malop.priority | The priority assigned to the MalOp. | keyword |
| cybereason.poll_malop.processes | An object containing details on processes associated with the MalOp. | flattened |
| cybereason.poll_malop.root_cause_element.hashes |  | keyword |
| cybereason.poll_malop.root_cause_element.names_count | A count of the items that are the root cause or causes of the Malop. | long |
| cybereason.poll_malop.root_cause_element.type | The Element that is the root cause of the Malop. | keyword |
| cybereason.poll_malop.severity | The Malop severity level. | keyword |
| cybereason.poll_malop.status | The status of the Malop. | keyword |
| cybereason.poll_malop.users.admin | Indicates whether the specified user has administrator privileges on the machine. | boolean |
| cybereason.poll_malop.users.display_name |  | keyword |
| cybereason.poll_malop.users.domain_user | Indicates whether the specified user is a domain user. | boolean |
| cybereason.poll_malop.users.guid |  | keyword |
| cybereason.poll_malop.users.local_system | Indicates whether the specified user has local system privileges on the machine. | boolean |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Suspicions Process

This is the `Suspicions Process` dataset.

#### Example

An example event for `suspicions_process` looks as following:

```json
{
    "@timestamp": "2024-03-12T15:13:27.872Z",
    "cybereason": {
        "suspicions_process": {
            "element_values": {
                "calculated_user": {
                    "element_values": [
                        {
                            "element_type": "User",
                            "guid": "AAAAGGZ3xLXVm27e",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "cy\\cymulator"
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                },
                "children": {
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 0
                },
                "image_file": {
                    "element_values": [
                        {
                            "element_type": "File",
                            "guid": "7vCmFKxNAQXpBIkL",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "msedge.exe",
                            "object": {
                                "fileHash": {
                                    "elementValues": [
                                        {
                                            "elementType": "FileHash",
                                            "guid": "AAAAHuaPtU7zGEJc",
                                            "hasMalops": false,
                                            "hasSuspicions": false,
                                            "name": "a3c06b947549921d60d59917575df5ee5dfc472a",
                                            "simpleValues": {
                                                "iconBase64": {
                                                    "totalValues": 1,
                                                    "values": [
                                                        "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"
                                                    ]
                                                }
                                            }
                                        }
                                    ],
                                    "guessedTotal": 0,
                                    "totalMalicious": 0,
                                    "totalSuspicious": 0,
                                    "totalValues": 1
                                }
                            },
                            "simple_values": {
                                "companyName": {
                                    "totalValues": 1,
                                    "values": [
                                        "Microsoft Corporation"
                                    ]
                                },
                                "maliciousClassificationType": {
                                    "totalValues": 1,
                                    "values": [
                                        "indifferent"
                                    ]
                                },
                                "md5String": {
                                    "totalValues": 1,
                                    "values": [
                                        "5ac5ddc4c27ecc203b2ed62bbe8fb8b9"
                                    ]
                                },
                                "productName": {
                                    "totalValues": 1,
                                    "values": [
                                        "Microsoft Edge"
                                    ]
                                },
                                "sha1String": {
                                    "totalValues": 1,
                                    "values": [
                                        "a3c06b947549921d60d59917575df5ee5dfc472a"
                                    ]
                                }
                            }
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                },
                "owner_machine": {
                    "element_values": [
                        {
                            "element_type": "Machine",
                            "guid": "7vCmFBCi55eyTiwX",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "dim-win10"
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                },
                "parent_process": {
                    "element_values": [
                        {
                            "element_type": "Process",
                            "guid": "7vCmFMsvYy739EW5",
                            "has_malops": false,
                            "has_suspicions": false,
                            "name": "msedge.exe"
                        }
                    ],
                    "guessed_total": 0,
                    "total_malicious": 0,
                    "total_suspicious": 0,
                    "total_values": 1
                }
            },
            "evidence_map": {
                "evidence": "map"
            },
            "filter_data": {
                "group_by_value": "msedge.exe"
            },
            "guid_string": "7vCmFCPB0XpbELrD",
            "is_malicious": true,
            "malicious": true,
            "simple_values": {
                "command_line": {
                    "total_values": 1,
                    "values": [
                        "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --no-appcompat-clear --mojo-platform-channel-handle=2744 --field-trial-handle=2328,i,5521555393418764293,4286640738456912470,262144 --variations-seed-version /prefetch:3"
                    ]
                },
                "creation_time": {
                    "total_values": 1,
                    "values": [
                        "2024-03-12T08:40:35.122Z"
                    ]
                },
                "element_display_name": {
                    "total_values": 1,
                    "values": [
                        "msedge.exe"
                    ]
                },
                "end_time": {
                    "total_values": 1,
                    "values": [
                        "2024-03-12T15:13:27.872Z"
                    ]
                },
                "execution_prevented": {
                    "total_values": 1,
                    "values": [
                        false
                    ]
                },
                "group": {
                    "total_values": 1,
                    "values": [
                        "72a61eac-6f79-4670-8607-a1334ddd2ff0"
                    ]
                },
                "icon_base64": {
                    "total_values": 1,
                    "values": [
                        "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"
                    ]
                },
                "image_file_company_name": {
                    "total_values": 1,
                    "values": [
                        "Microsoft Corporation"
                    ]
                },
                "image_file_hash_icon_base64": {
                    "total_values": 1,
                    "values": [
                        "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"
                    ]
                },
                "image_file_malicious_classification_type": {
                    "total_values": 1,
                    "values": [
                        "indifferent"
                    ]
                },
                "image_file_md5_string": {
                    "total_values": 1,
                    "values": [
                        "5ac5ddc4c27ecc203b2ed62bbe8fb8b9"
                    ]
                },
                "image_file_product_name": {
                    "total_values": 1,
                    "values": [
                        "Microsoft Edge"
                    ]
                },
                "image_file_sha1_string": {
                    "total_values": 1,
                    "values": [
                        "a3c06b947549921d60d59917575df5ee5dfc472a"
                    ]
                },
                "is_image_file_signed_and_verified": {
                    "total_values": 1,
                    "values": [
                        true
                    ]
                },
                "is_white_list_classification": {
                    "total_values": 1,
                    "values": [
                        false
                    ]
                },
                "product_type": {
                    "total_values": 1,
                    "values": [
                        "BROWSER"
                    ]
                },
                "ransomware_auto_remediation_suspended": {
                    "total_values": 1,
                    "values": [
                        false
                    ]
                }
            },
            "suspect": true,
            "suspicion_count": 1,
            "suspicions": {
                "connectingToBlackListAddressSuspicion": 1710232863248
            },
            "suspicions_map": {
                "connectingToBlackListAddressSuspicion": {
                    "firstTimestamp": 1710232863248,
                    "potentialEvidence": [
                        "hasBlackListConnectionEvidence"
                    ],
                    "totalSuspicions": 4
                }
            }
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "malware"
        ],
        "created": [
            "2024-03-12T08:40:35.122Z"
        ],
        "id": "7vCmFCPB0XpbELrD",
        "kind": "alert",
        "original": "[{\"simpleValues\":{\"commandLine\":{\"totalValues\":1,\"values\":[\"\\\"C:\\\\Program Files (x86)\\\\Microsoft\\\\Edge\\\\Application\\\\msedge.exe\\\" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --no-appcompat-clear --mojo-platform-channel-handle=2744 --field-trial-handle=2328,i,5521555393418764293,4286640738456912470,262144 --variations-seed-version \\/prefetch:3\"]},\"group\":{\"totalValues\":1,\"values\":[\"72a61eac-6f79-4670-8607-a1334ddd2ff0\"]},\"imageFile.maliciousClassificationType\":{\"totalValues\":1,\"values\":[\"indifferent\"]},\"ransomwareAutoRemediationSuspended\":{\"totalValues\":1,\"values\":[\"false\"]},\"imageFile.fileHash.iconBase64\":{\"totalValues\":1,\"values\":[\"iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAh4SURBVFhHpdd7UFNnGgbwWBURCAQVtu0\\/OzudcXVFVEBATdWKLVvkIuEmWAoUtOttqsICIiqKiEQBoV4xut1O1d11lW4RvFTSQ0ggECABkhAIIF4QpXZTt1Pcdbt59j050QoBq+07804YhuT5fe\\/58p0D70XLi3kQM69mgJlb02+aU9OHObIeeMqMmCM3YI5Ci3n1Gmr1kE+jsptaskhd\\/WvrW39Z+TDfSnwY05BXzQNQOPVtsIDZsm7qLnjWdsBTrsWculYCNMOnQQn\\/phoINdfNS9oudy\\/TVgitH\\/Vy5cs8Evoy35t8mIfwrvkGXjWDFH6Hwm\\/Cs+YGZtewgA54yPSYLW+Dp6IVc+ub4KVUYUEzC7iGpW0VWK67iKCuM+qwXsmLT8SPeZTvywyZLeHMP+HFDGJezT0C3OVWT+EelnAO4FHbRgg1AVTwbqiHb5MMC1qqLYDAjnN413AGK3tPDMX158dYI8YuP+Y\\/Elo55jPfgQXQ+C2rn0fh7AQsq6fRz2KDLa2jn1lAK02hGfOUjfBVsRO4agWcRVh3GQsAAcyr+\\/PGRvgzj\\/MJAFo99fcU\\/i1N4AEB7lsAnjLu2nvIDJbVs8GzZO34nawVs2pZQAvtBRXtAxmE6itY1n4RgfrPCHAC0TcLQeFIGNhhTh5Mt90X\\/sx\\/hRRu9mP+bQHMZ\\/5F\\/ZCC2Wt\\/l177afUsoJNCtU+DR\\/ZseTMhGmgjfonFmgoEaM8juOsEIm4UIe52LpLuZ2HN16lD1tgfy495bKKm8EdWwHfwkpow84tbmFnRS92DGZe6CGCkcP2o4Wx7yFtoLyixsPkKAf6BgHYWUIaIXjFib+UhaSAVawY3YaMpRWKNtqxewoY\\/Wf30c31w230NLqnlEGRWwjXrCqZkVVFfwtSMcryaX4U3\\/t48BoD9KjLwbZRiUUsllmvPIMhQhugbuYi9mY3E\\/i1IubceGx7Em63xFsAQXX94fP4NBFnXwM+4BudsBi67FBDk1sM1rwFT8pSYmleHabkyTNstxbSdl\\/FqbhWmV2qGAWbLVZhbJ4e\\/6hIWt\\/wNAa2fYEVHCUI7xVjVtw0JdzYh+e5a\\/OF+PDY9iJRQ+A8xBMD0M\\/1wSL0Kp+214Oc0wnmvBi772yEQ6+B6UIcp1FMLdXArbIPbgRa47a+HW64UbtkVeOMCNw2P2hY6lBQEUGB+fRUWNV\\/EMs0pBHcUQ2TMQUxvBuJubMYH\\/Wvx4b14rB+MHuAtqn6kmXn+a0xOk8IhWwnH3Wrw83RwLjDARdwJQWEXXIuMmHLIiKnU00qoDxngXqyD+4EmuOfJ4LajEr+tUtKpKMdcuRReisvwbziPN5s+xTL1MQTr8hBu2I5o4xa835eCpNuJSOmPxYd3ReB5Vzz8H39nI+yzVXDY3QbHvA445XeCX2CE8wEjXA52Q1DUDdfiHkL0YGpJDyE68XppR\\/evSg0F7kXqdPd9CuVrBdfhwbCA6wSoxALlZ3hTdQpvNR9BiC4XIkMWAbZide9aJN5MRPKtKA4w4y+DmLS9Gfa72jA5Vw+HvE447qPe3zUcUcghBNl1+M2Wz0us2+dpuefVJk4vr4a3\\/AJ8FefgX\\/dnLFaVIaBJjOC2TIRqMxFp2Ij3ehKR0LfaAlhzJxw8t+Iu2GW3YlKOHva5Bkzea7AgHKwIpwKCiDmESzoDxyCx0pppUzM+ufrYW3aWAGexsP4kFisPYplKjCBNBkLb0yDSb0CsIQ7x3VFIuiFCys1Q8FwPGjFxpw52u\\/SYtNsA+z0cYvJIRKaCwgvgFFaabs2zKZ+\\/Xm33ln0Kv9ojWKQoxJIGMd5pzECgKg0hmnUIb09GlC4e7xkj8b4xBCl9gWbehGwtJhBg4q4O2OV0EKLDgrB\\/FrFXD8fQIgovAV90PNWaZ1PejCTfR3aKAIcJcABL6vYgoD6NABsQ0pIIUXsCYvTRNAUR4jt\\/j0RjQDdv\\/HYC7NATQm+LYC8Ji9hQBccQAoiOgR95ssCaZ1M+X5UMzK85goW1+6n34S1FKpYrUxHYuA4rGhMQpo6HSBOFWH0IYnXvIt4QIOS9sl2H8dm6URGTrAiHiKNwWnmYDQc\\/+nS3NW9YeUk\\/FnpLi+k0FcOfyYWwdieWyrciQLEegfUJHKBJBFFLKCI1QYjTBzKWN76SpTONhbBjJ5HVDIeQQlr9cfCjTrEAMz\\/qtM3DhXe1uNxbWghf6R4sZHZCyGzF0tqNCJAn4526BAQ1rEKoKhwidQgL4MLZGrdNxxACTxDjR04inQ6n0ENwiihjw6n\\/RJDTA9a3Dyvf6hy1nzTHvECaToBUAqwjwAd4Wx6HoPpwBDeEm8JUoZutf87VuG3aGELABkE9kb4Z9usq4RhWah0\\/hXMAdhrl1o+wKaF002Yh85FkCZPMBMhWM2\\/XrpIEyiPGfjYkxBCLGPcsIptD2KXVw3Hlx6MB4Bx5ctT98PKVqc0nBCw9AjExXUUTKIHT6AA4R5QNOYtODB\\/rc8p1RWGMa9DBUR5QM7Um3ggEB6EzIPww7YETFP50DzwLAAGojw+5hB8rd1l51OaZTxByKEYQXCwRBBeZCAACjDK5TK2Q2jwaYlLKF3AKP0qhEg4xOgAEAAGoj8Al7DAEoaXUJSAACEBdBAKYCTDGfqBLQY2RiPEZLXCMOEaXgb4J7FfxlwHyrWljVKZWYoOgtlt3jaZwhNuMkSziZwF+fA58bnGTMLOQZxH2SRe4S8GeCZESAlD4iwHMBPiJlY8sbk+YRiIsk6AAuilROBvMhTvTfWIMgIkAP+\\/\\/Q0tx06BzgoVwiPHpLZicdBF8uj8400ScKZR95YKp6fcEGCLAS676eZXJnphahhCmJ6fmhKw22P2xge6WX8Lxo6\\/gmsr88Fpa9cPXU86PecseXjze\\/wGADjhbeB2rcwAAAABJRU5ErkJggg==\"]},\"executionPrevented\":{\"totalValues\":1,\"values\":[\"false\"]},\"isWhiteListClassification\":{\"totalValues\":1,\"values\":[\"false\"]},\"imageFile.md5String\":{\"totalValues\":1,\"values\":[\"5ac5ddc4c27ecc203b2ed62bbe8fb8b9\"]},\"creationTime\":{\"totalValues\":1,\"values\":[\"1710232835122\"]},\"endTime\":{\"totalValues\":1,\"values\":[\"1710256407872\"]},\"imageFile.sha1String\":{\"totalValues\":1,\"values\":[\"a3c06b947549921d60d59917575df5ee5dfc472a\"]},\"isImageFileSignedAndVerified\":{\"totalValues\":1,\"values\":[\"true\"]},\"iconBase64\":{\"totalValues\":1,\"values\":[\"iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAh4SURBVFhHpdd7UFNnGgbwWBURCAQVtu0\\/OzudcXVFVEBATdWKLVvkIuEmWAoUtOttqsICIiqKiEQBoV4xut1O1d11lW4RvFTSQ0ggECABkhAIIF4QpXZTt1Pcdbt59j050QoBq+07804YhuT5fe\\/58p0D70XLi3kQM69mgJlb02+aU9OHObIeeMqMmCM3YI5Ci3n1Gmr1kE+jsptaskhd\\/WvrW39Z+TDfSnwY05BXzQNQOPVtsIDZsm7qLnjWdsBTrsWculYCNMOnQQn\\/phoINdfNS9oudy\\/TVgitH\\/Vy5cs8Evoy35t8mIfwrvkGXjWDFH6Hwm\\/Cs+YGZtewgA54yPSYLW+Dp6IVc+ub4KVUYUEzC7iGpW0VWK67iKCuM+qwXsmLT8SPeZTvywyZLeHMP+HFDGJezT0C3OVWT+EelnAO4FHbRgg1AVTwbqiHb5MMC1qqLYDAjnN413AGK3tPDMX158dYI8YuP+Y\\/Elo55jPfgQXQ+C2rn0fh7AQsq6fRz2KDLa2jn1lAK02hGfOUjfBVsRO4agWcRVh3GQsAAcyr+\\/PGRvgzj\\/MJAFo99fcU\\/i1N4AEB7lsAnjLu2nvIDJbVs8GzZO34nawVs2pZQAvtBRXtAxmE6itY1n4RgfrPCHAC0TcLQeFIGNhhTh5Mt90X\\/sx\\/hRRu9mP+bQHMZ\\/5F\\/ZCC2Wt\\/l177afUsoJNCtU+DR\\/ZseTMhGmgjfonFmgoEaM8juOsEIm4UIe52LpLuZ2HN16lD1tgfy495bKKm8EdWwHfwkpow84tbmFnRS92DGZe6CGCkcP2o4Wx7yFtoLyixsPkKAf6BgHYWUIaIXjFib+UhaSAVawY3YaMpRWKNtqxewoY\\/Wf30c31w230NLqnlEGRWwjXrCqZkVVFfwtSMcryaX4U3\\/t48BoD9KjLwbZRiUUsllmvPIMhQhugbuYi9mY3E\\/i1IubceGx7Em63xFsAQXX94fP4NBFnXwM+4BudsBi67FBDk1sM1rwFT8pSYmleHabkyTNstxbSdl\\/FqbhWmV2qGAWbLVZhbJ4e\\/6hIWt\\/wNAa2fYEVHCUI7xVjVtw0JdzYh+e5a\\/OF+PDY9iJRQ+A8xBMD0M\\/1wSL0Kp+214Oc0wnmvBi772yEQ6+B6UIcp1FMLdXArbIPbgRa47a+HW64UbtkVeOMCNw2P2hY6lBQEUGB+fRUWNV\\/EMs0pBHcUQ2TMQUxvBuJubMYH\\/Wvx4b14rB+MHuAtqn6kmXn+a0xOk8IhWwnH3Wrw83RwLjDARdwJQWEXXIuMmHLIiKnU00qoDxngXqyD+4EmuOfJ4LajEr+tUtKpKMdcuRReisvwbziPN5s+xTL1MQTr8hBu2I5o4xa835eCpNuJSOmPxYd3ReB5Vzz8H39nI+yzVXDY3QbHvA445XeCX2CE8wEjXA52Q1DUDdfiHkL0YGpJDyE68XppR\\/evSg0F7kXqdPd9CuVrBdfhwbCA6wSoxALlZ3hTdQpvNR9BiC4XIkMWAbZide9aJN5MRPKtKA4w4y+DmLS9Gfa72jA5Vw+HvE447qPe3zUcUcghBNl1+M2Wz0us2+dpuefVJk4vr4a3\\/AJ8FefgX\\/dnLFaVIaBJjOC2TIRqMxFp2Ij3ehKR0LfaAlhzJxw8t+Iu2GW3YlKOHva5Bkzea7AgHKwIpwKCiDmESzoDxyCx0pppUzM+ufrYW3aWAGexsP4kFisPYplKjCBNBkLb0yDSb0CsIQ7x3VFIuiFCys1Q8FwPGjFxpw52u\\/SYtNsA+z0cYvJIRKaCwgvgFFaabs2zKZ+\\/Xm33ln0Kv9ojWKQoxJIGMd5pzECgKg0hmnUIb09GlC4e7xkj8b4xBCl9gWbehGwtJhBg4q4O2OV0EKLDgrB\\/FrFXD8fQIgovAV90PNWaZ1PejCTfR3aKAIcJcABL6vYgoD6NABsQ0pIIUXsCYvTRNAUR4jt\\/j0RjQDdv\\/HYC7NATQm+LYC8Ji9hQBccQAoiOgR95ssCaZ1M+X5UMzK85goW1+6n34S1FKpYrUxHYuA4rGhMQpo6HSBOFWH0IYnXvIt4QIOS9sl2H8dm6URGTrAiHiKNwWnmYDQc\\/+nS3NW9YeUk\\/FnpLi+k0FcOfyYWwdieWyrciQLEegfUJHKBJBFFLKCI1QYjTBzKWN76SpTONhbBjJ5HVDIeQQlr9cfCjTrEAMz\\/qtM3DhXe1uNxbWghf6R4sZHZCyGzF0tqNCJAn4526BAQ1rEKoKhwidQgL4MLZGrdNxxACTxDjR04inQ6n0ENwiihjw6n\\/RJDTA9a3Dyvf6hy1nzTHvECaToBUAqwjwAd4Wx6HoPpwBDeEm8JUoZutf87VuG3aGELABkE9kb4Z9usq4RhWah0\\/hXMAdhrl1o+wKaF002Yh85FkCZPMBMhWM2\\/XrpIEyiPGfjYkxBCLGPcsIptD2KXVw3Hlx6MB4Bx5ctT98PKVqc0nBCw9AjExXUUTKIHT6AA4R5QNOYtODB\\/rc8p1RWGMa9DBUR5QM7Um3ggEB6EzIPww7YETFP50DzwLAAGojw+5hB8rd1l51OaZTxByKEYQXCwRBBeZCAACjDK5TK2Q2jwaYlLKF3AKP0qhEg4xOgAEAAGoj8Al7DAEoaXUJSAACEBdBAKYCTDGfqBLQY2RiPEZLXCMOEaXgb4J7FfxlwHyrWljVKZWYoOgtlt3jaZwhNuMkSziZwF+fA58bnGTMLOQZxH2SRe4S8GeCZESAlD4iwHMBPiJlY8sbk+YRiIsk6AAuilROBvMhTvTfWIMgIkAP+\\/\\/Q0tx06BzgoVwiPHpLZicdBF8uj8400ScKZR95YKp6fcEGCLAS676eZXJnphahhCmJ6fmhKw22P2xge6WX8Lxo6\\/gmsr88Fpa9cPXU86PecseXjze\\/wGADjhbeB2rcwAAAABJRU5ErkJggg==\"]},\"imageFile.productName\":{\"totalValues\":1,\"values\":[\"Microsoft Edge\"]},\"elementDisplayName\":{\"totalValues\":1,\"values\":[\"msedge.exe\"]},\"imageFile.companyName\":{\"totalValues\":1,\"values\":[\"Microsoft Corporation\"]},\"productType\":{\"totalValues\":1,\"values\":[\"BROWSER\"]}},\"elementValues\":{\"children\":{\"totalValues\":0,\"elementValues\":[],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"calculatedUser\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"User\",\"guid\":\"AAAAGGZ3xLXVm27e\",\"name\":\"cy\\\\cymulator\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"ownerMachine\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"Machine\",\"guid\":\"7vCmFBCi55eyTiwX\",\"name\":\"dim-win10\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"parentProcess\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"Process\",\"guid\":\"7vCmFMsvYy739EW5\",\"name\":\"msedge.exe\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0},\"imageFile\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"File\",\"guid\":\"7vCmFKxNAQXpBIkL\",\"name\":\"msedge.exe\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{\"fileHash\":{\"totalValues\":1,\"elementValues\":[{\"elementType\":\"FileHash\",\"guid\":\"AAAAHuaPtU7zGEJc\",\"name\":\"a3c06b947549921d60d59917575df5ee5dfc472a\",\"hasSuspicions\":false,\"hasMalops\":false,\"elementValues\":{},\"simpleValues\":{\"iconBase64\":{\"totalValues\":1,\"values\":[\"iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAh4SURBVFhHpdd7UFNnGgbwWBURCAQVtu0\\/OzudcXVFVEBATdWKLVvkIuEmWAoUtOttqsICIiqKiEQBoV4xut1O1d11lW4RvFTSQ0ggECABkhAIIF4QpXZTt1Pcdbt59j050QoBq+07804YhuT5fe\\/58p0D70XLi3kQM69mgJlb02+aU9OHObIeeMqMmCM3YI5Ci3n1Gmr1kE+jsptaskhd\\/WvrW39Z+TDfSnwY05BXzQNQOPVtsIDZsm7qLnjWdsBTrsWculYCNMOnQQn\\/phoINdfNS9oudy\\/TVgitH\\/Vy5cs8Evoy35t8mIfwrvkGXjWDFH6Hwm\\/Cs+YGZtewgA54yPSYLW+Dp6IVc+ub4KVUYUEzC7iGpW0VWK67iKCuM+qwXsmLT8SPeZTvywyZLeHMP+HFDGJezT0C3OVWT+EelnAO4FHbRgg1AVTwbqiHb5MMC1qqLYDAjnN413AGK3tPDMX158dYI8YuP+Y\\/Elo55jPfgQXQ+C2rn0fh7AQsq6fRz2KDLa2jn1lAK02hGfOUjfBVsRO4agWcRVh3GQsAAcyr+\\/PGRvgzj\\/MJAFo99fcU\\/i1N4AEB7lsAnjLu2nvIDJbVs8GzZO34nawVs2pZQAvtBRXtAxmE6itY1n4RgfrPCHAC0TcLQeFIGNhhTh5Mt90X\\/sx\\/hRRu9mP+bQHMZ\\/5F\\/ZCC2Wt\\/l177afUsoJNCtU+DR\\/ZseTMhGmgjfonFmgoEaM8juOsEIm4UIe52LpLuZ2HN16lD1tgfy495bKKm8EdWwHfwkpow84tbmFnRS92DGZe6CGCkcP2o4Wx7yFtoLyixsPkKAf6BgHYWUIaIXjFib+UhaSAVawY3YaMpRWKNtqxewoY\\/Wf30c31w230NLqnlEGRWwjXrCqZkVVFfwtSMcryaX4U3\\/t48BoD9KjLwbZRiUUsllmvPIMhQhugbuYi9mY3E\\/i1IubceGx7Em63xFsAQXX94fP4NBFnXwM+4BudsBi67FBDk1sM1rwFT8pSYmleHabkyTNstxbSdl\\/FqbhWmV2qGAWbLVZhbJ4e\\/6hIWt\\/wNAa2fYEVHCUI7xVjVtw0JdzYh+e5a\\/OF+PDY9iJRQ+A8xBMD0M\\/1wSL0Kp+214Oc0wnmvBi772yEQ6+B6UIcp1FMLdXArbIPbgRa47a+HW64UbtkVeOMCNw2P2hY6lBQEUGB+fRUWNV\\/EMs0pBHcUQ2TMQUxvBuJubMYH\\/Wvx4b14rB+MHuAtqn6kmXn+a0xOk8IhWwnH3Wrw83RwLjDARdwJQWEXXIuMmHLIiKnU00qoDxngXqyD+4EmuOfJ4LajEr+tUtKpKMdcuRReisvwbziPN5s+xTL1MQTr8hBu2I5o4xa835eCpNuJSOmPxYd3ReB5Vzz8H39nI+yzVXDY3QbHvA445XeCX2CE8wEjXA52Q1DUDdfiHkL0YGpJDyE68XppR\\/evSg0F7kXqdPd9CuVrBdfhwbCA6wSoxALlZ3hTdQpvNR9BiC4XIkMWAbZide9aJN5MRPKtKA4w4y+DmLS9Gfa72jA5Vw+HvE447qPe3zUcUcghBNl1+M2Wz0us2+dpuefVJk4vr4a3\\/AJ8FefgX\\/dnLFaVIaBJjOC2TIRqMxFp2Ij3ehKR0LfaAlhzJxw8t+Iu2GW3YlKOHva5Bkzea7AgHKwIpwKCiDmESzoDxyCx0pppUzM+ufrYW3aWAGexsP4kFisPYplKjCBNBkLb0yDSb0CsIQ7x3VFIuiFCys1Q8FwPGjFxpw52u\\/SYtNsA+z0cYvJIRKaCwgvgFFaabs2zKZ+\\/Xm33ln0Kv9ojWKQoxJIGMd5pzECgKg0hmnUIb09GlC4e7xkj8b4xBCl9gWbehGwtJhBg4q4O2OV0EKLDgrB\\/FrFXD8fQIgovAV90PNWaZ1PejCTfR3aKAIcJcABL6vYgoD6NABsQ0pIIUXsCYvTRNAUR4jt\\/j0RjQDdv\\/HYC7NATQm+LYC8Ji9hQBccQAoiOgR95ssCaZ1M+X5UMzK85goW1+6n34S1FKpYrUxHYuA4rGhMQpo6HSBOFWH0IYnXvIt4QIOS9sl2H8dm6URGTrAiHiKNwWnmYDQc\\/+nS3NW9YeUk\\/FnpLi+k0FcOfyYWwdieWyrciQLEegfUJHKBJBFFLKCI1QYjTBzKWN76SpTONhbBjJ5HVDIeQQlr9cfCjTrEAMz\\/qtM3DhXe1uNxbWghf6R4sZHZCyGzF0tqNCJAn4526BAQ1rEKoKhwidQgL4MLZGrdNxxACTxDjR04inQ6n0ENwiihjw6n\\/RJDTA9a3Dyvf6hy1nzTHvECaToBUAqwjwAd4Wx6HoPpwBDeEm8JUoZutf87VuG3aGELABkE9kb4Z9usq4RhWah0\\/hXMAdhrl1o+wKaF002Yh85FkCZPMBMhWM2\\/XrpIEyiPGfjYkxBCLGPcsIptD2KXVw3Hlx6MB4Bx5ctT98PKVqc0nBCw9AjExXUUTKIHT6AA4R5QNOYtODB\\/rc8p1RWGMa9DBUR5QM7Um3ggEB6EzIPww7YETFP50DzwLAAGojw+5hB8rd1l51OaZTxByKEYQXCwRBBeZCAACjDK5TK2Q2jwaYlLKF3AKP0qhEg4xOgAEAAGoj8Al7DAEoaXUJSAACEBdBAKYCTDGfqBLQY2RiPEZLXCMOEaXgb4J7FfxlwHyrWljVKZWYoOgtlt3jaZwhNuMkSziZwF+fA58bnGTMLOQZxH2SRe4S8GeCZESAlD4iwHMBPiJlY8sbk+YRiIsk6AAuilROBvMhTvTfWIMgIkAP+\\/\\/Q0tx06BzgoVwiPHpLZicdBF8uj8400ScKZR95YKp6fcEGCLAS676eZXJnphahhCmJ6fmhKw22P2xge6WX8Lxo6\\/gmsr88Fpa9cPXU86PecseXjze\\/wGADjhbeB2rcwAAAABJRU5ErkJggg==\"]}}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0}},\"simpleValues\":{\"sha1String\":{\"totalValues\":1,\"values\":[\"a3c06b947549921d60d59917575df5ee5dfc472a\"]},\"maliciousClassificationType\":{\"totalValues\":1,\"values\":[\"indifferent\"]},\"md5String\":{\"totalValues\":1,\"values\":[\"5ac5ddc4c27ecc203b2ed62bbe8fb8b9\"]},\"productName\":{\"totalValues\":1,\"values\":[\"Microsoft Edge\"]},\"companyName\":{\"totalValues\":1,\"values\":[\"Microsoft Corporation\"]}}}],\"totalSuspicious\":0,\"totalMalicious\":0,\"guessedTotal\":0}},\"suspicions\":{\"connectingToBlackListAddressSuspicion\":1710232863248},\"filterData\":{\"sortInGroupValue\":\"\",\"groupByValue\":\"msedge.exe\"},\"isMalicious\":true,\"suspicionCount\":1,\"guidString\":\"7vCmFCPB0XpbELrD\",\"labelsIds\":null,\"malopPriority\":null,\"suspect\":true,\"malicious\":true}, {\"connectingToBlackListAddressSuspicion\":{\"potentialEvidence\":[\"hasBlackListConnectionEvidence\"],\"firstTimestamp\":1710232863248,\"totalSuspicions\":4}}, {\"evidence\":\"map\"}]",
        "type": [
            "info"
        ]
    },
    "file": {
        "hash": {
            "md5": [
                "5ac5ddc4c27ecc203b2ed62bbe8fb8b9"
            ],
            "sha1": [
                "a3c06b947549921d60d59917575df5ee5dfc472a"
            ]
        },
        "name": [
            "msedge.exe"
        ],
        "uid": [
            "7vCmFKxNAQXpBIkL"
        ]
    },
    "process": {
        "command_line": [
            "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --no-appcompat-clear --mojo-platform-channel-handle=2744 --field-trial-handle=2328,i,5521555393418764293,4286640738456912470,262144 --variations-seed-version /prefetch:3"
        ],
        "parent": {
            "entity_id": [
                "7vCmFMsvYy739EW5"
            ],
            "name": [
                "msedge.exe"
            ]
        },
        "real_user": {
            "id": [
                "7vCmFBCi55eyTiwX"
            ],
            "name": [
                "dim-win10"
            ]
        }
    },
    "related": {
        "hash": [
            "5ac5ddc4c27ecc203b2ed62bbe8fb8b9",
            "a3c06b947549921d60d59917575df5ee5dfc472a"
        ],
        "user": [
            "7vCmFBCi55eyTiwX",
            "dim-win10"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cybereason.suspicions_process.element_values.calculated_user.element_values.element_type |  | keyword |
| cybereason.suspicions_process.element_values.calculated_user.element_values.guid |  | keyword |
| cybereason.suspicions_process.element_values.calculated_user.element_values.has_malops |  | boolean |
| cybereason.suspicions_process.element_values.calculated_user.element_values.has_suspicions |  | boolean |
| cybereason.suspicions_process.element_values.calculated_user.element_values.name |  | keyword |
| cybereason.suspicions_process.element_values.calculated_user.element_values.object |  | flattened |
| cybereason.suspicions_process.element_values.calculated_user.element_values.simple_values |  | flattened |
| cybereason.suspicions_process.element_values.calculated_user.guessed_total |  | long |
| cybereason.suspicions_process.element_values.calculated_user.total_malicious |  | long |
| cybereason.suspicions_process.element_values.calculated_user.total_suspicious |  | long |
| cybereason.suspicions_process.element_values.calculated_user.total_values |  | long |
| cybereason.suspicions_process.element_values.children.element_values.element_type |  | keyword |
| cybereason.suspicions_process.element_values.children.element_values.guid |  | keyword |
| cybereason.suspicions_process.element_values.children.element_values.has_malops |  | boolean |
| cybereason.suspicions_process.element_values.children.element_values.has_suspicions |  | boolean |
| cybereason.suspicions_process.element_values.children.element_values.name |  | keyword |
| cybereason.suspicions_process.element_values.children.element_values.object |  | flattened |
| cybereason.suspicions_process.element_values.children.element_values.simple_values |  | flattened |
| cybereason.suspicions_process.element_values.children.guessed_total |  | long |
| cybereason.suspicions_process.element_values.children.total_malicious |  | long |
| cybereason.suspicions_process.element_values.children.total_suspicious |  | long |
| cybereason.suspicions_process.element_values.children.total_values |  | long |
| cybereason.suspicions_process.element_values.image_file.element_values.element_type |  | keyword |
| cybereason.suspicions_process.element_values.image_file.element_values.guid |  | keyword |
| cybereason.suspicions_process.element_values.image_file.element_values.has_malops |  | boolean |
| cybereason.suspicions_process.element_values.image_file.element_values.has_suspicions |  | boolean |
| cybereason.suspicions_process.element_values.image_file.element_values.name |  | keyword |
| cybereason.suspicions_process.element_values.image_file.element_values.object |  | flattened |
| cybereason.suspicions_process.element_values.image_file.element_values.simple_values |  | flattened |
| cybereason.suspicions_process.element_values.image_file.guessed_total |  | long |
| cybereason.suspicions_process.element_values.image_file.total_malicious |  | long |
| cybereason.suspicions_process.element_values.image_file.total_suspicious |  | long |
| cybereason.suspicions_process.element_values.image_file.total_values |  | long |
| cybereason.suspicions_process.element_values.owner_machine.element_values.element_type |  | keyword |
| cybereason.suspicions_process.element_values.owner_machine.element_values.guid |  | keyword |
| cybereason.suspicions_process.element_values.owner_machine.element_values.has_malops |  | boolean |
| cybereason.suspicions_process.element_values.owner_machine.element_values.has_suspicions |  | boolean |
| cybereason.suspicions_process.element_values.owner_machine.element_values.name |  | keyword |
| cybereason.suspicions_process.element_values.owner_machine.element_values.object |  | flattened |
| cybereason.suspicions_process.element_values.owner_machine.element_values.simple_values |  | flattened |
| cybereason.suspicions_process.element_values.owner_machine.guessed_total |  | long |
| cybereason.suspicions_process.element_values.owner_machine.total_malicious |  | long |
| cybereason.suspicions_process.element_values.owner_machine.total_suspicious |  | long |
| cybereason.suspicions_process.element_values.owner_machine.total_values |  | long |
| cybereason.suspicions_process.element_values.parent_process.element_values.element_type |  | keyword |
| cybereason.suspicions_process.element_values.parent_process.element_values.guid |  | keyword |
| cybereason.suspicions_process.element_values.parent_process.element_values.has_malops |  | boolean |
| cybereason.suspicions_process.element_values.parent_process.element_values.has_suspicions |  | boolean |
| cybereason.suspicions_process.element_values.parent_process.element_values.name |  | keyword |
| cybereason.suspicions_process.element_values.parent_process.element_values.object |  | flattened |
| cybereason.suspicions_process.element_values.parent_process.element_values.simple_values |  | flattened |
| cybereason.suspicions_process.element_values.parent_process.guessed_total |  | long |
| cybereason.suspicions_process.element_values.parent_process.total_malicious |  | long |
| cybereason.suspicions_process.element_values.parent_process.total_suspicious |  | long |
| cybereason.suspicions_process.element_values.parent_process.total_values |  | long |
| cybereason.suspicions_process.evidence_map |  | flattened |
| cybereason.suspicions_process.filter_data.group_by_value |  | keyword |
| cybereason.suspicions_process.filter_data.sort_in_group_value |  | keyword |
| cybereason.suspicions_process.guid_string |  | keyword |
| cybereason.suspicions_process.is_malicious |  | boolean |
| cybereason.suspicions_process.labels_ids |  | keyword |
| cybereason.suspicions_process.malicious |  | boolean |
| cybereason.suspicions_process.malop_priority |  | keyword |
| cybereason.suspicions_process.simple_values.command_line.total_values |  | long |
| cybereason.suspicions_process.simple_values.command_line.values |  | keyword |
| cybereason.suspicions_process.simple_values.creation_time.total_values |  | long |
| cybereason.suspicions_process.simple_values.creation_time.values |  | date |
| cybereason.suspicions_process.simple_values.element_display_name.total_values |  | long |
| cybereason.suspicions_process.simple_values.element_display_name.values |  | keyword |
| cybereason.suspicions_process.simple_values.end_time.total_values |  | long |
| cybereason.suspicions_process.simple_values.end_time.values |  | date |
| cybereason.suspicions_process.simple_values.execution_prevented.total_values |  | long |
| cybereason.suspicions_process.simple_values.execution_prevented.values |  | boolean |
| cybereason.suspicions_process.simple_values.group.total_values |  | long |
| cybereason.suspicions_process.simple_values.group.values |  | keyword |
| cybereason.suspicions_process.simple_values.icon_base64.total_values |  | long |
| cybereason.suspicions_process.simple_values.icon_base64.values |  | keyword |
| cybereason.suspicions_process.simple_values.image_file_company_name.total_values |  | long |
| cybereason.suspicions_process.simple_values.image_file_company_name.values |  | keyword |
| cybereason.suspicions_process.simple_values.image_file_hash_icon_base64.total_values |  | long |
| cybereason.suspicions_process.simple_values.image_file_hash_icon_base64.values |  | keyword |
| cybereason.suspicions_process.simple_values.image_file_malicious_classification_type.total_values |  | long |
| cybereason.suspicions_process.simple_values.image_file_malicious_classification_type.values |  | keyword |
| cybereason.suspicions_process.simple_values.image_file_md5_string.total_values |  | long |
| cybereason.suspicions_process.simple_values.image_file_md5_string.values |  | keyword |
| cybereason.suspicions_process.simple_values.image_file_product_name.total_values |  | long |
| cybereason.suspicions_process.simple_values.image_file_product_name.values |  | keyword |
| cybereason.suspicions_process.simple_values.image_file_sha1_string.total_values |  | long |
| cybereason.suspicions_process.simple_values.image_file_sha1_string.values |  | keyword |
| cybereason.suspicions_process.simple_values.is_image_file_signed_and_verified.total_values |  | long |
| cybereason.suspicions_process.simple_values.is_image_file_signed_and_verified.values |  | boolean |
| cybereason.suspicions_process.simple_values.is_white_list_classification.total_values |  | long |
| cybereason.suspicions_process.simple_values.is_white_list_classification.values |  | boolean |
| cybereason.suspicions_process.simple_values.product_type.total_values |  | long |
| cybereason.suspicions_process.simple_values.product_type.values |  | keyword |
| cybereason.suspicions_process.simple_values.ransomware_auto_remediation_suspended.total_values |  | long |
| cybereason.suspicions_process.simple_values.ransomware_auto_remediation_suspended.values |  | boolean |
| cybereason.suspicions_process.suspect |  | boolean |
| cybereason.suspicions_process.suspicion_count |  | long |
| cybereason.suspicions_process.suspicions |  | flattened |
| cybereason.suspicions_process.suspicions_map |  | flattened |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
