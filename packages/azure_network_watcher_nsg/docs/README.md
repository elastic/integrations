# Azure Network Watcher NSG

[Network security group](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview) (NSG) flow logging is a feature of Azure Network Watcher that allows you to log information about IP traffic flowing through a network security group. Flow logs are the source of truth for all network activity in your cloud environment. Whether you're in a startup that's trying to optimize resources or a large enterprise that's trying to detect intrusion, flow logs can help. You can use them for optimizing network flows, monitoring throughput, verifying compliance, detecting intrusions, and more.

## Data streams

This integration supports ingestion of logs from Azure Network Watcher NSG, via [Azure Blob Storage](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-blob-storage.html) input.

**Log** is used to retrieve NSG Flow data. See more details in the documentation [here](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview).

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#_minimum_requirements).

The minimum **Kibana version** required is **8.12.0**.

## Setup

### To collect data from Azure Network Watcher NSG follow the below steps:

1. In the [Azure portal](https://portal.azure.com/), go to your **storage account**.
2. Under **Security + networking**, Click on **Access keys**. Your account access keys appear, as well as the complete connection string for each key.
3. Click on **Show** keys to show your **access keys** and **connection strings** and to enable buttons to copy the values.
4. Under key1, find the Key value. Click on the Copy button to copy the **account key**. Same way you can copy the **storage account name** shown above keys.
5. Go to **Containers** under **Data storage** in your storage account to copy the **container name**.

**Note**:  Enable virtual network flow logs using the steps provided in [reference](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-portal).

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Azure Network Watcher NSG.
3. Click on the "Azure Network Watcher NSG" integration from the search results.
4. Click on the "Add Azure Network Watcher NSG" button to add the integration.
5. While adding the integration, to collect logs via Azure Blob Storage, keep **Collect NSG logs via Azure Blob Storage** toggle on and then configure following parameters:
   - account name
   - containers
   - service account key/service account uri
6. Save the integration.

## Logs Reference

### Log

This is the `Log` dataset.

#### Example

An example event for `log` looks as following:

```json
{
    "@timestamp": "2018-11-13T12:00:35.389Z",
    "agent": {
        "ephemeral_id": "b9d6de84-93bd-40d6-9dc8-c06a84e0718e",
        "id": "7a02b789-2d3c-4e39-a804-6995ecfd6bc0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "azure": {
        "resource": {
            "group": "FABRIKAMRG",
            "id": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/FABRIKAMRG/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/FABRIAKMVM1-NSG",
            "name": "FABRIAKMVM1-NSG",
            "provider": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS"
        },
        "storage": {
            "blob": {
                "content_type": "application/json",
                "name": "testblob"
            },
            "container": {
                "name": "azure-container1"
            }
        },
        "subscription_id": "00000000-0000-0000-0000-000000000000"
    },
    "azure_network_watcher_nsg": {
        "log": {
            "category": "NetworkSecurityGroupFlowEvent",
            "operation_name": "NetworkSecurityGroupFlowEvents",
            "properties": {
                "flows": [
                    {
                        "flows": [
                            {
                                "mac": "00-0D-3A-F8-78-56",
                                "tuples": [
                                    {
                                        "destination": {
                                            "ip": "10.5.16.4",
                                            "port": 443
                                        },
                                        "flow_state": "Begin",
                                        "protocol": "UDP",
                                        "source": {
                                            "ip": "94.102.49.190",
                                            "port": 28746
                                        },
                                        "timestamp": "2018-11-13T12:00:02.000Z",
                                        "traffic": {
                                            "decision": "Denied",
                                            "flow": "Inbound"
                                        }
                                    },
                                    {
                                        "destination": {
                                            "ip": "10.5.16.4",
                                            "port": 59336
                                        },
                                        "flow_state": "Begin",
                                        "protocol": "TCP",
                                        "source": {
                                            "ip": "176.119.4.10",
                                            "port": 56509
                                        },
                                        "timestamp": "2018-11-13T12:00:24.000Z",
                                        "traffic": {
                                            "decision": "Denied",
                                            "flow": "Inbound"
                                        }
                                    },
                                    {
                                        "destination": {
                                            "ip": "10.5.16.4",
                                            "port": 8088
                                        },
                                        "flow_state": "Begin",
                                        "protocol": "TCP",
                                        "source": {
                                            "ip": "167.99.86.8",
                                            "port": 48495
                                        },
                                        "timestamp": "2018-11-13T12:00:32.000Z",
                                        "traffic": {
                                            "decision": "Denied",
                                            "flow": "Inbound"
                                        }
                                    }
                                ]
                            }
                        ],
                        "rule": "DefaultRule_DenyAllInBound"
                    },
                    {
                        "flows": [
                            {
                                "mac": "00-0D-3A-F8-78-56",
                                "tuples": [
                                    {
                                        "destination": {
                                            "ip": "13.67.143.118",
                                            "port": 443
                                        },
                                        "flow_state": "Begin",
                                        "protocol": "TCP",
                                        "source": {
                                            "ip": "10.5.16.4",
                                            "port": 59831
                                        },
                                        "timestamp": "2018-11-13T11:59:37.000Z",
                                        "traffic": {
                                            "decision": "Allowed",
                                            "flow": "Outbound"
                                        }
                                    },
                                    {
                                        "bytes": {
                                            "received": 66,
                                            "sent": 66
                                        },
                                        "destination": {
                                            "ip": "13.67.143.117",
                                            "port": 443
                                        },
                                        "flow_state": "End",
                                        "packets": {
                                            "received": 1,
                                            "sent": 1
                                        },
                                        "protocol": "TCP",
                                        "source": {
                                            "ip": "10.5.16.4",
                                            "port": 59932
                                        },
                                        "timestamp": "2018-11-13T11:59:39.000Z",
                                        "traffic": {
                                            "decision": "Allowed",
                                            "flow": "Outbound"
                                        }
                                    },
                                    {
                                        "bytes": {
                                            "received": 14008,
                                            "sent": 16978
                                        },
                                        "destination": {
                                            "ip": "13.67.143.115",
                                            "port": 443
                                        },
                                        "flow_state": "Continuing",
                                        "packets": {
                                            "received": 24,
                                            "sent": 30
                                        },
                                        "protocol": "TCP",
                                        "source": {
                                            "ip": "10.5.16.4",
                                            "port": 44931
                                        },
                                        "timestamp": "2018-11-13T11:59:39.000Z",
                                        "traffic": {
                                            "decision": "Allowed",
                                            "flow": "Outbound"
                                        }
                                    },
                                    {
                                        "bytes": {
                                            "received": 7054,
                                            "sent": 8489
                                        },
                                        "destination": {
                                            "ip": "40.71.12.225",
                                            "port": 443
                                        },
                                        "flow_state": "End",
                                        "packets": {
                                            "received": 12,
                                            "sent": 15
                                        },
                                        "protocol": "TCP",
                                        "source": {
                                            "ip": "10.5.16.4",
                                            "port": 59929
                                        },
                                        "timestamp": "2018-11-13T12:00:06.000Z",
                                        "traffic": {
                                            "decision": "Allowed",
                                            "flow": "Outbound"
                                        }
                                    }
                                ]
                            }
                        ],
                        "rule": "DefaultRule_AllowInternetOutBound"
                    }
                ],
                "version": "2"
            },
            "resource_id": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/FABRIKAMRG/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/FABRIAKMVM1-NSG",
            "system_id": "a0fca5ce-022c-47b1-9735-89943b42f2fa",
            "time": "2018-11-13T12:00:35.389Z"
        }
    },
    "cloud": {
        "provider": "azure"
    },
    "data_stream": {
        "dataset": "azure_network_watcher_nsg.log",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": [
            66,
            7054,
            14008
        ],
        "ip": [
            "13.67.143.118",
            "13.67.143.117",
            "10.5.16.4",
            "40.71.12.225",
            "13.67.143.115"
        ],
        "packets": [
            1,
            12,
            24
        ],
        "port": [
            8088,
            443,
            59336
        ]
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7a02b789-2d3c-4e39-a804-6995ecfd6bc0",
        "snapshot": false,
        "version": "8.12.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "azure_network_watcher_nsg.log",
        "ingested": "2024-05-03T08:30:09Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "azure-blob-storage"
    },
    "log": {
        "file": {
            "path": "http://elastic-package-service-azure-network-watcher-nsg-log-1:10000/devstoreaccount1/azure-container1/testblob"
        },
        "offset": 1
    },
    "network": {
        "direction": [
            "outbound",
            "inbound"
        ],
        "transport": [
            "udp",
            "tcp"
        ]
    },
    "related": {
        "ip": [
            "13.67.143.118",
            "13.67.143.117",
            "10.5.16.4",
            "40.71.12.225",
            "13.67.143.115",
            "176.119.4.10",
            "94.102.49.190",
            "167.99.86.8"
        ]
    },
    "rule": {
        "name": [
            "DefaultRule_DenyAllInBound",
            "DefaultRule_AllowInternetOutBound"
        ]
    },
    "source": {
        "bytes": [
            66,
            8489,
            16978
        ],
        "ip": [
            "176.119.4.10",
            "10.5.16.4",
            "94.102.49.190",
            "167.99.86.8"
        ],
        "mac": [
            "00-0D-3A-F8-78-56"
        ],
        "packets": [
            1,
            15,
            30
        ],
        "port": [
            59932,
            44931,
            59831,
            28746,
            56509,
            59929,
            48495
        ]
    },
    "tags": [
        "forwarded",
        "azure_network_watcher_nsg-log"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.resource.group | Resource group. | keyword |
| azure.resource.id | Resource ID. | keyword |
| azure.resource.name | Name. | keyword |
| azure.resource.provider | Resource type/namespace. | keyword |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object. | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object. | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container. | keyword |
| azure.subscription_id | Azure subscription ID. | keyword |
| azure_network_watcher_nsg.log.category | Category of the event. | keyword |
| azure_network_watcher_nsg.log.operation_name | Always NetworkSecurityGroupFlowEvents. | keyword |
| azure_network_watcher_nsg.log.properties.flows.flows.mac | MAC address of the network interface on which the flows are listed. | keyword |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.bytes.received | Total number of TCP packet bytes sent from destination to source. | long |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.bytes.sent | Total number of TCP packet bytes sent from source to destination. | long |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.destination.ip | Destination IP address. | ip |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.destination.port | Destination port. | long |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.flow_state | State of the flow. | keyword |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.packets.received | Total number of TCP packets sent from destination to source. | long |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.packets.sent | Total number of TCP packets sent from source to destination. | long |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.protocol | Protocol of the flow. | keyword |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.source.ip | Source IP address. | ip |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.source.port | Source port. | long |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.timestamp | Time stamp of when the flow occurred in UNIX epoch format. | date |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.traffic.decision | Whether traffic was allowed or denied. | keyword |
| azure_network_watcher_nsg.log.properties.flows.flows.tuples.traffic.flow | Direction of the traffic flow. | keyword |
| azure_network_watcher_nsg.log.properties.flows.rule | Rule for which the flows are listed. | keyword |
| azure_network_watcher_nsg.log.properties.version | Version number of the flow log's event schema. | keyword |
| azure_network_watcher_nsg.log.resource_id | Resource ID of the network security group. | keyword |
| azure_network_watcher_nsg.log.system_id | System ID of the network security group. | keyword |
| azure_network_watcher_nsg.log.time | Time in UTC when the event was logged. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| tags | User defined tags. | keyword |

