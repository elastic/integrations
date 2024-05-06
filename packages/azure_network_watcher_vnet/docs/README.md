# Azure Network Watcher VNet

[VNet](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview) flow logs in Azure Network Watcher track IP traffic in virtual networks, sending data to Azure Storage for analysis. Unlike NSG flow logs, VNet flow logs offer enhanced monitoring capabilities. They are crucial for understanding network activity, identifying connections, and monitoring open ports. Flow logs serve as the primary source for optimizing resources, ensuring compliance, and detecting intrusions in cloud environments, catering to both startups and enterprises.

## Data streams

This integration supports ingestion of logs from Azure Network Watcher VNet, via [Azure Blob Storage](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-blob-storage.html) input.

**Log** is used to retrieve VNet Flow data. See more details in the documentation [here](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview).

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

### To collect data from Azure Network Watcher VNet follow the below steps:

1. In the [Azure portal](https://portal.azure.com/), go to your **storage account**.
2. Under **Security + networking**, Click On **Access keys**. Your account access keys appear, as well as the complete connection string for each key.
3. Click On **Show** keys to show your **access keys** and **connection strings** and to enable buttons to copy the values.
4. Under key1, find the Key value. Click On the Copy button to copy the **account key**. Same way you can copy the **storage account name** shown above keys.
5. Go to **Containers** under **Data storage** in your storage account to copy the **container name**.

**Note**:  Enable virtual network flow logs using the steps provided in [reference](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-portal).

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Azure Network Watcher VNet.
3. Click on the "Azure Network Watcher VNet" integration from the search results.
4. Click on the "Add Azure Network Watcher VNet" button to add the integration.
5. While adding the integration, to collect logs via Azure Blob Storage, keep **Collect VNet logs via Azure Blob Storage** toggle on and then configure following parameters:
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
    "@timestamp": "2022-09-14T09:00:52.562Z",
    "agent": {
        "ephemeral_id": "de847db6-f5bf-4453-8aed-e34625b9fbfa",
        "id": "43c0b2ea-ece0-4773-bd18-10caab20c820",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "azure": {
        "resource": {
            "group": "NETWORKWATCHERRG",
            "id": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/NETWORKWATCHERRG/PROVIDERS/MICROSOFT.NETWORK/NETWORKWATCHERS/NETWORKWATCHER_EASTUS2EUAP/FLOWLOGS/VNETFLOWLOG",
            "name": "NETWORKWATCHER_EASTUS2EUAP/FLOWLOGS/VNETFLOWLOG",
            "provider": "MICROSOFT.NETWORK/NETWORKWATCHERS"
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
    "azure_network_watcher_vnet": {
        "log": {
            "category": "FlowLogFlowEvent",
            "flow_log": {
                "guid": "abcdef01-2345-6789-0abc-def012345678",
                "resource_id": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/NETWORKWATCHERRG/PROVIDERS/MICROSOFT.NETWORK/NETWORKWATCHERS/NETWORKWATCHER_EASTUS2EUAP/FLOWLOGS/VNETFLOWLOG",
                "version": "4"
            },
            "mac_address": "00-22-48-71-C2-05",
            "operation_name": "FlowLogFlowEvent",
            "records": {
                "flows": [
                    {
                        "acl_id": "00000000-1234-abcd-ef00-c1c2c3c4c5c6",
                        "groups": [
                            {
                                "rule": "DefaultRule_AllowInternetOutBound",
                                "tuples": [
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "52.239.184.180",
                                            "port": 443
                                        },
                                        "flow": {
                                            "direction": "Outbound",
                                            "encryption": "NX",
                                            "state": "Begin"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "10.0.0.6",
                                            "port": 23956
                                        },
                                        "timestamp": "2022-09-14T09:00:03.599Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 1580,
                                            "sent": 767
                                        },
                                        "destination": {
                                            "ip": "52.239.184.180",
                                            "port": 443
                                        },
                                        "flow": {
                                            "direction": "Outbound",
                                            "encryption": "NX",
                                            "state": "End"
                                        },
                                        "packets": {
                                            "received": 2,
                                            "sent": 3
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "10.0.0.6",
                                            "port": 23956
                                        },
                                        "timestamp": "2022-09-14T09:00:03.606Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "40.74.146.17",
                                            "port": 443
                                        },
                                        "flow": {
                                            "direction": "Outbound",
                                            "encryption": "NX",
                                            "state": "Begin"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "10.0.0.6",
                                            "port": 22730
                                        },
                                        "timestamp": "2022-09-14T09:00:03.637Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 4569,
                                            "sent": 705
                                        },
                                        "destination": {
                                            "ip": "40.74.146.17",
                                            "port": 443
                                        },
                                        "flow": {
                                            "direction": "Outbound",
                                            "encryption": "NX",
                                            "state": "End"
                                        },
                                        "packets": {
                                            "received": 4,
                                            "sent": 3
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "10.0.0.6",
                                            "port": 22730
                                        },
                                        "timestamp": "2022-09-14T09:00:03.640Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "40.74.146.17",
                                            "port": 443
                                        },
                                        "flow": {
                                            "direction": "Outbound",
                                            "encryption": "NX",
                                            "state": "Begin"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "10.0.0.6",
                                            "port": 22732
                                        },
                                        "timestamp": "2022-09-14T09:00:04.251Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 4569,
                                            "sent": 705
                                        },
                                        "destination": {
                                            "ip": "40.74.146.17",
                                            "port": 443
                                        },
                                        "flow": {
                                            "direction": "Outbound",
                                            "encryption": "NX",
                                            "state": "End"
                                        },
                                        "packets": {
                                            "received": 4,
                                            "sent": 3
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "10.0.0.6",
                                            "port": 22732
                                        },
                                        "timestamp": "2022-09-14T09:00:04.251Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "40.74.146.17",
                                            "port": 443
                                        },
                                        "flow": {
                                            "direction": "Outbound",
                                            "encryption": "NX",
                                            "state": "Begin"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "10.0.0.6",
                                            "port": 22734
                                        },
                                        "timestamp": "2022-09-14T09:00:04.622Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 108,
                                            "sent": 134
                                        },
                                        "destination": {
                                            "ip": "40.74.146.17",
                                            "port": 443
                                        },
                                        "flow": {
                                            "direction": "Outbound",
                                            "encryption": "NX",
                                            "state": "End"
                                        },
                                        "packets": {
                                            "received": 1,
                                            "sent": 2
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "10.0.0.6",
                                            "port": 22734
                                        },
                                        "timestamp": "2022-09-14T09:00:04.622Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "104.16.218.84",
                                            "port": 443
                                        },
                                        "flow": {
                                            "direction": "Outbound",
                                            "encryption": "NX",
                                            "state": "Begin"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "10.0.0.6",
                                            "port": 36776
                                        },
                                        "timestamp": "2022-09-14T09:00:17.343Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 32466,
                                            "sent": 2217
                                        },
                                        "destination": {
                                            "ip": "104.16.218.84",
                                            "port": 443
                                        },
                                        "flow": {
                                            "direction": "Outbound",
                                            "encryption": "NX",
                                            "state": "End"
                                        },
                                        "packets": {
                                            "received": 33,
                                            "sent": 22
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "10.0.0.6",
                                            "port": 36776
                                        },
                                        "timestamp": "2022-09-14T09:00:22.793Z"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "acl_id": "01020304-abcd-ef00-1234-102030405060",
                        "groups": [
                            {
                                "rule": "BlockHighRiskTCPPortsFromInternet",
                                "tuples": [
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "10.0.0.6",
                                            "port": 22
                                        },
                                        "flow": {
                                            "direction": "Inbound",
                                            "encryption": "NX",
                                            "state": "Deny"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "101.33.218.153",
                                            "port": 55188
                                        },
                                        "timestamp": "2022-09-14T08:59:58.065Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "10.0.0.6",
                                            "port": 119
                                        },
                                        "flow": {
                                            "direction": "Inbound",
                                            "encryption": "NX",
                                            "state": "Deny"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "192.241.200.164",
                                            "port": 35276
                                        },
                                        "timestamp": "2022-09-14T09:00:05.503Z"
                                    }
                                ]
                            },
                            {
                                "rule": "Internet",
                                "tuples": [
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "10.0.0.6",
                                            "port": 44357
                                        },
                                        "flow": {
                                            "direction": "Inbound",
                                            "encryption": "NX",
                                            "state": "Deny"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "20.106.221.10",
                                            "port": 50557
                                        },
                                        "timestamp": "2022-09-14T08:59:49.563Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "10.0.0.6",
                                            "port": 35945
                                        },
                                        "flow": {
                                            "direction": "Inbound",
                                            "encryption": "NX",
                                            "state": "Deny"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "20.55.117.81",
                                            "port": 62797
                                        },
                                        "timestamp": "2022-09-14T08:59:49.679Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "10.0.0.6",
                                            "port": 65515
                                        },
                                        "flow": {
                                            "direction": "Inbound",
                                            "encryption": "NX",
                                            "state": "Deny"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "20.55.113.5",
                                            "port": 51961
                                        },
                                        "timestamp": "2022-09-14T08:59:49.709Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "10.0.0.6",
                                            "port": 40129
                                        },
                                        "flow": {
                                            "direction": "Inbound",
                                            "encryption": "NX",
                                            "state": "Deny"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "13.65.224.51",
                                            "port": 40497
                                        },
                                        "timestamp": "2022-09-14T08:59:50.049Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "10.0.0.6",
                                            "port": 30472
                                        },
                                        "flow": {
                                            "direction": "Inbound",
                                            "encryption": "NX",
                                            "state": "Deny"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "20.55.117.81",
                                            "port": 62797
                                        },
                                        "timestamp": "2022-09-14T08:59:50.145Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "10.0.0.6",
                                            "port": 28184
                                        },
                                        "flow": {
                                            "direction": "Inbound",
                                            "encryption": "NX",
                                            "state": "Deny"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "20.55.113.5",
                                            "port": 51961
                                        },
                                        "timestamp": "2022-09-14T08:59:50.175Z"
                                    },
                                    {
                                        "bytes": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "destination": {
                                            "ip": "10.0.0.6",
                                            "port": 31244
                                        },
                                        "flow": {
                                            "direction": "Inbound",
                                            "encryption": "NX",
                                            "state": "Deny"
                                        },
                                        "packets": {
                                            "received": 0,
                                            "sent": 0
                                        },
                                        "protocol": "6",
                                        "source": {
                                            "ip": "20.106.221.10",
                                            "port": 50557
                                        },
                                        "timestamp": "2022-09-14T09:00:15.545Z"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            },
            "target_resource_id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVNet",
            "time": "2022-09-14T09:00:52.562Z"
        }
    },
    "cloud": {
        "provider": "azure"
    },
    "data_stream": {
        "dataset": "azure_network_watcher_vnet.log",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": [
            1580,
            0,
            32466,
            108,
            4569
        ],
        "ip": [
            "52.239.184.180",
            "104.16.218.84",
            "40.74.146.17",
            "10.0.0.6"
        ],
        "packets": [
            33,
            0,
            1,
            2,
            4
        ],
        "port": [
            22,
            44357,
            65515,
            40129,
            31244,
            443,
            30472,
            119,
            28184,
            35945
        ]
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "43c0b2ea-ece0-4773-bd18-10caab20c820",
        "snapshot": false,
        "version": "8.12.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "azure_network_watcher_vnet.log",
        "ingested": "2024-05-03T08:01:53Z",
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
            "path": "http://elastic-package-service-azure-network-watcher-vnet-log-1:10000/devstoreaccount1/azure-container1/testblob"
        },
        "offset": 1
    },
    "network": {
        "direction": [
            "inbound",
            "outbound"
        ],
        "iana_number": [
            "6"
        ]
    },
    "related": {
        "ip": [
            "52.239.184.180",
            "104.16.218.84",
            "40.74.146.17",
            "10.0.0.6",
            "13.65.224.51",
            "20.106.221.10",
            "20.55.113.5",
            "192.241.200.164",
            "20.55.117.81",
            "101.33.218.153"
        ]
    },
    "rule": {
        "name": [
            "DefaultRule_AllowInternetOutBound",
            "BlockHighRiskTCPPortsFromInternet",
            "Internet"
        ]
    },
    "source": {
        "bytes": [
            0,
            2217,
            134,
            767,
            705
        ],
        "ip": [
            "13.65.224.51",
            "20.106.221.10",
            "20.55.113.5",
            "192.241.200.164",
            "10.0.0.6",
            "20.55.117.81",
            "101.33.218.153"
        ],
        "mac": "00-22-48-71-C2-05",
        "packets": [
            22,
            0,
            2,
            3
        ],
        "port": [
            22734,
            23956,
            40497,
            35276,
            62797,
            22730,
            22732,
            55188,
            51961,
            36776,
            50557
        ]
    },
    "tags": [
        "forwarded",
        "azure_network_watcher_vnet-log"
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
| azure_network_watcher_vnet.log.category | Category of the event. | keyword |
| azure_network_watcher_vnet.log.flow_log.guid | Resource GUID of the FlowLog resource. | keyword |
| azure_network_watcher_vnet.log.flow_log.resource_id | Resource ID of the FlowLog resource. | keyword |
| azure_network_watcher_vnet.log.flow_log.version | Version of the flow log schema. | keyword |
| azure_network_watcher_vnet.log.mac_address | MAC address of the network interface where the event was captured. | keyword |
| azure_network_watcher_vnet.log.operation_name | Always FlowLogFlowEvent. | keyword |
| azure_network_watcher_vnet.log.records.flows.acl_id | Identifier of the resource that's evaluating traffic, either a network security group or Virtual Network Manager. | keyword |
| azure_network_watcher_vnet.log.records.flows.groups.mac | MAC address of the network interface on which the flows are listed. | keyword |
| azure_network_watcher_vnet.log.records.flows.groups.rule | Name of the rule that allowed or denied the traffic. | keyword |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.bytes.received | Total number of TCP packet bytes sent from destination to source. | long |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.bytes.sent | Total number of TCP packet bytes sent from source to destination. | long |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.destination.ip | Destination IP address. | ip |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.destination.port | Destination port. | long |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.flow.direction | Direction of the traffic flow. | keyword |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.flow.encryption | Encryption state of the flow. | keyword |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.flow.state | State of the flow. | keyword |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.packets.received | Total number of packets sent from destination to source. | long |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.packets.sent | Total number of packets sent from source to destination. | long |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.protocol | Protocol of the flow. | keyword |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.source.ip | Source IP address. | ip |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.source.port | Source port. | long |
| azure_network_watcher_vnet.log.records.flows.groups.tuples.timestamp | Time stamp of when the flow occurred in UNIX epoch format. | date |
| azure_network_watcher_vnet.log.records.flows.rule | Rule for which the flows are listed. | keyword |
| azure_network_watcher_vnet.log.records.version | Version number of the flow log's event schema. | keyword |
| azure_network_watcher_vnet.log.target_resource_id | Resource ID of the target resource that's associated with the FlowLog resource. | keyword |
| azure_network_watcher_vnet.log.time | Time in UTC when the event was logged. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| tags | User defined tags. | keyword |

