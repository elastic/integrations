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

{{event "log"}}

{{fields "log"}}
