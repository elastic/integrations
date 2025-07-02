# Azure Network Watcher VNet

[VNet](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview) flow logs in Azure Network Watcher track IP traffic in virtual networks, sending data to Azure Storage for analysis. Unlike NSG flow logs, VNet flow logs offer enhanced monitoring capabilities. They are crucial for understanding network activity, identifying connections, and monitoring open ports. Flow logs serve as the primary source for optimizing resources, ensuring compliance, and detecting intrusions in cloud environments, catering to both startups and enterprises.

## Data streams

This integration supports ingestion of logs from Azure Network Watcher VNet, via [Azure Blob Storage](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-blob-storage.html) input.

- **Log** is used to retrieve VNet Flow data. For more details, check the [Microsoft documentation](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview).

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Collect data from Azure Network Watcher VNet

1. On the [Azure portal](https://portal.azure.com/), go to your storage account.
2. Under **Security + networking**, click **Access keys**. Your account access keys appear, as well as the complete connection string for each key.
3. Click **Show keys** to show your **access keys** and **connection strings** to enable buttons to copy the values.
4. Under **key1**, find the key value. Click **Copy** to copy the **account key**. In the same way, copy the storage account name shown above the keys.
5. In your storage account, go to **Data storage** > **Containers** to copy the container name.
6. Configure the integration using either Service Account Credentials or Microsoft Entra ID RBAC with OAuth2 options. For OAuth2 (Entra ID RBAC), you'll need the Client ID, Client Secret, and Tenant ID. For Service Account Credentials, you'll need either the Service Account Key or the URI to access the data.

- How to setup the `auth.oauth2` credentials can be found in the Azure documentation [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
- For more details about the Azure Blob Storage input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-blob-storage.html).

Note:
- Follow [these steps](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-portal) to enable virtual network flow logs.
- The service principal must be granted the appropriate permissions to read blobs. Ensure that the necessary role assignments are in place for the service principal to access the storage resources. For more information, please refer to the [Azure Role-Based Access Control (RBAC) documentation](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/storage).
- We recommend assigning either the **Storage Blob Data Reader** or **Storage Blob Data Owner** role. The **Storage Blob Data Reader** role provides read-only access to blob data and is aligned with the principle of least privilege, making it suitable for most use cases. The **Storage Blob Data Owner** role grants full administrative access — including read, write, and delete permissions — and should be used only when such elevated access is explicitly required.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Azure Network Watcher VNet**.
3. Select the **Azure Network Watcher VNet** integration and add it.
5. To collect logs via Azure Blob Storage, select **Collect VNet logs via Azure Blob Storage** and configure the following parameters:
   For OAuth2 (Microsoft Entra ID RBAC):
   - Toggle on **Collect logs using OAuth2 authentication**
   - Account Name
   - Client ID
   - Client Secret
   - Tenant ID
   - Container Details.

   For Service Account Credentials:
   - Service Account Key or the URI
   - Account Name
   - Container Details
6. Save the integration.

## Limitations

The filebeat's [Azure Blob Storage](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-blob-storage.html#attrib-expand_event_list_from_field) input can only split events based on a key at root level of JSON. Also the Elasticsearch ingest pipeline [cannot split a message into multiple documents](https://github.com/elastic/elasticsearch/issues/56769). Due to these limitations, the Azure Network Watcher VNet integration cannot split `flowTuples` records, exported via field `azure_network_watcher_vnet.log.records.flows.groups.tuples`, into multiple documents. Each document contains multiple `flowTuples` grouped together. This grouping leads to a loss of direct correlation between fields across a single tuple.

## Logs Reference

### Log

This is the `Log` dataset.

#### Example

{{event "log"}}

{{fields "log"}}
