# Azure Network Watcher NSG

[Network security group](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview) (NSG) flow logging is a feature of Azure Network Watcher that allows you to log information about IP traffic flowing through a network security group. Flow logs are the source of truth for all network activity in your cloud environment. Whether you're in a startup that's trying to optimize resources or a large enterprise that's trying to detect intrusion, flow logs can help. You can use them for optimizing network flows, monitoring throughput, verifying compliance, detecting intrusions, and more.

## Data streams

This integration supports ingestion of logs from Azure Network Watcher NSG, via [Azure Blob Storage](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-blob-storage.html) input.

- **Log** is used to retrieve NSG Flow data. See more details in the documentation [here](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview).

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### To collect data from Azure Network Watcher NSG follow the below steps:

1. In the [Azure portal](https://portal.azure.com/), go to your **storage account**.
2. Under **Security + networking**, Click on **Access keys**. Your account access keys appear, as well as the complete connection string for each key.
3. Click on **Show** keys to show your **access keys** and **connection strings** and to enable buttons to copy the values.
4. Under key1, find the Key value. Click on the Copy button to copy the **account key**. Same way you can copy the **storage account name** shown above keys.
5. Go to **Containers** under **Data storage** in your storage account to copy the **container name**.
6. Configure the integration using either Service Account Credentials or Microsoft Entra ID RBAC with OAuth2 options. For OAuth2 (Entra ID RBAC), you'll need the Client ID, Client Secret, and Tenant ID. For Service Account Credentials, you'll need either the Service Account Key or the URI to access the data.

- How to setup the `auth.oauth2` credentials can be found in the Azure documentation [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
- For more details about the Azure Blob Storage input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-blob-storage.html).

Note:
- Enable virtual network flow logs using the steps provided in [reference](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-portal).
- The service principal must be granted the appropriate permissions to read blobs. Ensure that the necessary role assignments are in place for the service principal to access the storage resources. For more information, please refer to the [Azure Role-Based Access Control (RBAC) documentation](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/storage).
- We recommend assigning either the **Storage Blob Data Reader** or **Storage Blob Data Owner** role. The **Storage Blob Data Reader** role provides read-only access to blob data and is aligned with the principle of least privilege, making it suitable for most use cases. The **Storage Blob Data Owner** role grants full administrative access — including read, write, and delete permissions — and should be used only when such elevated access is explicitly required.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Azure Network Watcher NSG`.
3. Select the "Azure Network Watcher NSG" integration from the search results.
4. Select "Add Azure Network Watcher NSG" to add the integration.
5. While adding the integration, to collect logs via Azure Blob Storage, keep **Collect NSG logs via Azure Blob Storage** toggle on and then configure following parameters:
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

## Logs Reference

### Log

This is the `Log` dataset.

#### Example

{{event "log"}}

{{fields "log"}}
