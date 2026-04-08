# Azure Frontdoor Logs Integration

Azure Front Door provides different logging to help you track, monitor, and debug your Front Door.

- Access logs have detailed information about every request that AFD receives and help you analyze and monitor access patterns, and debug issues.
- Activity logs provide visibility into the operations done on Azure resources.
- Health Probe logs provides the logs for every failed probe to your origin.
- Web Application Firewall (WAF) logs provide detailed information of requests that gets logged through either detection or prevention mode of an Azure Front Door endpoint. A custom domain that gets configured with WAF can also be viewed through these logs.

The Azure Frontdoor logs integration retrieves the following types of log data from AFD:

- **Access Logs**: Logs categorized as `FrontDoorAccessLog`.
- **Web Application Firewall (WAF) Logs**: Logs categorized as `FrontDoorWebApplicationFirewallLog`.

Currently, the integration does not support **Activity Logs** or **Health Probe logs**.

## Data streams

This integration collects two types of data streams:

- access log
- waf logs

## Requirements

### Authentication

The integration supports two authentication methods: **connection string** (shared access key) and **client secret** (Microsoft Entra ID). The same method is used for both Event Hub and Storage Account.

#### Connection string authentication

The Elastic Agent can use a connection string to access the event hub and fetch the exported logs. The connection string contains details about the event hub and the credentials required to access it.

To get the connection string for your Event Hubs namespace:

1. Visit the **Event Hubs namespace** you created in a previous step.
1. Select **Settings** > **Shared access policies**.

Create a new Shared Access Policy (SAS):

1. Select **Add** to open the creation panel.
1. Add a **Policy name** (for example, "ElasticAgent").
1. Select the **Listen** claim.
1. Click **Create**.

When the SAS Policy is ready, select it to display the information panel.

Take note of the **Connection string–primary key**, which you will use later when specifying a **connection_string** in the integration settings.

#### Client secret authentication (Microsoft Entra ID)

Instead of a connection string, you can authenticate using a Microsoft Entra ID app registration (service principal) with a client secret. This uses Azure RBAC and is useful when you want to avoid shared keys or enforce role-based access.

**Prerequisites:** An Event Hub, a Storage Account, and a Microsoft Entra ID app registration with a client secret.

**Steps:**

1. **Register an app in Microsoft Entra ID**  
   In the [Azure Portal](https://portal.azure.com/), go to **Microsoft Entra ID** > **App registrations** > **New registration**. Note the **Application (client) ID** and **Directory (tenant) ID**.

2. **Create a client secret**  
   In the app, go to **Certificates & secrets** > **New client secret**. Copy the secret value; you will need it in the integration (for example `client_secret`). It is shown only once.

3. **Assign required permissions to the app**  
   The service principal needs the following Azure RBAC permissions (see the [Filebeat azure-eventhub input reference](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-eventhub.html) for the same requirements):

   **For Azure Event Hubs:**
   - **Azure Event Hubs Data Receiver** role on the Event Hubs namespace or Event Hub, or
   - A custom role with: `Microsoft.EventHub/namespaces/eventhubs/read`, `Microsoft.EventHub/namespaces/eventhubs/consumergroups/read`

   **For Azure Storage Account:**
   - **Storage Blob Data Contributor** role on the Storage Account or container, or
   - A custom role with: `Microsoft.Storage/storageAccounts/blobServices/containers/read`, `Microsoft.Storage/storageAccounts/blobServices/containers/write`, `Microsoft.Storage/storageAccounts/blobServices/containers/delete`, `Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action`

   For detailed setup, see the Microsoft documentation: [Create an Azure service principal with Azure CLI](https://learn.microsoft.com/en-us/cli/azure/create-an-azure-service-principal-azure-cli), [Create an Azure AD app registration using the Azure portal](https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal), [Assign Azure roles using Azure CLI](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-cli), [Azure Event Hubs authentication and authorization](https://learn.microsoft.com/en-us/azure/event-hubs/authorize-access-azure-active-directory), [Authorize access to blobs using Azure Active Directory](https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-access-azure-active-directory).

4. **Configure the integration**  
   Set **Authentication type** to **Client Secret**. Provide **Tenant ID**, **Client ID**, **Client Secret**, and the fully qualified **Event Hub namespace** (for example `yournamespace.servicebus.windows.net`). Use the same Storage Account and container as for connection string authentication; the integration will use the client secret to access both Event Hubs and Storage.

### Settings

`auth_type` :
_string_
Authentication method for Event Hub and Storage Account. **Connection String** (default): use `connection_string` and `storage_account_key`. **Client Secret**: use Microsoft Entra ID with `tenant_id`, `client_id`, `client_secret`, and `eventhub_namespace` (RBAC); no connection string or storage key needed.

`eventhub` :
_string_
Is the fully managed, real-time data ingestion service.

`consumer_group` :
_string_
The publish/subscribe mechanism of Event Hubs is enabled through consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_
(Required when `auth_type` is **Connection String**.) The connection string required to communicate with Event Hubs. See [Get an Event Hubs connection string](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string).

`storage_account` :
_string_
The name of the storage account where the state/offsets will be stored and updated.

`storage_account_key` :
_string_
(Required when `auth_type` is **Connection String**.) The storage account key used to authorize access to checkpoint data. Not used when `auth_type` is **Client Secret**; the integration uses the same client secret for Storage.

`eventhub_namespace` :
_string_
(Required when `auth_type` is **Client Secret**.) The fully qualified Event Hubs namespace (for example `yournamespace.servicebus.windows.net`). Do not use the short namespace name.

`tenant_id` :
_string_
(Required when `auth_type` is **Client Secret**.) Microsoft Entra ID (directory) tenant ID where the app is registered.

`client_id` :
_string_
(Required when `auth_type` is **Client Secret**.) Microsoft Entra ID application (client) ID. The app's service principal must have **Azure Event Hubs Data Receiver** on the Event Hub and **Storage Blob Data Contributor** on the Storage Account.

`client_secret` :
_string_
(Required when `auth_type` is **Client Secret**.) Microsoft Entra ID application client secret from the app's Certificates & secrets.

`authority_host` :
_string_
(Optional, for client secret authentication.) Microsoft Entra ID authority endpoint. Defaults to `https://login.microsoftonline.com` (Azure Public Cloud). Use a different endpoint for other clouds (for example Azure Government, China, Germany).

`resource_manager_endpoint` :
_string_
Optional, by default we are using the azure public environment, to override, users can provide a specific resource manager endpoint in order to use a different azure environment.
Ex:
https://management.chinacloudapi.cn/ for azure ChinaCloud
https://management.microsoftazure.de/ for azure GermanCloud
https://management.azure.com/ for azure PublicCloud
https://management.usgovcloudapi.net/ for azure USGovernmentCloud
Users can also use this in case of a Hybrid Cloud model, where one may define their own endpoints.

## Access Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.frontdoor.access.backend_hostname | The host name in the request from client. If you enable custom domains and have wildcard domain (\*.contoso.com), hostname is a.contoso.com. if you use Azure Front Door domain (contoso.azurefd.net), hostname is contoso.azurefd.net. | keyword |
| azure.frontdoor.access.cache_status | Provides the status code of how the request gets handled by the CDN service when it comes to caching. | keyword |
| azure.frontdoor.access.error_info | This field provides detailed info of the error token for each response. | keyword |
| azure.frontdoor.access.identity.authorization.action | Action | keyword |
| azure.frontdoor.access.identity.authorization.evidence.principal_id | Principal ID | keyword |
| azure.frontdoor.access.identity.authorization.evidence.principal_type | Principal type | keyword |
| azure.frontdoor.access.identity.authorization.evidence.role | Role | keyword |
| azure.frontdoor.access.identity.authorization.evidence.role_assignment_id | Role assignment ID | keyword |
| azure.frontdoor.access.identity.authorization.evidence.role_assignment_scope | Role assignment scope | keyword |
| azure.frontdoor.access.identity.authorization.evidence.role_definition_id | Role definition ID | keyword |
| azure.frontdoor.access.identity.authorization.scope | Scope | keyword |
| azure.frontdoor.access.identity.claims.\* | Claims | object |
| azure.frontdoor.access.identity.claims_initiated_by_user.fullname | Fullname | keyword |
| azure.frontdoor.access.identity.claims_initiated_by_user.givenname | Givenname | keyword |
| azure.frontdoor.access.identity.claims_initiated_by_user.name | Name | keyword |
| azure.frontdoor.access.identity.claims_initiated_by_user.schema | Schema | keyword |
| azure.frontdoor.access.identity.claims_initiated_by_user.surname | Surname | keyword |
| azure.frontdoor.access.identity_name | identity name | keyword |
| azure.frontdoor.access.is_received_from_client | Boolean value. | boolean |
| azure.frontdoor.access.pop | The edge pop, which responded to the user request. | keyword |
| azure.frontdoor.access.routing_rule_name | The name of the route that the request matched. | keyword |
| azure.frontdoor.access.rules_engine_match_names | The names of the rules that were processed. | keyword |
| azure.frontdoor.access.time_taken | The length of time from the time AFD edge server receives a client's request to the time that AFD sends the last byte of response to client, in milliseconds. This field doesn't take into account network latency and TCP buffering. | double |
| azure.frontdoor.access.time_to_first_byte | The length of time in milliseconds from AFD receives the request to the time the first byte gets sent to client, as measured on Azure Front Door. This property doesn't measure the client data. | double |
| azure.frontdoor.category | Azure frontdoor category name. | keyword |
| azure.frontdoor.operation_name | Azure operation name. | keyword |
| azure.frontdoor.resource_id | Azure Resource ID. | keyword |
| azure.frontdoor.tracking_reference | The unique reference string that identifies a request served by AFD, also sent as X-Azure-Ref header to the client. Required for searching details in the access logs for a specific request. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| log.offset | Log offset. | long |


## WAF Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.frontdoor.category | Azure frontdoor category name. | keyword |
| azure.frontdoor.operation_name | Azure operation name. | keyword |
| azure.frontdoor.resource_id | Azure Resource ID. | keyword |
| azure.frontdoor.tracking_reference | The unique reference string that identifies a request served by AFD, also sent as X-Azure-Ref header to the client. Required for searching details in the access logs for a specific request. | keyword |
| azure.frontdoor.waf.details.data | Detail data. | keyword |
| azure.frontdoor.waf.details.msg | Detail msg. | keyword |
| azure.frontdoor.waf.identity.authorization.action | Action | keyword |
| azure.frontdoor.waf.identity.authorization.evidence.principal_id | Principal ID | keyword |
| azure.frontdoor.waf.identity.authorization.evidence.principal_type | Principal type | keyword |
| azure.frontdoor.waf.identity.authorization.evidence.role | Role | keyword |
| azure.frontdoor.waf.identity.authorization.evidence.role_assignment_id | Role assignment ID | keyword |
| azure.frontdoor.waf.identity.authorization.evidence.role_assignment_scope | Role assignment scope | keyword |
| azure.frontdoor.waf.identity.authorization.evidence.role_definition_id | Role definition ID | keyword |
| azure.frontdoor.waf.identity.authorization.scope | Scope | keyword |
| azure.frontdoor.waf.identity.claims.\* | Claims | object |
| azure.frontdoor.waf.identity.claims_initiated_by_user.fullname | Fullname | keyword |
| azure.frontdoor.waf.identity.claims_initiated_by_user.givenname | Givenname | keyword |
| azure.frontdoor.waf.identity.claims_initiated_by_user.name | Name | keyword |
| azure.frontdoor.waf.identity.claims_initiated_by_user.schema | Schema | keyword |
| azure.frontdoor.waf.identity.claims_initiated_by_user.surname | Surname | keyword |
| azure.frontdoor.waf.identity_name | identity name | keyword |
| azure.frontdoor.waf.policy | WAF policy name. | keyword |
| azure.frontdoor.waf.policy_mode | WAF policy mode. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| log.offset | Log offset. | long |

