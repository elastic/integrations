# Azure Functions

The Azure Functions integration allows you to monitor Azure Functions. Azure Functions is an event-driven, serverless compute platform that helps you develop more efficiently using the programming language of your choice. Triggers cause a function to run. A trigger defines how a function is invoked and a function must have exactly one trigger. 

Use Azure Functions to build web APIs, respond to database changes, process IoT streams, manage message queues, and more. Refer to common [Azure Functions scenarios](https://learn.microsoft.com/en-us/azure/azure-functions/functions-scenarios?pivots=programming-language-csharp) for more information.

## Hosting plans and metrics

Each Azure Functions app requires a hosting plan: Consumption plan, Flex Consumption plan, Premium plan, Dedicated plan, or Container Apps. For more details on the various plans, check the [Azure Functions hosting options](https://learn.microsoft.com/en-us/azure/azure-functions/functions-scale?WT.mc_id=Portal-WebsitesExtension).

These plans differ from eachother in the number of metrics they generate, which are then exported outside of Azure for other monitoring solutions like Elastic Observability. For example, metrics specific to Azure Function Apps, such as 'FunctionExecutionCount' and 'FunctionExecutionUnits', are only available for function apps operating on a Consumption (serverless) plan and are not observed in other plans. On the other hand, all other metrics are generated exclusively for Premium and Dedicated plans and are not available for the Consumption plan.

## Data streams
The Azure Functions integration contains two data streams: [Function App Logs](#logs) and [Metrics](#metrics)

### Logs

Supported log categories:

| Log Category                 | Description                                                                                                                          |
|:----------------------------:|:------------------------------------------------------------------------------------------------------------------------------------:|
| Functionapplogs | Function app logs.        |


#### Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information on how to set up and use this integration.

#### Authentication

The integration supports two authentication methods: **connection string** (shared access key) and **client secret** (Microsoft Entra ID). The same method is used for both Event Hub and Storage Account.

##### Connection string authentication

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

##### Client secret authentication (Microsoft Entra ID)

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

#### Configuration options

`auth_type` :
_string_
Authentication method for Event Hub and Storage Account. **Connection String** (default): use `connection_string` and `storage_account_key`. **Client Secret**: use Microsoft Entra ID with `tenant_id`, `client_id`, `client_secret`, and `eventhub_namespace` (RBAC); no connection string or storage key needed.

`eventhub` :
_string_
An Event Hub is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You can use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (for example, the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
Default value `insights-operational-logs`.

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

`storage_account_container` :
_string_
The storage account container where the integration stores the checkpoint data for the consumer group. It is an advanced option to use with extreme care. You must use a dedicated storage account container for each Azure log type (activity, sign-in, audit logs, and others). Do not reuse the same container name for more than one Azure log type. Refer to [Container Names](https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata#container-names) for details on naming rules from Microsoft. The integration generates a default container name, if not specified.

`resource_manager_endpoint` :
_string_
Optional. By default, the integration uses the Azure public environment. To override, you can provide a specific Azure environment.

Resource manager endpoints:

```text
# Azure ChinaCloud
https://management.chinacloudapi.cn/

# Azure GermanCloud
https://management.microsoftazure.de/

# Azure PublicCloud 
https://management.azure.com/

# Azure USGovernmentCloud
https://management.usgovcloudapi.net/
```

{{event "functionapplogs"}}

**ECS Field Reference**

Check the [ECS field reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for more information.

{{fields "functionapplogs"}}

### Metrics
**Metrics** give you insight into the performance of your Azure Function Apps. The integration includes an out-of-the-box dashboard for visualising the monitoring data generated by apps hosted in Azure Functions.

#### Requirements

* **Azure App Registration**: You need to set up an Azure App Registration to allow the Agent to access the Azure APIs. The App Registration requires the Monitoring Reader role to collect metrics from Function Apps. Check the Setup section for more details.

* **Elasticsearch and Kibana**: You need Elasticsearch to store and search your data and Kibana to visualize and manage it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, the [Native Azure Integration](https://azuremarketplace.microsoft.com/en/marketplace/apps/elastic.ec-azure-pp?tab=overview), or self-manage the Elastic Stack on your hardware.

#### Setup


```text
         ┌────────────────────┐       ┌─────────┐       ┌─-─────────────────────┐
         │                    │       │         │       │    azure.functions    │
         │     Azure APIs     │──────▶│  Agent  │──────▶│    <<data stream>>    │
         │                    │       │         │       │                       │
         └────────────────────┘       └─────────┘       └───-───────────────────┘                                              
```

Elastic Agent needs an App Registration to access Azure on your behalf to collect data using the Azure REST APIs. App Registrations are required to access Azure APIs programmatically.

To start collecting data with this integration, you need to:

* Set up a new Azure app registration by registering an app, adding credentials, and assigning an appropriate role.
* Specify integration [settings](#main-options) in Kibana, which will determine how the integration will access the Azure APIs.

#### Register a new app

To create a new app registration:

1. Sign in to the [Azure Portal](https://portal.azure.com/).
2. Search for and select **Microsoft Entra ID**.
3. Under **Manage**, select **App registrations** > **New registration**.
4. Enter a display _Name_ for your application (for example, "elastic-agent").
5. Specify who can use the application.
6. Don't enter anything for _Redirect URI_. This is optional and the agent doesn't use it.
7. Select **Register** to complete the initial app registration.

Take note of the **Application (client) ID**, which you will use later when specifying the **Client ID** in the integration settings.

#### Add credentials

Credentials allow your application to access Azure APIs and authenticate itself, requiring no interaction from a user at runtime.

This integration uses Client Secrets to prove its identity.

1. In the [Azure Portal](https://portal.azure.com/), select the application you created in the previous section.
2. Select **Certificates & secrets** > **Client secrets** > **New client secret**.
3. Add a description (for example, "Elastic Agent client secrets").
4. Select an expiration for the secret or specify a custom lifetime.
5. Select **Add**.

Take note of the content in the **Value** column in the **Client secrets** table, which you will use later when specifying a **Client Secret** in the integration settings. **This secret value is never displayed again after you leave this page.** Record the secret's value in a safe place.

#### Assign role

1. In the [Azure Portal](https://portal.azure.com/), search for and select **Subscriptions**.
2. Select the subscription to assign the application.
3. Select **Access control (IAM)**.
4. Select **Add** > **Add role assignment** to open the _Add role assignment page_.
5. In the **Role** tab, search and select the role **Monitoring Reader**.
6. Select the **Next** button to move to the **Members** tab.
7. Select **Assign access to** > **User, group, or service principal**, and select **Select members**. This page does not display Azure AD applications in the available options by default.
8. To find your application, search by name (for example, "elastic-agent") and select it from the list.
9. Click the **Select** button.
10. Click the **Review + assign** button.

Take note of the following values, which you will use later when specifying settings.

* `Subscription ID`: use the content of the "Subscription ID" you selected.
* `Tenant ID`: use the "Tenant ID" from the Azure Active Directory you use.

Your App Registration is now ready to be used with the Elastic Agent.

#### Additional Resources

To learn more about this process, check the following Microsoft guides:

* [Quickstart: Register an application with the Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) 
* [Use the portal to create an Azure AD application and service principal that can access resources](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)

#### Main options

The Settings main section contains all the options needed to access the Azure APIs and collect the Azure Functions metrics data. You will now use all the values from [App registration](#register-a-new-app) including:

`Client ID` _string_
: The unique identifier of the App Registration (sometimes referred to as Application ID).

`Client Secret` _string_
: The client secret for authentication.

`Subscription ID` _string_
: The unique identifier for the Azure subscription. You can provide just one subscription ID. The Agent uses this ID to access Azure APIs. 

`Tenant ID` _string_
: The unique identifier of the Azure Active Directory's Tenant ID.

#### Advanced options

There are two additional advanced options:

`Resource Manager Endpoint` _string_
: Optional. By default, the integration uses the Azure public environment. To override, you can provide a specific resource manager endpoint to use a different Azure environment.

Examples:

* `https://management.chinacloudapi.cn` for Azure ChinaCloud
* `https://management.microsoftazure.de` for Azure GermanCloud
* `https://management.azure.com` for Azure PublicCloud
* `https://management.usgovcloudapi.net` for Azure USGovernmentCloud

`Active Directory Endpoint`  _string_
: Optional. By default, the integration uses the associated Active Directory Endpoint. To override, you can provide a specific active directory endpoint to use a different Azure environment.

Examples:

* `https://login.chinacloudapi.cn` for Azure ChinaCloud
* `https://login.microsoftonline.de` for Azure GermanCloud
* `https://login.microsoftonline.com` for Azure PublicCloud
* `https://login.microsoftonline.us` for Azure USGovernmentCloud

#### Metrics Reference

{{event "metrics"}}

**ECS Field Reference**

Check the [ECS field reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for more information.

{{fields "metrics"}}
