# Azure Resource Metrics Integration

The [Azure Monitor](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/data-platform-metrics) feature collects and aggregates logs and metrics from a variety of sources into a common data platform where it can be used for analysis, visualization, and alerting.

The Azure Resource Metrics will periodically retrieve the Azure Monitor metrics using the Azure REST APIs as MetricList. Additional Azure API calls can be used to retrieve information regarding the resources targeted by the user.

## Data streams

The Azure Resource Metrics collects one type of data: metrics.

**Metrics** are numerical values that describe some aspects of a system at a particular point in time. They are collected at regular intervals and are identified with a timestamp, a name, a value, and one or more defining labels.

The following data streams are available:

**`monitor`** - Allows users to retrieve metrics from specified resources. Added filters can apply here as the interval of retrieving these metrics, metric names,
aggregation list, namespaces and metric dimensions. The monitor metrics will have a minimum timegrain of 5 minutes, so the `period` for `monitor` dataset should be `300s` or multiples of `300s`.

**`compute_vm`** - Collects metrics from the virtual machines, these metrics will have a timegrain every 5 minutes,
so the `period` for `compute_vm` should be `300s` or multiples of `300s`.

**`compute_vm_scaleset`** - Collects metrics from the virtual machine scalesets, these metrics will have a timegrain every 5 minutes,
so the `period` for `compute_vm_scaleset` should be `300s` or multiples of `300s`.

**`storage_account`** - Collects metrics from the storage accounts, these metrics will have a timegrain every 5 minutes,
so the `period` for `storage_account` should be `300s` or multiples of `300s`.

**`container_instance`** - Collects metrics from specified container groups, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_instance` should be `300s` or multiples of `300s`.

**`container_registry`** - Collects metrics from the container registries, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_registry` should be `300s` or multiples of `300s`.

**`container_service`** - Collects metrics from the container services, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_service` should be `300s` or multiples of `300s`.

**`database_account`** - Collects relevant metrics from specified database accounts, these metrics will have a timegrain every 5 minutes,
so the `period` for `database_account` should be `300s` or multiples of `300s`.

For each individual data stream, you can check the exported fields in the [Metrics reference](#metrics-reference) section.

## Requirements

The Elastic Agent fetches metric data from the Azure Monitor API and sends it to dedicated data streams named `azure-monitor.<metricset>-default` in Elasticsearch.

```text
                       ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐

                       │  ┌─────────────────┐  │
┌─────────────────┐       │  azure-monitor  │       ┌─────────────────┐
│    Azure API    │◀───┼──│  <<metricset>>  │──┼───▶│  Elasticsearch  │
└─────────────────┘       └─────────────────┘       └─────────────────┘
                       │                       │
                        ─ Elastic Agent ─ ─ ─ ─
```

Elastic Agent needs an App Registration to access Azure on your behalf to collect data using the Azure APIs programmatically.

To use this integration you will need:

* **Azure App Registration**: You need to set up an Azure App Registration to allow the Agent to access the Azure APIs. See more details in the [Setup section](#setup).
* **Elasticsearch and Kibana**: You need Elasticsearch to store and search your data and Kibana to visualize and manage it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, the [Native Azure Integration](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/elastic.elasticsearch?tab=Overview), or self-manage the Elastic Stack on your hardware.


### Authentication and costs

**Authentication on the Azure side**
All the tasks executed against the Azure Monitor REST API use the Azure Resource Manager authentication model. Therefore, all requests must be authenticated with Microsoft Entra.
To authenticate the client application, create a Microsoft Entra service principal and retrieve the authentication (JWT) token. For more details, check the following procedures:
* [Create an Azure service principal with Azure PowerShell](https://docs.microsoft.com/en-us/powershell/azure/create-azure-service-principal-azureps?view=azps-2.7.0.)
* [Use the portal to create a Microsoft Entra application and service principal that can access resources](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal).

NOTE: When you create an Azure service principal with Azure PowerShell, a linked App Registration is automatically created and is visible on the Azure portal.

Make sure that the roles assigned to the application contain at least reading permissions to the monitor data. Check [Azure built-in roles](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles) for more details.

**Authentication on the Elastic side**
Elastic handles authentication by creating or renewing the authentication token. It is recommended to use dedicated credentials for Metricbeat only.

**Costs**
Metric queries are charged based on the number of standard API calls. 
Check [Azure Monitor pricing](https://azure.microsoft.com/en-gb/pricing/details/monitor/) for more detailsgit.

## Setup

To start collecting data with this integration, you need to:
- Register a new Azure app, by adding credentials, and assigning roles.
- Specify the integration settings in Kibana, which will determine how the integration will access the Azure APIs.

### Register a new Azure app

To register your app, follow these steps:

**Step 1: Create the app registration**

1. Sign in to the [Azure Portal](https://portal.azure.com/).
2. Search for and select **Microsoft Entra ID**.
3. Under **Manage**, select **App registrations** > **New registration**.
4. Enter a display _Name_ for your application (for example, "elastic-agent").
5. Specify who can use the application.
6. Don't enter anything for _Redirect URI_. This is optional and the agent doesn't use it.
7. Select **Register** to complete the initial app registration.

Take note of the **Application (client) ID**, which you will use later when specifying the **Client ID** in the integration settings.

**Step 2: Add credentials**

Credentials allow your application to access Azure APIs and authenticate itself, requiring no interaction from a user at runtime.

This integration uses Client Secrets to prove its identity.

1. In the [Azure Portal](https://portal.azure.com/), select the application you created in the previous section.
1. Select **Certificates & secrets** > **Client secrets** > **New client secret**.
1. Add a description (for example, "Elastic Agent client secrets").
1. Select an expiration for the secret or specify a custom lifetime.
1. Select **Add**.

Take note of the content in the **Value** column in the **Client secrets** table, which you will use later when specifying a **Client Secret** in the integration settings. **This secret value is never displayed again after you leave this page.** Record the secret's value in a safe place.

**Step 3: Assign role**

1. In the [Azure Portal](https://portal.azure.com/), search for and select **Subscriptions**.
1. Select the subscription to assign the application.
1. Select **Access control (IAM)**.
1. Select **Add** > **Add role assignment** to open the _Add role assignment page_.
1. In the **Role** tab, search and select the role **Monitoring Reader**.
1. Select the **Next** button to move to the **Members** tab.
1. Select **Assign access to** > **User, group, or service principal**, and select **Select members**. This page does not display Microsoft Entra applications in the available options by default.
1. To find your application, search by name (for example, "elastic-agent") and select it from the list.
1. Click the **Select** button.
1. Then click the **Review + assign** button.

Take note of the following values, which you will use later when specifying settings.

* `Subscription ID`: use the content of the "Subscription ID" you selected.
* `Tenant ID`: use the "Tenant ID" from the  Microsoft Entra you use.

Your App Registration is now ready for the Elastic Agent.

### Specify the integration settings in Kibana

Add the Azure Resource Metrics integration in Kibana and specify settings.

If you're new to integrations, you can find step-by-step instructions on how to set up an integration in the {{ url "getting-started-observability" "Getting started" }} guide.

The settings' main section contains all the options needed to access the Azure APIs and collect the monitoring data. You will now use all the values from [App registration](#app-registration) including:

`Client ID` _string_
: The unique identifier of the App Registration (sometimes referred to as Application ID).

`Client Secret` _string_
: The client secret for authentication.

`Subscription ID` _string_
: The unique identifier for the Azure subscription. You can provide just one subscription ID. The Agent uses this ID to access Azure APIs. 

`Tenant ID` _string_
: The unique identifier of the  Microsoft Entra Tenant ID.

### Advanced options

There are two additional advanced options:

`Resource Manager Endpoint` _string_
: Optional. By default, the integration uses the Azure public environment. To override, users can provide a specific resource manager endpoint to use a different Azure environment.

Examples:

* `https://management.chinacloudapi.cn` for Azure ChinaCloud
* `https://management.microsoftazure.de` for Azure GermanCloud
* `https://management.azure.com` for Azure PublicCloud
* `https://management.usgovcloudapi.net` for Azure USGovernmentCloud

` Microsoft Entra Endpoint`  _string_
: Optional. By default, the integration uses the associated  Microsoft Entra Endpoint. To override, users can provide a specific active directory endpoint to use a different Azure environment.

Examples:

* `https://login.chinacloudapi.cn` for Azure ChinaCloud
* `https://login.microsoftonline.de` for Azure GermanCloud
* `https://login.microsoftonline.com` for Azure PublicCloud
* `https://login.microsoftonline.us` for Azure USGovernmentCloud

## Metrics reference

`monitor`
This data stream allows users to retrieve metrics from specified resources. Added filters can apply here as the interval of retrieving these metrics, metric names,
aggregation list, namespaces and metric dimensions. The monitor metrics will have a minimum timegrain of 5 minutes, so the `period` for `monitor` dataset should be `300s` or multiples of `300s`.

{{fields "monitor"}}

`compute_vm`
This data stream will collect metrics from the virtual machines, these metrics will have a timegrain every 5 minutes,
so the `period` for `compute_vm` should be `300s` or multiples of `300s`.

{{fields "compute_vm"}}

`compute_vm_scaleset`
This data stream will collect metrics from the virtual machine scalesets, these metrics will have a timegrain every 5 minutes,
so the `period` for `compute_vm_scaleset` should be `300s` or multiples of `300s`.

{{fields "compute_vm_scaleset"}}

 `storage_account`
This data stream will collect metrics from the storage accounts, these metrics will have a timegrain every 5 minutes,
so the `period` for `storage_account` should be `300s` or multiples of `300s`.

{{fields "storage_account"}}

`container_instance`
This data stream will collect metrics from specified container groups, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_instance` should be `300s` or multiples of `300s`.

{{fields "container_instance"}}

`container_registry`
This data stream will collect metrics from the container registries, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_registry` should be `300s` or multiples of `300s`.

{{fields "container_registry"}}

`container_service`
This data stream will collect metrics from the container services, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_service` should be `300s` or multiples of `300s`.

{{fields "container_service"}}

`database_account`
This data stream will collect relevant metrics from specified database accounts, these metrics will have a timegrain every 5 minutes,
so the `period` for `database_account` should be `300s` or multiples of `300s`.

{{fields "database_account"}}
