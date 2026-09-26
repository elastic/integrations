# Azure Billing Metrics Integration

The Azure Billing Metrics integration allows you to monitor your actual and future Azure spending to optimize resource use.

The integration uses the [Azure Consumption API](https://docs.microsoft.com/en-us/azure/cost-management-billing/manage/consumption-api-overview) to collect usage details and leverages the [Azure Cost Management API](https://docs.microsoft.com/en-us/rest/api/cost-management/forecast) to bring forecast data.

Use the Azure Billing Metrics integration to collect detailed resource usage and forecast expenses for the coming weeks. For example, if you want to know which resources cost you most, you could view the top resources donut chart included in the dashboard for this integration. Then you can visualize the prediction for the coming weeks by looking at the forecast chart.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/docs/reference/fleet/install-elastic-agents). You can install only one Elastic Agent per host.

Elastic Agent is required to collect data from Azure and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Elastic Managed deployment

Elastic Managed integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html)

Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data streams


The Azure Billing Metrics integration collects one type of data stream: metrics.

**Metrics** give you insight into the state of your Azure costs.
Data streams collected by this integration include usage details and forecast metrics.
Usage details metrics track actual expenses including details like subscription ID, resource group, type and name. Forecast metrics track projected expenses over the coming weeks.

## Requirements

To use this integration you will need:

* **Azure App Registration**: You need to set up an Azure App Registration to allow the Agent to access the Azure APIs. The App Registration requires a role to access the billing information. The required role is different depending on the subscription, department, or billing account scope. Check the [Setup section](#setup) for more details.
* **Elasticsearch and Kibana**: You need Elasticsearch to store and search your data and Kibana to visualize and manage it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, the [Native Azure Integration](https://azuremarketplace.microsoft.com/en/marketplace/apps/elastic.ec-azure-pp?tab=overview), or self-manage the Elastic Stack on your hardware.
* **Payment method**: Azure Billing Metrics integration queries are charged based on the number of standard API calls. One integration makes two calls every 24 hours in the standard configuration.

## Setup


The Elastic Agent connects to Azure APIs, fetches usage details and forecast data, and sends it to a dedicated data stream named `metrics-azure.billing-default` in Elasticsearch.

```text
         ┌────────────────────┐       ┌─────────┐       ┌─-─────────────────────┐
         │                    │       │         │       │ metrics-azure.billing │
         │     Azure APIs     │──────▶│  Agent  │──────▶│    <<data stream>>    │
         │                    │       │         │       │                       │
         └────────────────────┘       └─────────┘       └───-───────────────────┘                                              
```

Elastic Agent needs an App Registration to access Azure on your behalf to collect data using the Azure REST APIs. App Registrations are required to access Azure APIs programmatically.

To start collecting data with this integration, you need to:

* Set up a new Azure [app registration](#app-registration) by registering an app, adding credentials, and assigning the role.
* Specify integration [settings](#settings) in Kibana, which will determine how the integration will access the Azure APIs.
* Define the [scope](#scope).


### App registration

Set up a new app registration in Azure.

#### Register a new app

To create the app registration:

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
1. Select **Certificates & secrets** > **Client secrets** > **New client secret**.
1. Add a description (for example, "Elastic Agent client secrets").
1. Select an expiration for the secret or specify a custom lifetime.
1. Select **Add**.

Take note of the content in the **Value** column in the **Client secrets** table, which you will use later when specifying a **Client Secret** in the integration settings. **This secret value is never displayed again after you leave this page.** Record the secret's value in a safe place.

#### Assign role

Assign a role to the App Registration depending on the scope you're interested in.

To collect billing metrics from a single subscription, assign the **Billing Reader** to the App Registration on that subscription:

1. In the [Azure Portal](https://portal.azure.com/), search for and select **Subscriptions**.
1. Select the subscription to assign the application.
1. Select **Access control (IAM)**.
1. Select **Add** > **Add role assignment** to open the _Add role assignment page_.
1. In the **Role** tab, search and select the role **Billing Reader**.
1. Select the **Next** button to move to the **Members** tab.
1. Select **Assign access to** > **User, group, or service principal**, and select **Select members**. This page does not display Azure AD applications in the available options by default.
1. To find your application, search by name (for example, "elastic-agent") and select it from the list.
1. Click the **Select** button.
1. Then click the **Review + assign** button.

You can use the department scope (EA accounts only) or the billing account scope (EA and MCA accounts) to collect billing metrics from multiple subscriptions.

To collect billing metrics from a department (instead of a subscription):

1. In the [Azure Portal](https://portal.azure.com/), search for and select **Cost Management + Billing**.
1. Select **Billing** > **Departments** and select the department you're interested in.
1. Select **Access control (IAM)**.
1. Select **Add**.
1. In the **Add role assignment** panel, select the role **Department reader**.
1. In the **Users, groups, or apps** search box, type the name of the App Registration you created and select it.
1. Click on the **Add** button.

To collect billing metrics from a billing account (instead of a subscription):

1. In the [Azure Portal](https://portal.azure.com/), search for and select **Cost Management + Billing**.
1. Select **Access control (IAM)**.
1. Select **Add**.
1. In the **Add role assignment** panel, select the role **Billing account reader** (view-only access).
1. In the **Users, groups, or apps** search box, type the name of the App Registration you created and select it.
1. Click on the **Add** button.

Take note of the following values, which you will use later when specifying settings.

* `Tenant ID`: use the "Tenant ID" from your Microsoft Entra ID.
* `Subscription ID`: use the "Subscription Id" to access Azure APIs.

* Only one of the following (Optional):
    * `Department ID`: use the "Department Id" content if you decide to collect metrics from a department.
    * `Billing account ID`: use the "Billing account ID" content if you decide to collect metrics from a billing account.

Your App Registration is now ready for the Elastic Agent.

#### Additional Resources

If you want to learn more about this process, you can read these two general guides from Microsoft:

* [Quickstart: Register an application with the Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) 
* [Use the portal to create an Azure AD application and service principal that can access resources](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)

### Settings

Add the Azure Billing Metrics integration in Kibana and specify settings.

If you're new to integrations, you can find  step-by-step instructions on how to set up an integration in the [Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

#### Main options

The settings' main section contains all the options needed to access the Azure APIs and collect the billing data. You will now use all the values from [App registration](#app-registration) including:

`Client ID` _string_
: The unique identifier of the App Registration (sometimes referred to as Application ID).

`Client Secret` _string_
: The client secret for authentication.

`Subscription ID` _string_
: The unique identifier for the Azure subscription. You can provide just one subscription ID. The Agent uses this ID to access Azure APIs. The Agent also uses this ID as the default scope for billing information: see the "Scope" section for more details about how to collect data for more than one subscription.

`Tenant ID` _string_
: The unique identifier of the Azure Active Directory's Tenant ID.

#### Advanced options

There are a few additional advanced options:

`Resource Manager Endpoint` _string_
: Optional. By default, the integration uses the Azure public environment. To override, users can provide a specific resource manager endpoint to use a different Azure environment.

Examples:

* `https://management.chinacloudapi.cn` for Azure ChinaCloud
* `https://management.microsoftazure.de` for Azure GermanCloud
* `https://management.azure.com` for Azure PublicCloud
* `https://management.usgovcloudapi.net` for Azure USGovernmentCloud

`Active Directory Endpoint`  _string_
: Optional. By default, the integration uses the associated Active Directory Endpoint. To override, users can provide a specific active directory endpoint to use a different Azure environment.

Examples:

* `https://login.chinacloudapi.cn` for Azure ChinaCloud
* `https://login.microsoftonline.de` for Azure GermanCloud
* `https://login.microsoftonline.com` for Azure PublicCloud
* `https://login.microsoftonline.us` for Azure USGovernmentCloud

`Resource Manager Audience` _string_
: Optional. By default, the integration uses the associated Resource Manager Audience. To override, users can provide a specific resource manager audience to use a different Azure environment.

Examples:

* `https://management.core.chinacloudapi.cn` for Azure ChinaCloud
* `https://management.core.windows.net` for Azure PublicCloud
* `https://management.core.usgovcloudapi.net` for Azure USGovernmentCloud

#### Data stream options

The data stream has some additional options about scope and period. To learn more about the scope, read the [Scope](#scope) section.

`Billing Scope Department ID` _string_
: Retrieve data based on the department ID.

`Billing Scope Account ID`  _string_
: Retrieve data based on the billing account ID. The billing account ID is available on the [Azure Portal](https://portal.azure.com/) at **Cost Management + Billing**, select a billing scope of the type "billing account", then **Setting** > **Properties** > **ID**.

`Billing Usage Lookback` _string_
: The lookback window for retrieving billing usage data. The default is `24h`. The value must be a positive multiple of `24h`.

`Billing Forecast Window` _string_
: The window for retrieving billing forecast data. The default is `720h` (30 days). The value must be a positive multiple of `24h`.

`Period` _string_
: The time interval to use when retrieving metric values.

### Scope

There are three supported scopes for this integration:

* Subscription
* Department
* Billing Account

>Note: The integration uses the Subscription ID as the default scope for the billing data.

To change the scope, expand the data stream section named **Collect Azure Billing metrics** in the integration settings and set one of the two available options (if you set both, the billing account scope take precedence over the department):

* `Billing Scope Department ID` : Collect user details and forecast data for the given department ID.
* `Billing Scope Account ID` : Collect user details and forecast data for the given billing account ID.

## Deduplication and transforms

### Why duplicates happen

The Azure billing metricset re-fetches the most recent days on every run, and it starts
over whenever the Elastic Agent restarts. Azure also keeps revising cost rows for about
72 hours after they first appear, so re-fetching them is intentional and must keep
happening. The consequence is that `metrics-azure.billing-*` holds several copies of the
same cost row, and any visualization that sums `azure.billing.pretax_cost` over the raw
data stream over-reports the cost.

### The transforms

To solve this, the integration installs two Elasticsearch [transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview)
that maintain a deduplicated view of the raw data stream:

| Transform | Alias | Deduplicates | How |
| --- | --- | --- | --- |
| `usage` | `azure_billing.usage_latest` | Usage detail rows (documents with `azure.billing.pretax_cost`) | A pivot per usage day, meter (`azure.billing.billing_period_id`), and resource. For each bucket it keeps only the rows written by the **most recent fetch** and sums their `pretax_cost`. Older fetches of the same day are discarded, so agent restarts and short collection periods no longer inflate the cost, and the newest fetch carries Azure's latest revision. |
| `latest_forecast` | `azure_billing.forecast_latest` | Actual and forecast cost rows from the Cost Management forecast API | A `latest` transform keyed on `azure.subscription_id`, `azure.billing.usage_date`, `azure.billing.currency`, and a derived `azure.billing.cost_status` that separates actual rows from forecast rows. The most recently collected row wins. |

The usage transform does not deduplicate individual rows on purpose. The Azure Usage Details
API does not give every row a unique ID: rows for the same day, meter, and resource share one
`id` and legitimately appear more than once, for example one row per VM instance of a scale
set. The fields that tell those rows apart are not part of the document, so the only safe unit
of deduplication is the fetch. Each fetch is a complete snapshot of a day, and the newest
snapshot replaces the previous ones.

This also makes a longer `Billing Usage Lookback` safe: with `72h`, every fetch re-reads the last
three days and picks up Azure's late revisions, and the transform replaces each day with the
newest snapshot instead of adding the re-read rows to the total.

```text
                                                              ┌───────────────────────────┐
                                                        ┌────▶│ azure_billing.usage_latest│
                                                        │     │        <<alias>>          │
┌────────────────┐    ┌─────────┐    ┌────────────────┐  │     └───────────────────────────┘
│                │    │         │    │ metrics-azure. │  │
│   Azure APIs   │───▶│  Agent  │───▶│    billing     │──┤     ┌───────────────────────────┐
│                │    │         │    │ <<data stream>>│  │     │azure_billing.forecast_    │
└────────────────┘    └─────────┘    └────────────────┘  └────▶│         latest            │
                                                               │        <<alias>>          │
                                                               └───────────────────────────┘
```

The raw `metrics-azure.billing-*` data stream is **not** modified and remains the system
of record: nothing is deleted from it, and no retention policy is applied to the
transform destination indices. The transforms simply maintain a second, deduplicated copy
of the data. The destination indices are `azure_billing.usage-v1` and
`azure_billing.forecast-v1`; they are deliberately named so they do **not** match
`metrics-*`, otherwise a `metrics-*` data view would count both the raw and the
deduplicated documents.

### Dashboard

The **[Azure Billing] Billing overview** dashboard reads from the
`azure_billing.usage_latest` and `azure_billing.forecast_latest` aliases, so its cost
figures are deduplicated. All cost panels are broken down by `azure.billing.currency`, so
amounts in different currencies are never added together.

The transforms must be running for the dashboard to show data. You can check their status
in Kibana under **Stack Management > Transforms**. If you prefer to query the raw,
non-deduplicated documents, use the `metrics-azure.billing-*` data stream directly.

## Metrics Reference

### Azure Billing Metrics

The Azure Billing Metrics data stream provides events from Consumption and Cost Management APIs of the following types: usage details and forecast.

#### Example

An example event for `billing` looks as following:

```json
{
    "@timestamp": "2021-11-16T14:53:50.309Z",
    "agent": {
        "ephemeral_id": "00acbc2a-2f96-4c8a-99fe-790f724e9b9e",
        "hostname": "docker-fleet-agent",
        "id": "ac0aba17-80ba-472c-a850-25b8eee31b4a",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "7.15.3"
    },
    "azure": {
        "billing": {
            "account_name": "R&D",
            "billing_period_id": "/subscriptions/7657426d-c4c3-44ac-88a2-3b2cd59e6dba/providers/Microsoft.Billing/billingPeriods/20211101",
            "currency": "USD",
            "department_name": "DEpartment",
            "pretax_cost": 0.000002327970961,
            "product": "Bandwidth Inter-Region - Data Transfer Out - North America",
            "usage_end": "2021-11-15T23:59:59.000Z",
            "usage_start": "2021-11-15T00:00:00.000Z"
        },
        "resource": {
            "group": "alex-test-resources",
            "name": "testthis",
            "type": "Microsoft.Storage"
        },
        "subscription_id": "7657426d-c4c3-44ac-88a2-3b2cd59e6dba"
    },
    "cloud": {
        "instance": {
            "id": "/subscriptions/7657426d-c4c3-44ac-88a2-3b2cd59e6dba/resourceGroups/alex-test-resources/providers/Microsoft.Storage/storageAccounts/testthis",
            "name": "alextest223"
        },
        "provider": "azure",
        "region": "CentralUS"
    },
    "data_stream": {
        "dataset": "azure.billing",
        "namespace": "default",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ac0aba17-80ba-472c-a850-25b8eee31b4a",
        "snapshot": true,
        "version": "7.15.3"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "azure.billing",
        "duration": 37147626300,
        "ingested": "2021-11-16T14:53:51Z",
        "module": "azure"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "0e45dc0f765dee79aa8992abcd05b189",
        "ip": [
            "192.168.16.7"
        ],
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "4.19.128-microsoft-standard",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "billing",
        "period": 86400000
    },
    "service": {
        "type": "azure"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.application_id | The application ID | keyword |
| azure.billing.account_name | The billing account name | keyword |
| azure.billing.actual_cost | The actual cost | float |
| azure.billing.billing_period_id | The billing period id | keyword |
| azure.billing.currency | The currency | keyword |
| azure.billing.department_name | The department name | keyword |
| azure.billing.forecast_cost | The forecast cost | float |
| azure.billing.pretax_cost | Cost | float |
| azure.billing.product | The product type | keyword |
| azure.billing.usage_date | The usage date | date |
| azure.billing.usage_end | The usage end date | date |
| azure.billing.usage_start | The usage start date | date |
| azure.dimensions | Azure metric dimensions. | flattened |
| azure.metrics.\*.\* | Metrics returned. | object |
| azure.namespace | The namespace selected | keyword |
| azure.resource.group | The resource group | keyword |
| azure.resource.id | The id of the resource | keyword |
| azure.resource.name | The name of the resource | keyword |
| azure.resource.tags | Azure resource tags. | flattened |
| azure.resource.type | The type of the resource | keyword |
| azure.subscription_id | The subscription ID | keyword |
| azure.timegrain | The Azure metric timegrain | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |

