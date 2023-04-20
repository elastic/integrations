# Azure Billing Metrics Integration

The Azure Billing Metrics integration allows you to monitor your actual and future Azure spending to optimize resource use.

The integration uses the [Azure Consumption API](https://docs.microsoft.com/en-us/azure/cost-management-billing/manage/consumption-api-overview) to collect usage details and leverages the [Azure Cost Management API](https://docs.microsoft.com/en-us/rest/api/cost-management/forecast) to bring forecast data.

Use the Azure Billing Metrics integration to collect detailed resource usage and forecast expenses for the coming weeks. For example, if you want to know which resources cost you most, you could view the top resources donut chart included in the dashboard for this integration. Then you can visualize the prediction for the coming weeks by looking at the forecast chart.

## Data streams


The Azure Billing Metrics integration collects one type of data stream: metrics.

**Metrics** give you insight into the state of your Azure costs.
Data streams collected by this integration include usage details and forecast metrics.
Usage details metrics track actual expenses including details like subscription ID, resource group, type and name. Forecast metrics track projected expenses over the coming weeks.

## Requirements

To use this integration you will need:

* **Azure App Registration**: You need to set up an Azure App Registration to allow the Agent to access the Azure APIs. The App Registration requires the Billing Reader role to access the billing information for the subscription, department, or billing account. See more details in the [Setup section](#setup).
* **Elasticsearch and Kibana**: You need Elasticsearch to store and search your data and Kibana to visualize and manage it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, the [Native Azure Integration](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/elastic.elasticsearch?tab=Overview), or self-manage the Elastic Stack on your hardware.
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
2. Search for and select **Azure Active Directory**.
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

Take note of the following values, which you will use later when specifying settings.

* `Subscription ID`: use the content of the "Subscription ID" you selected.
* `Tenant ID`: use the "Tenant ID" from the Azure Active Directory you use.

Your App Registration is now ready for the Elastic Agent.

#### Additional Resources

If you want to learn more about this process, you can read these two general guides from Microsoft:

* [Quickstart: Register an application with the Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) 
* [Use the portal to create an Azure AD application and service principal that can access resources](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)

### Settings

Add the Azure Billing Metrics integration in Kibana and specify settings.

If you're new to integrations, you can find  step-by-step instructions on how to set up an integration in the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

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

There are two additional advanced options:

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

#### Data stream options

The data stream has some additional options about scope and period. To learn more about the scope, read the [Scope](#scope) section.

`Billing Scope Department ID` _string_
: Retrieve data based on the department ID.

`Billing Scope Account ID`  _string_
: Retrieve data based on the billing account ID. The billing account ID is available on the [Azure Portal](https://portal.azure.com/) at **Cost Management + Billing**, select a billing scope of the type "billing account", then **Setting** > **Properties** > **ID**.

`Period` _string_
: The time interval to use when retrieving metric values.

### Scope

There are three supported scopes for this integration:

* Subscription
* Department
* Billing Account

The integration uses the Subscription ID as the default scope for the billing data.

To change the scope, expand the data stream section named **Collect Azure Billing metrics** in the integration settings and set one of the two available options (if you set both, the billing account scope take precedence over the department):

* `Billing Scope Department ID` : Collect user details and forecast data for the given department ID.
* `Billing Scope Account ID` : Collect user details and forecast data for the given billing account ID.

## Metrics Reference

### Azure Billing Metrics

The Azure Billing Metrics data stream provides events from Consumption and Cost Management APIs of the following types: usage details and forecast.

#### Example

An example event for `billing` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "ac0aba17-80ba-472c-a850-25b8eee31b4a",
        "type": "metricbeat",
        "ephemeral_id": "00acbc2a-2f96-4c8a-99fe-790f724e9b9e",
        "version": "7.15.3"
    },
    "elastic_agent": {
        "id": "ac0aba17-80ba-472c-a850-25b8eee31b4a",
        "version": "7.15.3",
        "snapshot": true
    },
    "cloud": {
        "instance": {
            "name": "alextest223",
            "id": "/subscriptions/7657426d-c4c3-44ac-88a2-3b2cd59e6dba/resourceGroups/alex-test-resources/providers/Microsoft.Storage/storageAccounts/testthis"
        },
        "provider": "azure",
        "region": "CentralUS"
    },
    "@timestamp": "2021-11-16T14:53:50.309Z",
    "ecs": {
        "version": "1.11.0"
    },
    "service": {
        "type": "azure"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "azure.billing"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "4.19.128-microsoft-standard",
            "codename": "Core",
            "name": "CentOS Linux",
            "type": "linux",
            "family": "redhat",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "192.168.16.7"
        ],
        "name": "docker-fleet-agent",
        "id": "0e45dc0f765dee79aa8992abcd05b189",
        "mac": [
            "02:42:c0:a8:10:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 86400000,
        "name": "billing"
    },
    "event": {
        "duration": 37147626300,
        "agent_id_status": "verified",
        "ingested": "2021-11-16T14:53:51Z",
        "module": "azure",
        "dataset": "azure.billing"
    },
    "azure": {
        "subscription_id": "7657426d-c4c3-44ac-88a2-3b2cd59e6dba",
        "resource": {
            "name": "testthis",
            "type": "Microsoft.Storage",
            "group": "alex-test-resources"
        },
        "billing": {
            "product": "Bandwidth Inter-Region - Data Transfer Out - North America",
            "pretax_cost": 0.000002327970961,
            "usage_start": "2021-11-15T00:00:00.000Z",
            "usage_end": "2021-11-15T23:59:59.000Z",
            "department_name": "DEpartment",
            "account_name": "R\u0026D",
            "currency": "USD",
            "billing_period_id": "/subscriptions/7657426d-c4c3-44ac-88a2-3b2cd59e6dba/providers/Microsoft.Billing/billingPeriods/20211101"
        }
    }
}
```

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
| azure.dimensions.\* | Azure metric dimensions. | flattened |
| azure.metrics.\*.\* | Metrics returned. | object |
| azure.namespace | The namespace selected | keyword |
| azure.resource.group | The resource group | keyword |
| azure.resource.id | The id of the resource | keyword |
| azure.resource.name | The name of the resource | keyword |
| azure.resource.tags.\* | Azure resource tags. | flattened |
| azure.resource.type | The type of the resource | keyword |
| azure.subscription_id | The subscription ID | keyword |
| azure.timegrain | The Azure metric timegrain | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| ecs.version | ECS version | keyword |
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Service address | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |

