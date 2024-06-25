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

* **Azure App Registration**: You need to set up an Azure App Registration to allow the Agent to access the Azure APIs. The App Registration requires a role to access the billing information. The required role is different depending on the subscription, department, or billing account scope. Check the [Setup section](#setup) for more details.
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
* Only one of the following:
	* `Subscription ID`: use the "Subscription Id" content if you decide to collect metrics from a subscription.
	* `Department Id`: use the "Department Id" content if you decide to collect metrics from a department.
	* `Billing account ID`: use the "Billing account ID" content if you decide to collect metrics from a billing account.

Your App Registration is now ready for the Elastic Agent.

#### Additional Resources

If you want to learn more about this process, you can read these two general guides from Microsoft:

* [Quickstart: Register an application with the Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) 
* [Use the portal to create an Azure AD application and service principal that can access resources](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)

### Settings

Add the Azure Billing Metrics integration in Kibana and specify settings.

If you're new to integrations, you can find  step-by-step instructions on how to set up an integration in the {{ url "getting-started-observability" "Getting started" }} guide.

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

{{event "billing"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "billing"}}
