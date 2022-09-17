# Azure Billing Metrics Integration

## Overview

The Azure Billing Metrics integration allows you to monitor your actual and future Azure spending to optimize resource use.

The integration uses [Azure Consumption API](https://docs.microsoft.com/en-us/azure/cost-management-billing/manage/consumption-api-overview#usage-details-api) to collect usage details and leverages [Azure Cost Management API](https://docs.microsoft.com/en-us/rest/api/cost-management/forecast) to bring forecast data.

Use the Azure Billing Metrics integration to collect detailed resource usage and forecast expense for the coming weeks. For example, if you want to know which resources cost you more, you could check the top resources pie chart. Then you can visualize the prediction for the coming weeks by looking at the forecast chart.

## Data streams

### Azure Billing Metrics

The Azure Billing Metrics data stream collects two types metrics: usage details and forecast.

Usage details metrics track actual expenses including details like subscription ID, resource group, type and name. Forecast metrics track projected expenses over the coming weeks.

## Requirements

You need Elasticsearch to store and search your data and Kibana to visualize and manage it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

You need to set up an Azure App Registration to allow the Agent to access the Azure APIs. See more details in the Setup section.

The App Registration requires the Billing Reader role to access the billing information for the subscription, department or billing account. See more details in the Setup section.

Azure Billing Metrics integration queries are charged based on the number of standard API calls. One integration makes two calls every 24 hours in the standard configuration.

## Setup

### How it works

The Elastic Agent connects to Azure APIs, fetches usage details and forecast data, and sends it to a dedicated data stream named `metrics-azure.billing-default` in Elasticsearch.

```text
         ┌────────────────────┐       ┌─────────┐       ┌─-─────────────────────┐
         │                    │       │         │       │ metrics-azure.billing │
         │     Azure APIs     │──────▶│  Agent  │──────▶│    <<data stream>>    │
         │                    │       │         │       │                       │
         └────────────────────┘       └─────────┘       └───-───────────────────┘                                              
```

Elastic Agent needs an App Registration to access Azure on your behalf to collect data using the Azure REST APIs. App Registrations are required to access Azure APIs programmatically.

To set up a new App Registration, you need to:

* Register a new App
* Add credentials
* Assign Role

In the next section, we will create a new App Registration for the Agent.

### App Registration

#### Register a new App

Follow these steps to create the app registration:

1. Sign in to the [Azure Portal](https://portal.azure.com/).
2. Search for and select Azure Active Directory.
3. Under Manage, select App registrations > New registration.
4. Enter a display Name for your application. Possible names are "elastic-agent."
5. Specify who can use the application.
6. Don't enter anything for Redirect URI. It's optional; the Agent doesn't use it.
7. Select Register to complete the initial app registration.

Take note of the following value. We will use it in the Settings section later:

`Client ID`: use the content of the "Application (client) ID."

You now have a new App Registration ready for the next steps.

#### Add Credentials

Credentials allow your application to access Azure APIs and authenticate itself, requiring no interaction from a user at runtime.

This integration uses Client Secrets to prove its identity.

1. In the [Azure Portal](https://portal.azure.com/), select the application we created in the previous "Register a new App" section.
1. Select Certificates & secrets > Client secrets > New client secret.
1. Add a description (for example, "Elastic Agent client secrets").
1. Select an expiration for the secret or specify a custom lifetime.
1. Select Add.

Take note of the following value. We will use it in the Settings section later:

`Client Secret`: use the content of the "Value" field.

This secret value is never displayed again after you leave this page. Record the secret's value in a safe place. You will need it on the integration's settings page.

#### Assign Role

1. In the [Azure Portal](https://portal.azure.com/), search for and select Subscriptions.
1. Select the subscription to assign the application.
1. Select Access control (IAM).
1. Select Add > Add role assignment to open the Add role assignment page.
1. In the Role tab, search and select the role "Billing Reader".
1. Select the Next button to move to the Members tab.
1. Select Assign access to-> User, group, or service principal, and select Select members. This page does not display Azure AD applications in the available options by default.
1. To find your application, search by name (for example, "elastic-agent") and select it from the list.
1. Click the Select button.
1. Then click the Review + assign button.

Take note of the following values. We will use them in the Settings section later:

* `Subscription ID`: use the content of the "Subscription ID" you selected.
* `Tenant ID`: use the "Tenant ID" from the Azure Active Directory you use.

Your App Registration is now ready for the Elastic Agent.

#### Additional Resources

If you want to learn more about this process, you can read these two general guides from Microsoft:

* [Quickstart: Register an application with the Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) 
* [Use the portal to create an Azure AD application and service principal that can access resources](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)

### Settings

#### Main Options

The settings' main section contains all the options to access the Azure APIs and collect the billing data. You will now use all the notes you collected in the previous sections.

`Client ID` ::
_string_
The unique identifier of the App Registration (sometimes referred to as Application ID).

`Client Secret` ::
_string_
The client secret for authentication.

`Subscription ID` ::
_string_
The unique identifier for the Azure subscription. You can provide just one subscription ID. The Agent uses this ID to access Azure APIs. The Agent also uses this ID as the default scope for billing information: see the "Scope" section for more details about how to collect data for more than one subscription.

`Tenant ID` :: The unique identifier of the Azure Active Directory's Tenant ID.

#### Advanced Options

In addition, there are two additional advanced options:

`Resource Manager Endpoint` ::
_string_
Optional. By default, the integration uses the Azure public environment. To override, users can provide a specific resource manager endpoint to use a different Azure environment.

Examples:

* https://management.chinacloudapi.cn for azure ChinaCloud
* https://management.microsoftazure.de for azure GermanCloud
* https://management.azure.com for azure PublicCloud
* https://management.usgovcloudapi.net for azure USGovernmentCloud

`Active Directory Endpoint` ::
_string_
Optional. By default, the integration uses the associated Active Directory Endpoint. To override, users can provide a specific active directory endpoint to use a different Azure environment.

Examples:

* https://login.microsoftonline.com for azure ChinaCloud
* https://login.microsoftonline.us for azure GermanCloud
* https://login.chinacloudapi.cn for azure PublicCloud
* https://login.microsoftonline.de for azure USGovernmentCloud

#### Data Stream Options

The data stream has some additional options about scope and period. Please read the "Scope" section to learn more about the scope.

`Billing Scope Department ID`:: (_string_) Retrieve data based on the department ID.

`Billing Scope Account ID`:: (_string_) Retrieve data based on the billing account ID. The billing account ID is available on the [Azure Portal](https://portal.azure.com/) at Cost Management + Billing, select a billing scope of the type "billing account", then Setting > Properties > ID.

`Period`:: (_string_) The time interval to use when retrieving metric values.

### Scope

There are three supported scopes for this integration:

* Subscription
* Department
* Billing Account

The integration uses the Subscription ID as the default scope for the billing data.

To change the scope, expand the data stream section named "Collect Azure Billing metrics" in the integration settings and set one of the two available options (if you set both, the billing account scope take precedence over the department):

* `Billing Scope Department ID` :: Collect user details and forecast data for the given deparment ID.
* `Billing Scope Account ID` :: Collect user details and forecast data for the given billing account ID.

## Metrics Reference

### Azure Billing Metrics

The Azure Billing Metrics data stream provides events from Consumption and Cost Management APIs of the following types: usage details and forecast.

#### Example

{{event "billing"}}

{{fields "billing"}}
