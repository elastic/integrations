# Azure Billing Metrics Integration

The Azure Billing Metrics integration allows users to monitor their Azure spending to optimize resource use.

The integration supports metrics collection at subscription, department, or billing account levels.

## How it works

The Elastic Agent connect to Azure APIs, fetches usage details and forecast data, and sent it to a dedicated data stream named `metrics-azure.billing-default` in Elasticsearch.

```text
         ┌────────────────────┐       ┌─────────┐       ┌─-─────────────────────┐
         │                    │       │         │       │ metrics-azure.billing │
         │     Azure APIs     │──────▶│  Agent  │──────▶│    <<data stream>>    │
         │                    │       │         │       │                       │
         └────────────────────┘       └─────────┘       └───-───────────────────┘                                              
```

Elastic Agent needs an App Registration to access to Azure on you behalf the collect data using the Azure REST APIs. App Registrations are clients used to programmatically access Azure APIs.

To set up a new App Registration you need to:

* Register a new App
* Add credentials
* Assign Role

In the next section we will create a new App Registration for the Agent.

## App Registration

If you want to learn more about this process, you can read the guides:

* [Quickstart: Register an application with the Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) 
* [Use the portal to create an Azure AD application and service principal that can access resources](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)

This section of the integration docs is an adaptation for the Elastic Agent of these two guides.

### Register a new App

Follow these steps to create the app registration:

1. Sign in to the [Azure Portal](https://portal.azure.com/).
2. Search for and select Azure Active Directory.
3. Under Manage, select App registrations > New registration.
4. Enter a display Name for your application. Possible names are "elastic-agent".
5. Specify who can use the application.
6. Don't enter anything for Redirect URI. It's optional, the the Agent doesn't use it.
7. Select Register to complete the initial app registration.

Take note of the following values, we will use it in the integration settings later:

* `Client ID`: use the content of the "Application (client) ID".

You now have a new App Registration ready for the next steps.

### Add Credentials

Credentials allow your application access Azure APIs and authenticate as itself, requiring no interaction from a user at runtime.

This integration uses Client Secrets to prove its identity.

1. In the [Azure Portal](https://portal.azure.com/), in App registrations, select the application we created in the previous section.
1. Select Certificates & secrets > Client secrets > New client secret.
1. Add a description (for example, "Elastic Agent client secrets").
1. Select an expiration for the secret or specify a custom lifetime.
1. Select Add.

Take note of the following values, we will use it in the integration settings later:

* `Client Secret`: use the content of the "Value".

This secret value is never displayed again after you leave this page. Record the secret's value in a safe place, you will need it in the integration settings page.

### Assign Role

1. In the [Azure Portal](https://portal.azure.com/), search for and select Subscriptions.
1. Select the particular subscription to assign the application to.
1. Select Access control (IAM).
1. Select Add > Add role assignment to open the Add role assignment page.
1. In the Role tab, search and select the role "Billing Reader".
1. Select the Next button to move to the Members tab.
1. Select Assign access to-> User, group, or service principal and then select Select members. By default, Azure AD applications aren't displayed in the available options.
1. To find your application, search by name (for example, "elastic-agent") and select it from the returned list.
1. Click the Select button.
1. Then click the Review + assign button.

Your App Registration is set up.

Take note of the following values from this section, we will use it in the integration settings later:

* `Subscription ID`: use the content of the "Subscription ID" you selected.
* `Tenant ID`: use the "Tenant ID" from the Azure Active Directory you are using.

## Settings

### Main Options

The main section of the settings contain all the option to access the Azure APIs and collect the billing data. You will now use all the notes you collected in the previous sections.

`Client ID` :: The unique identifier of the App Registration (sometimes is referred as Application ID).

`Client Secret` :: The client secret used for authentication.

`Subscription ID` :: The unique identifier for the azure subscription. It is used to access Azure APIs, and it is also used as default scope for billing information. See the Scope section for more information.

`Tenant ID` :: The unique identifier of the Azure Active Directory's Tenant ID.

### Advanced Options

In addition, there are two additional advanced options:

`Resource Manager Endpoint` ::
_string_
Optional, by default the azure public environment will be used, to override, users can provide a specific resource manager endpoint in order to use a different azure environment.
Examples:

* https://management.chinacloudapi.cn for azure ChinaCloud
* https://management.microsoftazure.de for azure GermanCloud
* https://management.azure.com for azure PublicCloud
* https://management.usgovcloudapi.net for azure USGovernmentCloud

`Active Directory Endpoint` ::
_string_
Optional, by default the associated active directory endpoint to the resource manager endpoint will be used, to override, users can provide a specific active directory endpoint in order to use a different azure environment.
Examples:

* https://login.microsoftonline.com for azure ChinaCloud
* https://login.microsoftonline.us for azure GermanCloud
* https://login.chinacloudapi.cn for azure PublicCloud
* https://login.microsoftonline.de for azure USGovernmentCloud

### Data Stream Options

The data streams has some additional options about scope and period. To learn more about the scope, please read the "Scope" ssection.

`Billing Scope Department`:: (_string_) Retrieve data based on the department scope.

`Billing Scope Account Id`:: (_string_) Retrieve data based on the billing account ID scope.

`Period`:: (_string_) The time interval to use when retrieving metric values.

## Scope

There are three supported scope for this integration:

* Subscription
* Department
* Billing Account

The integration uses the Subscription ID as default scope for the billing data.

To change the scope, expand the section "Collect Azure Billing metrics" in the integration settings and set one of the two available options (if you set both, the billing account scope take precedence over deparment):

* `Billing Scope Department`
* `Billing Scope Account ID`


## Data Sources

The integration retrieves two kinds of data:

* [Usage details](https://docs.microsoft.com/en-us/azure/cost-management-billing/manage/consumption-api-overview#usage-details-api), from the Consumption API.
* [Forecast](https://docs.microsoft.com/en-us/rest/api/cost-management/forecast) information, from the Cost Management API.



## Costs

Metric queries are charged based on the number of standard API calls.

## Reference

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
