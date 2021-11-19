# Azure Billing Integration

The Azure Billing Integration allows users to retrieve usage details and forecast information of the subscription configured.

### Integration level configuration options

All the tasks executed against the Azure Consumption REST API will use the Azure Resource Manager authentication model (https://docs.microsoft.com/en-us/azure/cost-management-billing/manage/consumption-api-overview).
Therefore, all requests must be authenticated with Azure Active Directory (Azure AD).
One approach to authenticate the client application is to create an Azure AD service principal and retrieve the authentication (JWT) token.
For a more detailed walk-through, have a look at using Azure PowerShell to create a service principal to access resources https://docs.microsoft.com/en-us/powershell/azure/create-azure-service-principal-azureps?view=azps-2.7.0.
It is also possible to create a service principal via the Azure portal https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal.
Users will have to make sure the roles assigned to the application contain at least reading permissions to the monitor data, more on the roles here https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles.

Required credentials for the `azure_billing` integration:

`Client ID`:: The unique identifier for the application (also known as Application Id)

`Client Secret`:: The client/application secret/key

`Subscription ID`:: The unique identifier for the azure subscription

`Tenant ID`:: The unique identifier of the Azure Active Directory instance


The azure credentials keys can be used if configured `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`

`Resource Manager Endpoint` ::
_string_
Optional, by default the azure public environment will be used, to override, users can provide a specific resource manager endpoint in order to use a different azure environment.
Ex:
https://management.chinacloudapi.cn for azure ChinaCloud
https://management.microsoftazure.de for azure GermanCloud
https://management.azure.com for azure PublicCloud
https://management.usgovcloudapi.net for azure USGovernmentCloud

`Active Directory Endpoint` ::
_string_
Optional, by default the associated active directory endpoint to the resource manager endpoint will be used, to override, users can provide a specific active directory endpoint in order to use a different azure environment.
Ex:
https://login.microsoftonline.com for azure ChinaCloud
https://login.microsoftonline.us for azure GermanCloud
https://login.chinacloudapi.cn for azure PublicCloud
https://login.microsoftonline.de for azure USGovernmentCloud
The integration contains the following data streams:

### billing



#### Configuration options

`Period`:: (_string_) The time interval to use when retrieving metric values.

`Billing Scope Department`:: (_string_) Retrieve usage details based on the department scope.

`Billing Scope Account Id`:: (_string_) Retrieve usage details based on the billing account ID scope.

If none of the 2 options are entered then the subscription ID will be used as scope.


## Additional notes about metrics and costs

Costs: Metric queries are charged based on the number of standard API calls.


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









