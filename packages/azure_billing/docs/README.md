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

`period`:: (_string_) The time interval to use when retrieving metric values.

`billing_scope_department`:: (_string_) Retrieve usage details based on the department scope.

`billing_scope_account_id`:: (_string_) Retrieve usage details based on the billing account ID scope.

If none of the 2 options are entered then the subscription ID will be used as scope.


## Additional notes about metrics and costs

Costs: Metric queries are charged based on the number of standard API calls.


An example event for `billing` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "d979a8cf-ddeb-458f-9019-389414e0ab47",
        "ephemeral_id": "4162d5df-ab00-4c1b-b4f3-7db2e3b599d4",
        "type": "metricbeat",
        "version": "7.15.0"
    },
    "elastic_agent": {
        "id": "d979a8cf-ddeb-458f-9019-389414e0ab47",
        "version": "7.15.0",
        "snapshot": true
    },
    "cloud": {
        "provider": "azure"
    },
    "@timestamp": "2021-08-23T14:37:42.268Z",
    "ecs": {
        "version": "1.12.0"
    },
    "service": {
        "type": "azure"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "azure.app_insights"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "4.19.128-microsoft-standard",
            "codename": "Core",
            "name": "CentOS Linux",
            "family": "redhat",
            "type": "linux",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "192.168.96.7"
        ],
        "name": "docker-fleet-agent",
        "id": "1642d255f9a32fc6926cddf21bb0d5d3",
        "mac": [
            "02:42:c0:a8:60:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 300000,
        "name": "app_insights"
    },
    "event": {
        "duration": 503187300,
        "agent_id_status": "verified",
        "ingested": "2021-08-23T14:37:41Z",
        "module": "azure",
        "dataset": "azure.app_insights"
    },
    "azure": {
        "app_insights": {
            "end_date": "2021-08-23T14:37:42.268Z",
            "start_date": "2021-08-23T14:32:42.268Z"
        },
        "metrics": {
            "requests_count": {
                "sum": 4
            }
        },
        "application_id": "42cb59a9-d5be-400b-a5c4-69b0a0026ac6",
        "dimensions": {
            "request_name": "GET Home/Index",
            "request_url_host": "demoappobs.azurewebsites.net"
        }
    }
}
```









