# Azure Container Registry Integration


The Azure Container Registry data stream collects and aggregates storage account related metrics from azure container registry type resources where it can be used for analysis, visualization, and alerting.
The Azure Container Registry will periodically retrieve the azure monitor metrics using the Azure REST APIs as MetricList.
Additional azure API calls will be executed in order to retrieve information regarding the resources targeted by the user.

## Integration specific configuration notes

All the tasks executed against the Azure Monitor REST API will use the Azure Resource Manager authentication model.
Therefore, all requests must be authenticated with Azure Active Directory (Azure AD).
One approach to authenticate the client application is to create an Azure AD service principal and retrieve the authentication (JWT) token.
For a more detailed walk-through, have a look at using Azure PowerShell to create a service principal to access resources https://docs.microsoft.com/en-us/powershell/azure/create-azure-service-principal-azureps?view=azps-2.7.0.
 It is also possible to create a service principal via the Azure portal https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal.
Users will have to make sure the roles assigned to the application contain at least reading permissions to the monitor data, more on the roles here https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles.

Required credentials for the `azure` resource metrics integration:

`client_id`:: The unique identifier for the application (also known as Application Id)

`client_secret`:: The client/application secret/key

`subscription_id`:: The unique identifier for the azure subscription

`tenant_id`:: The unique identifier of the Azure Active Directory instance


The azure credentials keys can be used if configured `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`

`resource_manager_endpoint` ::
_string_
Optional, by default the azure public environment will be used, to override, users can provide a specific resource manager endpoint in order to use a different azure environment.
Ex:
https://management.chinacloudapi.cn for azure ChinaCloud
https://management.microsoftazure.de for azure GermanCloud
https://management.azure.com for azure PublicCloud
https://management.usgovcloudapi.net for azure USGovernmentCloud

`active_directory_endpoint` ::
_string_
Optional, by default the associated active directory endpoint to the resource manager endpoint will be used, to override, users can provide a specific active directory endpoint in order to use a different azure environment.
Ex:
https://login.microsoftonline.com for azure ChinaCloud
https://login.microsoftonline.us for azure GermanCloud
https://login.chinacloudapi.cn for azure PublicCloud
https://login.microsoftonline.de for azure USGovernmentCloud


This data stream will collect metrics from the container registries, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_registry` should be `300s` or multiples of `300s`.

{{fields "container_registry"}}


## Additional notes about metrics and costs

Costs: Metric queries are charged based on the number of standard API calls. More information on pricing here https://azure.microsoft.com/id-id/pricing/details/monitor/.

Authentication: we are handling authentication on our side (creating/renewing the authentication token), so we advise users to use dedicated credentials for metricbeat only.
