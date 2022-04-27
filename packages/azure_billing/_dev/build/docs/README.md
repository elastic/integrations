# Azure Billing Integration

The [Azure Billing](https://docs.microsoft.com/en-us/azure/cost-management-billing/) Integration allows users to retrieve usage details and forecast information of the subscription configured.

### Integration level configuration options

All the tasks executed against the Azure Consumption REST API will use the [Azure Resource Manager authentication model](https://docs.microsoft.com/en-us/azure/cost-management-billing/manage/consumption-api-overview).
Therefore, all requests must be authenticated with Azure Active Directory (Azure AD).
One approach to authenticate the client application is to create an Azure AD service principal and retrieve the authentication (JWT) token.
For a more detailed walk-through, see: [Using Azure PowerShell to create a service principal to access resources](https://docs.microsoft.com/en-us/powershell/azure/create-azure-service-principal-azureps?view=azps-2.7.0).
It is also possible to create a service principal via the [Azure portal](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal).
Users will have to make sure the roles assigned to the application contain at least reading permissions to the monitor data. See: [Role-based access control](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles).

Required credentials for the `azure_billing` integration:

`Client ID`:: The unique identifier for the application (also known as Application Id)

`Client Secret`:: The client/application secret/key

`Subscription ID`:: The unique identifier for the azure subscription

`Tenant ID`:: The unique identifier of the Azure Active Directory instance


The azure credentials keys can be used if configured `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`

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

The integration contains the following data streams:

### billing



#### Configuration options

`Period`:: (_string_) The time interval to use when retrieving metric values.

`Billing Scope Department`:: (_string_) Retrieve usage details based on the department scope.

`Billing Scope Account Id`:: (_string_) Retrieve usage details based on the billing account ID scope.

If none of the 2 options are entered then the subscription ID will be used as scope.


## Additional notes about metrics and costs

Costs: Metric queries are charged based on the number of standard API calls.


{{event "billing"}}









