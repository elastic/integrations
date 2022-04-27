# Azure Resource Metrics Integration

The [Azure Monitor](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/data-platform-metrics) feature collects and aggregates logs and metrics from a variety of sources into a common data platform where it can be used for analysis, visualization, and alerting.

The azure monitor metrics are numerical values that describe some aspect of a system at a particular point in time. They are collected at regular intervals and are identified with a timestamp, a name, a value, and one or more defining labels.

The Azure Resource Metrics will periodically retrieve the azure monitor metrics using the Azure REST APIs as MetricList.
Additional azure API calls will be executed in order to retrieve information regarding the resources targeted by the user.

## Integration specific configuration notes

All the tasks executed against the Azure Monitor REST API will use the Azure Resource Manager authentication model.
Therefore, all requests must be authenticated with Azure Active Directory (Azure AD).
One approach to authenticate the client application is to create an Azure AD service principal and retrieve the authentication (JWT) token.
For a more detailed walk-through, see:
* [Create an Azure service principal with Azure PowerShell](https://docs.microsoft.com/en-us/powershell/azure/create-azure-service-principal-azureps?view=azps-2.7.0.)
* [Use the portal to create an Azure AD application and service principal that can access resources](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal).

Users will have to make sure the roles assigned to the application contain at least reading permissions to the monitor data. See: [Azure built-in roles](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles).

Required credentials for the `azure` resource metrics integration:

`client_id`:: The unique identifier for the application (also known as Application Id)

`client_secret`:: The client/application secret/key

`subscription_id`:: The unique identifier for the azure subscription

`tenant_id`:: The unique identifier of the Azure Active Directory instance


The azure credentials keys can be used if configured `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`

`resource_manager_endpoint` ::
_string_
Optional, by default the azure public environment will be used, to override, users can provide a specific resource manager endpoint in order to use a different azure environment.
Examples:
* https://management.chinacloudapi.cn for azure ChinaCloud
* https://management.microsoftazure.de for azure GermanCloud
* https://management.azure.com for azure PublicCloud
* https://management.usgovcloudapi.net for azure USGovernmentCloud

`active_directory_endpoint` ::
_string_
Optional, by default the associated active directory endpoint to the resource manager endpoint will be used, to override, users can provide a specific active directory endpoint in order to use a different azure environment.
Examples:
* https://login.microsoftonline.com for azure ChinaCloud
* https://login.microsoftonline.us for azure GermanCloud
* https://login.chinacloudapi.cn for azure PublicCloud
* https://login.microsoftonline.de for azure USGovernmentCloud

## Data streams

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

## Additional notes about metrics and costs

Costs: Metric queries are charged based on the number of standard API calls. 
See: [Azure Monitor pricing](https://azure.microsoft.com/en-gb/pricing/details/monitor/).

Authentication: We are handling authentication on our side (creating/renewing the authentication token), so we advise users to use dedicated credentials for metricbeat only.
