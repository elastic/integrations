# Azure Resource Metrics Integration

The Azure Monitor feature collects and aggregates logs and metrics from a variety of sources into a common data platform where it can be used for analysis, visualization, and alerting.

The azure monitor metrics are numerical values that describe some aspect of a system at a particular point in time. They are collected at regular intervals and are identified with a timestamp, a name, a value, and one or more defining labels.

The Azure Resource Metrics will periodically retrieve the azure monitor metrics using the Azure REST APIs as MetricList.
Additional azure API calls will be executed in order to retrieve information regarding the resources targeted by the user.

## Integration specific configuration notes

All the tasks executed against the Azure Monitor REST API will use the Azure Resource Manager authentication model.
Therefore, all requests must be authenticated with Azure Active Directory (Azure AD).
One approach to authenticate the client application is to create an Azure AD service principal and retrieve the authentication (JWT) token.
For a more detailed walk-through, have a look at using Azure PowerShell to create a service principal to access resources https://docs.microsoft.com/en-us/powershell/azure/create-azure-service-principal-azureps?view=azps-2.7.0.
 It is also possible to create a service principal via the Azure portal https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal.
Users will have to make sure the roles assigned to the application contain at least reading permissions to the monitor data, more on the roles here https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles.

Required credentials for the `azure_metrics` integration:

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

### Data stream specific configuration notes

`Period`:: (_string_) Reporting interval. Metrics will have a timegrain of 5 minutes, so the `Period` configuration option  for `monitor` should have a value of `300s` or multiple of `300s`for relevant results.

`Resources`:: (_string_) Contains following options:

`resource_id`:: (_[]string_) The fully qualified ID's of the resource, including the resource name and resource type. Has the format `/subscriptions/{guid}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}`.
  Should return a list of resources.

Users might have large number of resources they would like to gather metrics from. In order to reduce verbosity, they will have
 the options of entering a resource group and filtering by resource type, or type in a “resource_query” where they can filter resources inside their subscription.
Source for the resource API’s:
https://docs.microsoft.com/en-us/rest/api/resources/resources/list
https://docs.microsoft.com/en-us/rest/api/resources/resources/listbyresourcegroup

`resource_group`:: (_[]string_) Using the resource_type configuration option as a filter is required for the resource groups entered. This option should return a list resources we want to apply our metric configuration options on.

`resource_type`:: (_string_) As mentioned above this will be a filter option for the resource group api, will check for all resources under the specified group that are the type under this configuration.

`resource_query`:: (_string_) Should contain a filter entered by the user, the output will be a list of resources


### Resource metric configurations

`metrics`:: List of different metrics to collect information

`namespace`:: (_string_) Namespaces are a way to categorize or group similar metrics together. By using namespaces, users can achieve isolation between groups of metrics that might collect different insights or performance indicators.

`name`:: (_[]string_) Name of the metrics that's being reported. Usually, the name is descriptive enough to help identify what's measured. A list of metric names can be entered as well

`aggregations`:: (_[]string_) List of supported aggregations.
Azure Monitor stores all metrics at one-minute granularity intervals. During a given minute, a metric might need to be sampled several times or it might need to be measured for many discrete events.
To limit the number of raw values we have to emit and pay for in Azure Monitor, they will locally pre-aggregate and emit the values:
Minimum: The minimum observed value from all the samples and measurements during the minute.
Maximum: The maximum observed value from all the samples and measurements during the minute.
Sum: The summation of all the observed values from all the samples and measurements during the minute.
Count: The number of samples and measurements taken during the minute.
Total: The total number of all the observed values from all the samples and measurements during the minute.
If no aggregations are filled, the primary aggregation assigned for this metric will be considered.

`dimensions`:: List of metric dimensions. Dimensions are optional, not all metrics may have dimensions. A custom metric can have up to 10 dimensions.
A dimension is a key or value pair that helps describe additional characteristics about the metric being collected. By using the additional characteristics, you can collect more information about the metric, which allows for deeper insights.
By using this key, you can filter the metric to see how much memory specific processes use or to identify the top five processes by memory usage.
Metrics with dimensions are exported as flattened single dimensional metrics, aggregated across dimension values.

`name`:: Dimension key
`value`:: Dimension value. (Users can select * to return metric values for each dimension)

`ignore_unsupported`:: (_bool_) Namespaces can be unsupported by some resources and supported in some, this configuration option makes sure no error messages are returned if the namespace is unsupported.
The same will go for the metrics configured, some can be removed from Azure Monitor and it should not affect the state of the module.

Users can select the options to retrieve all metrics from a specific namespace using the following:

Example configuration:

```
    - resource_query: "resourceType eq 'Microsoft.DocumentDb/databaseAccounts'"
      metrics:
      - name: ["DataUsage", "DocumentCount", "DocumentQuota"]
        namespace: "Microsoft.DocumentDb/databaseAccounts"
        ignore_unsupported: true
        dimensions:
        - name: "DatabaseName"
          value: "*"
```


## Additional notes about metrics and costs

Costs: Metric queries are charged based on the number of standard API calls. More information on pricing here https://azure.microsoft.com/id-id/pricing/details/monitor/.

Authentication: we are handling authentication on our side (creating/renewing the authentication token), so we advise users to use dedicated credentials for metricbeat only.

{{fields "monitor"}}