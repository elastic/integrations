# Azure Storage Account Integration

The Azure Storage Account data stream collects and aggregates storage account related metrics from Azure Storage Account type resources where it can be used for analysis, visualization, and alerting.
The Azure Storage Account will periodically retrieve the Azure Monitor metrics using the Azure REST APIs as MetricList.
Additional Azure API calls will be executed to retrieve information regarding the resources targeted by the user.

## Requirements

Before you start, check the [Authentication and costs](https://docs.elastic.co/integrations/azure_metrics#authentication-and-costs) section.

## Setup

Follow these [step-by-step instructions](https://docs.elastic.co/integrations/azure_metrics#setup) on how to set up an Azure metrics integration.

## Data stream specific configuration notes

`Period`:: (_string_) Reporting interval. Metrics will have a timegrain of 5 minutes, so the `Period` configuration option  for `storage_account` should have a value of `300s` or multiple of `300s`for relevant results.

`Resource IDs`:: (_[]string_) The fully qualified ID's of the resource, including the resource name and resource type. Has the format `/subscriptions/{guid}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}`.
  Should return a list of resources.

`Resource Groups`:: (_[]string_) This option will return all storage accounts inside the resource group.

`Service Types`:: (_[]string_) The service type values allowed are `blob`, `table`, `queue`, `file`, they can be used to filter on the type of the storage account container.

If no resource filter is specified, then all storage accounts inside the subscription will be considered.

The primary aggregation value will be retrieved for all the metrics contained in the namespaces. The aggregation options are `avg`, `sum`, `min`, `max`, `total`, `count`.

{{fields "storage_account"}}
