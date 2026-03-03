# Azure Compute VM Scaleset Integration

The Azure Compute Scaleset VM data stream collects and aggregates compute scaleset VM related metrics from Azure Virtual Machine scaleset type resources where it can be used for analysis, visualization, and alerting.
The Azure Compute VM Scaleset will periodically retrieve the Azure Monitor metrics using the Azure REST APIs as MetricList.
Additional Azure API calls will be executed to retrieve information regarding the resources targeted by the user.

## Requirements

Before you start, check the [Authentication and costs](https://docs.elastic.co/integrations/azure_metrics#authentication-and-costs) section.

## Setup

Follow these [step-by-step instructions](https://docs.elastic.co/integrations/azure_metrics#setup) on how to set up an Azure metrics integration.

## Data stream specific configuration notes

`Period`:: (_string_) Reporting interval. Metrics will have a timegrain of 5 minutes, so the `Period` configuration option  for `compute_vm_scaleset` should have a value of `300s` or multiple of `300s`for relevant results.

`Resource IDs`:: (_[]string_) The fully qualified ID's of the resource, including the resource name and resource type. Has the format `/subscriptions/{guid}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}`.
  Should return a list of resources.

`Resource Groups`:: (_[]string_) This option will return all virtual machine scalesets inside the resource group.

If no resource filter is specified, then all virtual machine scalesets inside the entire subscription will be considered.

The primary aggregation value will be retrieved for all the metrics contained in the namespaces. The aggregation options are `avg`, `sum`, `min`, `max`, `total`, `count`.

{{fields "compute_vm_scaleset"}}