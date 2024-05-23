# Azure Compute VM Integration

The Azure Compute VM data stream collects and aggregates virtual machine related metrics from Azure Compute VM type resources where it can be used for analysis, visualization, and alerting.
The Azure Compute VM will periodically retrieve the Azure Monitor metrics using the Azure REST APIs as MetricList.
Additional Azure API calls will be executed to retrieve information regarding the resources targeted by the user.

## Requirements

Before you start, check the [Authentication and costs](https://docs.elastic.co/integrations/azure_metrics#authentication-and-costs) section.

## Setup

Follow these [step-by-step instructions](https://docs.elastic.co/integrations/azure_metrics#setup) on how to set up an Azure metrics integration.

## Data stream specific configuration notes

`Period`:: (_string_) Reporting interval. Metrics will have a timegrain of 5 minutes, so the `Period` configuration option  for `compute_vm` should have a value of `300s` or multiple of `300s`for relevant results.

`Resource IDs`:: (_[]string_) The fully qualified ID's of the resource, including the resource name and resource type. Has the format `/subscriptions/{guid}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}`.
  Should return a list of resources.

`Resource Groups`:: (_[]string_) This option will return all virtual machines inside the resource group.

If no resource filter is specified, then all virtual machines inside the entire subscription will be considered.

The primary aggregation value will be retrieved for all the metrics contained in the namespaces. The aggregation options are `avg`, `sum`, `min`, `max`, `total`, `count`.

## Guest metrics

To collect monitoring data from the guest operating system of your virtual machine, you can configure a diagnostic agent, which is an [Azure Diagnostics extension](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/diagnostics-extension-overview). The monitoring data is collected into an Azure storage account and can be viewed from the Azure Monitor. 

IMPORTANT: Before you continue, make sure you have a storage account to store the metrics you collect. The storage account must be in the same region as your virtual machine.

To enable the diagnostic agent:

1. Sign in to the [Azure Portal](https://portal.azure.com/) and select your virtual machine.
1. From **Monitoring** > **Diagnostic settings** configure the diagnostic agent and select the storage account you want to use to collect your data.
1. From the **Sinks** tab, check **Enable Azure Monitor** to view your data from Azure Monitor dashboards.

For more information on sending guest OS metrics to Azure Monitor, check the [Microsoft documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/collect-custom-metrics-guestos-resource-manager-vm).

{{fields "compute_vm"}}