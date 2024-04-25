# Azure Resource Metrics Integration

The Azure Monitor feature collects and aggregates logs and metrics from a variety of sources into a common data platform where it can be used for analysis, visualization, and alerting.

The Azure Monitor metrics are numerical values that describe some aspect of a system at a particular point in time. They are collected at regular intervals and are identified with a timestamp, a name, a value, and one or more defining labels.

The Azure Resource Metrics will periodically retrieve the Azure Monitor metrics using the Azure REST APIs as MetricList.
Additional Azure API calls will be executed to retrieve information regarding the resources targeted by the user.

## Requirements

Before you start, check the [Authentication and costs](https://docs.elastic.co/integrations/azure_metrics#authentication-and-costs) section.

## Setup

Follow these [step-by-step instructions](https://docs.elastic.co/integrations/azure_metrics#setup) on how to set up an Azure metrics integration.

## Data stream specific configuration notes

`Period`:: (_string_) Reporting interval. Metrics will have a timegrain of 5 minutes, so the `Period` configuration option  for `monitor` should have a value of `300s` or multiple of `300s`for relevant results.

`Resources`:: (_string_) Contains following options:

`resource_id`:: (_[]string_) The fully qualified ID's of the resource, including the resource name and resource type. Has the format `/subscriptions/{guid}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}`.
  Should return a list of resources.

You can gather metrics from a large number of resources. To reduce verbosity, you can enter a resource group and filter by resource type, or type in a “resource_query” where you can filter resources inside your subscription.
Check the following resources API:
- [Resources - List](https://docs.microsoft.com/en-us/rest/api/resources/resources/list)
- [Resources - List By Resource Group](https://docs.microsoft.com/en-us/rest/api/resources/resources/listbyresourcegroup)

`resource_group`:: (_[]string_) Using the resource_type configuration option as a filter is required for the resource groups entered. This option should return a list resources we want to apply our metric configuration options on.

`resource_type`:: (_string_) As mentioned above this will be a filter option for the resource group api, will check for all resources under the specified group that are the type under this configuration.

`resource_query`:: (_string_) Should contain a filter entered by the user, the output will be a list of resources.

## Resource metric configurations

`metrics`:: List of different metrics to collect information.

`namespace`:: (_string_) Namespaces are a way to categorize or group similar metrics together. By using namespaces, users can achieve isolation between groups of metrics that might collect different insights or performance indicators.

`name`:: (_[]string_) Name of the metrics that's being reported. Usually, the name is descriptive enough to help identify what's measured. A list of metric names can be entered as well.

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


**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| azure.application_id | The application ID | keyword |  |
| azure.dimensions.\* | Azure metric dimensions. | object |  |
| azure.dimensions.fingerprint | Autogenerated ID representing the fingerprint of the azure.dimensions object | keyword |  |
| azure.metrics.\*.\* | Metrics returned. | object | gauge |
| azure.namespace | The namespace selected | keyword |  |
| azure.resource.group | The resource group | keyword |  |
| azure.resource.id | The id of the resource | keyword |  |
| azure.resource.name | The name of the resource | keyword |  |
| azure.resource.tags.\* | Azure resource tags. | object |  |
| azure.resource.type | The type of the resource | keyword |  |
| azure.subscription_id | The subscription ID | keyword |  |
| azure.timegrain | The Azure metric timegrain | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.labels | Image labels. | object |  |
| container.name | Container name. | keyword |  |
| container.runtime | Runtime managing this container. | keyword |  |
| data_stream.dataset | Data stream dataset name. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| dataset.name | Dataset name. | constant_keyword |  |
| dataset.namespace | Dataset namespace. | constant_keyword |  |
| dataset.type | Dataset type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.mac | Host mac addresses. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |
| service.address | Service address | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |
