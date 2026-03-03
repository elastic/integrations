# Azure Container Registry Integration

The Azure Container Registry data stream collects and aggregates container registry related metrics from Azure Container Registry type resources where it can be used for analysis, visualization, and alerting.
The Azure Container Registry will periodically retrieve the Azure Monitor metrics using the Azure REST APIs as MetricList.
Additional Azure API calls will be executed to retrieve information regarding the resources targeted by the user.

## Requirements

Before you start, check the [Authentication and costs](https://docs.elastic.co/integrations/azure_metrics#authentication-and-costs) section.

## Setup

Follow these [step-by-step instructions](https://docs.elastic.co/integrations/azure_metrics#setup) on how to set up an Azure metrics integration.

## Data stream specific configuration notes

`Period`:: (_string_) Reporting interval. Metrics will have a timegrain of 5 minutes, so the `Period` configuration option  for `container_registry` should have a value of `300s` or multiple of `300s`for relevant results.

`Resource IDs`:: (_[]string_) The fully qualified ID's of the resource, including the resource name and resource type. Has the format `/subscriptions/{guid}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}`.
  Should return a list of resources.

`Resource Groups`:: (_[]string_) This option will return all container registries inside the resource group.

If no resource filter is specified, then all container registries inside the entire subscription will be considered.

The primary aggregation value will be retrieved for all the metrics contained in the namespaces. The aggregation options are `avg`, `sum`, `min`, `max`, `total`, `count`.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| azure.application_id | The application ID | keyword |  |  |
| azure.container_registry.agent_pool_cpu_time.total | AgentPool CPU Time in seconds | float | s | gauge |
| azure.container_registry.run_duration.total | ACR tasks run duration in milliseconds | float | ms | gauge |
| azure.container_registry.storage_used.avg | The amount of storage used by the container registry. For a registry account, it's the sum of capacity used by all the repositories within a registry. It's sum of capacity used by shared layers, manifest files, and replica copies in each of its repositories. | float | byte | gauge |
| azure.container_registry.successful_pull_count.total | Number of successful image pulls | float |  | gauge |
| azure.container_registry.successful_push_count.total | Number of successful image pushes | float |  | gauge |
| azure.container_registry.total_pull_count.total | Number of image pulls in total | float |  | gauge |
| azure.container_registry.total_push_count.total | Number of image pushes in total | float |  | gauge |
| azure.dimensions.geolocation | Geolocation of the container registry | keyword |  |  |
| azure.namespace | The namespace selected | keyword |  |  |
| azure.resource.group | The resource group | keyword |  |  |
| azure.resource.id | The id of the resource | keyword |  |  |
| azure.resource.name | The name of the resource | keyword |  |  |
| azure.resource.tags.\* | Azure resource tags. | object |  |  |
| azure.resource.type | The type of the resource | keyword |  |  |
| azure.subscription_id | The subscription ID | keyword |  |  |
| azure.timegrain | The Azure metric timegrain | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| container.runtime | Runtime managing this container. | keyword |  |  |
| data_stream.dataset | Data stream dataset name. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| dataset.name | Dataset name. | constant_keyword |  |  |
| dataset.namespace | Dataset namespace. | constant_keyword |  |  |
| dataset.type | Dataset type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| service.address | Service address | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
