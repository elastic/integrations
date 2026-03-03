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

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| azure.application_id | The application ID | keyword |  |  |
| azure.compute_vm_scaleset.available_memory_bytes.avg | Amount of physical memory, in bytes, immediately available for allocation to a process or for system use in the Virtual Machine | float | byte | gauge |
| azure.compute_vm_scaleset.cpu_credits_consumed.avg | Total number of credits consumed by the Virtual Machine. Only available on B-series burstable VMs | float |  | gauge |
| azure.compute_vm_scaleset.cpu_credits_remaining.avg | Total number of credits available to burst. Only available on B-series burstable VMs | float |  | gauge |
| azure.compute_vm_scaleset.data_disk_bandwidth_consumed_percentage.avg | Percentage of data disk bandwidth consumed per minute | float | percent | gauge |
| azure.compute_vm_scaleset.data_disk_queue_depth.avg | Data Disk Queue Depth(or Queue Length) | float |  | gauge |
| azure.compute_vm_scaleset.data_disk_read_bytes_per_sec.avg | Bytes/Sec read from a single disk during monitoring period | float |  | gauge |
| azure.compute_vm_scaleset.data_disk_read_operations_per_sec.avg | Read IOPS from a single disk during monitoring period | float |  | gauge |
| azure.compute_vm_scaleset.data_disk_write_bytes_per_sec.avg | Bytes/Sec written to a single disk during monitoring period | float |  | gauge |
| azure.compute_vm_scaleset.data_disk_write_operations_per_sec.avg | Write IOPS from a single disk during monitoring period | float |  | gauge |
| azure.compute_vm_scaleset.disk_read_bytes.total | Bytes read from disk during monitoring period | float | byte | gauge |
| azure.compute_vm_scaleset.disk_read_operations_per_sec.avg | Disk Read IOPS | float |  | gauge |
| azure.compute_vm_scaleset.disk_write_bytes.total | Bytes written to disk during monitoring period | float | byte | gauge |
| azure.compute_vm_scaleset.disk_write_operations_per_sec.avg | Disk Write IOPS | float |  | gauge |
| azure.compute_vm_scaleset.inbound_flows.avg | Inbound Flows are number of current flows in the inbound direction (traffic going into the VM) | float |  | gauge |
| azure.compute_vm_scaleset.inbound_flows_maximum_creation_rate.avg | The maximum creation rate of inbound flows (traffic going into the VM) | float |  | gauge |
| azure.compute_vm_scaleset.memory_available_bytes.avg | Available Bytes is the amount of physical memory, in bytes, immediately available for allocation to a process or for system use. It is equal to the sum of memory assigned to the standby (cached), free and zero page lists. | float | byte | gauge |
| azure.compute_vm_scaleset.memory_commit_limit.avg | Memory commit limit | float | byte | gauge |
| azure.compute_vm_scaleset.memory_committed_bytes.avg | Committed Bytes is the amount of committed virtual memory, in bytes. Committed memory is the physical memory which has space reserved on the disk paging file(s). There can be one or more paging files on each physical drive. This counter displays the last observed value only. | float | byte | gauge |
| azure.compute_vm_scaleset.memory_pct_committed_bytes_in_use.avg | Committed Bytes In Use is the ratio of Memory \ Committed Bytes to the Memory \ Commit Limit. Committed memory is the physical memory in use for which space has been reserved in the paging file should it need to be written to disk. The commit limit is determined by the size of the paging file. If the paging file is enlarged, the commit limit increases, and the ratio is reduced). This value displays the current percentage value only. | float | percent | gauge |
| azure.compute_vm_scaleset.network_in_total.total | The number of bytes received on all network interfaces by the Virtual Machine(s) (Incoming Traffic) | float |  | gauge |
| azure.compute_vm_scaleset.network_out_total.total | The number of bytes out on all network interfaces by the Virtual Machine(s) (Outgoing Traffic) | float |  | gauge |
| azure.compute_vm_scaleset.os_disk_queue_depth.avg | OS Disk Queue Depth(or Queue Length) | float |  | gauge |
| azure.compute_vm_scaleset.os_disk_read_bytes_per_sec.avg | Bytes/Sec read from a single disk during monitoring period for OS disk | float |  | gauge |
| azure.compute_vm_scaleset.os_disk_read_operations_per_sec.avg | Read IOPS from a single disk during monitoring period for OS disk | float |  | gauge |
| azure.compute_vm_scaleset.os_disk_write_bytes_per_sec.avg | Bytes/Sec written to a single disk during monitoring period for OS disk | float |  | gauge |
| azure.compute_vm_scaleset.os_disk_write_operations_per_sec.avg | Write IOPS from a single disk during monitoring period for OS disk | float |  | gauge |
| azure.compute_vm_scaleset.outbound_flows.avg | Outbound Flows are number of current flows in the outbound direction (traffic going out of the VM) | float |  | gauge |
| azure.compute_vm_scaleset.outbound_flows_maximum_creation_rate.avg | The maximum creation rate of outbound flows (traffic going out of the VM) | float |  | gauge |
| azure.compute_vm_scaleset.percentage_cpu.avg | The percentage of allocated compute units that are currently in use by the Virtual Machine(s) | float | percent | gauge |
| azure.dimensions.lun | Logical Unit Number is a number that is used to identify a specific storage device | keyword |  |  |
| azure.dimensions.virtual_machine | The VM name | keyword |  |  |
| azure.dimensions.vmname | The VM name | keyword |  |  |
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
