# Azure Resource Metrics Integration

The [Azure Monitor](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/data-platform-metrics) feature collects and aggregates logs and metrics from a variety of sources into a common data platform where it can be used for analysis, visualization, and alerting.

The Azure Resource Metrics will periodically retrieve the Azure Monitor metrics using the Azure REST APIs as MetricList. Additional Azure API calls can be used to retrieve information regarding the resources targeted by the user.

## Data streams

The Azure Resource Metrics collects one type of data: metrics.

**Metrics** are numerical values that describe some aspects of a system at a particular point in time. They are collected at regular intervals and are identified with a timestamp, a name, a value, and one or more defining labels.

The following data streams are available:

**`monitor`** - Allows users to retrieve metrics from specified resources. Added filters can apply here as the interval of retrieving these metrics, metric names,
aggregation list, namespaces and metric dimensions. The monitor metrics will have a minimum timegrain of 5 minutes, so the `period` for `monitor` dataset should be `300s` or multiples of `300s`.

**`compute_vm`** - Collects metrics from the virtual machines, these metrics will have a timegrain every 5 minutes,
so the `period` for `compute_vm` should be `300s` or multiples of `300s`.

**`compute_vm_scaleset`** - Collects metrics from the virtual machine scalesets, these metrics will have a timegrain every 5 minutes,
so the `period` for `compute_vm_scaleset` should be `300s` or multiples of `300s`.

**`storage_account`** - Collects metrics from the storage accounts, these metrics will have a timegrain every 5 minutes,
so the `period` for `storage_account` should be `300s` or multiples of `300s`.

**`container_instance`** - Collects metrics from specified container groups, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_instance` should be `300s` or multiples of `300s`.

**`container_registry`** - Collects metrics from the container registries, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_registry` should be `300s` or multiples of `300s`.

**`container_service`** - Collects metrics from the container services, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_service` should be `300s` or multiples of `300s`.

**`database_account`** - Collects relevant metrics from specified database accounts, these metrics will have a timegrain every 5 minutes,
so the `period` for `database_account` should be `300s` or multiples of `300s`.

For each individual data stream, you can check the exported fields in the [Metrics reference](#metrics-reference) section.

## Requirements

The Elastic Agent fetches metric data from the Azure Monitor API and sends it to dedicated data streams named `azure-monitor.<metricset>-default` in Elasticsearch.

```text
                       ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐

                       │  ┌─────────────────┐  │
┌─────────────────┐       │  azure-monitor  │       ┌─────────────────┐
│    Azure API    │◀───┼──│  <<metricset>>  │──┼───▶│  Elasticsearch  │
└─────────────────┘       └─────────────────┘       └─────────────────┘
                       │                       │
                        ─ Elastic Agent ─ ─ ─ ─
```

Elastic Agent needs an App Registration to access Azure on your behalf to collect data using the Azure APIs programmatically.

To use this integration you will need:

* **Azure App Registration**: You need to set up an Azure App Registration to allow the Agent to access the Azure APIs. See more details in the [Setup section](#setup).
* **Elasticsearch and Kibana**: You need Elasticsearch to store and search your data and Kibana to visualize and manage it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, the [Native Azure Integration](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/elastic.elasticsearch?tab=Overview), or self-manage the Elastic Stack on your hardware.


### Authentication and costs

**Authentication on the Azure side**
All the tasks executed against the Azure Monitor REST API use the Azure Resource Manager authentication model. Therefore, all requests must be authenticated with Microsoft Entra.
To authenticate the client application, create a Microsoft Entra service principal and retrieve the authentication (JWT) token. For more details, check the following procedures:
* [Create an Azure service principal with Azure PowerShell](https://docs.microsoft.com/en-us/powershell/azure/create-azure-service-principal-azureps?view=azps-2.7.0.)
* [Use the portal to create a Microsoft Entra application and service principal that can access resources](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal).

NOTE: When you create an Azure service principal with Azure PowerShell, a linked App Registration is automatically created and is visible on the Azure portal.

Make sure that the roles assigned to the application contain at least reading permissions to the monitor data. Check [Azure built-in roles](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles) for more details.

**Authentication on the Elastic side**
Elastic handles authentication by creating or renewing the authentication token. It is recommended to use dedicated credentials for Metricbeat only.

**Costs**
Metric queries are charged based on the number of standard API calls. 
Check [Azure Monitor pricing](https://azure.microsoft.com/en-gb/pricing/details/monitor/) for more detailsgit.

## Setup

To start collecting data with this integration, you need to:
- Register a new Azure app, by adding credentials, and assigning roles.
- Specify the integration settings in Kibana, which will determine how the integration will access the Azure APIs.

### Register a new Azure app

To register your app, follow these steps:

**Step 1: Create the app registration**

1. Sign in to the [Azure Portal](https://portal.azure.com/).
2. Search for and select **Microsoft Entra ID**.
3. Under **Manage**, select **App registrations** > **New registration**.
4. Enter a display _Name_ for your application (for example, "elastic-agent").
5. Specify who can use the application.
6. Don't enter anything for _Redirect URI_. This is optional and the agent doesn't use it.
7. Select **Register** to complete the initial app registration.

Take note of the **Application (client) ID**, which you will use later when specifying the **Client ID** in the integration settings.

**Step 2: Add credentials**

Credentials allow your application to access Azure APIs and authenticate itself, requiring no interaction from a user at runtime.

This integration uses Client Secrets to prove its identity.

1. In the [Azure Portal](https://portal.azure.com/), select the application you created in the previous section.
1. Select **Certificates & secrets** > **Client secrets** > **New client secret**.
1. Add a description (for example, "Elastic Agent client secrets").
1. Select an expiration for the secret or specify a custom lifetime.
1. Select **Add**.

Take note of the content in the **Value** column in the **Client secrets** table, which you will use later when specifying a **Client Secret** in the integration settings. **This secret value is never displayed again after you leave this page.** Record the secret's value in a safe place.

**Step 3: Assign role**

1. In the [Azure Portal](https://portal.azure.com/), search for and select **Subscriptions**.
1. Select the subscription to assign the application.
1. Select **Access control (IAM)**.
1. Select **Add** > **Add role assignment** to open the _Add role assignment page_.
1. In the **Role** tab, search and select the role **Monitoring Reader**.
1. Select the **Next** button to move to the **Members** tab.
1. Select **Assign access to** > **User, group, or service principal**, and select **Select members**. This page does not display Microsoft Entra applications in the available options by default.
1. To find your application, search by name (for example, "elastic-agent") and select it from the list.
1. Click the **Select** button.
1. Then click the **Review + assign** button.

Take note of the following values, which you will use later when specifying settings.

* `Subscription ID`: use the content of the "Subscription ID" you selected.
* `Tenant ID`: use the "Tenant ID" from the  Microsoft Entra you use.

Your App Registration is now ready for the Elastic Agent.

### Specify the integration settings in Kibana

Add the Azure Resource Metrics integration in Kibana and specify settings.

If you're new to integrations, you can find step-by-step instructions on how to set up an integration in the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

The settings' main section contains all the options needed to access the Azure APIs and collect the monitoring data. You will now use all the values from [App registration](#app-registration) including:

`Client ID` _string_
: The unique identifier of the App Registration (sometimes referred to as Application ID).

`Client Secret` _string_
: The client secret for authentication.

`Subscription ID` _string_
: The unique identifier for the Azure subscription. You can provide just one subscription ID. The Agent uses this ID to access Azure APIs. 

`Tenant ID` _string_
: The unique identifier of the  Microsoft Entra Tenant ID.

### Advanced options

There are two additional advanced options:

`Resource Manager Endpoint` _string_
: Optional. By default, the integration uses the Azure public environment. To override, users can provide a specific resource manager endpoint to use a different Azure environment.

Examples:

* `https://management.chinacloudapi.cn` for Azure ChinaCloud
* `https://management.microsoftazure.de` for Azure GermanCloud
* `https://management.azure.com` for Azure PublicCloud
* `https://management.usgovcloudapi.net` for Azure USGovernmentCloud

` Microsoft Entra Endpoint`  _string_
: Optional. By default, the integration uses the associated  Microsoft Entra Endpoint. To override, users can provide a specific active directory endpoint to use a different Azure environment.

Examples:

* `https://login.chinacloudapi.cn` for Azure ChinaCloud
* `https://login.microsoftonline.de` for Azure GermanCloud
* `https://login.microsoftonline.com` for Azure PublicCloud
* `https://login.microsoftonline.us` for Azure USGovernmentCloud

## Metrics reference

`monitor`
This data stream allows users to retrieve metrics from specified resources. Added filters can apply here as the interval of retrieving these metrics, metric names,
aggregation list, namespaces and metric dimensions. The monitor metrics will have a minimum timegrain of 5 minutes, so the `period` for `monitor` dataset should be `300s` or multiples of `300s`.

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


`compute_vm`
This data stream will collect metrics from the virtual machines, these metrics will have a timegrain every 5 minutes,
so the `period` for `compute_vm` should be `300s` or multiples of `300s`.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| azure.application_id | The application ID | keyword |  |
| azure.compute_vm.\*.\* | Returned compute_vm metrics | object | gauge |
| azure.dimensions.cpu | Cpu core on the linux instance | keyword |  |
| azure.dimensions.device | Name of the device of the linux instance, eg. sda2 | keyword |  |
| azure.dimensions.host | Name of the linux host | keyword |  |
| azure.dimensions.interface | Name of the network interface on the linux instance | keyword |  |
| azure.dimensions.name | Name of the device of the linux instance | keyword |  |
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


`compute_vm_scaleset`
This data stream will collect metrics from the virtual machine scalesets, these metrics will have a timegrain every 5 minutes,
so the `period` for `compute_vm_scaleset` should be `300s` or multiples of `300s`.

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


 `storage_account`
This data stream will collect metrics from the storage accounts, these metrics will have a timegrain every 5 minutes,
so the `period` for `storage_account` should be `300s` or multiples of `300s`.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| azure.application_id | The application ID | keyword |  |
| azure.dimensions.api_name | The name of operation. | keyword |  |
| azure.dimensions.authentication | Authentication type used in transactions like OAuth. | keyword |  |
| azure.dimensions.blob_type | Specifies the type of a blob. | keyword |  |
| azure.dimensions.file_share | Specifies file share. | keyword |  |
| azure.dimensions.geo_type | Transaction from Primary or Secondary cluster. The available values include Primary and Secondary. | keyword |  |
| azure.dimensions.response_type | Transaction response type like Success, ClientOtherError, etc. | keyword |  |
| azure.dimensions.tier | Specifies access tier. | keyword |  |
| azure.dimensions.transaction_type | Type of transaction. The available values include User and System. | keyword |  |
| azure.metrics.\*.\* | Metrics returned. | object |  |
| azure.namespace | The namespace selected | keyword |  |
| azure.resource.group | The resource group | keyword |  |
| azure.resource.id | The id of the resource | keyword |  |
| azure.resource.name | The name of the resource | keyword |  |
| azure.resource.tags.\* | Azure resource tags. | object |  |
| azure.resource.type | The type of the resource | keyword |  |
| azure.storage_account.\*.\* | storage account | object | gauge |
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


`container_instance`
This data stream will collect metrics from specified container groups, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_instance` should be `300s` or multiples of `300s`.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| azure.application_id | The application ID | keyword |  |  |
| azure.container_instance.cpu_usage.avg | CPU usage on all cores in millicores. | float |  | gauge |
| azure.container_instance.memory_usage.avg | Total memory usage in byte. | float | byte | gauge |
| azure.container_instance.network_bytes_received_per_second.avg | The network bytes received per second. | float | byte | gauge |
| azure.container_instance.network_bytes_transmitted_per_second.avg | The network bytes transmitted per second. | float | byte | gauge |
| azure.dimensions.container_name | The container name | keyword |  |  |
| azure.metrics.cpu_usage.avg |  | alias |  |  |
| azure.metrics.memory_usage.avg |  | alias |  |  |
| azure.metrics.network_bytes_received_per_second.avg |  | alias |  |  |
| azure.metrics.network_bytes_transmitted_per_second.avg |  | alias |  |  |
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


`container_registry`
This data stream will collect metrics from the container registries, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_registry` should be `300s` or multiples of `300s`.

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


`container_service`
This data stream will collect metrics from the container services, these metrics will have a timegrain every 5 minutes,
so the `period` for `container_service` should be `300s` or multiples of `300s`.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| azure.application_id | The application ID | keyword |  |
| azure.container_service.kube_node_status_allocatable_cpu_cores.avg | Total number of available cpu cores in a managed cluster | float | gauge |
| azure.container_service.kube_node_status_allocatable_memory_bytes.avg | Total amount of available memory in a managed cluster | float | gauge |
| azure.container_service.kube_node_status_condition.avg | Statuses for various node conditions | float | gauge |
| azure.container_service.kube_pod_status_phase.avg | Number of pods by phase | float | gauge |
| azure.container_service.kube_pod_status_ready.avg | Number of pods in Ready state | float | gauge |
| azure.dimensions.condition | Pod or Node conditions | keyword |  |
| azure.dimensions.namespace | Pod namespace | keyword |  |
| azure.dimensions.node | Node name | keyword |  |
| azure.dimensions.phase | Pod phase | keyword |  |
| azure.dimensions.pod | Pod name | keyword |  |
| azure.dimensions.status | Statuses for various node conditions | keyword |  |
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


`database_account`
This data stream will collect relevant metrics from specified database accounts, these metrics will have a timegrain every 5 minutes,
so the `period` for `database_account` should be `300s` or multiples of `300s`.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| azure.application_id | The application ID | keyword |  |
| azure.database_account.\*.\* | database account | object | gauge |
| azure.dimensions.closure_reason | Reason of the Cassandra Connection Closures | keyword |  |
| azure.dimensions.command_name | Mongo requests command name | keyword |  |
| azure.dimensions.database_name | Database name | keyword |  |
| azure.dimensions.resource_name | Name of the resource | keyword |  |
| azure.dimensions.status_code | Status code of the made to database requests | keyword |  |
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

