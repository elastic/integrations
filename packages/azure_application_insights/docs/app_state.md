# Azure Application State Integration

The Application State Integration allows users to retrieve application insights state related metrics from specified applications.

### Integration level configuration options

`Application ID`:: (_[]string_) ID of the application. This is Application ID from the API Access settings blade in the Azure portal.

`Api Key`:: (_[]string_) The API key which will be generated, more on the steps here https://dev.applicationinsights.io/documentation/Authorization/API-key-and-App-ID.


## Additional notes about metrics and costs

Costs: Metric queries are charged based on the number of standard API calls. More information on pricing here https://azure.microsoft.com/en-us/pricing/details/monitor/.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.app_state.browser_timings_network_duration.avg | Browser timings network duration | float |
| azure.app_state.browser_timings_processing_duration.avg | Browser timings processing duration | float |
| azure.app_state.browser_timings_receive_uration.avg | Browser timings receive duration | float |
| azure.app_state.browser_timings_send_duration.avg | Browser timings send duration | float |
| azure.app_state.browser_timings_total_duration.avg | Browser timings total duration | float |
| azure.app_state.end_date | The end date | date |
| azure.app_state.exceptions_browser.sum | Exception count at browser level | float |
| azure.app_state.exceptions_count.sum | Exception count | float |
| azure.app_state.exceptions_server.sum | Exception count at server level | float |
| azure.app_state.performance_counters_memory_available_bytes.avg | Performance counters memory available bytes | float |
| azure.app_state.performance_counters_process_cpu_percentage.avg | Performance counters process cpu percentage | float |
| azure.app_state.performance_counters_process_cpu_percentage_total.avg | Performance counters process cpu percentage total | float |
| azure.app_state.performance_counters_process_private_bytes.avg | Performance counters process private bytes | float |
| azure.app_state.performance_counters_processiobytes_per_second.avg | Performance counters process IO bytes per second | float |
| azure.app_state.requests_count.sum | Request count | float |
| azure.app_state.requests_failed.sum | Request failed count | float |
| azure.app_state.sessions_count.unique | Session count | float |
| azure.app_state.start_date | The start date | date |
| azure.app_state.users_authenticated.unique | Authenticated users count | float |
| azure.app_state.users_count.unique | User count | float |
| azure.application_id | The application ID | keyword |
| azure.dimensions.\* | Azure metric dimensions. | flattened |
| azure.metrics.\*.\* | Metrics returned. | object |
| azure.namespace | The namespace selected | keyword |
| azure.resource.group | The resource group | keyword |
| azure.resource.id | The id of the resource | keyword |
| azure.resource.name | The name of the resource | keyword |
| azure.resource.tags.\* | Azure resource tags. | flattened |
| azure.resource.type | The type of the resource | keyword |
| azure.subscription_id | The subscription ID | keyword |
| azure.timegrain | The Azure metric timegrain | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Service address | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |








