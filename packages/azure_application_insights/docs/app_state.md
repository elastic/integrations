# Azure Application State Integration

The Application State Integration allows users to retrieve application insights state related metrics from specified applications.

### Integration level configuration options

`Application ID`:: (_[]string_) ID of the application. This is Application ID from the API Access settings blade in the Azure portal.

`Api Key`:: (_[]string_) The API key which will be generated, more on the steps here https://dev.applicationinsights.io/documentation/Authorization/API-key-and-App-ID.


## Additional notes about metrics and costs

Costs: Metric queries are charged based on the number of standard API calls. More information on pricing here https://azure.microsoft.com/en-us/pricing/details/monitor/.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| azure.app_state.browser_timings_network_duration.avg | Browser timings network duration | float | gauge |
| azure.app_state.browser_timings_processing_duration.avg | Browser timings processing duration | float | gauge |
| azure.app_state.browser_timings_receive_duration.avg | Browser timings receive duration | float | gauge |
| azure.app_state.browser_timings_send_duration.avg | Browser timings send duration | float | gauge |
| azure.app_state.browser_timings_total_duration.avg | Browser timings total duration | float | gauge |
| azure.app_state.end_date | The end date | date |  |
| azure.app_state.exceptions_browser.sum | Exception count at browser level | float | gauge |
| azure.app_state.exceptions_count.sum | Exception count | float | gauge |
| azure.app_state.exceptions_server.sum | Exception count at server level | float | gauge |
| azure.app_state.performance_counters_memory_available_bytes.avg | Performance counters memory available bytes | float | gauge |
| azure.app_state.performance_counters_process_cpu_percentage.avg | Performance counters process cpu percentage | float | gauge |
| azure.app_state.performance_counters_process_cpu_percentage_total.avg | Performance counters process cpu percentage total | float | gauge |
| azure.app_state.performance_counters_process_private_bytes.avg | Performance counters process private bytes | float | gauge |
| azure.app_state.performance_counters_processiobytes_per_second.avg | Performance counters process IO bytes per second | float | gauge |
| azure.app_state.requests_count.sum | Request count | float | gauge |
| azure.app_state.requests_failed.sum | Request failed count | float | gauge |
| azure.app_state.sessions_count.unique | Session count | float | gauge |
| azure.app_state.start_date | The start date | date |  |
| azure.app_state.users_authenticated.unique | Authenticated users count | float | gauge |
| azure.app_state.users_count.unique | User count | float | gauge |
| azure.application_id | The application ID | keyword |  |
| azure.dimensions.browser_timing_url_host | The host part of the URL that the browser was accessing when timings were captured. | keyword |  |
| azure.dimensions.browser_timing_url_path | The path part of the URL that the browser was accessing when timings were captured. | keyword |  |
| azure.dimensions.cloud_role_instance | The unique identifier of the cloud instance where the application is running. | keyword |  |
| azure.dimensions.cloud_role_name | The name of the role that the cloud instance is performing. | keyword |  |
| azure.dimensions.exception_type | The type of exception that was thrown. | keyword |  |
| azure.dimensions.request_name | The name of the request that was made. | keyword |  |
| azure.dimensions.request_url_host | The host part of the URL that was requested. | keyword |  |
| azure.namespace | The namespace selected | keyword |  |
| azure.resource.group | The resource group | keyword |  |
| azure.resource.id | The id of the resource | keyword |  |
| azure.resource.name | The name of the resource | keyword |  |
| azure.resource.tags | Azure resource tags. | flattened |  |
| azure.resource.type | The type of the resource | keyword |  |
| azure.subscription_id | The subscription ID | keyword |  |
| azure.timegrain | The Azure metric timegrain | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| data_stream.dataset | Data stream dataset name. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| dataset.name | Dataset name. | constant_keyword |  |
| dataset.namespace | Dataset namespace. | constant_keyword |  |
| dataset.type | Dataset type. | constant_keyword |  |
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |








