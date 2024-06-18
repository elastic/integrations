# Azure Application Insights Integration

The [Application Insights](https://docs.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview) Integration allows users to retrieve application insights metrics from specified applications.  

### Integration level configuration options

`Application ID`:: (_[]string_) ID of the application. This is Application ID from the API Access settings blade in the Azure portal.

`Api Key`:: (_[]string_) The API key which will be generated. See [Azure Monitor Log Analytics API Overview](https://dev.applicationinsights.io/documentation/Authorization/API-key-and-App-ID) for more information.


The integration contains the following data streams:

### app_insights
Users can retrieve any application insights metrics and make use of the filters below in order to concentrate on the type of data they want to collect.


#### Configuration options

`Metrics`:: List of different metrics to collect information

`id`:: (_[]string_) IDs of the metrics that's being reported. Usually, the id is descriptive enough to help identify what's measured.
A list of metric names can be entered as well. 
Default metrics include a curated selection of requests counters, performance, and service availability.  See the [Microsoft Azure Metrics web page](https://docs.microsoft.com/en-us/rest/api/application-insights/metrics/get#metricid) for a list of the available options.

`interval`:: (_string_) The time interval to use when retrieving metric values. This is an ISO8601 duration.
If interval is omitted, the metric value is aggregated across the entire timespan.
If interval is supplied, the result may adjust the interval to a more appropriate size based on the timespan used for the query.

`aggregation`:: (_[]string_) The aggregation to use when computing the metric values.
To retrieve more than one aggregation at a time, separate them with a comma.
If no aggregation is specified, then the default aggregation for the metric is used.

`segment`:: (_[]string_) The name of the dimension to segment the metric values by.
This dimension must be applicable to the metric you are retrieving.
In this case, the metric data will be segmented in the order the dimensions are listed in the parameter.

`top`:: (_int_) The number of segments to return. This value is only valid when segment is specified.

`order_by`:: (_string_) The aggregation function and direction to sort the segments by.
This value is only valid when segment is specified.

`filter`:: (_string_) An expression used to filter the results.
This value should be a valid OData filter expression where the keys of each clause should be applicable dimensions for the metric you are retrieving.

Example configuration:

```
 - id: ["requests/count", "requests/failed"]
   segment: "request/name"
   aggregation: ["sum"]
```


### app_state
Will retrieve application related state metrics.


## Additional notes about metrics and costs

Costs: Metric queries are charged based on the number of standard API calls. See [Azure Monitor pricing](https://azure.microsoft.com/en-us/pricing/details/monitor/) for more information. 


An example event for `app_insights` looks as following:

```json
{
    "@timestamp": "2021-08-23T14:37:42.268Z",
    "agent": {
        "ephemeral_id": "4162d5df-ab00-4c1b-b4f3-7db2e3b599d4",
        "hostname": "docker-fleet-agent",
        "id": "d979a8cf-ddeb-458f-9019-389414e0ab47",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "7.15.0"
    },
    "azure": {
        "app_insights": {
            "end_date": "2021-08-23T14:37:42.268Z",
            "start_date": "2021-08-23T14:32:42.268Z"
        },
        "application_id": "42cb59a9-d5be-400b-a5c4-69b0a0026ac6",
        "dimensions": {
            "request_name": "GET Home/Index",
            "request_url_host": "demoappobs.azurewebsites.net"
        },
        "metrics": {
            "requests_count": {
                "sum": 4
            }
        }
    },
    "cloud": {
        "provider": "azure"
    },
    "data_stream": {
        "dataset": "azure.app_insights",
        "namespace": "default",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d979a8cf-ddeb-458f-9019-389414e0ab47",
        "snapshot": true,
        "version": "7.15.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "azure.app_insights",
        "duration": 503187300,
        "ingested": "2021-08-23T14:37:41Z",
        "module": "azure"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "1642d255f9a32fc6926cddf21bb0d5d3",
        "ip": [
            "192.168.96.7"
        ],
        "mac": [
            "02:42:c0:a8:60:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "4.19.128-microsoft-standard",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "metricset": {
        "name": "app_insights",
        "period": 300000
    },
    "service": {
        "type": "azure"
    }
}
```

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








