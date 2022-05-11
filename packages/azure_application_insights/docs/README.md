# Azure Application Insights Integration

The Application Insights Integration allows users to retrieve application insights metrics from specified applications.

### Integration level configuration options

`Application ID`:: (_[]string_) ID of the application. This is Application ID from the API Access settings blade in the Azure portal.

`Api Key`:: (_[]string_) The API key which will be generated, more on the steps here https://dev.applicationinsights.io/documentation/Authorization/API-key-and-App-ID.


The integration contains the following data streams:

### app_insights
Users can retrieve any application insights metrics and make use of the filters below in order to concentrate on the type of data they want to collect.


#### Configuration options

`Metrics`:: List of different metrics to collect information

`id`:: (_[]string_) IDs of the metrics that's being reported. Usually, the id is descriptive enough to help identify what's measured.
A list of metric names can be entered as well. 
Default metrics include a curated selection of requests counters, performance, and service availability. 
The list of options can be found here https://docs.microsoft.com/en-us/rest/api/application-insights/metrics/get#metricid

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

Costs: Metric queries are charged based on the number of standard API calls. More information on pricing here https://azure.microsoft.com/en-us/pricing/details/monitor/.


An example event for `app_insights` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "d979a8cf-ddeb-458f-9019-389414e0ab47",
        "ephemeral_id": "4162d5df-ab00-4c1b-b4f3-7db2e3b599d4",
        "type": "metricbeat",
        "version": "7.15.0"
    },
    "elastic_agent": {
        "id": "d979a8cf-ddeb-458f-9019-389414e0ab47",
        "version": "7.15.0",
        "snapshot": true
    },
    "cloud": {
        "provider": "azure"
    },
    "@timestamp": "2021-08-23T14:37:42.268Z",
    "ecs": {
        "version": "1.12.0"
    },
    "service": {
        "type": "azure"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "azure.app_insights"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "4.19.128-microsoft-standard",
            "codename": "Core",
            "name": "CentOS Linux",
            "family": "redhat",
            "type": "linux",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "192.168.96.7"
        ],
        "name": "docker-fleet-agent",
        "id": "1642d255f9a32fc6926cddf21bb0d5d3",
        "mac": [
            "02:42:c0:a8:60:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 300000,
        "name": "app_insights"
    },
    "event": {
        "duration": 503187300,
        "agent_id_status": "verified",
        "ingested": "2021-08-23T14:37:41Z",
        "module": "azure",
        "dataset": "azure.app_insights"
    },
    "azure": {
        "app_insights": {
            "end_date": "2021-08-23T14:37:42.268Z",
            "start_date": "2021-08-23T14:32:42.268Z"
        },
        "metrics": {
            "requests_count": {
                "sum": 4
            }
        },
        "application_id": "42cb59a9-d5be-400b-a5c4-69b0a0026ac6",
        "dimensions": {
            "request_name": "GET Home/Index",
            "request_url_host": "demoappobs.azurewebsites.net"
        }
    }
}
```

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
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.cpu.usage | Percent CPU used which is normalized by the number of CPU cores and it ranges from 0 to 1. Scaling factor: 1000. For example: For a two core host, this value should be the average of the two cores, between 0 and 1. | scaled_float |
| host.disk.read.bytes | The total number of bytes (gauge) read successfully (aggregated from all disks) since the last metric collection. | long |
| host.disk.write.bytes | The total number of bytes (gauge) written successfully (aggregated from all disks) since the last metric collection. | long |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.geo.city_name | City name. | keyword |
| host.geo.continent_code | Two-letter code representing continent's name. | keyword |
| host.geo.continent_name | Name of the continent. | keyword |
| host.geo.country_iso_code | Country ISO code. | keyword |
| host.geo.country_name | Country name. | keyword |
| host.geo.location | Longitude and latitude. | geo_point |
| host.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| host.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| host.geo.region_iso_code | Region ISO code. | keyword |
| host.geo.region_name | Region name. | keyword |
| host.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.network.egress.bytes | The number of bytes (gauge) sent out on all network interfaces by the host since the last metric collection. | long |
| host.network.egress.packets | The number of packets (gauge) sent out on all network interfaces by the host since the last metric collection. | long |
| host.network.ingress.bytes | The number of bytes received (gauge) on all network interfaces by the host since the last metric collection. | long |
| host.network.ingress.packets | The number of packets (gauge) received on all network interfaces by the host since the last metric collection. | long |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.full.text | Multi-field of `host.os.full`. | match_only_text |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. One of these following values should be used (lowercase): linux, macos, unix, windows. If the OS you're dealing with is not in the list, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| host.uptime | Seconds the host has been up. | long |
| service.address | Service address | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |








