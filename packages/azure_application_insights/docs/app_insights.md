# Azure Application Insights Integration

The Application Insights Integration allows users to retrieve application insights metrics from specified applications.

### Integration level configuration options

`Application ID`:: (_[]string_) ID of the application. This is Application ID from the API Access settings blade in the Azure portal.

`Api Key`:: (_[]string_) The API key which will be generated, more on the steps here https://dev.applicationinsights.io/documentation/Authorization/API-key-and-App-ID.


#### Configuration options

`Metrics`:: List of different metrics to collect information

`id`:: (_[]string_) IDs of the metrics that's being reported. Usually, the id is descriptive enough to help identify what's measured.
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


## Additional notes about metrics and costs

Costs: Metric queries are charged based on the number of standard API calls. More information on pricing here https://azure.microsoft.com/en-us/pricing/details/monitor/.


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







