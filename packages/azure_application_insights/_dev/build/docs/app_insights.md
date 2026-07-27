# Configure Azure Application Insights Integration

The Application Insights Integration allows users to retrieve application insights metrics from specified applications.

### Integration level configuration options

`Application ID`:: (_[]string_) ID of the application. This is Application ID from the API Access settings blade in the Azure portal.

`Authentication Type`:: (_string_) Optional. The authentication method to use. Accepted values: `api_key` or `client_secret`. Defaults to `client_secret` if not set.

`Api Key`:: (_string_) Optional. The API key used for authentication when `auth_type` is set to `api_key`. More on the steps here https://dev.applicationinsights.io/documentation/Authorization/API-key-and-App-ID.

`Client ID`:: (_string_) Optional. The client (application) ID of the Entra ID application. Required when `auth_type` is `client_secret`.

`Client Secret`:: (_string_) Optional. The client secret of the Entra ID application. Required when `auth_type` is `client_secret`.

`Tenant ID`:: (_string_) Optional. The tenant (directory) ID of the Entra ID tenant. Required when `auth_type` is `client_secret`.


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


{{event "app_insights"}}







