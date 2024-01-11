# OTEL Nginx Metrics

Use the OTEL Nginx Metrics integration to {purpose}. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference {data stream type} when troubleshooting an issue.

For example, if you wanted to {sample use case} you could {action}. Then you can {visualize|alert|troubleshoot} by {action}. -->

## Data streams

Collect Nginx Stubstatus metrics from Open Telemetry.

The fields for OTEL metrics is listed below:

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| nginx.connections_accepted | The total number of accepted client connections | long | gauge |
| nginx.connections_current | The current number of nginx connections by state | long | gauge |
| nginx.connections_handled | The total number of handled connections. Generally, the parameter value is the same as accepts unless some resource limits have been reached (for example, the worker_connections limit). | long | gauge |
| nginx.hostname | Nginx hostname. | keyword |  |
| nginx.requests | Total number of requests made to the server since it started | long | gauge |
