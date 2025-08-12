# NGINX metrics from OpenTelemetry Collector 

The NGINX metrics from NGINX OTEL integration allows you to monitor [Nginx](https://nginx.org/), a high-performance web server, reverse proxy, and load balancer. NGINX is widely used for serving web content, proxying traffic, and load balancing across multiple servers.

Use the NGINX OTEL integration to analyze performance metrics from your NGINX instances. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting performance issues.

For example, if you want to monitor the request rate or connection status of your NGINX server, you can use [NGINX Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/nginxreceiver#nginx-receiver) to collect metrics such as `nginx.requests` or `nginx.connections_current`, and then the NGINX OTEL integration to visualize these metrics in Kibana dashboards, set up alerts for high error rates, or troubleshoot by analyzing metric trends.


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

1. Compatibility and supported versions: This integration is compatible with systems running either [EDOT Collector](https://www.elastic.co/docs/reference/opentelemetry/quickstart/) or vanilla upstream Collector and NGINX with the `stub_status` module enabled. This integration has been tested with OTEL collector version [v0.129.0](https://github.com/open-telemetry/opentelemetry-collector/tree/v0.129.0), EDOT collector version [9.0](https://www.elastic.co/docs/reference/opentelemetry/compatibility/collectors), and NGINX version 1.27.5. 

2. Permissions required: The collector requires access to the NGINX `stub_status` endpoint (for example, http://localhost:80/nginx_status). When running the collector, make sure you have the appropriate permissions to access this endpoint.

3. NGINX configuration: The NGINX `stub_status` module must be enabled, and the status endpoint must be accessible. For example:
```
server {
    listen 80;
    server_name localhost;
    location /nginx_status {
        stub_status on;
        allow 127.0.0.1;
        deny all;
    }
}
```


## Setup

1. Make sure the NGINX `stub_status` module is enabled and the status endpoint is accessible.

2. Install and configure the EDOT Collector or upstream Collector to export metrics to Elasticsearch, as shown in the following example:

```
receivers:
  nginx:  
    endpoint: "http://localhost:8085/nginx_status"
    collection_interval: 10s
processors:
  resourcedetection:
    detectors: ["system", "ec2"]
exporters:
  debug:
    verbosity: detailed
  elasticsearch/otel:
    endpoints: https://localhost:9200
    user: <userid>
    password: <pwd>
    mapping:
      mode: otel 
    metrics_dynamic_index:
      enabled: true
service:
  pipelines:
    metrics:
      receivers: [nginx]
      processors: [resourcedetection]
      exporters: [debug, elasticsearch/otel]
```
Use this configuration to run the collector.

The `resourcedetection` processor is required to get the host information for the dashboard.

## Metrics reference

### NGINX metrics
The [NGINX receiver]((https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/nginxreceiver/documentation.md)) collects performance metrics from the NGINX `stub_status` module. Key metrics include:


| Metric Name | Description | Type | Attributes |
|-------------|-------------|------|------------|
| `nginx.requests` | Total number of client requests | Counter | - |
| `nginx.connections_accepted` | Total number of accepted client connections | Counter | - |
| `nginx.connections_handled` | Total number of handled connections | Counter | - |
| `nginx.connections_current` | Current number of client connections by state | Gauge | `state`: `active`, `reading`, `writing`, `waiting` |

#### Connection States

- `active`: Currently active client connections
- `reading`: Connections currently reading request headers
- `writing`: Connections currently writing response to client  
- `waiting`: Idle client connections waiting for a request

These metrics provide insights into:
- **Request volume and patterns** through request counts
- **Connection health** via accepted, and handled connection statistics  
- **Server performance** using active, reading, writing, and waiting connection states

For a complete list of all available metrics and their detailed descriptions, refer to the [NGINX Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/nginxreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.








