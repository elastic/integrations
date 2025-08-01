# NGINX metrics from Opentelemtry Collector 

The NGINX metrics from NGINX OTEL integration allows you to monitor [Nginx](https://nginx.org/), a high-performance web server, reverse proxy, and load balancer. NGINX is widely used for serving web content, proxying traffic, and load balancing across multiple servers.

Use the NGINX OTEL integration to analyze performance metrics from your NGINX instances. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting performance issues.

For example, if you want to monitor the request rate or connection status of your NGINX server, you can use [NGINX Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/nginxreceiver#nginx-receiver) to collect metrics such as `nginx.requests` or `nginx.connections_current`, and then the NGINX OTEL integration to visualize these metrics in Kibana dashboards, set up alerts for high error rates, or troubleshoot by analyzing metric trends.


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

1. Compatibility and supported versions: This integration is compatible with systems running either [EDOT Collector](https://www.elastic.co/docs/reference/opentelemetry/quickstart/) or vanilla upstream Collector and NGINX with the `stub_status` module enabled. This integration has been tested with OTEL collector version v0.129.0, EDOT collector version 9.x, and NGINX version 1.27.5. 

2. Permissions needed: The Collector requires access to the NGINX stub_status endpoint (e.g., http://localhost:80/nginx_status). Ensure the user running the collector has appropriate permissions to access this endpoint.

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

1. Ensure the NGINX stub_status module is enabled and the status endpoint is accessible.

2. Install and configure the EDOT Collector or upstream Collector to export metrics to Elasticsearch. Example Config:

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
Use this config to run the Collector.

The resourcedetection processor is required to get the host information for the dashboard.

## Metrics Reference

### NGINX Metrics
The [NGINX receiver]((https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/nginxreceiver/documentation.md)) collects performance metrics from the NGINX stub_status module. Key metrics include:

| Metric Name | Description | Type |
|-------------|-------------|------|
| `nginx.requests` | Total number of client requests | Counter |
| `nginx.connections_active` | Current number of active client connections | Gauge |
| `nginx.connections_accepted` | Total number of accepted client connections | Counter |
| `nginx.connections_handled` | Total number of handled connections | Counter |
| `nginx.connections_reading` | Current number of connections reading request headers | Gauge |
| `nginx.connections_writing` | Current number of connections writing response to client | Gauge |
| `nginx.connections_waiting` | Current number of idle client connections waiting for a request | Gauge |

These metrics provide insights into:
- **Request volume and patterns** through request counts
- **Connection health** via active, accepted, and handled connection statistics  
- **Server performance** using reading, writing, and waiting connection states

For a complete list of all available metrics and their detailed descriptions, refer to the [NGINX Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/nginxreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.








