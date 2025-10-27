# NGINX OpenTelemetry Input Package 

## Overview
The NGINX OpenTelemetry Input Package integration for Elastic enables collection of telemetry data from NGINX web servers through OpenTelemetry protocols using the [nginxreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/nginxreceiver#nginx-receiver).

This integration facilitates comprehensive monitoring of NGINX web server performance, request processing, error tracking, and operational metrics to provide insights into web application infrastructure health and performance.

### Compatibility
 This Integration uses the upstream [nginxreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/nginxreceiver#nginx-receiver) to collect the metrics. 

### How it works
This integration receives telemetry data from NGINX servers by configuring the NGINX endpoint in the integration, which then gets applied to the nginxreceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis. Once the data arrives into Elasticsearch, its corresponding [NGINX OpenTelemetry Assets Package](https://www.elastic.co/docs/reference/integrations/nginx_otel) gets auto installed and the dashboards light up.

## What data does this integration collect?
The NGINX OpenTelemetry Input Package integration collects telemetry data of the following types:

* **Metrics** - Performance metrics including request rates, response times, connection counts, and server status


## What do I need to use this integration?
1. Permissions required: The collector requires access to the NGINX `stub_status` endpoint (for example, http://localhost:80/nginx_status). When running the collector, make sure you have the appropriate permissions to access this endpoint.

2. NGINX configuration: The NGINX `stub_status` module must be enabled, and the status endpoint must be accessible. For example:
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
3. The NGINX endpoint configured in the Integration configuration from the UI. 


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