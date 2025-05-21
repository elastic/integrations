# NGINX metrics from Opentelemtry Collector 

The NGINX metrics from NGINX OTEL integration allows you to monitor [Nginx](https://nginx.org/), a high-performance web server, reverse proxy, and load balancer. NGINX is widely used for serving web content, proxying traffic, and load balancing across multiple servers.

Use the NGINX metrics OTEL integration to collect and analyze performance metrics from your NGINX instances. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting performance issues.

For example, if you wanted to monitor the request rate or connection status of your NGINX server, you could use this integration to collect metrics such as `nginx.requests` or `nginx.connections_current`. Then you can visualize these metrics in Kibana dashboards, set up alerts for high error rates, or troubleshoot by analyzing metric trends.


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

1. System compatibility: The integration is compatible with systems running the EDOT Collector and NGINX with the stub_status module enabled.

2. Supported versions: NGINX versions that support the stub_status module.

3. Permissions needed: The EDOT Collector requires access to the NGINX stub_status endpoint (e.g., http://localhost:80/nginx_status). Ensure the user running the collector has appropriate permissions to access this endpoint.

4. NGINX configuration: The NGINX `stub_status` module must be enabled, and the status endpoint must be accessible. For example:
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

2. Install and configure the standalone EDOT Collector or Elastic Agent. 

3. Configure the EDOT Collector config to export metrics to Elasticsearch. Example Config:

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
Use this config to run the EDOT Collector.


## Metrics Reference

NGINX Metrics
The nginx metrics data stream provides metrics from the NGINX stub_status module, including request counts, connection statistics, and server zone metrics (for NGINX Plus). The metrics include the following types








