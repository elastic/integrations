# NGINX OpenTelemetry Input Package 

## Overview
The NGINX OpenTelemetry Input Package for Elastic enables collection of telemetry data from NGINX web servers through OpenTelemetry protocols using the [nginxreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/nginxreceiver#nginx-receiver).


### How it works
This package receives telemetry data from NGINX servers by configuring the NGINX endpoint in the Input Package, which then gets applied to the nginxreceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis. Once the data arrives into Elasticsearch, its corresponding [NGINX OpenTelemetry Assets Package](https://www.elastic.co/docs/reference/integrations/nginx_otel) gets auto installed and the dashboards light up.



## Metrics reference
For a complete list of all available metrics and their detailed descriptions, refer to the [NGINX Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/nginxreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.