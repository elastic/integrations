# IIS OpenTelemetry Input Package 

## Overview
The IIS OpenTelemetry Input Package for Elastic enables collection of telemetry data from Internet Information Services (IIS) web servers through OpenTelemetry protocols using the [iisreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/iisreceiver#iis-receiver).


### How it works
This package receives telemetry data from IIS servers by configuring the IIS receiver in the Input Package, which then gets applied to the iisreceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis. Once the data arrives into Elasticsearch, its corresponding [IIS OpenTelemetry Assets Package](https://www.elastic.co/docs/reference/integrations/iis_otel) gets auto installed and the dashboards light up.



## Metrics reference
For a complete list of all available metrics and their detailed descriptions, refer to the [IIS Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/iisreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.
