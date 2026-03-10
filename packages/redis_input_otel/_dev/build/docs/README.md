# Redis OpenTelemetry Input Package 

## Overview
The Redis OpenTelemetry Input Package for Elastic enables collection of telemetry data from Redis database servers through OpenTelemetry protocols using the [redisreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/redisreceiver).


### How it works
This package receives telemetry data from Redis servers by configuring the Redis endpoint and credentials in the Input Package, which then gets applied to the redisreceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.


## Configuration

For the full list of settings exposed for the receiver and examples, refer to the [configuration](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/redisreceiver#configuration) section.



## Metrics reference
For a complete list of all available metrics and their detailed descriptions, refer to the [Redis Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/redisreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.
