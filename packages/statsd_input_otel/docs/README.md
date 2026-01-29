# StatsD OpenTelemetry Input Package

## Overview
The StatsD OpenTelemetry Input Package for Elastic enables collection of metrics from StatsD-compatible applications through OpenTelemetry protocols using the [statsdreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/statsdreceiver#statsd-receiver).


### How it works
This package receives telemetry data from StatsD-compatible applications by configuring the StatsD endpoint in the Input Package, which then gets applied to the statsdreceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.

The StatsD receiver listens on a UDP (default), TCP, or Unix socket endpoint for incoming StatsD messages and parses them into OTLP equivalent metric representations.


### Supported metric types

**Counter (c)**
:   Measurement which accumulates over period of time until flushed.

**Gauge (g)**
:   Measurement which can increase, decrease or be set to a value.

**Timer (ms)**
:   Time measurement (in milliseconds) of an event.

**Histogram (h)**
:   Time measurement, alias for timer.


### Supported tag extensions

The StatsD receiver supports the following tag formats:

**DogStatsD**
`<metric name>:<value>|<type>|@<sample-rate>|#<tag-key>:<tag-value>,<tag-key>:<tag-value>`

**InfluxDB**
`<metric name>,<tag-key>=<tag-value>,<tag-key>=<tag-value>:<value>|<type>|@<sample-rate>`

**Graphite 1.1.x**
`<metric name>;<tag-key>=<tag-value>;<tag-key>=<tag-value>:<value>|<type>|@<sample-rate>`


## Configuration options

**Endpoint**
:   Address and port to listen on. Default is `localhost:8125` for UDP and TCP transports.

**Transport Protocol**
:   Protocol used by the StatsD server. Supported values are `udp` (default), `tcp`, and `unixgram`.

**Aggregation Interval**
:   The aggregation time that the receiver aggregates the metrics, similar to the flush interval in StatsD server. Default is `60s`.

**Enable Metric Type**
:   When enabled, emits the StatsD metric type (gauge, counter, timer, histogram) as a label on the metric.

**Monotonic Counter**
:   When enabled, sets all counter metrics as monotonic.


## Metrics reference
For a complete list of all available metrics and their detailed descriptions, refer to the [StatsD Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/statsdreceiver) in the upstream OpenTelemetry Collector repository.
