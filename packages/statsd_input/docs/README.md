# StatsD input

The `statsd input package` spawns a UDP server and listens for metrics in StatsD compatible format.
The user can use this input for any service that collects metrics through the StatsD endpoint. The user has the flexibility to provide custom mappings and custom ingest pipelines through the Kibana UI to get the tailored data.

## Metric types

The input supports the following types of metrics:

**Counter (c)**:: Measurement which accumulates over a period of time until flushed (value set to 0).

**Gauge (g)**:: Measurement which can increase, decrease or be set to a value.

**Timer (ms)**:: Time measurement (in milliseconds) of an event.

**Histogram (h)**:: Time measurement, an alias for the *Timer*.

**Set (s)***:: Measurement which counts unique occurrences until flushed (value set to 0).


## Compatibility

Node.js version v18.12.1 is used to test the Statsd input package 
