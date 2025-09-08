# StatsD input

## Overview

The `statsd input package` spawns a UDP server and listens for metrics in StatsD compatible format.
This input can be used to collect metrics from services that send data over the StatsD protocol. To tailor the data you can provide custom mappings and ingest pipelines through Kibana.

### Compatibility

#### Metric types

The input supports the following types of metrics:

**Counter (c)**
:   Measurement which accumulates over period of time until flushed (value set to 0).

**Gauge (g)**
:   Measurement which can increase, decrease or be set to a value.

**Timer (ms)**
:   Time measurement (in milliseconds) of an event.

**Histogram (h)**
:   Time measurement, alias for timer.

**Set (s)**
:   Measurement which counts unique occurrences until flushed (value set to 0).

#### Supported tag extensions

Example of tag styles supported by the `statsd` input:

[DogStatsD](https://docs.datadoghq.com/developers/dogstatsd/datagram_shell/?tab=metrics#the-dogstatsd-protocol)

`<metric name>:<value>|<type>|@samplerate|#<k>:<v>,<k>:<v>`

[InfluxDB](https://github.com/influxdata/telegraf/blob/master/plugins/inputs/statsd/README.md#influx-statsd)

`<metric name>,<k>=<v>,<k>=<v>:<value>|<type>|@samplerate`

[Graphite_1.1.x](https://graphite.readthedocs.io/en/latest/tags.html#graphite-tag-support)

`<metric name>;<k>=<v>;<k>=<v>:<value>|<type>|@samplerate`

## What data does this integration collect?

The StatsD input integration collects one type of data streams: metrics.

## What do I need to use this integration?

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## How do I deploy this integration?

For step-by-step instructions on how to set up an integration, check the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

### Configuration options

The `statsd` input has these additional configuration options:

**Listen Address and Listen Port**
:   Bind address and port for the UDP server to listen on.

**TTL**
:   It defines how long a metric will be reported after it was last recorded. Metrics are always reported at least once, regardless of the specified TTL. A TTL of zero indicates that the metrics never expire.

**StatsD metric mappings (Optional)**
:   It defines how metrics will be mapped from the original metric label to the event JSON. Here’s an example configuration:

```yaml
- metric: 'ti_failures' <1>
  value:
    field: task_failures <2>
- metric: '<job_name>_start' <1>
  labels:
    - attr: job_name <3>
      field: job_name <4>
  value:
    field: started <2>
```

1. `metric`, required: The label key of the metric in statsd, either as an exact match string, or as a template with named label placeholder in the format `<label_placeholder>`.
2. `value.field`, required: Field name where to save the metric value in the event JSON.
3. `label[].attr`, required when using the label placeholder: Reference to the label placeholder defined in `metric`.
4. `label[].field`, required when using the label placeholder field name where to save the label placeholder value from the template in the event JSON.

## Troubleshooting

General troubleshooting checklist (detailed steps depend on the environment):
- Ensure Elastic Agent is Running.
- Check that the Elastic Agent is listening on the specified UDP port.
- Inspect Network Connectivity and check firewall rules.
- Examine Elastic Agent logs.
- Ensure that the application or service sending metrics is correctly configured to point to the right UDP endpoint.

If the `nc` is available in the environment, a sample UDP packet with StatsD payload may be sent using `nc` to check if the configuration is correct and the document appears in Kibana:

```bash
# Replace "localhost" and "8125" with your values
echo "sample:1|g"  | nc -u -w0 localhost 8125
```

## Metrics reference

### Example

Provided that the elastic-agent with StatsD input integration is listening on `localhost:8125`, it is possible to send a UDP packet like the following one:

```bash
echo "python_gauge_foo:10|g"  | nc -u -w0 localhost 8125
```

The resulting event will look like this:

```json
{
    "@timestamp": "2024-06-19T06:26:36.664Z",
    "agent": {
        "ephemeral_id": "f9a3bc3e-14ed-4245-a140-38032ec3e459",
        "id": "b138c66d-6261-4eac-a652-7f30ea89bcfc",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "statsd_input.statsd",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "b138c66d-6261-4eac-a652-7f30ea89bcfc",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "statsd_input.statsd",
        "ingested": "2024-06-19T06:26:46Z",
        "module": "statsd"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.253.7"
        ],
        "mac": [
            "02-42-C0-A8-FD-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.102.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "labels": {},
    "metricset": {
        "name": "server"
    },
    "service": {
        "type": "statsd"
    },
    "statsd": {
        "python_gauge_foo": {
            "value": 10
        }
    }
}
```