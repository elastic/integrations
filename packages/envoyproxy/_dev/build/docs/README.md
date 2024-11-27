# Envoy Proxy

This integration is for Envoy proxy [access logs](https://www.envoyproxy.io/docs/envoy/v1.10.0/configuration/access_log) and [statsd metrics](https://www.envoyproxy.io/docs/envoy/latest/operations/stats_overview). It supports both standalone deployment and Envoy proxy deployment in Kubernetes.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Requires version ^8.15.0 of Elastic Agent

## Compatibility

This integration was tested using Envoy proxy version 1.32.1

## Setup

### Logs

Update `paths` in the integration configuration to the location of your envoyproxy logs if access logs are not being written to `/var/log/envoy.log` (default location).

For Kubernetes deployment see [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-kubernetes-autodiscovery.html) for autodiscovery with Elastic Agent.

### Stats

Add the following to your envoy configuration and set `address` to the IP address of the Elastic Agent running this integration.

> NOTE: Hostnames are not supported by Envoy and must use the IP address where Elastic Agent is installed

```yaml
stats_sinks:
  - name: graphite_statsd
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.stat_sinks.graphite_statsd.v3.GraphiteStatsdSink
      address:
        socket_address:
          address: 127.0.0.1 # Replace with the IP of elastic-agent
          port_value: 8125
```

## Logs reference

{{event "log"}}

{{fields "log"}}

## Stats reference

{{event "stats"}}

{{fields "stats"}}
