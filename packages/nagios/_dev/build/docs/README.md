# Nagios

The Nagios integration is used to fetch observability data from [Nagios](https://www.nagios.org/documentation/) and ingest it into Elasticsearch.

## Compatibility

This module has been tested against `nagios-xi Version: 5.8.7`

## Requirements

In order to ingest data from Nagios:
- You must know the host for Nagios, add that host while configuring the integration package.

## Logs

### Logs logs

This is the `logs` dataset.

- This dataset gives Nagios system logs.

{{event "logs"}}

{{fields "logs"}}

## Metrics

### Host Metrics

This is the `host` dataset.

- This dataset gives Host Round Trip Travel Time (rta) and Packet Loss (pl) metrics.

{{event "host"}}

{{fields "host"}}

### Service Metrics

This is the `service` dataset.

- This dataset gives services current load, current users, ping, http, ssh, root partition, swap users and total processes metrics.

{{event "service"}}

{{fields "service"}}
