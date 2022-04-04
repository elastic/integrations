# Nagios XI

The Nagios XI integration is used to fetch observability data from [Nagios XI](https://www.nagios.org/documentation/) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Nagios-XI Version: 5.8.7`

## Requirements

In order to ingest data from Nagios XI:
- You must know the host for Nagios XI, add that host while configuring the integration package.

## Logs

### Event Logs 

This is the `events` data stream.

- This data stream gives Nagios XI system event logs.

{{event "events"}}

{{fields "events"}}

## Metrics

### Host Metrics

This is the `host` data stream.

- This data stream gives Nagios XI Host Round Trip Travel Time (rta) and Packet Loss (pl) metrics.

{{event "host"}}

{{fields "host"}}
