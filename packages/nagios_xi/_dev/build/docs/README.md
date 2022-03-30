# Nagios XI

The Nagios XI integration is used to fetch observability data from [Nagios XI](https://www.nagios.org/documentation/) and ingest it into Elasticsearch.

## Compatibility

This Integration has been tested against `Nagios-XI Version: 5.8.7`

## Requirements

In order to ingest data from Nagios XI:
- You must know the host for Nagios XI, add that host while configuring the integration package.

## Metrics

### Host Metrics

This is the `host` dataset.

- This dataset gives Nagios XI Host Round Trip Travel Time (rta) and Packet Loss (pl) metrics.

{{event "host"}}

{{fields "host"}}
