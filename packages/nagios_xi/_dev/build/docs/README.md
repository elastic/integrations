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

### Service Metrics

This is the `service` dataset.

- This dataset gives Nagios XI services current load, current users, ping, http, ssh, root partition, swap users and total processes metrics by default.
- If the user enters a display name of a custom check command, then the integration would also fetch and index that but not parse/perform additional extractions. Additionally, the user can provide a custom processor through the configuration page if they are interested in parsing it
- If the user enters the host name and no display name, then similar to 1, the integration will fetch all the services from that host and index, but only parse the default one i.e the 8 services. The user can provide a custom processor in this case
- If the user enters both the host name and the display name, then the integration would only fetch those services with the entered display name and only from the entered hosts. It is not possible to fetch 1 service from host1 and another service from host2 in this case as it will fetch all the services from all the hosts that are configured

{{event "service"}}

{{fields "service"}}
