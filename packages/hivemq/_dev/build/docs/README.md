{{- generatedHeader }}
# HiveMQ Community Edition Integration for Elastic

## Overview

[HiveMQ Community Edition](https://github.com/hivemq/hivemq-community-edition) is an open source MQTT broker that supports MQTT 3.x and MQTT 5. The HiveMQ Community Edition integration for Elastic collects the broker's server log and its client event log and parses them into ECS fields. Client connections and disconnections, dropped messages, expired sessions and broker errors become searchable, and you can chart them or alert on them.

### Compatibility

This integration has been tested against HiveMQ Community Edition 2026.5. The client event log has had the same wording since at least HiveMQ Community Edition 2024.3.

It is built for the log format of HiveMQ Community Edition. It does not parse HiveMQ Enterprise logs, such as the audit log.

### How it works

HiveMQ writes its logs with logback into the folder `log` below the HiveMQ home directory, `/opt/hivemq/log` in the official Docker image. Elastic Agent tails the log files with the `filestream` input and forwards each event to Elasticsearch. There, the integration's ingest pipelines parse the timestamp, the message and, for the server and migration logs, the log level, and map the result onto ECS fields. No connection is made to the broker itself.

All logs are read as multiline events, so Java stack traces and multi-line warnings stay together with the line that introduced them.

## What data does this integration collect?

The HiveMQ Community Edition integration collects three kinds of logs:

* Broker server log (`hivemq.log`): start-up and shutdown, listeners, extensions, configuration warnings and errors. Errors with a Java stack trace are split into `error.type` and `error.stack_trace`.
* Client event log (`event.log`): clients connecting, clients disconnecting gracefully, ungracefully or by the broker, together with the reason, outgoing messages and packets dropped by the broker, and expired client sessions. The client identifier, client IP address, clean start flag, session expiry interval, topic, QoS and reason are mapped to fields.
* Persistence migration log (`migration.log`): the checks HiveMQ runs on every start for persistence migrations, and the migrations it performs after an upgrade, together with the persistence versions from its metadata file.

Lines that do not match a known message shape are still indexed, with the full text kept in `message`.

### Supported use cases

Track which MQTT clients connect to and disconnect from a HiveMQ broker and why, spot clients that are disconnected in a loop because another client takes over their client identifier, find messages that the broker drops because a subscriber is too slow or its maximum packet size is too small, and alert on broker errors or restarts. Because client addresses are mapped to `source.ip` and `related.ip`, broker activity can be correlated with the rest of the data in the cluster.

## What do I need to use this integration?

Elastic Agent must be able to read the HiveMQ log folder. When HiveMQ runs in a container, mount its log folder to a host path or volume that Elastic Agent can read.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent reads the HiveMQ log files with the `filestream` input and ships the events to Elastic, where the integration's ingest pipelines process them.

### Set up steps in HiveMQ Community Edition

1. Locate the HiveMQ log folder. By default it is `<HIVEMQ_HOME>/log`, which is `/opt/hivemq/log` in the official Docker image. You can move it with the environment variable `HIVEMQ_LOG_FOLDER` or the Java system property `hivemq.log.folder`.
2. Keep the default `conf/logback.xml`, or make sure that a customized one still writes `hivemq.log`, `event.log` and `migration.log` with the default patterns. The integration parses the default patterns `%-30(%d %level)- %msg%n%ex` for the server and migration logs and `%-24(%d)- %msg%n%ex` for the event log.
3. When HiveMQ runs in a container, mount the log folder so Elastic Agent can read it, for example with `-v /var/log/hivemq:/opt/hivemq/log`. The client event log and the migration log are only written to files, never to the container's standard output.

#### Vendor resources

- [HiveMQ logging documentation](https://docs.hivemq.com/hivemq/latest/user-guide/logging.html)
- [Default logback.xml of HiveMQ Community Edition](https://github.com/hivemq/hivemq-community-edition/blob/master/src/distribution/conf/logback.xml)

### Set up steps in Kibana

1. In Kibana, go to **Management** → **Integrations**, search for **HiveMQ Community Edition** and select **Add HiveMQ Community Edition**.
2. Set the **Paths** of each data stream to the log files: `/opt/hivemq/log/hivemq.log` for the broker logs, `/opt/hivemq/log/event.log` for the client events and `/opt/hivemq/log/migration.log` for the persistence migrations. Name the files exactly. A pattern such as `*.log` also matches the other files in the folder, including the daily rotated server logs.
3. Set **Timezone Offset** if HiveMQ runs in a different timezone than Elastic Agent. HiveMQ writes timestamps in the local time of its Java virtual machine without an offset. The official Docker image runs in UTC. Both a canonical ID such as `Europe/Berlin` and an offset such as `-05:00` are accepted.
4. For the broker logs only: enable **Parse Container Logs** when the paths point at container log files of the HiveMQ container, for example `/var/log/containers/*hivemq*.log`.
5. Optionally enable **Preserve original event** to keep the raw log event in `event.original`.
6. Select the agent policy to add the integration to, and save.

### Validation

1. Connect an MQTT client to the broker and disconnect it again, or restart the broker.
2. In Kibana, open **Discover** and select the `logs-*` data view.
3. Filter on `event.dataset : "hivemq.event"` and confirm that documents with `event.action` `client-connected` and `client-disconnected` arrive. Filter on `event.dataset : "hivemq.log"` for the broker logs and on `event.dataset : "hivemq.migration"` for the migration checks of each broker start.

## Troubleshooting

- No data is being collected: Confirm that the user running Elastic Agent can read the HiveMQ log folder and the files in it. Elastic Agent identifies files by a fingerprint of their first 1024 bytes, so a new and almost empty `event.log` is only collected once it has grown beyond that size.
- No migration events are collected: After the first start of a new installation, `migration.log` is smaller than 1024 bytes. HiveMQ appends its migration checks on every start, so the file is collected after one or two further restarts.
- No client events are collected: The default `logback.xml` writes client events only to `event.log`. Check that the paths of the client events point at this file and not at the container's standard output.
- Timestamps are off by a whole number of hours: HiveMQ writes local time without an offset. Set the **Timezone Offset** option to the timezone of the HiveMQ Java virtual machine.
- Authentication events are missing: HiveMQ logs enhanced authentication (`AUTH`) events at DEBUG level, and the default `logback.xml` has no logger for them. Add the following logger to `logback.xml`. Without `additivity="false"` and the `EVENT-FILE` appender, the events go to `hivemq.log` instead of `event.log`.

  ```xml
  <logger name="event.authentication" level="DEBUG" additivity="false">
      <appender-ref ref="EVENT-FILE"/>
  </logger>
  ```
- The container start banner is attached to the previous event: When the broker logs are collected from a container that restarts, the start script's banner has no timestamp and is joined to the last event of the previous run, for example `Shutdown completed.`.

## Performance and scaling

The client event log grows with the number of client connections. Brokers with many short-lived connections write several lines for each connection, so plan the ingest volume accordingly.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### Vendor documentation links

- [HiveMQ Community Edition on GitHub](https://github.com/hivemq/hivemq-community-edition)
- [HiveMQ Community Edition Docker image](https://hub.docker.com/r/hivemq/hivemq-ce)
- [HiveMQ logging documentation](https://docs.hivemq.com/hivemq/latest/user-guide/logging.html)

### Data streams

#### log

The `log` data stream provides events from the HiveMQ broker server log (`hivemq.log`): start-up and shutdown, listeners, extensions, warnings and errors. `log.level` is taken from the level that HiveMQ writes on each line.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

#### event

The `event` data stream provides events from the HiveMQ client event log (`event.log`): client connections and disconnections, dropped messages and packets, expired client sessions and, when configured, enhanced authentication. `event.action` names the kind of event: `client-connected`, `client-disconnected`, `message-dropped`, `packet-dropped`, `client-session-expired`, `authentication-received` or `authentication-sent`. The client details are stored in `source.ip` and in the `hivemq.event.*` fields, and `hivemq.event.disconnect.type` tells graceful, ungraceful and broker-initiated disconnects apart.

##### event fields

{{ fields "event" }}

##### event sample event

{{ event "event" }}

#### migration

The `migration` data stream provides events from the HiveMQ persistence migration log (`migration.log`). HiveMQ checks on every start whether the stored persistence data needs a migration, and after an upgrade it migrates the affected persistences. `event.action` names each step, for example `migration-check`, `migrations-found`, `migration-unit-completed` or `migration-finished`. The duration of each completed migration is stored in `event.duration`, and the persistence versions that HiveMQ reads from and writes to its metadata file are stored in the `hivemq.migration.metadata.*` fields.

##### migration fields

{{ fields "migration" }}

##### migration sample event

{{ event "migration" }}

{{ ilm }}

{{ transform }}
