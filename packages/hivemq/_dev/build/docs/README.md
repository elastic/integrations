{{- generatedHeader }}
# HiveMQ Community Edition Integration for Elastic

## Overview

[HiveMQ Community Edition](https://github.com/hivemq/hivemq-community-edition) is an open source MQTT broker that supports MQTT 3.x and MQTT 5. The HiveMQ Community Edition integration for Elastic collects the broker's server, client event and migration logs and parses them into ECS fields. Client connections and disconnections, dropped messages, expired sessions and broker errors become searchable, and you can chart them or alert on them. With the HiveMQ Prometheus Extension installed, the integration also collects the broker's metrics, such as message rates, open connections, sessions and subscriptions.

### Compatibility

This integration is tested against HiveMQ Community Edition 2026.5 and, for the metrics, the HiveMQ Prometheus Extension 4.1.1. The client event log has had the same wording since at least HiveMQ Community Edition 2024.3. Older versions such as 2020.1 write ungraceful disconnects without the listener and port; the integration parses these lines too.

It is built for the log format of HiveMQ Community Edition. It does not parse HiveMQ Enterprise logs, such as the audit log.

### How it works

HiveMQ writes its logs with logback into the folder `log` below the HiveMQ home directory, `/opt/hivemq/log` in the official Docker image. Elastic Agent tails the log files with the `filestream` input and forwards each event to Elasticsearch. There, the integration's ingest pipelines parse the timestamp, the message and, for the server and migration logs, the log level, and map the result onto ECS fields. Collecting the logs makes no connection to the broker itself.

All logs are read as multiline events, so Java stack traces and multi-line warnings stay together with the line that introduced them.

For the metrics, Elastic Agent scrapes the endpoint that the [HiveMQ Prometheus Extension](https://github.com/hivemq/hivemq-prometheus-extension) serves, by default `http://<host>:9399/metrics`, with the `prometheus/metrics` input. The extension exports every HiveMQ metric as a Prometheus gauge. The ingest pipeline maps each metric to its own field, and the field mappings mark the cumulative counts as counters, so that Kibana can calculate rates from them.

## What data does this integration collect?

The HiveMQ Community Edition integration collects three kinds of logs and the broker metrics:

* Broker server log (`hivemq.log`): start-up and shutdown, listeners, extensions, configuration warnings and errors. Errors with a Java stack trace are split into `error.type` and `error.stack_trace`.
* Client event log (`event.log`): clients connecting, clients disconnecting gracefully, ungracefully or by the broker, together with the reason, outgoing messages and packets dropped by the broker, and expired client sessions. The client identifier, client IP address, clean start flag, session expiry interval, topic, QoS and reason are mapped to fields.
* Persistence migration log (`migration.log`): the checks HiveMQ runs on every start for persistence migrations, and the migrations it performs after an upgrade, together with the persistence versions from its metadata file.
* Broker metrics (HiveMQ Prometheus Extension): incoming and outgoing messages and `PUBLISH` packets, `CONNECT` packets, dropped messages, open and closed connections, sessions, subscriptions, retained messages, will messages and network bytes. With in-memory persistence, also the size of the persisted client sessions, subscriptions, queued messages and retained messages.

Log lines that do not match a known message shape are still indexed, with the full text kept in `message`.

### Supported use cases

Track which MQTT clients connect to and disconnect from a HiveMQ broker and why, spot clients that are disconnected in a loop because another client takes over their client identifier, find messages that the broker drops because a subscriber is too slow or its maximum packet size is too small, alert on broker errors or restarts, and watch the load of the broker over time with its message, connection and session metrics. Because client addresses are mapped to `source.ip` and `related.ip`, broker activity can be correlated with the rest of the data in the cluster.

## What do I need to use this integration?

Elastic Agent must be able to read the HiveMQ log folder. When HiveMQ runs in a container, mount its log folder to a host path or volume that Elastic Agent can read.

To collect metrics, install the [HiveMQ Prometheus Extension](https://github.com/hivemq/hivemq-prometheus-extension) on each broker. Elastic Agent must be able to reach its HTTP endpoint. The extension has no authentication, so restrict network access to the endpoint.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent reads the HiveMQ log files with the `filestream` input, scrapes the metrics with the `prometheus/metrics` input, and ships the events to Elastic, where the integration's ingest pipelines process them.

### Set up steps in HiveMQ Community Edition

1. Locate the HiveMQ log folder. By default it is `<HIVEMQ_HOME>/log`, which is `/opt/hivemq/log` in the official Docker image. You can move it with the environment variable `HIVEMQ_LOG_FOLDER` or the Java system property `hivemq.log.folder`.
2. Keep the default `conf/logback.xml`, or make sure that a customized one still writes `hivemq.log`, `event.log` and `migration.log` with the default patterns. The integration parses the default patterns `%-30(%d %level)- %msg%n%ex` for the server and migration logs and `%-24(%d)- %msg%n%ex` for the event log.
3. When HiveMQ runs in a container, mount the log folder so Elastic Agent can read it, for example with `-v /var/log/hivemq:/opt/hivemq/log`. The client event log and the migration log are only written to files, never to the container's standard output.
4. To collect metrics, download the HiveMQ Prometheus Extension from its [releases page](https://github.com/hivemq/hivemq-prometheus-extension/releases) and unzip it into `<HIVEMQ_HOME>/extensions`. The extension serves the metrics on `0.0.0.0:9399` under `/metrics` by default. Change `ip`, `port` and `metric_path` in `extensions/hivemq-prometheus-extension/conf/config.properties` if needed. Restart HiveMQ and check that `hivemq.log` reports `Started HTTPServer exposing Prometheus metrics`.

#### Vendor resources

- [HiveMQ logging documentation](https://docs.hivemq.com/hivemq/latest/user-guide/logging.html)
- [Default logback.xml of HiveMQ Community Edition](https://github.com/hivemq/hivemq-community-edition/blob/master/src/distribution/conf/logback.xml)
- [HiveMQ Prometheus Extension](https://github.com/hivemq/hivemq-prometheus-extension)

### Set up steps in Kibana

1. In Kibana, go to **Management** → **Integrations**, search for **HiveMQ Community Edition** and select **Add HiveMQ Community Edition**.
2. Set the **Paths** of each data stream to the log files: `/opt/hivemq/log/hivemq.log` for the broker logs, `/opt/hivemq/log/event.log` for the client events and `/opt/hivemq/log/migration.log` for the persistence migrations. Name the files exactly. A pattern such as `*.log` also matches the other files in the folder, including the daily rotated server logs.
3. Set **Timezone Offset** if HiveMQ runs in a different timezone than Elastic Agent. HiveMQ writes timestamps in the local time of its Java virtual machine without an offset. The official Docker image runs in UTC. Both a canonical ID such as `Europe/Berlin` and an offset such as `-05:00` are accepted.
4. For the broker logs only: enable **Parse Container Logs** when the paths point at container log files of the HiveMQ container, for example `/var/log/containers/*hivemq*.log`.
5. Optionally enable **Preserve original event** to keep the raw log event in `event.original`.
6. To collect metrics, enable **Collect HiveMQ metrics from the Prometheus extension** and set **Hosts** to the extension endpoint of each broker, for example `http://localhost:9399`. Change **Metrics Path** only if you changed `metric_path` in the extension. **Period** sets how often the metrics are collected and defaults to `10s`.
7. Select the agent policy to add the integration to, and save.

### Validation

1. Connect an MQTT client to the broker and disconnect it again, or restart the broker.
2. In Kibana, open **Discover** and select the `logs-*` data view.
3. Filter on `event.dataset : "hivemq.event"` and confirm that documents with `event.action` `client-connected` and `client-disconnected` arrive. Filter on `event.dataset : "hivemq.log"` for the broker logs and on `event.dataset : "hivemq.migration"` for the migration checks of each broker start.
4. For the metrics, select the `metrics-*` data view and filter on `event.dataset : "hivemq.metrics"`. A document with the `hivemq.metrics.*` fields arrives every collection period.

## Troubleshooting

- No data is being collected: Confirm that the user running Elastic Agent can read the HiveMQ log folder and the files in it. Elastic Agent identifies files by a fingerprint of their first 1024 bytes. Elastic Agent 9.4 only starts collecting a new and almost empty `event.log` once it has grown to that size. Elastic Agent 9.5 and later collects smaller files right away. The migration data stream uses a fingerprint of the first 64 bytes, so a fresh `migration.log` is collected right away on all supported versions.
- No client events are collected: The default `logback.xml` writes client events only to `event.log`. Check that the paths of the client events point at this file and not at the container's standard output.
- Timestamps are off by a whole number of hours: HiveMQ writes local time without an offset. Set the **Timezone Offset** option to the timezone of the HiveMQ Java virtual machine.
- Authentication events are missing: HiveMQ logs enhanced authentication (`AUTH`) events at DEBUG level, and the default `logback.xml` has no logger for them. Add the following logger to `logback.xml`. Without `additivity="false"` and the `EVENT-FILE` appender, the events go to `hivemq.log` instead of `event.log`.

  ```xml
  <logger name="event.authentication" level="DEBUG" additivity="false">
      <appender-ref ref="EVENT-FILE"/>
  </logger>
  ```
- No metrics are collected: Open the extension endpoint, for example `http://<host>:9399/metrics`, from the host running Elastic Agent. If it does not answer, check that `hivemq.log` reports `Started HTTPServer exposing Prometheus metrics` and that the port is reachable.
- The in-memory persistence metrics are missing: HiveMQ only reports the `hivemq.metrics.persistence.*` sizes when it runs with in-memory persistence (`<persistence><mode>in-memory</mode></persistence>` in `config.xml`).
- Counters drop back to zero: The cumulative counts start at zero whenever the broker restarts.
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

#### metrics

The `metrics` data stream provides the broker metrics that the HiveMQ Prometheus Extension exports. Each document holds all metrics of one collection from one broker under `hivemq.metrics.*`. The field names follow the HiveMQ metric names, for example `hivemq.metrics.messages.incoming.publish.count` for `com.hivemq.messages.incoming.publish.count`. Cumulative counts are mapped as counters and current values as gauges. The data stream uses the time series index mode, with `agent.id` and `service.address` as dimensions. List each broker only once in **Hosts**: the same broker under two URLs is collected as two series and counted twice.

##### metrics fields

{{ fields "metrics" }}

##### metrics sample event

{{ event "metrics" }}

{{ ilm }}

{{ transform }}
