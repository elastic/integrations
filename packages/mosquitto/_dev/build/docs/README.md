{{- generatedHeader }}
# Mosquitto Integration for Elastic

## Overview

[Eclipse Mosquitto](https://mosquitto.org/) is an open source MQTT broker used to move telemetry and command messages between devices, gateways, and applications. The Mosquitto integration for Elastic collects the broker's own log file and parses it into ECS fields, so that client connections, subscriptions, published messages, and broker errors become searchable and can be charted or alerted on.

### Compatibility

This integration has been tested against Mosquitto 2.0.x. It also parses the log wording used by Mosquitto 1.6, including the older disconnect lines that omit the client address.

### How it works

Mosquitto writes its log to the destination named by `log_dest`. The Elastic Agent tails that file with the `filestream` input and forwards each line to Elasticsearch, where the integration's ingest pipeline splits off the timestamp prefix, parses the message body and maps the result onto ECS fields. No connection is made to the broker itself, so the integration works with any listener or authentication configuration.

### Timestamp formats, and why ISO is easier to read

Mosquitto can prefix log lines with either of two timestamp formats, and **this integration parses both** — no configuration change is required to use it.

By default `log_timestamp_format` is unset, and Mosquitto writes the number of seconds since the Unix epoch:

```
1756052767: New connection from 192.0.2.24:43985 on port 1883.
```

Setting `log_timestamp_format` makes the broker write a `strftime`-formatted timestamp instead. The format documented by Mosquitto produces an ISO 8601 style timestamp:

```
log_timestamp_format %Y-%m-%dT%H:%M:%S
```

```
2026-08-24T16:26:07: New connection from 192.0.2.24:43985 on port 1883.
```

Configuring the ISO format is recommended. The resulting log is far easier to read directly on the broker host — epoch seconds must be converted value by value to reveal when each event occurred. Both formats produce exactly the same fields in Elasticsearch, so the choice only affects readability on the broker itself.

One caveat applies to the formatted variant: Mosquitto renders it in the broker host's local time and writes no UTC offset, whereas the epoch default is always UTC. If Elastic Agent runs in a different timezone than the broker, set the **Timezone Offset** option on the integration policy to the broker's timezone so timestamps are interpreted correctly. Adding `%z` to the format, for example `%Y-%m-%dT%H:%M:%S%z`, makes the broker emit an explicit offset, which removes the ambiguity entirely.

## What data does this integration collect?

The Mosquitto integration collects the broker log and parses the following kinds of message:

* Connection lifecycle: new connections, clients and bridges connecting, disconnects with the broker's stated reason, expired and rejected clients.
* MQTT control packets sent and received by the broker, including `PUBLISH`, `CONNACK`, `SUBSCRIBE`, `SUBACK`, `PUBACK`, `PUBREC`, `PUBREL`, `PUBCOMP`, `PINGREQ`, `PINGRESP`, `AUTH` and `DISCONNECT`, together with their topic, QoS, message ID, payload size and flags.
* Subscription detail lines listing each topic filter and the QoS granted or denied.
* Broker lifecycle and configuration: version messages on start-up and shutdown, the configuration file that was loaded, listeners being opened, and records restored from the persistence database.
* Errors, warnings, refused connections and protocol errors.

Lines that do not match a known message shape are still indexed, with the full text kept in `message`.

One known limitation: the line Mosquitto writes for `log_type unsubscribe` consists of nothing but a client identifier and a topic filter separated by a space. That shape cannot be told apart from ordinary two-word log messages, so those lines are indexed with their text in `message` but without a parsed topic. The `UNSUBSCRIBE` packet line that accompanies them is parsed normally.

### Supported use cases

Track which clients connect to and disconnect from an MQTT broker and why, spot clients that reconnect in a loop or are rejected by an access control list, follow the topics being published and subscribed to, and alert on broker errors or restarts. Because source addresses and usernames are mapped to `source.ip`, `user.name` and the `related.*` fields, broker activity can be correlated with the rest of the data in the cluster.

## What do I need to use this integration?

Elastic Agent must be able to read the Mosquitto log file. If the broker runs in a container with `log_dest stdout`, point the integration at the container log files and enable the **Parse Container Logs** option.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Mosquitto

1. Configure the broker to write its log to a file that Elastic Agent can read, by setting `log_dest` in `mosquitto.conf`:

   ```
   log_dest file /var/log/mosquitto/mosquitto.log
   ```

   When the broker runs in a container, keep `log_dest stdout` and collect the container log file instead.

2. Optionally switch to the more readable ISO 8601 timestamp format:

   ```
   log_timestamp_format %Y-%m-%dT%H:%M:%S
   ```

3. Choose which message types the broker should log with `log_type`. The default of `error`, `warning`, `notice` and `information` covers connections, disconnects and broker lifecycle messages. Add `subscribe` to record which topic filters the broker grants, or set `log_type all` to include the per-packet `debug` messages. Be aware that `all` is very verbose on a busy broker.

4. Restart Mosquitto and confirm the log file is being written.

#### Vendor resources

- [mosquitto.conf manual page](https://mosquitto.org/man/mosquitto-conf-5.html)
- [Mosquitto documentation](https://mosquitto.org/documentation/)

### Set up steps in Kibana

1. In Kibana, go to **Management** → **Integrations**, search for **Mosquitto** and select **Add Mosquitto**.
2. Set **Paths** to the location of the broker log, for example `/var/log/mosquitto/mosquitto.log`. Container deployments typically use `/var/log/containers/*mosquitto*.log`.
3. Enable **Parse Container Logs** when the paths point at container log files, so the CRI or Docker JSON envelope is removed before parsing.
4. Set **Timezone Offset** if the broker uses `log_timestamp_format` and runs in a different timezone than Elastic Agent. Both a canonical ID such as `Europe/Amsterdam` and an offset such as `-05:00` are accepted.
5. Optionally enable **Preserve original event** to keep the raw log line in `event.original`.
6. Select the agent policy to add the integration to, and save.

### Validation

1. Publish or subscribe to a topic on the broker so that it writes new log lines, or restart the broker.
2. In Kibana, open **Discover** and select the `logs-*` data view.
3. Filter on `event.dataset : "mosquitto.log"` and confirm that documents arrive with a parsed `@timestamp`, an `event.action` and a populated `message`.

## Troubleshooting

- No data is being collected: Confirm that `log_dest` writes to a file and that the user running Elastic Agent has read access to it and to its parent directory. A broker configured with only `log_dest stdout` writes nothing to disk outside a container runtime.
- Timestamps are off by a whole number of hours: The broker is using `log_timestamp_format`, which writes local time with no offset. Set the **Timezone Offset** option to the broker's timezone, or append `%z` to the broker's `log_timestamp_format`.
- Documents are tagged `mosquitto_missing_timestamp`: The broker runs with `log_timestamp false`, or with a `log_timestamp_format` that omits the date. `@timestamp` falls back to the time the line was collected. Configure a format that includes a full date to resolve it.
- Every line arrives wrapped in a JSON envelope: The paths point at container log files. Enable the **Parse Container Logs** option.
- Fewer message types appear than expected: The broker's `log_type` setting controls which messages are written at all. Per-packet `PUBLISH` and `SUBSCRIBE` lines require `log_type all` or the `subscribe` and `unsubscribe` types.

## Performance and scaling

A broker logging with `log_type all` writes several lines for every message it handles, so log volume grows with message throughput rather than with client count. On busy brokers, prefer the default `log_type` and enable `subscribe` only while investigating, or use the **Exclude Lines** capability of the agent policy to drop the highest-volume packet lines.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### Vendor documentation links

- [Eclipse Mosquitto](https://mosquitto.org/)
- [mosquitto.conf manual page](https://mosquitto.org/man/mosquitto-conf-5.html)
- [Mosquitto logging documentation](https://mosquitto.org/man/mosquitto-conf-5.html)

### Data streams

#### log

The `log` data stream provides events from the Eclipse Mosquitto broker log, covering connection lifecycle, MQTT control packets, subscriptions, broker lifecycle and errors.

Mosquitto's file and standard output destinations write no severity marker, so `log.level` is derived from the wording of each message: lines beginning with `Error` or `Connection Refused:` become `error`, lines beginning with `Warning` or `Protocol error from` become `warning`, and everything else becomes `information`. Use `log_dest syslog` if the broker's own severity classification is required.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

{{ ilm }}

{{ transform }}
