# Custom MQTT Input Integration for Elastic

## Overview

The Custom MQTT Input integration for Elastic subscribes to one or more topics on an MQTT broker and ships every received message to Elasticsearch. MQTT is the dominant publish/subscribe protocol for IoT and telemetry, so this integration gives you a generic way to bring sensor readings, device events, and application messages into the Elastic Stack without writing a bespoke collector.

The integration is deliberately generic: it makes no assumption about the payload format or the meaning of your topics. You choose the data stream type, the dataset name, and an optional ingest pipeline that shapes the data to fit your use case.

### Compatibility

The integration is compatible with any broker that speaks MQTT 3.1 or 3.1.1, including Eclipse Mosquitto, HiveMQ, EMQX, VerneMQ, and the MQTT endpoints exposed by cloud IoT platforms.

It connects over plain TCP (`tcp://`) or TLS (`ssl://`), with optional username and password authentication.

### How it works

Elastic Agent runs an MQTT client that connects to the brokers you configure and subscribes to your chosen topics. The broker pushes matching messages to the agent as they are published; the agent does not poll. Each message payload becomes the `message` field of one document.

Because the agent is a subscriber rather than a listener, no inbound firewall rules are needed on the agent host — the agent opens the outbound connection to the broker.

## What data does this integration collect?

The integration collects the raw payload of every message published to the topics you subscribe to. It does not parse the payload; whatever the publisher sent is stored verbatim.

Typical payloads include:
- JSON documents from IoT devices and gateways
- Plain-text status or telemetry lines
- Line-delimited values from embedded hardware

The integration writes to a data stream you name yourself. You choose both parts:
- The **type**, by enabling one of the three data streams the integration ships: `logs`, `metrics` or `traces`. Each writes to its own index type.
- The **dataset**, through the Dataset name setting. Each data stream defaults to its own: `mqtt.logs`, `mqtt.metrics` or `mqtt.traces`.

### Supported use cases

The Custom MQTT Input integration is useful wherever data already flows through an MQTT broker:
- IoT and sensor telemetry: Collect readings from devices that publish to a broker, and route them into metrics data streams for dashboards and alerting.
- Building and industrial automation: Capture events from BACnet, KNX, or Modbus gateways that bridge to MQTT.
- Home and edge deployments: Ingest state changes from home automation hubs and edge controllers.
- Application messaging: Observe messages exchanged between services that use MQTT as a lightweight message bus.

## What do I need to use this integration?

To use the Custom MQTT Input integration, you'll need to meet several requirements.

### Vendor prerequisites

To subscribe to a broker, you must meet these prerequisites:
- Broker reachability: The Elastic Agent host must be able to open an outbound connection to the broker host and port. The default MQTT ports are `1883` for plain TCP and `8883` for TLS.
- Credentials: If the broker requires authentication, you need a username and password. Many brokers also restrict which topics a given account may subscribe to.
- Topic permissions: The account must be authorized to subscribe to the topics you configure, including any wildcard patterns.

### Elastic prerequisites

You need a running Elastic Stack and an installed Elastic Agent. For more information, refer to [Get started](https://www.elastic.co/docs/get-started).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent is required to subscribe to the MQTT broker and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Custom MQTT Input

Before adding the integration in Kibana, prepare the broker:

1. Identify the broker URI, including scheme, host, and port. For example, `tcp://broker.example.com:1883` or `ssl://broker.example.com:8883`.

2. Decide which topics to subscribe to. MQTT supports two wildcards:
   - `+` matches exactly one topic level, so `sensors/+/temperature` matches `sensors/kitchen/temperature`.
   - `#` matches all remaining levels and must be the final character, so `sensors/#` matches everything beneath `sensors`.

3. Create or obtain an account authorized to subscribe to those topics.

4. If the broker uses TLS, collect the certificate authority that signed the broker certificate.

5. Choose a client identifier. Brokers reject a second connection using an identifier that is already in use, so give each agent its own value when several agents share a broker.

### Set up steps in Kibana

1. In Kibana, go to **Management** > **Integrations**.

2. Search for **Custom MQTT** and select it.

3. Enable the data streams you want. The integration ships three, and you can enable any combination:
   - **MQTT logs** writes to `logs-*`.
   - **MQTT metrics** writes to `metrics-*`.
   - **MQTT traces** writes to `traces-*`.

   Each enabled data stream opens its own MQTT connection, so give each one a distinct **Client ID** — a broker evicts an existing client when a second one connects with the same identifier.

4. Configure the required settings:
    - **Broker Hosts**: One or more broker URIs. The default is `tcp://localhost:1883`.
    - **Topics**: One or more topic filters. The default is `#`, which subscribes to every topic on the broker.
    - **Dataset name**: The dataset to write to. The default matches the data stream you enabled: `mqtt.logs`, `mqtt.metrics` or `mqtt.traces`.

5. Configure the optional settings as needed:
    - **Client ID**, **QoS**, **Username**, and **Password** for the broker connection.
    - **SSL Configuration** when connecting over TLS.
    - **Ingest Pipeline** to parse the payload into structured fields.

6. Click **Save and continue**, then assign the policy to an agent.

### Validation

To confirm the integration is working:

1. Publish a test message to a subscribed topic. Using the Mosquitto client tools:

   ```
   mosquitto_pub -h broker.example.com -p 1883 -t 'sensors/test' -m 'hello from mqtt'
   ```

2. In Kibana, go to **Discover**.

3. Select the data view matching the type you chose, for example `logs-*`.

4. Filter on your dataset:

   ```
   data_stream.dataset : "mqtt.logs"
   ```

5. Confirm that a document appears with `hello from mqtt` in the `message` field.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

- No documents arrive: Confirm the agent host can reach the broker, and that the account is authorized to subscribe to the configured topics. Brokers usually accept the connection and then silently drop unauthorized subscriptions, so a healthy connection is not proof that the subscription succeeded.

- The agent connects and immediately disconnects in a loop: Two clients are almost certainly using the same client identifier. Brokers evict the older connection when a new one presents an identifier already in use, so two agents with the same **Client ID** will disconnect each other indefinitely. Give each agent a unique value.

- Messages are missing after an agent restart: With **Clean Session** enabled, the broker discards the subscription state whenever the client disconnects, and messages published while the agent was down are lost. Disable it and use a QoS of `1` or `2` if the broker should queue messages for a disconnected subscriber.

- TLS handshake failures: Supply the certificate authority that signed the broker certificate under **SSL Configuration**. Also confirm the URI uses the `ssl://` scheme; `tcp://` on a TLS port fails without a clear error.

- Payloads are stored as a single unparsed string: This is the default behaviour, since the integration makes no assumption about the payload format. Set **Ingest Pipeline** to a pipeline that parses your payload, or add processors to the pipeline associated with the dataset.

## Performance and scaling

- Topic breadth: Subscribing to `#` on a busy broker delivers every message published anywhere on it. Narrow the topic filters to the subtrees you actually need, both to reduce load on the agent and to avoid ingesting data you do not want.

- Quality of service: QoS `0` is the cheapest for both broker and agent but drops messages when the connection is unstable. QoS `1` and `2` add broker-side bookkeeping and redelivery, so raise them only where message loss actually matters.

- Horizontal scaling: A single agent handles one MQTT client connection. To spread load, run several agents that each subscribe to a disjoint set of topics, and give each one a distinct client identifier. Note that plain MQTT subscriptions are not load balanced — every subscriber to a topic receives every message — so splitting by topic, not by adding subscribers to the same topic, is what distributes work. Brokers that support shared subscriptions (`$share/`) can balance a single topic across several clients.

## Reference

### logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| mqtt.duplicate | Whether the broker flagged the message as a redelivery. Only meaningful at QoS 1 and 2. | boolean |
| mqtt.message_id | Broker-assigned packet identifier used to correlate delivery and acknowledgement. Unique only while the message is in flight. | long |
| mqtt.qos | Quality of service level the message was delivered with: 0 at most once, 1 at least once, 2 exactly once. | long |
| mqtt.retained | Whether the broker had this message stored as the retained message for its topic and replayed it on subscribe, rather than it arriving live. | boolean |
| mqtt.topic | Topic the message was published to. With a wildcard subscription this is the concrete topic, not the filter that matched it. | keyword |


An example event for `logs` looks as following:

```json
{
    "@timestamp": "2026-08-27T08:22:29.523Z",
    "agent": {
        "ephemeral_id": "da87986d-a950-4395-98d3-421e960d0c07",
        "id": "85728dd6-8f65-4777-90ee-d1e4410e5857",
        "name": "elastic-agent-21441",
        "type": "filebeat",
        "version": "9.4.3"
    },
    "data_stream": {
        "dataset": "mqtt.logs",
        "namespace": "46765",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "85728dd6-8f65-4777-90ee-d1e4410e5857",
        "snapshot": false,
        "version": "9.4.3"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "mqtt.logs",
        "ingested": "2026-08-27T08:22:32Z",
        "module": "mqtt",
        "original": "{\"device_id\":\"sensor-01\",\"location\":\"warehouse-a\",\"temperature\":21.4,\"humidity\":47,\"timestamp\":\"2026-08-27T09:00:00Z\"}"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-21441",
        "ip": [
            "10.89.2.2",
            "fe80::85b:7fff:fe51:5ea3",
            "10.89.1.51",
            "fe80::40cc:53ff:fe2f:2567"
        ],
        "mac": [
            "0A-5B-7F-51-5E-A3",
            "42-CC-53-2F-25-67"
        ],
        "name": "elastic-agent-21441",
        "os": {
            "family": "",
            "kernel": "6.15.10-200.fc42.aarch64",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "input": {
        "type": "mqtt"
    },
    "message": "{\"device_id\":\"sensor-01\",\"location\":\"warehouse-a\",\"temperature\":21.4,\"humidity\":47,\"timestamp\":\"2026-08-27T09:00:00Z\"}",
    "mqtt": {
        "duplicate": false,
        "message_id": 1,
        "qos": 1,
        "retained": true,
        "topic": "sensors/1"
    },
    "tags": [
        "preserve_original_event"
    ]
}
```

### metrics

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| mqtt.duplicate | Whether the broker flagged the message as a redelivery. Only meaningful at QoS 1 and 2. | boolean |
| mqtt.message_id | Broker-assigned packet identifier used to correlate delivery and acknowledgement. Unique only while the message is in flight. | long |
| mqtt.qos | Quality of service level the message was delivered with: 0 at most once, 1 at least once, 2 exactly once. | long |
| mqtt.retained | Whether the broker had this message stored as the retained message for its topic and replayed it on subscribe, rather than it arriving live. | boolean |
| mqtt.topic | Topic the message was published to. With a wildcard subscription this is the concrete topic, not the filter that matched it. | keyword |


An example event for `metrics` looks as following:

```json
{
    "@timestamp": "2026-08-27T08:23:26.636Z",
    "agent": {
        "ephemeral_id": "d31f27bc-8f4b-4b6f-ab09-72b567252d1e",
        "id": "35b73e65-3f89-40a1-b89e-d5c4b944f856",
        "name": "elastic-agent-47120",
        "type": "filebeat",
        "version": "9.4.3"
    },
    "data_stream": {
        "dataset": "mqtt.metrics",
        "namespace": "46017",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "35b73e65-3f89-40a1-b89e-d5c4b944f856",
        "snapshot": false,
        "version": "9.4.3"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "mqtt.metrics",
        "ingested": "2026-08-27T08:23:29Z",
        "original": "{\"device_id\":\"sensor-01\",\"location\":\"warehouse-a\",\"temperature\":21.4,\"humidity\":47,\"timestamp\":\"2026-08-27T09:00:00Z\"}"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-47120",
        "ip": [
            "10.89.2.2",
            "fe80::78a5:fdff:fefd:db96",
            "10.89.1.52",
            "fe80::7cc3:b0ff:fe65:c21d"
        ],
        "mac": [
            "7A-A5-FD-FD-DB-96",
            "7E-C3-B0-65-C2-1D"
        ],
        "name": "elastic-agent-47120",
        "os": {
            "family": "",
            "kernel": "6.15.10-200.fc42.aarch64",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "input": {
        "type": "mqtt"
    },
    "message": "{\"device_id\":\"sensor-01\",\"location\":\"warehouse-a\",\"temperature\":21.4,\"humidity\":47,\"timestamp\":\"2026-08-27T09:00:00Z\"}",
    "mqtt": {
        "duplicate": false,
        "message_id": 1,
        "qos": 1,
        "retained": true,
        "topic": "sensors/1"
    },
    "tags": [
        "preserve_original_event"
    ]
}
```

### traces

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| mqtt.duplicate | Whether the broker flagged the message as a redelivery. Only meaningful at QoS 1 and 2. | boolean |
| mqtt.message_id | Broker-assigned packet identifier used to correlate delivery and acknowledgement. Unique only while the message is in flight. | long |
| mqtt.qos | Quality of service level the message was delivered with: 0 at most once, 1 at least once, 2 exactly once. | long |
| mqtt.retained | Whether the broker had this message stored as the retained message for its topic and replayed it on subscribe, rather than it arriving live. | boolean |
| mqtt.topic | Topic the message was published to. With a wildcard subscription this is the concrete topic, not the filter that matched it. | keyword |


An example event for `traces` looks as following:

```json
{
    "@timestamp": "2026-08-27T08:24:24.869Z",
    "agent": {
        "ephemeral_id": "eedab199-6793-48c6-a5b4-3ff169dcdffd",
        "id": "c82c2606-e3fb-40df-b17c-e6b3fed0b35d",
        "name": "elastic-agent-78355",
        "type": "filebeat",
        "version": "9.4.3"
    },
    "data_stream": {
        "dataset": "mqtt.traces",
        "namespace": "85512",
        "type": "traces"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "c82c2606-e3fb-40df-b17c-e6b3fed0b35d",
        "snapshot": false,
        "version": "9.4.3"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "mqtt.traces",
        "ingested": "2026-08-27T08:24:27Z",
        "original": "{\"device_id\":\"sensor-01\",\"location\":\"warehouse-a\",\"temperature\":21.4,\"humidity\":47,\"timestamp\":\"2026-08-27T09:00:00Z\"}"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-78355",
        "ip": [
            "10.89.2.2",
            "fe80::e86d:b0ff:fead:36bd",
            "10.89.1.53",
            "fe80::3814:caff:fefb:375a"
        ],
        "mac": [
            "3A-14-CA-FB-37-5A",
            "EA-6D-B0-AD-36-BD"
        ],
        "name": "elastic-agent-78355",
        "os": {
            "family": "",
            "kernel": "6.15.10-200.fc42.aarch64",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "input": {
        "type": "mqtt"
    },
    "message": "{\"device_id\":\"sensor-01\",\"location\":\"warehouse-a\",\"temperature\":21.4,\"humidity\":47,\"timestamp\":\"2026-08-27T09:00:00Z\"}",
    "mqtt": {
        "duplicate": false,
        "message_id": 1,
        "qos": 1,
        "retained": true,
        "topic": "sensors/1"
    },
    "tags": [
        "preserve_original_event"
    ]
}
```

### Vendor documentation links

The following links provide additional information about the protocol and configuration supported by this integration:
- [MQTT 3.1.1 specification (OASIS)](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html)
- [Eclipse Mosquitto documentation](https://mosquitto.org/documentation/)
- [Filebeat MQTT input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-mqtt)
- [Filebeat SSL Configuration](https://www.elastic.co/docs/reference/beats/filebeat/configuration-ssl#ssl-common-config)
