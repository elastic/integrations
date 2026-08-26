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
- The **type**, by selecting one of the three integration options: `logs`, `metrics`, or `traces`.
- The **dataset**, through the Dataset name setting, which defaults to `mqtt.generic`.

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

3. Choose the integration option matching the data stream type you want:
   - **Custom MQTT Logs** writes to `logs-*`.
   - **Custom MQTT Metrics** writes to `metrics-*`.
   - **Custom MQTT Traces** writes to `traces-*`.

4. Configure the required settings:
    - **Broker Hosts**: One or more broker URIs. The default is `tcp://localhost:1883`.
    - **Topics**: One or more topic filters. The default is `#`, which subscribes to every topic on the broker.
    - **Dataset name**: The dataset to write to. The default is `mqtt.generic`.

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
   data_stream.dataset : "mqtt.generic"
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

### Vendor documentation links

The following links provide additional information about the protocol and configuration supported by this integration:
- [MQTT 3.1.1 specification (OASIS)](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html)
- [Eclipse Mosquitto documentation](https://mosquitto.org/documentation/)
- [Filebeat MQTT input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-mqtt)
- [Filebeat SSL Configuration](https://www.elastic.co/docs/reference/beats/filebeat/configuration-ssl#ssl-common-config)
