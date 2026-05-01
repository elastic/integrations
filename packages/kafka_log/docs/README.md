# Custom Kafka Integration

## Overview

The Custom Kafka integration is an **input** package for Elastic Agent. It runs the Filebeat **Kafka** input so agents can **consume** records from Apache Kafka topics and ship them to Elasticsearch. Use it when applications or pipelines already publish logs or events to Kafka and you want Elastic to read from those topics without an intermediate forwarder.

### Compatibility

This integration is intended for Kafka clusters where brokers speak the standard Kafka protocol. It is tested and supported for Kafka broker versions roughly between **0.11** and **2.8.0**. Earlier or later brokers can work but are not guaranteed.

### How it works

Elastic Agent connects to your cluster using the **bootstrap hosts** you configure, joins a **consumer group** (`group_id`), and subscribes to one or more **topics**. Messages are read by the agent, enriched with Kafka metadata (for example topic, partition, offset), and written to Elasticsearch using the **dataset** name you choose (default `kafka_log.generic`). Optional **SASL**, **Kerberos**, and **TLS** settings secure the connection to the brokers. Optional **parsers** and **processors** adjust the payload on the agent before ingest.

## What data does this integration collect?

The integration collects **events** derived from Kafka messages:

- **Message payload**: Typically stored in the `message` field (format depends on your producers—plain text, JSON, syslog, and so on).
- **Kafka metadata**: Fields such as `kafka.topic`, `kafka.partition`, `kafka.offset`, `kafka.key`, and `kafka.headers` where applicable.
- **Routing fields**: `data_stream.dataset`, `data_stream.type`, and `data_stream.namespace` follow your Fleet policy and dataset name.

The default **dataset** is `kafka_log.generic`. Changing the **Dataset name** in the policy sends data to a different backing data stream. Dataset names must follow Elasticsearch naming rules (no `-` in the dataset segment).

### Supported use cases

- Ingest logs or telemetry already landed on Kafka by microservices or stream processors.
- Centralize topic data for search and observability in Kibana without maintaining a separate log shipper per producer.
- Apply a custom **Ingest Pipeline** in Elasticsearch when you need parsing or ECS normalization beyond agent-side parsers.

## What do I need to use this integration?

### Kafka prerequisites

- **Network reachability** from the host running Elastic Agent to each configured bootstrap broker (hostnames and ports).
- **Topic access**: ACLs or permissions that allow your consumer **group** to read the configured topics.
- **Authentication details** if the cluster uses SASL (PLAIN, SCRAM), Kerberos, or TLS client certificates—match these to your broker configuration.

### Elastic prerequisites

- A stack version that satisfies the integration’s **Kibana** requirement (refer to the integration manifest in Kibana or this package’s `manifest.yml`).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent runs the Kafka input and forwards events to Elasticsearch. Install the agent on a host that can reach your Kafka brokers (same VPC or routed network, firewall rules allowing outbound connections to broker listeners).

### Set up steps for Kafka

1. Identify **bootstrap broker addresses** (for example `kafka1:9092`) and the **topic names** to consume.
2. Choose a unique **consumer group id** (`group_id`) for this policy integration—duplicate group membership affects partition assignment when multiple agents share the same group.
3. If the cluster uses TLS or SASL, gather certificates, credentials, or Kerberos configuration paths before editing the integration.

### Set up steps in Kibana

1. Go to **Management → Integrations**.
2. Search for **Custom Kafka Logs** and open it.
3. Click **Add Custom Kafka Logs** (or add the integration to an existing policy).
4. Configure the main options:
   - **Hosts**: Bootstrap servers for the Kafka cluster.
   - **Topics**: Topics to subscribe to.
   - **Group ID**: Consumer group for this input.
   - **Dataset name**: Target dataset (default `kafka_log.generic`).
   - **Client ID**, **Kafka protocol version**, **initial offset**, fetch/rebalance tuning: expand **Advanced options** when needed.
5. Configure **SSL**, **SASL**, or **Kerberos** under advanced sections if your brokers require them.
6. Optionally set **Parsers** (for example NDJSON) or **Processors**, and **Tags**.
7. Optionally set **Ingest Pipeline** to an Elasticsearch pipeline ID for server-side processing.
8. Save the policy and confirm the agent receives the updated configuration.

### Validation

1. Produce a test message to one of the configured topics (use your usual producer tooling or `kafka-console-producer`).
2. In Kibana, open **Analytics → Discover** and select a logs-related data view (for example `logs-*`).
3. Filter with KQL, for example: `data_stream.dataset : "kafka_log.generic"` — adjust to match your configured **Dataset name** (default `kafka_log.generic`).
4. Confirm fields such as `message`, `kafka.topic`, `input.type` (`kafka`), and timestamps look correct.

## Troubleshooting

For help with Elastic ingest tools, refer to [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

- **Connection or timeout errors**: Verify broker addresses, ports, TLS (`ssl.enabled`), and that firewalls allow outbound traffic from the agent host to every bootstrap broker.
- **Authentication failures**: Confirm SASL mechanism, username/password, or Kerberos settings align with the broker, check broker logs for `Authentication failed` or similar.
- **No documents in Discover**: Confirm the agent is healthy, the policy applied, and the **Dataset name** matches your Discover filter. Dataset names **must not** contain hyphens.
- **Duplicate or competing consumers**: Using the same `group_id` on many agents splits partitions across them by design, use distinct groups if you need full duplicate reads.
- **Offset / replay behavior**: `initial_offset` (for example `oldest` vs `newest`) affects where consumption starts for new groups. Changing `group_id` starts a new consumer group offset state.
- **Parsing issues**: If JSON or multiline payloads look wrong, review **Parsers** and consider an Elasticsearch **Ingest Pipeline** for complex structures.

## Performance and scaling

For architectures used to scale ingest, refer to [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures).

- **Throughput**: Kafka throughput scales with **partitions** and consumer parallelism, multiple agents with the **same** `group_id` share partitions (one consumer per partition per group).
- **Fetch settings**: Tune **fetch** sizes and **max_wait_time** in advanced options if you need higher batching or lower latency—balance broker load and agent memory.
- **Multiple integrations**: Separate policies or dataset names help isolate indices and retention for different topic groups.
- **Elasticsearch**: Size your cluster for the volume of documents and consider ingest pipelines and index lifecycle policies for hot/warm tiers.

## Reference

Refer to the [ECS field reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for ECS fields.

Additional documentation:

- [Filebeat Kafka input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-kafka.html)
- [Filebeat SSL settings](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config)
