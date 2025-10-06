# ActiveMQ Integration

## Overview

Apache [ActiveMQ](https://activemq.apache.org) is the most popular open-source, multi-protocol, Java-based message broker. It supports industry-standard protocols, facilitating client choices across various languages and platforms, including JavaScript, C, C++, Python, .Net, and more. ActiveMQ enables seamless integration of multi-platform applications through the widely used AMQP protocol and allows efficient message exchange between web applications using STOMP over WebSockets. Additionally, it supports IoT device management via MQTT and provides flexibility to accommodate any messaging use case, supporting both existing JMS infrastructure and beyond.

Use the ActiveMQ integration to:

- Collect audit and application logs and gather broker, queue, and topic metrics.
- Create visualizations to monitor usage trends, analyze key data, and derive business insights.
- Create alerts that reduce MTTD and MTTR by referencing relevant logs during troubleshooting.

## Data streams

The ActiveMQ integration collects log and metric data.

Logs help you keep a record of events that happen on your machine. The `audit` and `log` data streams let users track usernames, audit threads, messages, caller names, logging requests, and other logging events.

Metrics provide insight into ActiveMQ statistics. The `broker`, `queue`, and `topic` data streams help monitor and troubleshoot the performance of the ActiveMQ instance.

Data streams:
- `audit`: Collects information related to usernames, audit threads, and messages.
- `broker`: Collects statistics on enqueued and dequeued messages, consumers, producers, and memory usage (broker, store, temp).
- `log`: Collects information related to the startup and shutdown of the ActiveMQ application server, the deployment of new applications, or the failure of one or more subsystems.
- `queue`: Collects statistics on queue names and sizes, exchanged messages, and the number of producers and consumers.
- `topic`: Collects statistics on exchanged messages, consumers, producers, and memory usage.

Note:
- You can monitor logs in the ingested documents for ActiveMQ by using the `logs-*` index pattern in `Discover`, and view metrics with the `metrics-*` index pattern.

## Compatibility

This integration has been tested against ActiveMQ 5.17.1 (independent from the operating system).

## What do I need to use this integration?

You need Elasticsearch to store and search your data and Kibana to visualize and manage it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting Started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

## Supported Log Formats

Here are the supported log formats for the audit and ActiveMQ logs in the ActiveMQ instance:

### Audit Logs

```
%-5p | %m | %t%n
```

Here is the breakdown of the pattern:

- %-5p: Represents the log level left-aligned with a width of 5 characters. The - signifies left alignment.
- %m: Represents the log message.
- %t%n: Represents the thread name (%t) followed by a newline (%n).

### ActiveMQ Logs

```
%d | %-5p | %m | %c | %t%n%throwable{full}
```

Here is the breakdown of the pattern:
- %d: Represents the date and time of the log event in ISO8601 format.
- %-5p: Represents the log level left-aligned with a width of 5 characters. The - signifies left alignment.
- %m: Represents the log message.
- %c: Represents the logger category (class name).
- %t%n: Represents the thread name (%t) followed by a newline (%n).
- %throwable{full}: Represents the full stack trace if an exception is attached to the log entry.

## Validation

After the integration is successfully configured, the Assets tab of the ActiveMQ Integration displays a list of available dashboards. Select the dashboard for your configured data stream. It should be populated with the required data.

## Troubleshooting

If `host.ip` appears as conflicted in the ``logs-*`` data view, [reindex](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Audit`` and ``Log`` data stream indices.

If `host.ip` appears as conflicted in the ``metrics-*`` data view, [reindex](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds-reindex.html) the ``Broker``, ``Queue`` and ``Topic`` data stream indices.

## Logs

### ActiveMQ Logs

These logs are system logs of ActiveMQ.

{{event "log"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "log"}}

### Audit Logs

In secured environments, every user management action must be logged. ActiveMQ implements audit logging, which means that every management action made through the JMX or Web Console management interfaces is logged and available for later inspection.

{{event "audit"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "audit"}}

## Metrics

### Broker Metrics

ActiveMQ brokers serve as implementations of the Java Messaging Service (JMS), a Java specification facilitating the seamless exchange of data between applications. Metrics provide insights into statistics such as enqueued and dequeued messages, as well as details on consumers, producers, and memory usage (broker, store, temp).

{{event "broker"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "broker"}}

### Queue Metrics

Queues are FIFO (first-in, first-out) pipelines of messages produced and consumed by brokers and clients. Producers create messages and push them onto these queues. Then, those messages are polled and collected by consumer applications, one message at a time. Metrics show statistics on exchanged messages, consumers, producers, and memory usage.

{{event "queue"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "queue"}}

### Topic Metrics

Topics are subscription-based message broadcast channels. When a producing application sends a message, multiple recipients who are 'subscribed' to that topic receive a broadcast of the message. Metrics show statistics on exchanged messages, consumers, producers, and memory usage.

{{event "topic"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "topic"}}
