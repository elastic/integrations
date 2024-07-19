# ActiveMQ Integration

## Overview

Apache [ActiveMQ](https://activemq.apache.org) is the most popular open-source, multi-protocol, Java-based message broker. It supports industry-standard protocols, facilitating client choices across various languages and platforms, including JavaScript, C, C++, Python, .Net, and more. ActiveMQ enables seamless integration of multi-platform applications through the widely used AMQP protocol and allows efficient message exchange between web applications using STOMP over WebSockets. Additionally, it supports IoT device management via MQTT and provides flexibility to accommodate any messaging use case, supporting both existing JMS infrastructure and beyond.

Use the ActiveMQ integration to:

- Collect logs related to the audit and ActiveMQ instance and collect metrics related to the broker, queue and topic.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The ActiveMQ integration collects logs and metrics data.

Logs help you keep a record of events that happen on your machine. The `Log` data streams collected by ActiveMQ integration are `audit` and `log` so that users can keep track of the username, audit threads, messages, name of the caller issuing the logging requests, logging event etc.

Metrics give you insight into the statistics of the ActiveMQ. The `Metric` data streams collected by the ActiveMQ integration are `broker`, `queue` and `topic` so that the user can monitor and troubleshoot the performance of the ActiveMQ instance.

Data streams:
- `audit`: Collects information related to the username, audit threads and messages.
- `broker`: Collects information related to the statistics of enqueued and dequeued messages, consumers, producers and memory usage (broker, store, temp).
- `log`: Collects information related to the startup and shutdown of the ActiveMQ application server, the deployment of new applications, or the failure of one or more subsystems.
- `queue`: Collects information related to the statistics of queue name and size, exchanged messages and number of producers and consumers.
- `topic`: Collects information related to the statistics of exchanged messages, consumers, producers and memory usage.

Note:
- Users can monitor and see the log inside the ingested documents for ActiveMQ in the `logs-*` index pattern from `Discover`, and for metrics, the index pattern is `metrics-*`.

## Compatibility

This integration has been tested against ActiveMQ 5.17.1 (independent from the operating system).

## Prerequisites

You need Elasticsearch to store and search your data and Kibana to visualize and manage it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting Started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Supported Log Formats

Here are the supported log format for the Audit logs and ActiveMQ logs in the ActiveMQ instance,

### Audit Logs

```
%-5p | %m | %t%n
```

Here is the breakdown of the pattern:

- %-5p: This part represents the log level left-aligned with a width of 5 characters. The - signifies left alignment.

- %m: This part represents the log message.

- %t%n: This part represents the thread name (%t) followed by a newline (%n).

### ActiveMQ Logs

```
%d | %-5p | %m | %c | %t%n%throwable{full}
```

Here is the breakdown of the pattern:
- %d: This part represents the date and time of the log event in the ISO8601 format.

- %-5p: This part represents the log level left-aligned with a width of 5 characters. The - signifies left alignment.

- %m: This part represents the log message.

- %c: This part represents the logger category (class name).

- %t%n: This part represents the thread name (%t) followed by a newline (%n).

- %throwable{full}: This part represents the full stack trace if an exception is attached to the log entry.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the ActiveMQ Integration should display a list of available dashboards. Click on the dashboard available for your configured data stream. It should be populated with the required data.

## Troubleshooting

If `host.ip` is shown conflicted under ``logs-*`` data view, then this issue can be solved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Audit`` and ``Log`` data stream's indices.

If `host.ip` is shown conflicted under ``metrics-*`` data view, then this issue can be solved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds-reindex.html) the ``Broker``, ``Queue`` and ``Topic`` data stream's indices.

## Logs

### ActiveMQ Logs

These logs are System logs of ActiveMQ.

{{event "log"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "log"}}

### Audit Logs

In secured environments, it is required to log every user management action. ActiveMQ implements audit logging, which means that every management action made through JMX or Web Console management interface is logged and available for later inspection.

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

Queues are FIFO (first-in, first-out) pipelines of messages produced and consumed by brokers and clients. Producers create messages and push them onto these queues. Then, those messages are polled and collected by consumer applications, one message at a time. Metrics show statistics of exchanged messages, consumers, producers and memory usage.

{{event "queue"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "queue"}}

### Topic Metrics

Topics are subscription-based message broadcast channels. When a producing application sends a message, multiple recipients who are 'subscribed' to that topic receive a broadcast of the message. Metrics show statistics of exchanged messages, consumers, producers and memory usage.

{{event "topic"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "topic"}}
