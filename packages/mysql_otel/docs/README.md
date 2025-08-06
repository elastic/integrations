<!-- Use this template language as a starting point, replacing {placeholder text} with details about the integration. -->
<!-- Find more detailed documentation guidelines in https://github.com/elastic/integrations/blob/main/docs/documentation_guidelines.md -->

# MYSQL metrics for OpenTelemetry Collector

<!-- The MYSQL OTEL integration allows you to monitor {name of service}. {name of service} is {describe service}.

Use the MYSQL OTEL integration to {purpose}. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference {data stream type} when troubleshooting an issue.

For example, if you wanted to {sample use case} you could {action}. Then you can {visualize|alert|troubleshoot} by {action}. -->

## Data streams

<!-- The MYSQL OTEL integration collects {one|two} type{s} of data streams: {logs and/or metrics}. -->

<!-- If applicable -->
<!-- **Logs** help you keep a record of events happening in {service}.
Log data streams collected by the {name} integration include {sample data stream(s)} and more. See more details in the [Logs](#logs-reference). -->

<!-- If applicable -->
<!-- **Metrics** give you insight into the state of {service}.
Metric data streams collected by the {name} integration include {sample data stream(s)} and more. See more details in the [Metrics](#metrics-reference). -->

<!-- Optional: Any additional notes on data streams -->

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

The content pack has been tested with [OpenTelemetry MySQL receiver v0.129.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.129.0/receiver/mysqlreceiver/README.md).

Databases tested against:
- MySQL 8.0, 9.4
- MariaDB 10.11, 11.8

<!--
	Optional: Other requirements including:
	* System compatibility
	* Supported versions of third-party products
	* Permissions needed
	* Anything else that could block a user from successfully using the integration
-->

## Setup

<!-- Any prerequisite instructions -->

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

<!-- Additional set up instructions -->

The following metrics should be enabled in the `mysqlreceiver` configuration:

For Database Overview dashboard:
```yaml
mysql.query.client.count:
  enabled: true
mysql.client.network.io:
  enabled: true
mysql.commands:
  enabled: true
mysql.max_used_connections:
  enabled: true
mysql.connection.errors:
  enabled: true
mysql.table_open_cache:
  enabled: true
```

For Replica Status dashboard:
```yaml
mysql.replica.sql_delay:
  enabled: true
mysql.replica.time_behind_source:
  enabled: true
```

<!-- If applicable -->
<!-- ## Logs reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

<!-- Optional -->
<!-- #### Example

An example event for `{data stream name}` looks as following:

{code block with example} -->

<!-- #### Exported fields

{insert table} -->

<!-- If applicable -->
<!-- ## Metrics reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

<!-- Optional -->
<!-- #### Example

An example event for `{data stream name}` looks as following:

{code block with example} -->

<!-- #### Exported fields

{insert table} -->
