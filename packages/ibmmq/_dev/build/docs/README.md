# IBM MQ integration

## Overview

[IBM MQ](https://www.ibm.com/docs/en/ibm-mq) is a message-oriented middleware for secure and reliable communication between distributed systems. It supports messaging patterns like queuing, publish/subscribe, and assures message delivery without a direct connection between sender and receiver.

Use the IBM MQ integration to:

- Collect Queue Manager performance metrics and error logs, providing insights into messages, topics, subscriptions, and operational events.
- Streamline observability by ingesting IBM MQ metrics and logs into Elasticsearch, enabling centralized monitoring and analysis of IBM MQ environments.
- Enhance system reliability through real-time analysis and proactive alerting based on collected metrics and logs.

## Data streams

The IBM MQ integration collects logs and metrics data.

Logs provide insights into operations and events within the IBM MQ environment. The errorlog data stream collected by the IBM MQ integration enables users to track errors and warnings, understand their causes, and address issues related to message handling and processing.

Metrics provide statistics on the performance and health of IBM MQ. The qmgr data stream collected by the IBM MQ integration covers Queue Manager performance metrics, including message throughput, topics, subscriptions, and other operational statistics. This allows users to monitor and optimize the performance and reliability of their IBM MQ instances.

Data streams:

- `errorlog`: Collects error and warning messages from the IBM MQ Queue Manager, providing details like error descriptions, actions, explanations, and error codes.
- `qmgr`: Collects performance metrics from the Queue Manager, including message throughput, topics, subscriptions, and other vital operational statistics.

Note:
- Users can monitor and view logs within the ingested documents for IBM MQ using the logs-* index pattern in Discover. For metrics, the corresponding index pattern is metrics-*.

## Compatibility

This integration has been tested against `IBM MQ v9.1` and `IBM MQ v9.2`. The ibmmq `qmgr` data stream is compatible with a containerized distribution of IBM MQ (since version 9.1.0).

## Prerequisites

Users require Elasticsearch for storing and searching their data, and Kibana for visualizing and managing it. They can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on their own hardware.

In order to ingest data from IBM MQ:

- User should specify Hostname and Port (example: localhost:9157) of Prometheus endpoint (/metrics).
- User should specify the path of IBM MQ Queue Manager Error logs. (default paths: `/var/mqm/errors/*.LOG` and `/var/mqm/qmgrs/*/errors/*.LOG`)

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Steps to setup Prometheus

Enable Metrics in IBM MQ: Ensure that the `MQ_ENABLE_METRICS` environment variable is set to true for user's IBM MQ service to expose the metrics endpoint.

The Docker image starts the runmqserver process, which spawns the HTTP server exposing metrics in Prometheus format on port `9157`.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the IBM MQ Integration should display a list of available dashboards. Click on the dashboard available for user's configured data stream. It should be populated with the required data.

## Troubleshooting

- In version 1.3.0 of this integration, the field type of `ibmmq.errorlog.error.description` has been changed from `text` to `keyword `. It is therefore recommended to update the `ibmmq.errorlog.error.description` field to use the `keyword` type wherever it is being used. This can be achieved by using the [Update By Query API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-update-by-query.html#docs-update-by-query-api-ingest-pipeline), allowing for a seamless transition of the field type from  `text` to `keyword` facross all relevant documents.

## Metrics reference

### Queue Manager performance metrics

The `qmgr` data stream collects [performance metrics of Queue Manager](https://www.ibm.com/docs/en/ibm-mq/9.2?topic=operator-metrics-published-when-using-mq) like messages, topics, subscriptions and calls.

{{event "qmgr"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "qmgr"}}

## Logs reference

### Queue Manager Error logs

The `errorlog` data stream collects [Error logs of Queue Manager](https://www.site24x7.com/help/log-management/ibm-mq-error-logs.html) which include the description, action, explanation and code of the error.

{{event "errorlog"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "errorlog"}}
