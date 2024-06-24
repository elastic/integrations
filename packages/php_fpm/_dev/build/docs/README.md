# PHP-FPM Integration

## Overview

PHP-FPM (FastCGI Process Manager) is a web tool used to speed up the performance of a website. It is much faster than traditional CGI based methods and has the ability to handle tremendous loads simultaneously.

Use the PHP-FPM integration to:

- Collect metrics related to the pool and process.
- Create visualizations to monitor, measure, and analyze usage trends and key data, deriving business insights.
- Create alerts to reduce the MTTD and MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The PHP-FPM integration collects metrics data.

Metrics provide insight into the statistics of the PHP-FPM. The Metrics data streams collected by the PHP-FPM integration include [pool](https://www.php.net/manual/en/fpm.status.php#:~:text=Basic%20information%20%2D%20Always%20displayed%20on%20the%20status%20page) and [process](https://www.php.net/manual/en/fpm.status.php#:~:text=Per%2Dprocess%20information%20%2D%20only%20displayed%20in%20full%20output%20mode) so that the user can monitor and troubleshoot the performance of the PHP-FPM instances.

Data streams:
- `pool`: Collects information related to the connection handling, queue metrics, process manager configuration, process activity and performance indicators.
- `process`: Collects information related to the request metrics, the latest CPU and memory usage and the current running state.

Note:
- Users can monitor and view the metrics inside the ingested documents for PHP-FPM in the `logs-*` index pattern in `Discover`.

## Compatibility

This integration has been tested against `v8.2` and `v8.1` standalone versions of PHP-FPM.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from PHP-FPM, you must know the host(s) and status path of the PHP-FPM instance.

Host configuration format: `http[s]://host[:port]`

Example host configuration: `http://localhost:8080`

Status path configuration format: `/path`

Example Status path configuration: `/status`

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting Started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Validation

After successfully configuring the integration, click on the *Assets* tab of the PHP-FPM integration to display the available dashboards. Select the dashboard for your configured data stream, which should be populated with the required data.

## Troubleshooting

If `host.ip` appears conflicted under the ``logs-*`` data view, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the indices of the ``Pool`` and ``Process`` data streams.

## Metrics reference

### Pool

The `pool` data stream collects metrics related to the setup and contents of the FPM status page.

{{event "pool"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "pool"}}

### Process

The `process` data stream collects metrics related to the request duration, content length, process state, etc.

{{event "process"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "process"}}