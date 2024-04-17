# IBM MQ integration

The IBM MQ Integration is used to fetch observability data from [IBM MQ web endpoints](https://www.ibm.com/docs/en/ibm-mq) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `IBM MQ v9.1` and `IBM MQ v9.2`. The ibmmq `qmgr` data stream is compatible with a containerized distribution of IBM MQ (since version 9.1.0).
The Docker image starts the `runmqserver` process, which spawns the HTTP server exposing metrics in Prometheus format.

## Requirements

In order to ingest data from IBM MQ:

- User should specify Hostname and Port (example: localhost:9157) of Prometheus endpoint (/metrics).
- User should specify the path of IBM MQ Queue Manager Error logs. (default paths: `/var/mqm/errors/*.LOG` and `/var/mqm/qmgrs/*/errors/*.LOG`)

## Metrics

### Queue Manager performance metrics

The `qmgr` data stream collects [performance metrics of Queue Manager](https://www.ibm.com/docs/en/ibm-mq/9.2?topic=operator-metrics-published-when-using-mq) like messages, topics, subscriptions and calls.

{{event "qmgr"}}

{{fields "qmgr"}}

## Logs

### Queue Manager Error logs

The `errorlog` data stream collects [Error logs of Queue Manager](https://www.site24x7.com/help/log-management/ibm-mq-error-logs.html) which include the description, action, explanation and code of the error.

{{event "errorlog"}}

{{fields "errorlog"}}
