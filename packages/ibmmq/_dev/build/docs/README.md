# IBM MQ integration

The IBM MQ Integration is used to fetch observability data from [IBM MQ web endpoints](https://www.ibm.com/docs/en/ibm-mq) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `IBM MQ v9.1` and `IBM MQ v9.2`.

## Requirements

In order to ingest data from IBM MQ:

- User should specify Hostname and Port (example: localhost:9157) of Prometheus endpoint (/metrics).

## Metrics

### Queue Manager performance metrics

The `qmgr` data stream collects [performance metrics of Queue Manager](https://www.ibm.com/docs/en/ibm-mq/9.2?topic=operator-metrics-published-when-using-mq) like messages, topics, subscriptions and calls.

{{event "qmgr"}}

{{fields "qmgr"}}
