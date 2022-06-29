# IBM MQ integration

The IBM MQ Integration is used to fetch observability data from [IBM MQ web endpoints](https://www.ibm.com/docs/en/ibm-mq/9.2?topic=operator-metrics-published-when-using-mq) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `IBM MQ v9.2`.

## Requirements

In order to ingest data from IBM MQ:
- User must know the path of IBM MQ Queue Manager Error logs. (default paths: /var/mqm/errors/*.LOG and /var/mqm/qmgrs/*/errors/*.LOG)

## Logs

### Queue Manager Error logs

The `errorlog` data stream collects Error logs of Queue Manager like error description, error action, error explanation and error code.

{{event "errorlog"}}

{{fields "errorlog"}}
