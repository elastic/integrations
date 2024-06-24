# HAProxy Integration

This integration periodically fetches logs and metrics from [HAProxy](https://www.haproxy.org/) servers.

## Compatibility

The `log` dataset was tested with logs from HAProxy 1.8, 1.9 and 2.0, 2.6 running on a Debian. It is not available on Windows. 
The integration supports the default log patterns below:
* [Default log format](https://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.1)
* [TCP log format](https://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.2)
* [HTTP log format](https://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.3)
* [HTTPS log format](https://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.4)
* [Error log format](https://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.5)

The `info` and `stat` datasets were tested with tested with HAProxy versions from 1.6, 1.7, 1.8 to 2.0. 

## Troubleshooting

If `source.address` is shown conflicted under ``metrics-*`` data view, then this issue can be solved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds-reindex.html) the `stat` data stream indices.

## Logs

### log

The `log` dataset collects the HAProxy application logs.

{{event "log"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "log"}}


## Metrics

### info

The HAProxy `info` dataset collects general information about HAProxy processes.

{{event "info"}}

The fields reported are:

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "info"}}

### stat

The HAProxy `stat` metricset collects stat fields from HAProxy processes.

See section "9.1. CSV format" of the official [HAProxy Management Guide](http://www.haproxy.org/download/2.0/doc/management.txt) for a full list of stat fields.

{{event "stat"}}

The fields reported are:

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "stat"}}
