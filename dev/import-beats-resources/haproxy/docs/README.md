# HAProxy Integration

This integration periodically fetches logs and metrics from [HAProxy](https://www.haproxy.org/) servers.

## Compatibility

The `log` dataset was tested with logs from HAProxy 1.8, 1.9 and 2.0 running on a Debian. It is not available on Windows.

The `info` and `stat` datasets were tested with tested with HAProxy versions from 1.6, 1.7, 1.8 to 2.0. 

## Logs

### log

The `log` dataset collects the HAProxy application logs.

{{fields "log"}}

## Metrics

### info

The HAProxy `info` dataset collects general information about HAProxy processes.

{{event "info"}}

The fields reported are:

{{fields "info"}}

### stat

The HAProxy `stat` metricset collects stat fields from HAProxy processes.

See section "9.1. CSV format" of the official [HAProxy Management Guide](http://www.haproxy.org/download/2.0/doc/management.txt) for a full list of stat fields.

{{event "stat"}}

The fields reported are:

{{fields "stat"}}
