# Logstash

The `logstash` package collects metrics and logs of Logstash.

## Compatibility

The `logstash` package works with Logstash 7.3.0 and later

## Logs

Logstash package supports the plain text format and the JSON format. Also, two types of 
logs can be activated with the Logstash package:

* `log` collects and parses the logs that Logstash writes to disk.
* `slowlog` parses the logstash slowlog (make sure to configure the Logstash slowlog option).

### Log

{{event "log"}}

#### Known issues

When using the `log` data stream to parse plaintext logs, if a multiline plaintext log contains an embedded JSON object such that
the JSON object starts on a new line, the fileset may not parse the multiline plaintext log event correctly.

### Slowlog

{{event "slowlog"}}

## Metrics

Logstash metric related data streams works with Logstash 7.3.0 and later.

### Node

{{event "node"}}

{{fields "node"}}

### Node Stats

{{event "node_stats"}}

{{fields "node_stats"}}