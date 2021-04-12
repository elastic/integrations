# Synthetics integration

This integration creates and manages configuration for [Heartbeat monitors](https://www.elastic.co/guide/en/beats/heartbeat/current/configuration-heartbeat-options.html). 

## Compatibility

The Heartbeat datasets were tested with Heartbeat 7.12 and is expected to work with
all versions >= 7.12.

## Synthetics

### HTTP monitors

Fields for an http ping.

{{fields "http"}}

### TCP monitors

Fields for a tcp ping.

{{fields "tcp"}}

### ICMP monitors

Fields for an icmp ping.

{{fields "icmp"}}