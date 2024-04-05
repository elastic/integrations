# Fortinet FortiGate Integration

This integration is for Fortinet FortiGate logs sent in the syslog format.

## Compatibility

This integration has been tested against FortiOS versions 6.x and 7.x up to 7.4.1. Newer versions are expected to work but have not been tested.

## Note

- When using the TCP input, be careful with the configured TCP framing. According to the [Fortigate reference](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/405620/config-log-syslogd-setting), framing should be set to `rfc6587` when the syslog mode is reliable.

### Log

The `log` dataset collects Fortinet FortiGate logs.

{{event "log"}}

{{fields "log"}}