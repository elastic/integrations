# Fortinet FortiProxy Integration

This integration is for Fortinet FortiProxy logs sent in the syslog format.

## Compatibility

This integration has been tested against FortiProxy versions 7.x up to 7.4.3. Newer versions are expected to work but have not been tested.

## Note

- When using the TCP input, be careful with the configured TCP framing. According to the [FortiProxy reference](https://docs.fortinet.com/document/fortiproxy/7.4.3/cli-reference/294620/config-log-syslogd-setting), framing should be set to `rfc6587` when the syslog mode is `reliable`.

## Configuration

On Fortinet FortiProxy, `syslogd` should be configured for either `udp` or `reliable` modes and use the `default` format. 

| Setting  | Value          |
|----------|----------------|
| mode     | udp / reliable |
| format   | default        |

### Log

The `log` dataset collects Fortinet FortiProxy logs.

{{event "log"}}

{{fields "log"}}
