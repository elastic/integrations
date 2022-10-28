# Fortinet FortiEDR Integration

This integration is for Fortinet FortiEDR logs sent in the syslog format.

## Configuration

The Fortinet FortiEDR integration requires that the **Send Syslog Notification** opion be turned on in the FortiEDR Playbook policy that includes the devices that are to be monitored by the integration.

### Log

The `log` dataset collects Fortinet FortiEDR logs.

{{event "log"}}

{{fields "log"}}