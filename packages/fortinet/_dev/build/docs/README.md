# Fortinet Integration

This integration is for Fortinet FortiOS and FortiClient Endpoint logs sent in the syslog format. It includes the following datasets for receiving logs:

- `firewall` dataset: consists of Fortinet FortiGate logs.
- `clientendpoint` dataset: supports Fortinet FortiClient Endpoint Security logs.
- `fortimail` dataset: supports Fortinet FortiMail logs.
- `fortimanager` dataset: supports Fortinet Manager/Analyzer logs.

## Compatibility

This integration has been tested against FortiOS version 6.0.x and 6.2.x. Versions above this are expected to work but have not been tested.

## Logs

### Firewall

Contains log entries from Fortinet FortiGate applicances.

{{fields "firewall"}}

### Clientendpoint

The `clientendpoint` dataset collects Fortinet FortiClient Endpoint Security logs.

{{fields "clientendpoint"}}

### Fortimail

The `fortimail` dataset collects Fortinet FortiMail logs.

{{fields "fortimail"}}

### Fortimanager

The `fortimanager` dataset collects Fortinet Manager/Analyzer logs.

{{fields "fortimanager"}}
