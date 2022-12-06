# Fortinet Integration (Deprecated)

_This integration is deprecated. Please use one of the other Fortinet integrations
that are specific to a Fortinet product._

This integration is for Fortinet [FortiOS](https://docs.fortinet.com/product/fortigate/6.2) and [FortiClient](https://docs.fortinet.com/product/forticlient/) Endpoint logs sent in the syslog format. It includes the following datasets for receiving logs:

- `firewall` dataset: consists of Fortinet FortiGate logs.
- `clientendpoint` dataset: supports Fortinet FortiClient Endpoint Security logs.
- `fortimail` dataset: supports Fortinet FortiMail logs.
- `fortimanager` dataset: supports Fortinet Manager/Analyzer logs.

## Compatibility

This integration has been tested against FortiOS version 6.0.x and 6.2.x. Versions above this are expected to work but have not been tested.

## Logs

### Firewall

Contains log entries from Fortinet FortiGate applicances.

{{event "firewall"}}

{{fields "firewall"}}

### Clientendpoint

The `clientendpoint` dataset collects Fortinet FortiClient Endpoint Security logs.

{{event "clientendpoint"}}

{{fields "clientendpoint"}}

### Fortimail

The `fortimail` dataset collects Fortinet FortiMail logs.

{{event "fortimail"}}

{{fields "fortimail"}}

### Fortimanager

The `fortimanager` dataset collects Fortinet Manager/Analyzer logs.

{{event "fortimanager"}}

{{fields "fortimanager"}}
