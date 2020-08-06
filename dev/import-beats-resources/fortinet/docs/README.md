# Fortinet Integration

This integration is for Fortinet FortiOS logs sent in the syslog format. It includes the following datasets for receiving logs:

- `firewall` dataset: consists of Fortinet FortiGate logs.

## Compatibility

This integration has been tested against FortiOS version 6.0.x and 6.2.x. Versions above this are expected to work but have not been tested.

## Logs

### Firewall

Contains log entries from Fortinet FortiGate applicances.

{{fields "firewall"}}
