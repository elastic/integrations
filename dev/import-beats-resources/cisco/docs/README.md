# Cisco Integration

This integration is for Cisco network device's logs. It includes the following
datasets for receiving logs over syslog or read from a file:

- `asa` dataset: supports Cisco ASA firewall logs.
- `ftd` dataset: supports Cisco Firepower Threat Defense logs.
- `ios` dataset: supports Cisco IOS router and switch logs.

## Compatibility

## Logs

### ASA

The `asa` dataset collects the Cisco firewall logs.

{{fields "asa"}}

### FTD

The `ftd` dataset collects the Firepower Threat Defense logs.

{{fields "ftd"}}

### IOS

The `ios` dataset collects the Cisco IOS router and switch logs.

{{fields "ios"}}