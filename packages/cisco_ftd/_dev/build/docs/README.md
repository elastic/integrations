# Cisco FTD Integration

This integration is for [Cisco](https://www.cisco.com/c/en/us/support/security/index.html) Firepower Threat Defence (FTD) device's logs. The package processes syslog messages from Cisco Firepower devices 

It includes the following datasets for receiving logs over syslog or read from a file:

- `log` dataset: supports Cisco Firepower Threat Defense (FTD) logs.

## Configuration

Cisco provides a range of Firepower devices, which may have different configuration steps. We recommend users navigate to the device specific configuration page, and search for/go to the "FTD Logging" or "Configure Logging on FTD" page for the specific device.

## Logs

### FTD

The `log` dataset collects the Cisco Firepower Threat Defense (FTD) logs.

{{event "log"}}

{{fields "log"}}
