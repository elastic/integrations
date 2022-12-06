# Cisco Integration (Deprecated)

> Warning: This integration is deprecated. Please use one of the other Cisco integrations
> that are specific to a Cisco product.

This integration is for [Cisco network devices](https://developer.cisco.com/docs/) logs. It includes the following datasets for receiving logs over syslog or read from a file:

- `asa` dataset: supports Cisco ASA firewall logs.
- `ftd` dataset: supports Cisco Firepower Threat Defense logs.
- `ios` dataset: supports Cisco IOS router and switch logs.
- `nexus` fileset: supports Cisco Nexus switch logs.
- `meraki` dataset: supports Cisco Meraki logs.

## Compatibility

## Logs

### ASA

The `asa` dataset collects the Cisco firewall logs.

{{event "asa"}}

{{fields "asa"}}

### FTD

The `ftd` dataset collects the Firepower Threat Defense logs.

{{event "ftd"}}

{{fields "ftd"}}

### IOS

The `ios` dataset collects the Cisco IOS router and switch logs.

{{event "ios"}}

{{fields "ios"}}

### Nexus

The `nexus` dataset collects Cisco Nexus logs.

{{event "nexus"}}

{{fields "nexus"}}

### Meraki

The `meraki` dataset collects Cisco Meraki logs.

{{event "meraki"}}

{{fields "meraki"}}
