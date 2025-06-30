# Cyberark Privileged Threat Analytics

CyberArk's Privileged Threat Analytics (PTA) continuously monitors the use of privileged accounts that are managed in the CyberArk Privileged Access Security (PAS) platform. This integration collects analytics from PTA's syslog via CEF-formatted logs.

### Configuration

Follow the steps described under [Send PTA syslog records to SIEM](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PTA/Outbound-Sending-%20PTA-syslog-Records-to-SIEM.htm) documentation to setup the integration:

- Sample syslog configuration for `systemparm.properties`:

```ini
[SYSLOG]
syslog_outbound=[{"siem": "Elastic", "format": "CEF", "host": "SIEM_MACHINE_ADDRESS", "port": 9301, "protocol": "TCP"}]
```

### Events

{{event "events"}}

{{fields "events"}}