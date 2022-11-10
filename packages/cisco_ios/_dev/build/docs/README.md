# Cisco IOS Integration

This integration is for [Cisco IOS network devices'](https://developer.cisco.com/docs/) logs. It includes the following
datasets for receiving logs over syslog or read from a file:

## Log Configuration

The Cisco appliance may be [configured in a variety of ways](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html) to include or exclude fields. The Cisco IOS Integration expects the host name and timestamp to be present. If the `sequence-number` is configured to be present it will be used to populate `event.sequence`. If it is not, but `message-count` is configured to be present that field will be used in its place.

### IOS

The `log` dataset collects the Cisco IOS router and switch logs.

{{event "log"}}

{{fields "log"}}