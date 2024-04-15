# Cisco IOS Integration

This integration is for [Cisco IOS network devices'](https://developer.cisco.com/docs/) logs. It includes the following
datasets for receiving logs over syslog or read from a file:

## Log Configuration

The Cisco appliance may be [configured in a variety of ways](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html) to include or exclude fields. The Cisco IOS Integration expects the host name and timestamp to be present. If the `sequence-number` is configured to be present it will be used to populate `event.sequence`. If it is not, but `message-count` is configured to be present that field will be used in its place.

Timestamps and timezones are by default not enabled for Cisco IOS logging, to enable them please use `service timestamps log datetime`. For more information, please see the [Timestamp documentation](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html#wp1054710)

The format of timezones added to Cisco IOS logs does not always match the expected formats used in common programming languages, and therefore 2 options have been added to the integration configuration:

1. `Timezone` - This option allows the user to specify the timezone that the logs will be translated to. This will enforce all logs sent to the integration to the same timezone. This option is recommended for most users and default is `UTC`.

2. `Timezone Map` - This option is for users who have logs from multiple timezones and want to translate them to the correct timezone. This option allows the user to specify a map of timezones to translate from and to. This option is recommended for advanced users who have logs from multiple timezones being sent to the same integration instance. If the timezone in a Cisco IOS log entry does not match any of the configured mappings, the log will fall back to the timezone specified in the `Timezone` option, and also defaults to `UTC`.

If log messages are relayed resulting in additional syslog header prefixes or other text, this text must be removed for ingestion to be successful. This may be done by adding an appropriate Beats processor to the configuration.

### IOS

The `log` dataset collects the Cisco IOS router and switch logs.

{{event "log"}}

{{fields "log"}}