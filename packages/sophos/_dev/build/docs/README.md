# Sophos Integration

The Sophos integration collects and parses logs from Sophos Products.

Currently, it accepts logs in syslog format or from a file for the following devices:

- `utm` dataset: supports [Unified Threat Management](https://www.sophos.com/en-us/support/documentation/sophos-utm) (formerly known as Astaro Security Gateway) logs.
- `xg` dataset: supports [Sophos XG SFOS logs](https://docs.sophos.com/nsg/sophos-firewall/17.5/Help/en-us/webhelp/onlinehelp/nsg/sfos/concepts/Logs.html).

To configure a remote syslog destination, please reference the [SophosXG/SFOS Documentation](https://support.sophos.com/support/s/?language=en_US#t=AllTab&sort=relevancy).

The syslog format chosen should be `Default`.

## Compatibility

This module has been tested against SFOS version 17.5.x and 18.0.x.
Versions above this are expected to work but have not been tested.

## Logs

### UTM log

The `utm` dataset collects Unified Threat Management logs. Currently, it collects the following log categories: DNS, DHCP, HTTP and Packet Filter.

{{event "utm"}}

{{fields "utm"}}

### XG log

This is the Sophos `xg` dataset. Reference information about the log formats
can be found in the [Sophos syslog guide](
https://docs.sophos.com/nsg/sophos-firewall/18.5/PDF/SF%20syslog%20guide%2018.5.pdf).

#### Timezones

The format of timezones added to Sophos XG logs do not always match the expected formats used in common programming languages, and therefore 2 options have been added to the integration configuration:

1. `Timezone` - This option allows the user to specify the timezone that the logs will be translated to. This will enforce all logs sent to the integration to the same timezone. This option is recommended for most users and default is `UTC`.

2. `Timezone Map` - This option is for users who have logs from multiple timezones and want to translate them to the correct timezone. This option allows the user to specify a map of timezones to translate from and to. This option is recommended for advanced users who have logs from multiple timezones being sent to the same integration instance.

{{event "xg"}}

{{fields "xg"}}
