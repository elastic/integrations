# Sophos Integration

The Sophos integration collects and parses logs from Sophos Products.

Currently, it accepts logs in syslog format or from a file for the following devices:

- `utm` dataset: supports [Unified Threat Management](https://www.sophos.com/en-us/support/documentation/sophos-utm) (formerly known as Astaro Security Gateway) logs.
- `xg` dataset: supports [Sophos XG SFOS logs](https://docs.sophos.com/nsg/sophos-firewall/17.5/Help/en-us/webhelp/onlinehelp/nsg/sfos/concepts/Logs.html).

To configure a remote syslog destination, please reference the [SophosXG/SFOS Documentation](https://community.sophos.com/kb/en-us/123184).

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

{{event "xg"}}

{{fields "xg"}}
