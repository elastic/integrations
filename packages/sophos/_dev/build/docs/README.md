# Sophos Integration

The Sophos integration collects and parses logs from Sophos Products.

Currently it accepts logs in syslog format or from a file for the following devices:

- `utm` dataset: supports Astaro Security Gateway logs.
- `xg` dataset: supports Sophos XG SFOS logs.

To configure a remote syslog destination, please reference the [SophosXG/SFOS Documentation](https://community.sophos.com/kb/en-us/123184).

The syslog format chosen should be `Default`.

## Compatibility

This module has been tested against SFOS version 17.5.x and 18.0.x.
Versions above this are expected to work but have not been tested.

## Logs

### Utm log

The `utm` dataset collects Astaro Security Gateway logs.

{{fields "utm"}}

### XG log

This is the Sophos `xg` dataset. Reference information about the log formats
can be found in the [Sophos syslog guide](
https://docs.sophos.com/nsg/sophos-firewall/18.5/PDF/SF%20syslog%20guide%2018.5.pdf).

{{event "xg"}}

{{fields "xg"}}
