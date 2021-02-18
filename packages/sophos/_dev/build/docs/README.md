# Sophos Integration

The Sophos integration collects and parses logs from Sophos Products.

Currently it accepts logs in syslog format or from a file for the following devices:

- `utm` dataset: supports Astaro Security Gateway logs.
- `xg` dataset: supports Sophos XG SFOS logs.

To configure a remote syslog destination, please reference the [SophosXG/SFOS Documentation](https://community.sophos.com/kb/en-us/123184).

The syslog format choosen should be `Default`.

## Compatibility

This module has been tested against SFOS version 17.5.x and 18.0.x.
Versions above this are expected to work but have not been tested.

## Logs

### Utm log

The `utm` dataset collects Astaro Security Gateway logs.

{{fields "utm"}}

### XG log

This is the Sophos `xg` dataset.

{{event "xg"}}

{{fields "xg"}}
