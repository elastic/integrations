# OSQuery Integration

The OSQuery integration collects and decodes the result logs written by
[`osqueryd`](https://osquery.readthedocs.io/en/latest/introduction/using-osqueryd/)
in the JSON format. To set up `osqueryd` follow the osquery installation
instructions for your operating system and configure the `filesystem` logging
driver (the default). Make sure UTC timestamps are enabled.

## Compatibility

The  OSQuery integration was tested with logs from osquery version 2.10.2.
Since the results are written in the JSON format, it is likely that this module
works with any version of osquery.

This module is available on Linux, macOS, and Windows.

## Logs

### OSQuery result

This is the OSQuery `result` dataset.

{{event "result"}}

{{fields "result"}}
