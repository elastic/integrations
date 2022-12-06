# Google Santa Integration

The Google Santa integration collects and parses logs from [Google Santa](https://github.com/google/santa), a security tool for macOS that monitors process executions and can blacklist/whitelist
binaries.

## Compatibility

The Google Santa integration was tested with logs from Santa 2022.4.

**Google Santa is available for MacOS only.**

The integration is by default configured to read logs from `/var/db/santa/santa.log`.

## Logs

### Google Santa log

This is the Google Santa `log` dataset.

{{event "log"}}

{{fields "log"}}
