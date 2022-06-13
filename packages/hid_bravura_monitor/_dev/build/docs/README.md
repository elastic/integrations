# Hitachi ID Bravura Monitor Integration

The Hitachi ID Bravura Monitor integration fetches and parses logs from a [Bravura Security Fabric](https://docs.hitachi-id.net/#/index/10/11)  instance.

When you run the integration, it performs the following tasks automatically:

* Sets the default paths to the log files (you can override the
defaults)

* Makes sure each multiline log event gets sent as a single event

* Uses ingest pipelines to parse and process the log lines, shaping the data into a structure suitable
for visualizing in Kibana

* Deploys dashboards for visualizing the log data

## Compatibility

The Hitachi ID Bravura Monitor integration was tested with logs from `Bravura Security Fabric 12.3.0` running on Windows Server 2016.

The integration was also tested with Bravura Security Fabric/IDM Suite 11.x, 12.x series.

This integration is not available for Linux or Mac.

The integration is by default configured to read logs files stored in the `default` instance log directory.
However it can be configured for any file path. See the following example.

```yaml
- id: b5e895ed-0726-4fa3-870c-464379d1c27b
    name: hid_bravura_monitor-1
    revision: 1
    type: filestream
    use_output: default
    meta:
      package:
        name: hid_bravura_monitor
        version: 1.0.0
    data_stream:
      namespace: default
    streams:
      - id: >-
          filestream-hid_bravura_monitor.log-b5e895ed-0726-4fa3-870c-464379d1c27b
        data_stream:
          dataset: hid_bravura_monitor.log
          type: logs
        paths:
          - 'C:/Program Files/Hitachi ID/IDM Suite/Logs/default*/idmsuite*.log'
        prospector.scanner.exclude_files:
          - .gz$
        line_terminator: carriage_return_line_feed
        tags: null
        processors:
          - add_fields:
              target: ''
              fields:
                hid_bravura_monitor.instancename: default
                hid_bravura_monitor.node: 0.0.0.0
                hid_bravura_monitor.environment: PRODUCTION
                hid_bravura_monitor.instancetype: Privilege-Identity-Password
                event.timezone: UTC
        parsers:
          - multiline:
              type: pattern
              pattern: '^[[:cntrl:]]'
              negate: true
              match: after
```

*`hid_bravura_monitor.instancename`*

The name of the Bravura Security Fabric instance. The default is `default`. For example:

```yaml
processors:
  - add_fields:
      target: ''
      fields:
        hid_bravura_monitor.instancename: default
        ...
```

*`hid_bravura_monitor.node`*

The address of the instance node. If the default `0.0.0.0` is left, the value is filled with `host.name`. For example:

```yaml
processors:
  - add_fields:
      target: ''
      fields:
        hid_bravura_monitor.node: 127.0.0.1
        ...
```

*`event.timezone`*

The timezone for the given instance server. The default is `UTC`. For example:

```yaml
processors:
  - add_fields:
      target: ''
      fields:
        event.timezone: Canada/Mountain
        ...
```

*`hid_bravura_monitor.environment`*

The environment of the Bravura Security Fabric instance; choices are DEVELOPMENT, TESTING, PRODUCTION. The default is `PRODUCTION`. For example:

```yaml
processors:
  - add_fields:
      target: ''
      fields:
        hid_bravura_monitor.environment: DEVELOPMENT
        ...
```

*`hid_bravura_monitor.instancetype`*

The type of Bravura Security Fabric instance installed; choices are any combinations of Privilege, Identity or Password. The default is `Privilege-Identity-Password`. For example:

```yaml
processors:
  - add_fields:
      target: ''
      fields:
        hid_bravura_monitor.instancetype: Identity
        ...
```

*`paths`*

An array of glob-based paths that specify where to look for the log files. All
patterns supported by [Go Glob](https://golang.org/pkg/path/filepath/#Glob)
are also supported here. 

For example, you can use wildcards to fetch all files
from a predefined level of subdirectories: `/path/to/log/*/*.log`. This
fetches all `.log` files from the subfolders of `/path/to/log`. It does not
fetch log files from the `/path/to/log` folder itself. If this setting is left
empty, the integration will choose log paths based on your operating system.

## Logs

### log

The `log` dataset collects the Hitachi ID Bravura Security Fabric application logs.

{{event "log"}}

{{fields "log"}}

### winlog

The `winglog` dataset collects the Hitachi ID Bravura Security Fabric event logs.

{{event "winlog"}}

{{fields "winlog"}}