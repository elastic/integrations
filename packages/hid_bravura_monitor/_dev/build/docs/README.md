# Hitachi ID Bravura Monitor Integration

The *Hitachi ID Bravura Monitor* integration fetches and parses logs from a Bravura Security Fabric instance.

When you run the integration, it performs a few tasks under the hood:

* Sets the default paths to the log files (but don't worry, you can override the
defaults)

* Makes sure each multiline log event gets sent as a single event

* Uses ingest node to parse and process the log lines, shaping the data into a structure suitable
for visualizing in Kibana

* Deploys dashboards for visualizing the log data

## Compatibility

The *Hitachi ID Bravura Monitor* integration was tested with logs from `IDM Suite 12.3.0` running on Windows Server 2016.

The integration was also tested with IDM Suite 11.x, 12.x series.

This integration is not available for Linux or Mac.

The integration is by default configured to read logs files stored in the `default` instance log directory.
However it can be configured for any file path. See the following example.

```yaml
- module: hid_bravura_monitor
  log:
    enabled: true
    var.paths: ["C:/Program Files/Hitachi ID/IDM Suite/Logs/default*/idmsuite*.log"]
    var.instancename: default
    var.timezone: UTC
    var.environment: PRODUCTION
    var.instancetype: Privilege-Identity-Password
```

*`var.instancename`*::

The name of the IDM Suite instance. The default is `default`. For example:

```yaml
- module: hid_bravura_monitor
  log:
    enabled: true
    var.instancename: inst1
    ...
```

*`var.node`*::

The address of the instance node. The default is filled with `host.name`. For example:

```yaml
- module: hid_bravura_monitor
  log:
    enabled: true
    var.node: 127.0.0.1
    ...
```

*`var.timezone`*::

The timezone for the given instance server. The default is `UTC`. For example:

```yaml
- module: hid_bravura_monitor
  log:
    enabled: true
    var.timezone: Canada/Mountain
    ...
```

*`var.environment`*::

The environment of the IDM Suite instance; choices are DEVELOPMENT, TESTING, PRODUCTION. The default is `PRODUCTION`. For example:

```yaml
- module: hid_bravura_monitor
  log:
    enabled: true
    var.environment: DEVELOPMENT
    ...
```

*`var.instancetype`*::

The type of IDM Suite instance installed; choices are any combinations of Privilege, Identity or Password. The default is `Privilege-Identity-Password`. For example:

```yaml
- module: hid_bravura_monitor
  log:
    enabled: true
    var.instancetype: Identity-Password
    ...
```

*`var.paths`*::

An array of glob-based paths that specify where to look for the log files. All
patterns supported by https://golang.org/pkg/path/filepath/#Glob[Go Glob]
are also supported here. For example, you can use wildcards to fetch all files
from a predefined level of subdirectories: `/path/to/log/*/*.log`. This
fetches all `.log` files from the subfolders of `/path/to/log`. It does not
fetch log files from the `/path/to/log` folder itself. If this setting is left
empty, {beatname_uc} will choose log paths based on your operating system.

## Logs

### log

The `log` dataset collects the Hitachi ID IDM Suite application logs.

{{event "log"}}

{{fields "log"}}