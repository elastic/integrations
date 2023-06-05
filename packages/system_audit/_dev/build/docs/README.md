# System Audit Integration [Beta]

## Overview

The `System Audit` integration collects various security-related information about
a system. All data streams send both periodic state information (e.g. all currently
installed packages) and real-time changes (e.g. when a new package is installed/uninstalled
or an existing package is updated). Currently, the only implemented data stream is the
package data stream, which collects various information about system packages. In the future, 
more data streams like (process, socket, hosts .. etc) will be added.

## How it works

Each data stream sends two kinds of information: state and events.

State information is sent periodically. A state update will consist of events
for each package that is installed or has had its state change in the polling period.
All events belonging to the same state update will share the same UUID in `event.id`.

The frequency of state updates can be controlled for all data streams using the
`state.period` configuration option. The default is `12h`.

Event information is sent as the events occur (e.g. a package is installed, uninstalled or updated).
All data streams are currently using a poll model to retrieve their data.
The frequency of these polls is controlled by the `period` configuration parameter.

### Entity IDs

This module populates `entity_id` fields to uniquely identify entities (packages) within a host.
This requires the module to obtain a unique identifier for the host:

- macOS: Uses the value returned by `gethostuuid(2)` system call.
- Linux: Uses the content of one of the following files, created by either
`systemd` or `dbus`:
 * /etc/machine-id
 * /var/lib/dbus/machine-id
 * /var/db/dbus/machine-id

**NOTE:** Under CentOS 6.x, it's possible that none of the files above exist. In that case, running `dbus-uuidgen --ensure` (provided by the `dbus` package)
will generate one for you. One more thing to consider is that at the moment this integration is **not supported on Windows** systems.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting Started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

**NOTE:** If you want to supress `host` related information, please consider adding the tag: `forwarded`. Adding this tag to the tag list will remove
any host-related data from the output, this will also stop certain dashboards from displaying host/os-related information/charts.
## Data Streams
The data streams which are currently supported are:-
 - package

**Package** helps you keep a record of events and changes happening to different packages on your system. The fields & events associated with the
data stream are as follows:-

{{fields "package"}}

{{event "package"}}

### Example dashboard

The integration comes with a package & audit system dashboard for easy identification of events and data overview :

**Package Dashboard:**
![Package Dashboard](../img/system-audit-package-dashboard.png)

**System Audit Dashboard:**
![Audit System Dashboard](../img/system-audit-overview-dashboard.png)

## Reference
For further information, please look at the [Auditbeat System Module](https://www.elastic.co/guide/en/beats/auditbeat/master/auditbeat-module-system.html) documentation.