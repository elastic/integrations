# Windows AppLocker Integration

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Each data stream collects different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.

## Setup

For step-by-step instructions on how to set up an integration,
see the {{ url "getting-started-observability" "Getting started" }} guide.

Note: Because the Windows integration always applies to the local server, the `hosts` config option is not needed.

## Notes

### Windows Event ID clause limit

If you specify more than 22 query conditions (event IDs or event ID ranges), some
versions of Windows will prevent the integration from reading the event log due to
limits in the query system. If this occurs, a similar warning as shown below:

```
The specified query is invalid.
```

In some cases, the limit may be lower than 22 conditions. For instance, using a
mixture of ranges and single event IDs, along with an additional parameter such
as `ignore older`, results in a limit of 21 conditions.

If you have more than 22 conditions, you can work around this Windows limitation
by using a drop_event processor to do the filtering after filebeat has received
the events from Windows. The filter shown below is equivalent to
`event_id: 903, 1024, 2000-2004, 4624` but can be expanded beyond 22 event IDs.

```yaml
- drop_event.when.not.or:
  - equals.winlog.event_id: "903"
  - equals.winlog.event_id: "1024"
  - equals.winlog.event_id: "4624"
  - range:
      winlog.event_id.gte: 2000
      winlog.event_id.lte: 2004
```

## Logs reference

### AppLocker/EXE and DLL

The Windows `applocker_exe_and_dll` data stream provides events from the Windows
`Microsoft-Windows-AppLocker/EXE and DLL` event log.

{{event "applocker_exe_and_dll"}}

{{fields "applocker_exe_and_dll"}}

### AppLocker/MSI and Script

The Windows `applocker_msi_and_script` data stream provides events from the Windows
`Microsoft-Windows-AppLocker/MSI and Script` event log.

{{event "applocker_msi_and_script"}}

{{fields "applocker_msi_and_script"}}

### AppLocker/Packaged app-Deployment

The Windows `applocker_packaged_app_deployment` data stream provides events from the Windows
`Microsoft-Windows-AppLocker/Packaged app-Deployment` event log.

{{event "applocker_packaged_app_deployment"}}

{{fields "applocker_packaged_app_deployment"}}

### AppLocker/Packaged app-Execution

The Windows `applocker_packaged_app_execution` data stream provides events from the Windows
`Microsoft-Windows-AppLocker/Packaged app-Execution` event log.

{{event "applocker_packaged_app_execution"}}

{{fields "applocker_packaged_app_execution"}}