# Windows Integration

The Windows package allows you to monitor the Windows os, services, applications etc. Because the Windows integration
always applies to the local server, the `hosts` config option is not needed.

## Compatibility

The Windows datasets collect different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.

## Metrics

### Service

The Windows `service` dataset provides service details.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| windows.service.display_name | The display name of the service. | keyword |
| windows.service.exit_code | For `Stopped` services this is the error code that service reports when starting to stopping. This will be the generic Windows service error code unless the service provides a service-specific error code. | keyword |
| windows.service.id | A unique ID for the service. It is a hash of the machine's GUID and the service name. | keyword |
| windows.service.name | The service name. | keyword |
| windows.service.path_name | Fully qualified path to the file that implements the service, including arguments. | keyword |
| windows.service.pid | For `Running` services this is the associated process PID. | long |
| windows.service.start_name | Account name under which a service runs. | keyword |
| windows.service.start_type | The startup type of the service. The possible values are `Automatic`, `Boot`, `Disabled`, `Manual`, and `System`. | keyword |
| windows.service.state | The actual state of the service. The possible values are `Continuing`, `Pausing`, `Paused`, `Running`, `Starting`, `Stopping`, and `Stopped`. | keyword |
| windows.service.uptime.ms | The service's uptime specified in milliseconds. | long |



### Perfmon

The Windows `perfmon` dataset provides performance counter values.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| windows.perfmon.instance | Instance value. | keyword |
| windows.perfmon.metrics.*.* | Metric values returned. | object |
| windows.perfmon.object | Object value. | keyword |



Both datasets are available on Windows only.

