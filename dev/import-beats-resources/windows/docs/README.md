# Windows Integration

The Windows module allows you to monitor the Windows os, services, applications etc. Because the Windows module
always applies to the local server, the `hosts` config option is not needed.

The default metricset is `service`. To disable a default metricset, comment it out in the
`modules.d/windows.yml` configuration file. If _all_ metricsets are commented out
and the Windows module is enabled, {beatname_uc} uses the default metricsets.


## Compatibility

The Windows metricsets collect different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.

## Metrics

### Service

The Windows `service` metricset provides service details.

{{fields "service"}}


### Perfmon

The Windows `perfmon` metricset provides prformance counter values.

{{fields "perfmon"}}


Both metricsets are available on Windows only.

