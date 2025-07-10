# Custom WMI (Windows Management Instrumentation) Input Package

The Custom WMI Input integration is used to ingest data from the Windows Management Instrumentation (WMI) classes.
You can use this input to collect instances of any WMI class.

## Configuration

The extensive documentation for the input is currently available [here](https://www.elastic.co/docs/reference/beats/metricbeat/metricbeat-metricset-wmi). We highly encourage users to become familiar with the linked documentation.

The most commonly used configuration options are available on the main integration page, while more advanced and customizable options currently resides under the "Advanced options" part of the integration settings page.

## Requirements

This integration requires Elastic-Agent 8.19.0 or 9.1.0 and above.

This integration is only available on Windows. We refer to the Metricbeat input for the [Compatibility](https://docs-v3-preview.elastic.dev/elastic/beats/pull/45068/reference/metricbeat/metricbeat-metricset-windows-wmi#compatibility).

###  Date Fields Mapping

Elastic-Agent converts WMI properties of type "datetime" to timestamps, but these are serialized as strings in the output. Since date detection is disabled by default, these fields will be stored as strings unless explicitly mapped as dates. To ensure proper mapping, we recommend explicitly setting the mapping in the @custom template.
