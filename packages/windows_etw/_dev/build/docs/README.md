# Custom Windows ETW package

The custom Windows ETW ([Event Tracing for Windows](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)) package allows you to ingest events from any ETW provider available. Providers can be listed by running [`logman query providers`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman-query) in any Windows command-line interface.

This integration currently supports manifest-based, user-mode MOF (classic) and TraceLogging providers while WPP providers are not supported. [`Here`](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing#types-of-providers) you can find more information about the available types of providers.

It is supported in every Windows versions supported by [`Filebeat`](https://www.elastic.co/support/matrix), starting from Windows 10 and Windows Server 2016.

This package does not contain any ingest pipeline, so no pre-ingest data processing is applied out of the box. Custom ingest pipelines can be added through the Kibana UI to get the data in the desired format.

## Configuration

This integration can interact with ETW in three distinct ways: it can create a new session to capture events from user-mode providers, attach to an already existing session to collect ongoing event data, or read events from a pre-recorded .etl file. For that reason, when configuring the integration there are three parameters that are mutually exclusive, but at least one of them must be set: Provider (Name or GUID), File and Session.

Event trace level may be specified at `critical`, `error`, `warning`, `information`, or `verbose`. The system will ingest events that correspond to the specified trace level or exceed it in terms of severity.

Events may be filtered using event masks with the `Match Any Keyword` or `Match All Keyword` parameters. The `Match Any Keyword` parameter specifies a 64-bit bitmask where an event is ingested if any of the bits set in this bitmask match any of the keyword bits set in the event's properties, allowing for a broad selection of events based on multiple criteria. Conversely, the `Match All Keyword` parameter requires that all bits set in its 64-bit bitmask match the event's keyword bits for the event to be ingested.The correct format for both fields is `0x` followed by a 16-character hexadecimal number.

[Here](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2) you can read more information about these parameters.

The full documentation for the input are available [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-etw.html), including more examples about how to configure it.

## Fields Mapping

In addition to the fields specified below, this integration includes the ECS Dynamic Template. Any field that follow the ECS Schema will get assigned the correct index field mapping and does not need to be added manually.

{{ fields }}
