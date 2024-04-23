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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| winlog.activity_guid | A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity. Deprectad in favor of `winlog.activity_id` from 8.14.0, it will be removed in future releases. | keyword |
| winlog.activity_id | A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity. | keyword |
| winlog.channel | Used to enable special event processing. Channel values below 16 are reserved for use by Microsoft to enable special treatment by the ETW runtime. Channel values 16 and above will be ignored by the ETW runtime (treated the same as channel 0) and can be given user-defined semantics. | keyword |
| winlog.event_data | The event-specific data. The content of this object is specific to any provider and event. | object |
| winlog.event_data.Address |  | keyword |
| winlog.event_data.AddressLength |  | keyword |
| winlog.event_data.DynamicAddress |  | keyword |
| winlog.event_data.Index |  | keyword |
| winlog.event_data.Interface |  | keyword |
| winlog.event_data.TotalServerCount |  | keyword |
| winlog.flags | Flags that provide information about the event such as the type of session it was logged to and if the event contains extended data. | keyword |
| winlog.keywords | The keywords are used to indicate an event's membership in a set of event categories. | keyword |
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.process_id | Identifies the process that generated the event. | keyword |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.session | Configured session to forward ETW events from providers to consumers. | keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.thread_id | Identifies the thread that generated the event. | keyword |
| winlog.version | Specify the version of a manifest-based event. | long |

