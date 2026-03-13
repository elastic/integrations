# Custom macOS Unified Logs

The unified logging system provides a comprehensive and performant API to capture
telemetry across all levels of the system. This system centralizes the storage of
log data in memory and on disk, rather than writing that data to a text-based log file.

This package interacts with the `log` command-line tool to provide access to these events.

It starts streaming events from the current point in time unless a start date or
the backfill options are set. When restarted it will continue where it left off.

Alternatively, it can also do one off operations, such as:

- Stream events contained in a `.logarchive` file.
- Stream events contained in a `.tracev3` file.
- Stream events in a specific time span, by providing a specific end date.

After this one off operations complete, the package input will stop.

Other configuration options can be specified to filter what events to process.

NOTE: This package can cause some duplicated events when backfilling and/or
restarting. This is caused by how the underlying fetching method works and
should be taken into account when using the input.

## Ingest Pipeline

This package ships with a default ingest pipeline that parses the raw ndjson
output from the macOS `log` CLI into structured ECS and custom fields. The
pipeline is automatically applied when using the default configuration.

The pipeline performs the following:

1. **JSON parsing** — extracts the raw ndjson line from the `message` field
   into individual structured fields.
2. **ECS mapping** — maps Unified Log fields to their ECS equivalents:
   - `processImagePath` → `process.executable` / `process.name`
   - `processID` → `process.pid`
   - `threadID` → `process.thread.id`
   - `userID` → `user.id`
   - `senderImagePath` → `dll.path` / `dll.name`
   - `messageType` → `log.level`
   - `subsystem` → `event.provider`
3. **Custom field extraction** — maps Unified Log metadata to `unified_log.*`
   fields (subsystem, category, event_type, format_string, activity_id, etc.).
4. **Event categorization** — derives `event.category` and `event.type` from
   the subsystem (e.g. `com.apple.TCC` → `configuration`/`access`).
5. **Apple Event enrichment** — conditionally extracts structured fields from
   `com.apple.appleevents` debug messages into `apple_event.*` fields
   (type_code, direction, parameters, decoded payloads).

### Recommended Predicates for Security Monitoring

To collect security-relevant events while managing volume, use these predicates:

```
subsystem=="com.apple.appleevents" AND (eventMessage CONTAINS "event={" OR eventMessage CONTAINS "reply={")
```

```
subsystem=="com.apple.TCC" AND category=="access" AND (eventMessage CONTAINS "AUTHREQ_CTX" OR eventMessage CONTAINS "Denied" OR eventMessage CONTAINS "publishAccessChangedEvent")
```

```
subsystem=="com.apple.loginwindow.logging" AND eventMessage CONTAINS "performAutolaunch"
```

Enable **debug** level logging in the integration configuration to capture
Apple Event and TCC debug messages.

## Fields Mapping

In addition to the fields specified below, this integration includes the ECS Dynamic Template. Any field that follow the ECS Schema will get assigned the correct index field mapping and does not need to be added manually.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apple_event.decoded_payloads | Decoded ASCII text extracted from utxt (Unicode text) hex payloads in the Apple Event. Values are truncated to 16 characters by the Unified Log system. Useful for identifying short indicators like parameter values and script fragments. | keyword |
| apple_event.direction | The direction of the Apple Event. One of self (sendToSelf), remote (sendToModernProcess), or reply (Reply of SendToSelf or reply=\{\}). | keyword |
| apple_event.mute | Set to true when an Apple Event set volume command includes mute=true in its payload. Indicates a volume mute operation, which is a known pre-indicator of macOS stealer malware. | boolean |
| apple_event.parameters | List of four-character parameter codes present in the Apple Event payload (e.g. htxt for hidden text, dtxt for display text, prmp for prompt). These codes identify the types of data carried in the event. | keyword |
| apple_event.return_id | The return ID of the Apple Event, used to correlate requests with their replies. Extracted from returnID=N in the log message. | keyword |
| apple_event.target_process | The target process of the Apple Event, extracted from the target='psn' block in the log message. May contain process name, PID, or PSN identifiers. | keyword |
| apple_event.type_code | The four-character Apple Event class and ID pair (e.g. syso,dlog for display dialog, aevt,stvl for set volume, Jons,gClp for get clipboard). Extracted from the event=\{X,Y\} or reply=\{X,Y\} pattern in the log message. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dll.name | Name of the library. This generally maps to the name of the file on disk. | keyword |
| dll.path | Full file path of the library. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| tags | List of keywords used to tag each event. | keyword |
| unified_log.activity_id | The activity identifier for correlating related log entries. Corresponds to the ndjson `activityIdentifier` field. | long |
| unified_log.boot_uuid | The boot UUID identifying the system boot session. Corresponds to the ndjson `bootUUID` field. | keyword |
| unified_log.category | The category within the subsystem (e.g. access, connection). Corresponds to the ndjson `category` field. | keyword |
| unified_log.event_type | The Unified Log event type (e.g. logEvent, activityCreateEvent, traceEvent). Corresponds to the ndjson `eventType` field. | keyword |
| unified_log.format_string | The os_log format string used to compose the message. Useful for grouping events by log template. Corresponds to the ndjson `formatString` field. | keyword |
| unified_log.mach_timestamp | The Mach absolute time timestamp. Corresponds to the ndjson `machTimestamp` field. | long |
| unified_log.message_type | The original message severity before normalization to log.level. One of Default, Info, Debug, Error, or Fault. Corresponds to the ndjson `messageType` field. | keyword |
| unified_log.parent_activity_id | The parent activity identifier. Corresponds to the ndjson `parentActivityIdentifier` field. | long |
| unified_log.process.uuid | The UUID of the process image (Mach-O binary). Corresponds to the ndjson `processImageUUID` field. | keyword |
| unified_log.sender.program_counter | The program counter value of the sender at the time the log entry was emitted. Corresponds to the ndjson `senderProgramCounter` field. | long |
| unified_log.sender.uuid | The UUID of the sender image (shared library or framework). Corresponds to the ndjson `senderImageUUID` field. | keyword |
| unified_log.subsystem | The subsystem that emitted the log entry (e.g. com.apple.appleevents, com.apple.TCC). Corresponds to the ndjson `subsystem` field. | keyword |
| unified_log.timezone | The timezone name where the log was recorded. Corresponds to the ndjson `timezoneName` field. | keyword |
| unified_log.trace_id | The trace identifier for correlating log entries across processes. Stored as keyword because the value can exceed the long integer range. Corresponds to the ndjson `traceID` field. | keyword |
| user.id | Unique identifier of the user. | keyword |

