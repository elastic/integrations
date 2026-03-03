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
| apple_event.decoded_payloads | Decoded ASCII text from utxt hex payloads in Apple Events. Truncated to 16 characters by the Unified Log system. | keyword |
| apple_event.direction | Direction of the Apple Event: self, remote, or reply. | keyword |
| apple_event.mute | True when an Apple Event set volume command includes mute=true. Known stealer pre-indicator. | boolean |
| apple_event.parameters | Four-character parameter codes in the Apple Event payload (e.g. htxt, dtxt, prmp). | keyword |
| apple_event.return_id | Return ID correlating Apple Event requests with replies. | keyword |
| apple_event.target_process | Target process of the Apple Event from the target='psn' block. | keyword |
| apple_event.type_code | Apple Event class and ID pair (e.g. syso,dlog for display dialog). | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dll.name | Name of the sender library or framework. | keyword |
| dll.path | Full path of the sender library or framework. | keyword |
| event.category | Event category derived from the subsystem. | keyword |
| event.dataset | Event dataset (unifiedlogs.log). | keyword |
| event.kind | Event kind (event). | keyword |
| event.module | Event module (unifiedlogs). | keyword |
| event.provider | Event provider, set to the Unified Log subsystem. | keyword |
| event.type | Event type derived from the subsystem. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (darwin). | keyword |
| host.os.type | OS type (macos). | keyword |
| log.level | Normalized log level from messageType (info, debug, error, critical). | keyword |
| message | The human-readable log message (eventMessage from ndjson). | match_only_text |
| process.executable | Full path of the process that emitted the log entry. | keyword |
| process.name | Name of the process that emitted the log entry. | keyword |
| process.pid | PID of the process that emitted the log entry. | long |
| process.thread.id | Thread ID within the process. | long |
| unified_log.activity_id | Activity identifier for correlating related log entries. | long |
| unified_log.boot_uuid | Boot UUID identifying the system boot session. | keyword |
| unified_log.category | Category within the subsystem (e.g. access, connection). | keyword |
| unified_log.event_type | Unified Log event type (e.g. logEvent, activityCreateEvent). | keyword |
| unified_log.format_string | The os_log format string used to compose the message. | keyword |
| unified_log.mach_timestamp | Mach absolute time timestamp. | long |
| unified_log.message_type | Original message severity (Default, Info, Debug, Error, Fault). | keyword |
| unified_log.parent_activity_id | Parent activity identifier. | long |
| unified_log.process.uuid | UUID of the process image (Mach-O binary). | keyword |
| unified_log.sender.program_counter | Program counter of the sender at log emission time. | long |
| unified_log.sender.uuid | UUID of the sender image (shared library or framework). | keyword |
| unified_log.subsystem | Subsystem that emitted the log entry (e.g. com.apple.appleevents). | keyword |
| unified_log.timezone | Timezone name where the log was recorded. | keyword |
| unified_log.trace_id | Trace identifier for cross-process correlation. | keyword |
| user.id | User ID of the process that emitted the log entry. | keyword |
