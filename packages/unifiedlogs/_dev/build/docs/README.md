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

{{ fields }}
