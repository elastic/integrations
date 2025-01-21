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

## Fields Mapping

In addition to the fields specified below, this integration includes the ECS Dynamic Template. Any field that follow the ECS Schema will get assigned the correct index field mapping and does not need to be added manually.

{{ fields }}