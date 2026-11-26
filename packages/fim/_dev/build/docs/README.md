# File Integrity Monitoring Integration

This integration sends events when a file is changed (created, updated, or deleted) on disk. The events contain file metadata and hashes.

The integration is implemented for Linux, macOS (Darwin), and Windows.


| ⚠️ This integration should not be used to monitor paths on network file systems. |
| ---- |

## How it works

This integration uses features of the operating system to monitor file changes in realtime. When the integration starts it creates a subscription with the OS to receive notifications of changes to the specified files or directories. Upon receiving notification of a change the integration will read the file’s metadata and then compute a hash of the file’s contents.

At startup this integration will perform an initial scan of the configured files and directories to generate baseline data for the monitored paths and detect changes since the last time it was run. It uses locally persisted data in order to only send events for new or modified files.

## Compatibility

The operating system features that power this feature are as follows:
- **Linux** - inotify is used, and therefore the kernel must have inotify support. Inotify was initially merged into the 2.6.13 Linux kernel.
- **macOS (Darwin)** - Uses the FSEvents API, present since macOS 10.5. This API coalesces multiple changes to a file into a single event. Auditbeat translates this coalesced changes into a meaningful sequence of actions. However, in rare situations the reported events may have a different ordering than what actually happened.
- **Windows** - ReadDirectoryChangesW is used.

## Hash algorithms

The `hash_types` setting controls which hashes are computed for each file. If it is not set, the default depends on the Elastic Agent build: `sha1` for standard builds and `sha256` for FIPS builds. FIPS builds do not support the `md5`, `sha1` and `blake2b_*` hash types, and the input fails to start if one of them is configured.

Policies created before version 1.19.0 store `sha1` in the `hash_types` setting and keep it when the integration is upgraded. On FIPS builds, edit those policies and replace `sha1` with an approved algorithm such as `sha256`.

Hashes are reported in the `file.hash.<algorithm>` fields, so events collected after changing the algorithm have a different hash field from older events. Changing the algorithms of an existing policy also makes the integration report each monitored file once, with the `config_change` action.

{{ event "event" }}

{{ fields "event" }}
