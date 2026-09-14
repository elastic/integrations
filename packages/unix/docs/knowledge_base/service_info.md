# Service Info

The Custom Unix Logs integration allows the Elastic Agent to listen on a Unix domain socket, capturing raw log data or structured syslog messages from local processes on the same host. This integration is well-suited for applications and system daemons that support Unix socket output, providing a secure, low-overhead mechanism for local log collection without requiring network connectivity.

## Common use cases

- **Local Application Logging:** Applications on the same host can write log events directly to the Unix socket using standard POSIX socket APIs, eliminating network overhead.
- **System Daemon Log Collection:** Collect logs from system daemons (e.g., syslogd, journald, or custom daemons) that support Unix socket output.
- **Syslog Ingestion:** Collect syslog-formatted messages from local processes using `logger`, rsyslog's `unix-stream` action, or other syslog-compatible tools.
- **Secure Local Log Aggregation:** Since Unix domain sockets are filesystem objects, standard Unix file permissions (`group`, `mode`) restrict which processes can connect, providing access control without a network firewall.

## Data types collected

This integration can collect the following types of data:
- **Raw Streams:** Any text-based data sent over the Unix domain socket, typically separated by newline characters or other delimiters.
- **Syslog Messages:** Structured messages following RFC 3164 or RFC 5424, which include metadata such as facility, severity, and timestamps.

The following data stream is available:
- **unix.generic (logs):** This is the default data stream. It captures the raw message payload in the `message` field. If Syslog parsing is enabled, additional ECS fields are populated from the syslog header.

## Compatibility

The **Custom Unix Logs** integration is compatible with any process or application running on the same host as the Elastic Agent that is capable of writing to a Unix domain socket.
- **Syslog Standards:** Supports processes using **RFC 3164** (BSD syslog) and **RFC 5424** (The Syslog Protocol).
- **Framing Standards:** Supports **RFC 6587** for octet-counted framing.
- **Socket Types:** Supports both `stream` and `datagram` Unix socket varieties.

# Set Up Instructions

## Elastic prerequisites

- **Elastic Agent:** A running Elastic Agent managed by a Fleet policy or configured in standalone mode.
- **Filesystem Access:** The Elastic Agent must have write permission to the directory where the socket will be created.

## Source prerequisites

- The sending process must run on the same host as the Elastic Agent.
- The sending process must have permission to write to the Unix socket (controlled via the `group` and `mode` options).

## Kibana set up steps

### Custom Unix Logs
1. Navigate to **Management > Integrations** in Kibana.
2. Search for **Custom Unix Logs** and select it.
3. Click **Add Custom Unix Logs**.
4. Configure the following fields:
   - **Socket Path**: The filesystem path where the Unix domain socket will be created. Default: `/tmp/elastic-agent.sock`.
   - **Socket Type**: The socket variety: `stream` (default) or `datagram`.
   - **Dataset Name**: The name of the dataset to which logs will be written. Default: `unix.generic`.
   - **Framing**: Specify how the Agent identifies the end of a log message. Options include `delimiter` (default) or `rfc6587`.
   - **Line Delimiter**: The character used to split incoming data into separate log events. Default: `\n`.
   - **Max Message Size**: The maximum allowed size for a single log message. Default: `20MiB`.
   - **Syslog Parsing**: Enable this boolean if the incoming data is in standard Syslog format (RFC3164/5424).
5. (Optional) Configure advanced options:
   - **Socket Group**: Group ownership for the created Unix socket.
   - **Socket Mode**: File permissions as an octal string (e.g. `0660`).
   - **Max Connections**: Maximum number of simultaneous connections.
   - **Timeout**: Duration of inactivity before a connection is closed.
6. (Optional) Provide a **Custom Ingest Pipeline** name if you have pre-defined processing logic in Elasticsearch.
7. Click **Save and Continue** to deploy the configuration to your Agents.

# Validation Steps

After configuration is complete, follow these steps to verify data is flowing correctly.

### 1. Send a Test Event:
- Using `socat`:
  `echo "Integration Validation Test Message $(date)" | socat - UNIX-CONNECT:/tmp/elastic-agent.sock`
- Using `logger` (for syslog-formatted data):
  `logger -u /tmp/elastic-agent.sock "This is a test syslog message"`

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the following KQL filter: `data_stream.dataset : "unix.generic"`
4. Verify logs appear in the results. Expand a log entry and confirm these fields are populated:
   - `event.dataset` (should be `unix.generic`)
   - `log.syslog.priority` (if syslog parsing is enabled)
   - `message` (containing the test message)
   - `input.type` (should indicate `unix`)

# Troubleshooting

## Common Configuration Issues

- **Socket Creation Failure**: Verify that the Elastic Agent has write permission to the directory containing the socket path. Ensure no regular file already exists at the configured path.
- **Permission Denied When Connecting**: If client processes cannot connect to the socket, adjust the `group` and `mode` options to allow the appropriate users or groups access.
- **Dataset Naming Restriction**: If data is not appearing, check the integration configuration for hyphens in the **Dataset Name**. Hyphens are not supported in this field and will cause ingestion issues.

## Ingestion Errors

- **Parsing Failures**: If data appears in Kibana but is not parsed correctly, check the `error.message` field. This often happens if **Syslog Parsing** is enabled but the incoming logs do not strictly adhere to RFC 3164 or RFC 5424.
- **Framing Issues**: If multiple log lines appear as a single event or if events are cut off, verify that the **Framing** method matches the sender configuration.
- **Message Truncation**: If logs are incomplete, check if they exceed the **Max Message Size**. Increase this value if your application sends large payloads.

# Documentation sites
- [Filebeat Unix Input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-unix)
- [RFC 3164: The BSD Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc3164)
- [RFC 5424: The Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424)
- [RFC 6587: Transmission of Syslog Messages over TCP](https://datatracker.ietf.org/doc/html/rfc6587)
