# Custom Unix Logs Integration for Elastic

## Overview

The Custom Unix Logs integration for Elastic enables you to collect data through a stream-oriented Unix domain socket. It's a flexible solution for ingesting logs from local processes and applications into the Elastic Stack. By using this integration, you can centralize your log data, making it easier to monitor, search, and analyze your environment's activity.

### Compatibility

The Custom Unix Logs integration is compatible with any process or application capable of writing to a Unix domain socket on the same host as the Elastic Agent.

This integration supports the following standards:
- Syslog standards: Supports devices compliant with `RFC 3164` (BSD syslog) and `RFC 5424` (The Syslog Protocol).
- Framing standards: Supports `RFC 6587` for octet-counted framing, which is commonly used in high-reliability log transmission.

### How it works

This integration collects data by having an Elastic Agent listen on a Unix domain socket at a specified path. The agent creates the socket file and waits for local processes to connect and send data. When a process writes data to the socket, the Elastic Agent receives and processes it.

Once received, the data is processed according to your configuration—whether it's raw text, syslog formatted, or uses specific framing. The Elastic Agent then forwards the logs to your Elastic deployment, where you can analyze them using Kibana.

## What data does this integration collect?

The Custom Unix Logs integration collects log messages of the following types:
- Raw streams: Any text-based data sent over the Unix domain socket, typically separated by newline characters or other delimiters.
- Syslog messages: Structured messages following RFC 3164 or RFC 5424, which include metadata such as facility, severity, and timestamps.

This integration includes the following data stream:
- `unix.generic`: This is the default data stream. It captures the raw message payload in the `message` field. If you enable Syslog parsing, additional ECS fields are populated from the syslog header.

### Supported use cases

- Local application logging: Applications on the same host can write log events directly to the Unix socket, eliminating the need for network connectivity.
- System daemon log collection: Collect logs from system daemons that support Unix socket output.
- Syslog ingestion: Collect syslog-formatted messages from local processes using `logger` or other syslog-compatible tools.
- Secure local log aggregation: Since Unix domain sockets are filesystem objects, standard Unix file permissions (`group`, `mode`) can be used to control which processes can send data.

## What do I need to use this integration?

### Elastic prerequisites

- Elastic Agent: A running Elastic Agent managed by a Fleet policy or configured in standalone mode.
- The Elastic Agent must have write permission to the directory where the socket will be created.

### Source prerequisites

- The sending process must run on the same host as the Elastic Agent.
- The sending process must have permission to write to the Unix socket (controlled via the `group` and `mode` options).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

### Set up steps in Kibana

You'll follow these steps to add and configure the integration in Kibana:

1. Navigate to **Management > Integrations** in Kibana.
2. Search for **Custom Unix Logs** and select it.
3. Click **Add Custom Unix Logs**.
4. Configure the integration settings:
    - **Socket Path**: The filesystem path where the Unix domain socket will be created (e.g. `/tmp/example.sock`).
    - **Socket Type**: The socket variety: `stream` or `datagram`. The default is `stream`.
    - **Dataset Name**: The name of the dataset where logs will be written. The default is `unix.generic`.
    - **Framing**: Specify how the Agent identifies the end of a log message. Options include `delimiter` (default) or `rfc6587`.
    - **Line Delimiter**: The character used to split incoming data into separate log events. The default is `\n`.
    - **Max Message Size**: The maximum allowed size for a single log message. The default is `20MiB`.
    - **Syslog Parsing**: Enable this boolean if the incoming data is in standard Syslog format (RFC3164/5424).
5. Optionally configure advanced options:
    - **Socket Group**: The group ownership for the created Unix socket.
    - **Socket Mode**: File permissions for the socket as an octal string (e.g. `0660`).
    - **Max Connections**: Maximum number of simultaneous connections.
    - **Timeout**: Duration of inactivity before a connection is closed.
6. (Optional) Provide a **Custom Ingest Pipeline** name if you've already defined processing logic in Elasticsearch.
7. Click **Save and Continue** to deploy the configuration to your Agents.

### Configure the sending application

Once the Elastic Agent is running with this integration, configure your application to send data to the socket path you configured:

For rsyslog:
```
*.* unix-stream:/tmp/elastic-agent.sock
```

Using the `logger` command:
```bash
logger -u /tmp/elastic-agent.sock "This is a test message"
```

Using `socat`:
```bash
echo "Test log message" | socat - UNIX-CONNECT:/tmp/elastic-agent.sock
```

Using `nc` (if it supports Unix sockets):
```bash
echo "Test log message" | nc -U /tmp/elastic-agent.sock
```

### Validation

After configuration, verify that data is flowing correctly:

1. Send a test message to the socket:
   ```bash
   echo "Integration Validation Test Message $(date)" | socat - UNIX-CONNECT:/tmp/elastic-agent.sock
   ```

2. Check for the data in Kibana:
   1. Navigate to **Analytics > Discover**.
   2. Select the `logs-*` data view.
   3. Enter this KQL filter: `data_stream.dataset : "unix.generic"`
   4. Verify that logs appear in the results and confirm these fields are populated:
       - `event.dataset` (should be `unix.generic`)
       - `message` (containing the test message)
       - `input.type` (should indicate `unix`)

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

- Socket creation failure:
    - Verify that the Elastic Agent has write permission to the directory containing the socket path.
    - Ensure no file already exists at the configured socket path.
- Permission denied when connecting:
    - If client processes cannot connect to the socket, adjust the `group` and `mode` options to allow the appropriate users or groups access.
- Dataset naming restriction:
    - If data isn't appearing, check your integration configuration for hyphens in the `Dataset Name`. Hyphens aren't supported in this field and will cause ingestion issues.
- Parsing failures:
    - If data appears in Kibana but doesn't parse correctly, check the `error.message` field. This often happens if you've enabled `Syslog Parsing` but the incoming logs don't strictly adhere to RFC 3164 or RFC 5424.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-
architectures) documentation.

## Reference

### Vendor documentation links

- [Filebeat Unix Input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-unix)
- [RFC 3164: The BSD Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc3164)
- [RFC 5424: The Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424)
- [RFC 6587: Transmission of Syslog Messages over TCP](https://datatracker.ietf.org/doc/html/rfc6587)
