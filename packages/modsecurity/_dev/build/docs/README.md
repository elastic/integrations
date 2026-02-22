# ModSecurity Audit Integration for Elastic

> Note: This AI-assisted guide was validated by our engineers. You may need to adjust the steps to match your environment.

## Overview

The ModSecurity Audit integration for Elastic enables you to collect and analyze logs from ModSecurity, the open-source Web Application Firewall (WAF). This integration allows you to ingest detailed transaction logs into the Elastic Stack, providing visibility into HTTP requests and responses for real-time threat detection and forensic investigation.

### Compatibility

This integration is compatible with the following third-party components:
- ModSecurity v3 (LibModSecurity) with Nginx connector
- ModSecurity v2 for Apache (v2.9.x)

Support for JSON output in ModSecurity v3 [requires ModSecurity to be compiled with YAJL (Yet Another JSON Library) support](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#secauditlogformat).

### How it works

This integration collects data from ModSecurity by monitoring log files on the host where the WAF is running. You deploy an Elastic Agent to the host and configure it to read the JSON-formatted audit logs produced by the ModSecurity logging engine. The agent uses the `logfile` input to ingest the data, parses the JSON structure into Elastic Common Schema (ECS) fields, and forwards the information to your Elastic deployment.

The integration performs the following tasks:
- Monitors log files matching the default pattern `/var/log/modsec-audit*`
- Processes the data using the `auditlog` data stream
- Maps ModSecurity fields to ECS for consistent analysis across different log sources

## What data does this integration collect?

The ModSecurity Audit integration collects log messages of the following types:
- `auditlog`: This data stream collects ModSecurity audit logs using the `logfile` input and parses the `JSON` structure into Elastic Common Schema (ECS) fields. This provides records of HTTP requests and responses, including headers and metadata, used for security auditing and forensic analysis. By default, the integration monitors files matching the pattern `/var/log/modsec-audit*`.

### Supported use cases

Integrating ModSecurity audit logs with the Elastic Stack provides you with enhanced visibility and security analysis capabilities:
- Web application attack detection: You can monitor logs for common web attacks such as SQL injection (SQLi), Cross-Site Scripting (XSS), and Local File Inclusion (LFI) as identified by [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) rules.
- Regulatory compliance: You can maintain a comprehensive audit trail of all HTTP transactions and security interventions to satisfy your compliance requirements.
- WAF rule tuning and false positive analysis: You can review detailed audit logs to identify legitimate traffic being blocked by restrictive rules, enabling you to create rule exceptions and reduce business disruption.
- Security incident response: You can correlate WAF events with other system and network logs in Kibana to trace the path of an attacker across your infrastructure during a security breach.

## What do I need to use this integration?

### Vendor prerequisites

Before you configure the integration, ensure you meet these requirements on the ModSecurity host:
- Administrative access: You must have `sudo` or root privileges to modify web server configurations for Nginx or Apache and ModSecurity configuration files.
- `YAJL` support: Verify that your ModSecurity installation was compiled with `YAJL` support. Without it, the `SecAuditLogFormat JSON` directive will cause a configuration error.
- Logging directory permissions: The Elastic Agent must have read permissions for the directory and file where ModSecurity writes its audit logs, such as `/var/log/`.
- Disk space: Ensure you have adequate disk space available for the serial audit log file. You'll want to implement log rotation using a tool like `logrotate` to prevent disk exhaustion on high-traffic servers.

### Elastic prerequisites

To use this integration, you need the following Elastic Stack components:
- Elastic Agent: You must have an Elastic Agent installed on the host where ModSecurity is running and enrolled in a fleet policy.
- Kibana and Elasticsearch: This integration requires Kibana version 8.11.0 or later (or 9.0.0+).
- Network connectivity: The host must have outbound connectivity to the Elastic Stack (Elasticsearch and Fleet Server) on ports `443` or `9200`/`8220`.
- Integration asset installation: You must install the ModSecurity Audit integration in Kibana through the Integrations app before data can be correctly parsed.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the log file receiver and ship the data to Elastic, where the events will then be processed using the integration's ingest pipelines.

### Set up steps in ModSecurity Audit

To configure ModSecurity for log collection, follow these steps to enable JSON-formatted serial logging:

1.  **Locate the configuration file**: Identify your main `modsecurity.conf` file. Common paths include `/etc/nginx/modsec/modsecurity.conf` for Nginx or `/etc/modsecurity/modsecurity.conf` for Apache.
2.  **Enable the audit engine**: Set the engine to log only relevant events to reduce volume.
    ```apache
    SecAuditEngine RelevantOnly
    ```
3.  **Configure JSON format**: Ensure the logs are structured for the integration parser.
    ```apache
    SecAuditLogFormat JSON
    ```
4.  **Set logging type**: Use serial logging to write all events to a single file.
    ```apache
    SecAuditLogType Serial
    ```
5.  **Define log parts**: Specify which transaction parts to include. It's recommended to exclude part `K` to prevent ingestion issues. You can also include `C` for the full request body.
    ```apache
    SecAuditLogParts ABFHJZ
    ```
6.  **Specify log path**: Set the destination file for the audit logs (for example, `/var/log/modsec-audit.json`).
    ```apache
    SecAuditLog /var/log/modsec-audit.json
    ```
7.  **Integrate with the web server**: Ensure your web server configuration loads these rules.
    *   **Nginx**: Add `modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;` to your server block.
    *   **Apache**: Verify that `mod_security2` is enabled and includes the configuration file.
8.  **Restart the service**: Apply changes by restarting the web server.
    *   For Nginx, run `sudo systemctl restart nginx`.
    *   For Apache, run `sudo systemctl restart apache2` or `sudo systemctl restart httpd`.

### Set up steps in Kibana

To set up the integration in Kibana, follow these steps:

1. In Kibana, navigate to **Management > Integrations**.
2. Search for and select **ModSecurity Audit**.
3. Click **Add ModSecurity Audit**.
4. Under the **Collect logs from modsecurity instances** input, configure the settings listed below.
5. Select the **Elastic Agent policy** to which you want to add this integration.
6. Click **Save and continue** and then **Add Elastic Agent to your hosts** if you haven't already deployed an agent.

This integration supports the following configuration settings:
- **Paths**: The list of file paths to monitor (for example, `/var/log/modsec-audit.json`). This must match the `SecAuditLog` path defined in your configuration. The default is `['/var/log/modsec-audit*']`.
- **Preserve original event**: If enabled, a raw copy of the original log is stored in the `event.original` field. The default is `false`.
- **Timezone offset**: The timezone used for parsing timestamps. This accepts canonical IDs (like `Europe/Amsterdam`), abbreviated IDs (like `EST`), or HH:mm differentials (like `-05:00`). The default is `local`.
- **Tags**: Custom tags to include with the exported data for easier filtering. The default is `['modsec-audit']`.
- **Processors**: Optional processors to enhance or reduce event fields before parsing.

### Validation

To validate that the integration is working properly and data is flowing into Elasticsearch, follow these steps:

1. Verify the Elastic Agent status by navigating to **Management > Fleet > Agents** and confirming that the agent is online and healthy.
2. Trigger a security event by generating a request with a common malicious payload:
    ```bash
    curl "http://localhost/?id=1'%20OR%20'1'='1"
    ```
3. Attempt to access a sensitive system file to trigger local file inclusion rules:
    ```bash
    curl "http://localhost/../etc/passwd"
    ```
4. Verify that the log file is being updated locally on the host machine:
    ```bash
    tail -n 5 /var/log/modsec-audit.json
    ```
5. In Kibana, navigate to **Analytics > Discover**.
6. Select the `logs-*` data view.
7. Enter the following KQL filter in the search bar: `data_stream.dataset : "modsecurity.auditlog"`
8. Verify that events appear with recent timestamps. Expand an entry to confirm that fields such as `event.dataset`, `source.ip`, and `event.original` (if enabled) are populated correctly.

## Troubleshooting

For help with Elastic ingest tools, check the [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems) documentation. If you encounter issues specific to the ModSecurity Audit integration, refer to the sections below.

### Common configuration issues

If you encounter issues while setting up or running this integration, refer to these common problems and their solutions:

- Logs are not being parsed into fields:
    * Ensure that `SecAuditLogFormat JSON` is active in your `modsecurity.conf` file. If logs are written in a different format, the integration won't be able to structure the data correctly.
- Permission denied errors:
    * Check that the Elastic Agent user has read permissions for the log files and execution permissions for the parent directories. You can grant access by running a command like `chmod 644 /var/log/modsec-audit.json` as needed.
- ModSecurity fails to start with an unknown directive error:
    * If you get an error about `SecAuditLogFormat`, your version of ModSecurity might have been compiled without YAJL support. You'll need to reinstall or recompile ModSecurity with the YAJL library to enable JSON logging.
- Extremely large log lines causing truncation or ingestion failures:
    * You should exclude part `K` (the list of all rules matched) from your `SecAuditLogParts` directive. Including this part can create log entries that exceed the agent's buffer limits. Try using `SecAuditLogParts ABFHJZ` instead.
- Parsing errors like "cannot unmarshal":
    * This usually happens if the log file contains data that isn't valid JSON, possibly due to multiple logging formats writing to the same file. You can verify the file content by running the following command:
      ```bash
      jq . /var/log/modsec-audit.json
      ```
- Logs appear in the wrong time range:
    * Check the timezone settings on your web server. You can adjust the `tz_offset` (Timezone Offset) variable in the integration settings to match your server's local time.

## Performance and scaling

This integration uses the Elastic Agent `logfile` input to monitor local audit logs. To ensure optimal performance in high-volume environments, you can consider the following adjustments:

- Set `SecAuditLogType` to `Serial` to write all audit events to a single file. The `Concurrent` logging method creates a separate file for every transaction and increases the risk of I/O becoming a bottleneck.
- Exclude `Part K` (the list of all rules matched) from the `SecAuditLogParts` directive to manage data volume and prevent ingestion failures. Including `Part K` can create excessively large log entries that exceed the maximum line size limits for parsing.
- Reduce storage overhead and ingestion noise by only logging relevant transactions. Use `SecAuditEngine RelevantOnly` so only transactions that trigger a warning or error are logged, or use `SecAuditLogRelevantStatus` to filter for specific HTTP codes.
- Deploy an Elastic Agent on each node in distributed environments with multiple web server nodes to collect logs locally rather than forwarding them over the network.
- Ensure the host has enough CPU and memory for real-time JSON parsing if you're operating in a high-traffic environment.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

The ModSecurity Audit integration uses the following inputs to collect data:

{{ inputDocs }}

### Vendor documentation links

You can find more information about ModSecurity and its rulesets in these resources:

- [ModSecurity GitHub Repository](https://github.com/owasp-modsecurity/ModSecurity) - Source code and community issue tracker.
- [OWASP Core Rule Set (CRS)](https://coreruleset.org/) - The standard rule set used with ModSecurity.
- [ModSecurity v3 Reference Manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29)
- [ModSecurity v2 Reference Manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29)

### Data streams

The ModSecurity Audit integration provides the following data stream:

#### Auditlog

The `auditlog` data stream provides events from ModSecurity audit logs, specifically security audit logs. You'll get detailed information about HTTP transactions that match rules, which includes request and response headers as well as bodies.

##### Auditlog fields

This table provides a list of all fields exported by the `auditlog` data stream:

{{ fields "auditlog" }}

##### Auditlog sample event

This is a sample event from the `auditlog` data stream:

{{ event "auditlog" }}
