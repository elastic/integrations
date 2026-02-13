# Service Info

The ModSecurity integration allows users to ingest audit logs from the ModSecurity Web Application Firewall (WAF). This integration provides visibility into web traffic security events, helping administrators monitor and respond to malicious activities.

## Common use cases

The ModSecurity Audit integration provides robust monitoring and security analysis for the open-source Web Application Firewall (WAF) [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity). It allows security administrators to ingest detailed transaction logs into the Elastic Stack for real-time threat detection and forensic investigation.

- **Web Application Attack Detection:** Monitor logs for common web attacks such as SQL injection (SQLi), Cross-Site Scripting (XSS), and Local File Inclusion (LFI) as identified by ModSecurity rules.
- **Regulatory Compliance:** Maintain a comprehensive audit trail of all HTTP transactions and security interventions to satisfy compliance requirements.
- **WAF Rule Tuning and False Positive Analysis:** Review detailed audit logs to identify legitimate traffic being blocked by restrictive rules, enabling administrators to create rule exceptions and reduce business disruption.
- **Security Incident Response:** Correlate WAF events with other system and network logs in Kibana to trace the path of an attacker across the infrastructure during a security breach.

## Data types collected

This integration can collect the following types of data:

- **Modsecurity Audit Log**: Collect modsecurity audit logs. This data stream collects Modsecurity audit logs via the `logfile` input, parsing the JSON structure into Elastic Common Schema (ECS) fields. This provides records of HTTP requests and responses, including headers and metadata, used for security auditing and forensic analysis.
- **Data Formats:** The integration specifically processes logs in **JSON** format produced by ModSecurity's logging engine.
- **Specific File Paths:** By default, the integration monitors files matching the pattern `/var/log/modsec-audit*`.

## Compatibility

The ModSecurity integration is officially compatible with the following third-party components:

- **ModSecurity v3** (LibModSecurity)
- **ModSecurity v3 with Nginx connector**
- **ModSecurity v3 with Apache Connector**

The package also has tests for ModSecurity v2 for Apache (v2.9.x) but only ModSecurity v3 is officially supported.

Support for JSON output [requires ModSecurity to be compiled with **YAJL** (Yet Another JSON Library) support](<https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#secauditlogformat>).

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:

- **Transport/Collection Considerations:** This integration utilizes the Elastic Agent `logfile` input to monitor local audit logs. Note that Setting `SecAuditLogType` to `Serial` helps the performance by ensuring that all audit events are written to a single file. The `Concurrent` logging method creates a file per transaction and increases the risk of I/O being the bottleneck.
- **Data Volume Management:** To manage data volume and prevent ingestion failures, users should exclude **Part K** (the list of all rules matched) from the `SecAuditLogParts` directive. Including Part K can create excessively large log entries that exceed the maximum line size limits for parsing. One can significantly reducing storage overhead and ingestion noise by only logging relevant transactions: `SecAuditEngine RelevantOnly` ensures that only transactions that trigger a warning or error are logged, or `SecAuditLogRelevantStatus` can be used to filter for specific HTTP codes.
- **Elastic Agent Scaling:** In distributed environments with multiple web server nodes, deploy an Elastic Agent on each node to collect logs locally rather than forwarding over the network. For high-traffic servers, ensure the Agent host has sufficient CPU and memory for real-time JSON parsing.

# Set Up Instructions

## Vendor prerequisites

Before configuring the integration, ensure the following requirements are met on the ModSecurity host:

- **Administrative Access:** You must have `sudo` or root privileges to modify web server configurations (Nginx or Apache) and ModSecurity configuration files.
- **JSON Support:** Verify that your ModSecurity installation was compiled with **YAJL** support. Without this, the `SecAuditLogFormat JSON` directive will cause a configuration error.
- **Logging Directory Permissions:** The Elastic Agent must have read permissions for the directory and file where ModSecurity writes its audit logs (e.g., `/var/log/`).
- **Disk Space:** Ensure adequate disk space is available for the serial audit log file. Implement log rotation (e.g., via `logrotate`) to prevent disk exhaustion on high-traffic servers.

## Elastic prerequisites

- **Elastic Agent:** An Elastic Agent must be installed on the host where ModSecurity is running and enrolled in a fleet policy.
- **Kibana/Elasticsearch:** Requires Kibana version 8.11.0 or later (or 9.0.0+).
- **Network Connectivity:** The host must have outbound connectivity to the Elastic Stack (Elasticsearch and Fleet Server) on ports 443 or 9200/8220.
- **Integration Asset Installation:** The ModSecurity integration must be installed in Kibana via the Integrations app before data can be correctly parsed.

## Vendor set up steps

To configure ModSecurity for log collection, follow these steps to enable JSON-formatted serial logging.

### For Logfile Collection:

This includes suggested configuration, but can be modified for a specific use case.

1.  **Locate the Configuration File**: Identify your main `modsecurity.conf` file. Common paths include `/etc/nginx/modsec/modsecurity.conf` for Nginx or `/etc/modsecurity/modsecurity.conf` for Apache.
2.  **Enable the Audit Engine**: Set the engine to log only relevant events to reduce volume.
    ```apache
    SecAuditEngine RelevantOnly
    ```
3.  **Configure JSON Format**: Ensure the logs are structured for the integration parser.
    ```apache
    SecAuditLogFormat JSON
    ```
4.  **Set Logging Type**: Use serial logging to write all events to a single file.
    ```apache
    SecAuditLogType Serial
    ```
5.  **Define Log Parts**: Specify which transaction parts to include. Note it is recommended to exclude part `K` to prevent ingestion issues. Can also include `C` for full request body.
    ```apache
    SecAuditLogParts ABFHJZ
    ```
6.  **Specify Log Path**: Set the destination file for the audit logs.
    ```apache
    SecAuditLog /var/log/modsec-audit.json
    ```
7.  **Integrate with Web Server**: Ensure your web server configuration loads these rules.
    - **Nginx**: Add `modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;` to your server block.
    - **Apache**: Verify that `mod_security2` is enabled and includes the configuration file.
8.  **Restart Service**: Apply changes by restarting the web server.
    - For Nginx: `sudo systemctl restart nginx`
    - For Apache: `sudo systemctl restart apache2` (or `httpd`)

### Vendor Set up Resources

- [ModSecurity Integration | Elastic Docs](https://www.elastic.co/docs/reference/integrations/modsecurity) - Official Elastic documentation for the ModSecurity integration.
- [ModSecurity v3 Reference Manual - GitHub](<https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)>) - Comprehensive reference for ModSecurity v3 configuration directives.

## Kibana set up steps

### Collecting modsecurity audit logs

1. In Kibana, navigate to **Management > Integrations**.
2. Search for and select **ModSecurity Audit**.
3. Click **Add ModSecurity Audit**.
4. Under the **Collect logs from modsecurity instances** input, configure the settings below.
5. Select the **Elastic Agent policy** to which you want to add this integration.
6. Click **Save and continue** and then **Add Elastic Agent to your hosts** if you have not already deployed an agent.

| Setting                     | Variable                  | Default                      | Description                                                                                                                  |
| --------------------------- | ------------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Paths**                   | `paths`                   | `['/var/log/modsec-audit*']` | Paths to the ModSecurity JSON audit log files. Must match `SecAuditLog` path.                                                |
| **Preserve original event** | `preserve_original_event` | `false`                      | Stores raw event in `event.original`.                                                                                        |
| **Timezone Offset**         | `tz_offset`               | `local`                      | Timezone for log parsing. Accepts canonical IDs (`Europe/Amsterdam`), abbreviated (`EST`), or HH:mm differential (`-05:00`). |
| **Tags**                    | `tags`                    | `['modsec-audit']`           | Custom tags for filtering ingested events.                                                                                   |
| **Processors**              | `processors`              | —                            | Optional processors to reduce fields or enhance metadata before parsing.                                                     |

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on ModSecurity:

- **Generate a Security Event:** Attempt to access your web server with a common malicious payload in the query string: `curl "http://localhost/?id=1'%20OR%20'1'='1"`
- **Access Forbidden Path:** Try to access a sensitive system file to trigger local file inclusion rules: `curl "http://localhost/../etc/passwd"`
- **Verify Log Generation:** Check that the log file is being updated locally on the host machine: `tail -n 5 /var/log/modsec-audit.json`

### 2. Check Data in Kibana:

1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "modsecurity.auditlog"`
4. Verify logs appear. Expand a log entry and confirm fields of interest, such as:
   - `event.dataset` (should match `modsecurity.auditlog`)
   - `source.ip` (the client IP originating the request)
   - `event.original` (the raw JSON log payload, if `preserve_original_event` is set to `true`)
   - `http` fields (request and response metadata)

# Troubleshooting

## Common Configuration Issues

**Issue**: Logs appear in Kibana but are not parsed into fields

- **Solution**: Ensure `SecAuditLogFormat JSON` is active in `modsecurity.conf`

**Issue**: Elastic Agent reports "Permission Denied"

- **Solution**: Ensure the Agent user has read access to the log file and execute access to parent directories. Run a command like `chmod 644 /var/log/modsec-audit.json` as needed.

**Issue**: ModSecurity fails to start with `Unknown directive: SecAuditLogFormat`

- **Solution**: Your ModSecurity was compiled without the YAJL library. Reinstall with YAJL support to enable JSON output.

## Ingestion Errors

**Issue**: Extremely large log lines cause truncation or parse failures

- **Solution**: Exclude part `K` from `SecAuditLogParts`. Set to `ABFHJZ`. Part K contains a full list of matched rules which can exceed the agent's buffer limits.

**Issue**: `error.message` shows `json: cannot unmarshal`

- **Solution**: The log file contains non-JSON data, possibly from a configuration change or multiple formats writing to the same file. Validate with `jq . /var/log/modsec-audit.json`.

**Issue**: Logs appear in the wrong time range

- **Solution**: Adjust the **Timezone Offset** (`tz_offset`) variable in the Kibana integration settings to match the timezone of the web server.

## Vendor Resources

- [ModSecurity GitHub Repository](https://github.com/owasp-modsecurity/ModSecurity) - Source code and community issue tracker.
- [OWASP Core Rule Set (CRS)](https://coreruleset.org/) - The standard rule set used with ModSecurity.

# Documentation sites

- [ModSecurity Integration Reference | Elastic Docs](https://www.elastic.co/docs/reference/integrations/modsecurity)
- [ModSecurity v3 Reference Manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29)
- [Elastic Agent Troubleshooting](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems)
