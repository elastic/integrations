# ModSecurity Audit Integration for Elastic

## Overview
The ModSecurity Audit integration for Elastic enables the collection of audit logs from ModSecurity, an open-source web application firewall (WAF). This integration allows for real-time monitoring, logging, and access control for web applications. By ingesting ModSecurity logs, users can detect and prevent common security vulnerabilities like SQL injection and cross-site scripting (XSS), harden web applications, and help meet security compliance requirements.

This integration collects ModSecurity audit logs directly from log files.

### Compatibility
This integration has been tested with ModSecurity v3 using both the nginx and Apache connectors.

It is compatible with Kibana versions ^8.11.0 or ^9.0.0.

### How it works
The integration works by monitoring a specified log file where ModSecurity writes its audit logs. The Elastic Agent reads new log entries from this file, parses them, and sends them to Elasticsearch for indexing and analysis. For this to work, ModSecurity must be configured to produce audit logs in JSON format.

## What data does this integration collect?
The ModSecurity Audit integration collects audit logs. These logs contain detailed information about each HTTP transaction processed by the web server, including request and response headers, body content, and any security rules that were triggered.

### Supported use cases
- **Real-time Threat Detection**: Monitor web traffic to identify and respond to security threats as they happen.
- **Security Auditing and Compliance**: Maintain detailed logs of web application activity to meet compliance standards.
- **Vulnerability Analysis**: Analyze logs to understand how attackers are trying to exploit your applications and identify areas for improvement.
- **Incident Response**: Use detailed transaction logs to investigate security incidents and understand the scope of an attack.

## What do I need to use this integration?
To use this integration, you must configure ModSecurity to produce audit logs in JSON format. The following configuration should be added to your ModSecurity setup:

```
SecAuditLogParts ABDEFHIJZ
SecAuditLogType Serial
SecAuditLog /var/log/modsec_audit.json
SecAuditLogFormat JSON
```

It is important to exclude part 'K' (`SecAuditLogParts`) from the configuration, as it can create logs that are too large to be processed. The `SecAuditLog` path should be updated to the location where you want to store the audit logs.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed to collect logs and send them to Elastic. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Onboard / configure

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for "ModSecurity" and click on it.
3.  Click **Add ModSecurity Audit**.
4.  Configure the integration with a name and optionally a description.
5.  Under **Agent policy**, choose an existing policy or create a new one.
6.  In the agent policy, configure the `modsecurity` input. You will need to provide the path to the ModSecurity audit log file (e.g., `/var/log/modsec_audit.json` or `/var/log/modsec-audit*`).
7.  Save the integration policy. The Elastic Agent will now start collecting ModSecurity audit logs.

### Validation
To validate that the integration is working:
1.  After configuring the integration, generate some HTTP traffic to the web server that is being monitored by ModSecurity.
2.  In Kibana, navigate to the **Discover** tab.
3.  Select the appropriate data view (e.g., `logs-modsecurity.audit-*`).
4.  You should see events from ModSecurity appearing in Discover. You can inspect these events to ensure they are parsed correctly and contain the expected data.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common Configuration Issues

- **No data is being collected**:
  - *Solution*: Verify that the path to the ModSecurity audit log in your agent policy is correct and that the Elastic Agent has the necessary permissions to read the file. Ensure that ModSecurity is generating logs to that file.
- **Logs are not parsed correctly**:
  - *Solution*: Ensure that your ModSecurity configuration includes `SecAuditLogFormat JSON`. Also, as mentioned in the prerequisites, be sure to exclude part 'K' from `SecAuditLogParts` as it can make raw logs too long to parse.

## Scaling

ModSecurity can be deployed embedded within a web server process (like Apache or Nginx) or as part of a reverse proxy server. This allows it to scale along with your existing web infrastructure. When properly configured, the performance impact of ModSecurity is minimal. For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### auditlog

The `auditlog` data stream provides events from the ModSecurity audit log.

<!-- HUMAN-EDITED START -->
#### auditlog fields

{{ fields "auditlog" }}
<!-- HUMAN-EDITED END -->

### Vendor Resources
- [ModSecurity GitHub Repository](https://github.com/owasp-modsecurity/ModSecurity)
- [OWASP ModSecurity Project Page](https://owasp.org/www-project-modsecurity/)
- [ModSecurity Reference Manual (v2.x)](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29)
