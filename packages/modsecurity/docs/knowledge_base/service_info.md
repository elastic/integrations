# Service Info

## Common use cases

ModSecurity is an open-source web application firewall (WAF) that can be used for:
- Real-time monitoring, logging, and access control for web applications.
- Detecting and preventing common security vulnerabilities like SQL injection and cross-site scripting (XSS).
- Hardening web applications and helping to meet security compliance requirements.

## Data types collected

This integration collects ModSecurity audit logs. These logs contain detailed information about each HTTP transaction processed by the web server, including request and response headers, body content, and any security rules that were triggered.

## Compatibility

This integration has been tested with ModSecurity v3 using both the nginx and Apache connectors.

## Scaling and Performance

ModSecurity can be deployed embedded within a web server process (like Apache or Nginx) or as part of a reverse proxy server. This allows it to scale along with your existing web infrastructure. When properly configured, the performance impact of ModSecurity is minimal.

# Set Up Instructions

## Vendor prerequisites

To use this integration, you must configure ModSecurity to produce audit logs in JSON format. The following configuration should be added to your ModSecurity setup:

```
SecAuditLogParts ABDEFHIJZ
SecAuditLogType Serial
SecAuditLog /var/log/modsec_audit.json
SecAuditLogFormat JSON
```

It is important to exclude part 'K' from `SecAuditLogParts`, as it can create logs that are too large to be processed.

## Elastic prerequisites

/* If there are any Elastic specific prerequisites, add them here

    The stack version and agentless support is not needed, as this can be taken from the manifest */

## Vendor set up steps

Once ModSecurity is installed and configured to output JSON audit logs as described above, no further vendor-side setup is required for this integration.

## Kibana set up steps

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for "ModSecurity" and click on it.
3.  Click **Add ModSecurity Audit**.
4.  Configure the integration with a name and optionally a description.
5.  Under **Agent policy**, choose an existing policy or create a new one.
6.  In the agent policy, configure the `modsecurity` input. You will need to provide the path to the ModSecurity audit log file (e.g., `/var/log/modsec_audit.json` or `/var/log/modsec-audit*`).
7.  Save the integration policy. The Elastic Agent will now start collecting ModSecurity audit logs.

# Validation Steps

1.  After configuring the integration, generate some HTTP traffic to the web server that is being monitored by ModSecurity.
2.  In Kibana, navigate to the **Discover** tab.
3.  Select the appropriate data view (e.g., `logs-modsecurity.audit-*`).
4.  You should see events from ModSecurity appearing in Discover. You can inspect these events to ensure they are parsed correctly and contain the expected data.

# Troubleshooting

## Common Configuration Issues

- **No data is being collected**:
  - *Solution*: Verify that the path to the ModSecurity audit log in your agent policy is correct and that the Elastic Agent has the necessary permissions to read the file. Ensure that ModSecurity is generating logs to that file.
- **Logs are not parsed correctly**:
  - *Solution*: Ensure that your ModSecurity configuration includes `SecAuditLogFormat JSON`. Also, as mentioned in the prerequisites, be sure to exclude part 'K' from `SecAuditLogParts` as it can make raw logs too long to parse.

## Ingestion Errors

/* For problems that involve "error.message" being set on ingested data */

## API Authentication Errors

/* For API authentication failures, credential errors, and similar */

## Vendor Resources

/* If the vendor has a troubleshooting specific help page, add it here */

# Documentation sites

- [ModSecurity GitHub Repository](https://github.com/owasp-modsecurity/ModSecurity)
- [OWASP ModSecurity Project Page](https://owasp.org/www-project-modsecurity/)
- [ModSecurity Reference Manual (v2.x)](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29)
