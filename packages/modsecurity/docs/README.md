# ModSecurity Audit Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The ModSecurity Audit integration for Elastic enables you to collect and analyze logs from ModSecurity, the open-source Web Application Firewall (WAF). This integration allows you to ingest detailed transaction logs into the Elastic Stack, providing visibility into HTTP requests and responses for real-time threat detection and forensic investigation. By monitoring these logs, you can detect common web attacks like SQL injection (SQLi) and Cross-Site Scripting (XSS), maintain an audit trail for regulatory compliance, and perform false positive analysis to tune your WAF rules.

### Compatibility

This integration is compatible with the following third-party components:

*   ModSecurity v3 (LibModSecurity)
*   ModSecurity v3 with Nginx connector
*   ModSecurity v3 with Apache connector
*   JSON output, which requires ModSecurity to be compiled with YAJL (Yet Another JSON Library) support as described in the [ModSecurity Reference Manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#secauditlogformat)

### How it works

This integration collects data from ModSecurity by monitoring log files on the host where the WAF is running. You deploy an Elastic Agent to the host and configure it to read the JSON-formatted audit logs produced by ModSecurity's logging engine. The agent uses the `logfile` input to ingest the data, parses the JSON structure into Elastic Common Schema (ECS) fields, and forwards the information to your Elastic deployment.

The integration performs the following actions:

*   Monitors log files matching the default pattern `/var/log/modsec-audit*`.
*   Processes the data using the `auditlog` data stream.
*   Maps ModSecurity fields to ECS for consistent analysis across different log sources.

## What data does this integration collect?

The ModSecurity Audit integration collects log messages of the following types:
- `auditlog`: This data stream collects ModSecurity audit logs using the `logfile` input and parses the `JSON` structure into Elastic Common Schema (ECS) fields. This provides records of HTTP requests and responses, including headers and metadata, used for security auditing and forensic analysis. By default, the integration monitors files matching the pattern `/var/log/modsec-audit*`.

### Supported use cases

Integrating ModSecurity audit logs with the Elastic Stack provides you with enhanced visibility and security analysis capabilities:
- Web application attack detection: You can monitor logs for common web attacks such as SQL injection (SQLi), Cross-Site Scripting (XSS), and Local File Inclusion (LFI) as identified by [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) rules.
- Regulatory compliance: You can maintain a comprehensive audit trail of all HTTP transactions and security interventions to satisfy your compliance requirements.
- WAF rule tuning and false positive analysis: You can review detailed audit logs to identify legitimate traffic being blocked by restrictive rules, enabling you to create exceptions and reduce business disruption.
- Security incident response: You can correlate WAF events with other system and network logs in Kibana to trace the path of an attacker across your infrastructure during a security breach.

## What do I need to use this integration?

### Vendor prerequisites
Before you configure the integration, ensure the following requirements are met on the ModSecurity host:
- Administrative access: You must have `sudo` or root privileges to modify web server configurations (Nginx or Apache) and ModSecurity configuration files.
- JSON support: Verify that your ModSecurity installation was compiled with YAJL support. Without this, the `SecAuditLogFormat JSON` directive will cause a configuration error.
- Logging directory permissions: The Elastic Agent must have read permissions for the directory and file where ModSecurity writes its audit logs, such as `/var/log/`.
- Disk space: Ensure adequate disk space is available for the serial audit log file. You'll want to implement log rotation (for example, using `logrotate`) to prevent disk exhaustion on high-traffic servers.

### Elastic prerequisites
To use this integration, you need the following Elastic Stack components:
- Elastic Agent: You must have an Elastic Agent installed on the host where ModSecurity is running and enrolled in a fleet policy.
- Kibana and Elasticsearch: This integration requires Kibana version 8.11.0 or later (or 9.0.0+).
- Network connectivity: The host must have outbound connectivity to the Elastic Stack (Elasticsearch and Fleet Server) on ports 443 or 9200/8220.
- Integration asset installation: You must install the ModSecurity integration in Kibana through the Integrations app before data can be correctly parsed.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the log file receiver and ship the data to Elastic, where the events will then be processed using the integration's ingest pipelines.

### Set up steps in ModSecurity Audit

To configure ModSecurity for log collection, follow these steps to enable JSON-formatted serial logging:

1. Locate the configuration file: Identify your main `modsecurity.conf` file. Common paths include `/etc/nginx/modsec/modsecurity.conf` for Nginx or `/etc/modsecurity/modsecurity.conf` for Apache.
2. Enable the audit engine: Set the engine to log only relevant events to reduce volume.
    ```apache
    SecAuditEngine RelevantOnly
    ```
3. Configure JSON format: Ensure the logs are structured for the integration parser.
    ```apache
    SecAuditLogFormat JSON
    ```
4. Set logging type: Use serial logging to write all events to a single file.
    ```apache
    SecAuditLogType Serial
    ```
5. Define log parts: Specify which transaction parts to include. You must exclude part `K` to prevent ingestion issues. You can also include `C` for the full request body.
    ```apache
    SecAuditLogParts ABFHJZ
    ```
6. Specify log path: Set the destination file for the audit logs.
    ```apache
    SecAuditLog /var/log/modsec-audit.json
    ```
7. Integrate with the web server: Ensure your web server configuration loads these rules. For Nginx, add `modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;` to your server block. For Apache, verify that `mod_security2` is enabled and includes the configuration file.
8. Restart service: Apply changes by restarting the web server. For Nginx, use `sudo systemctl restart nginx`. For Apache, use `sudo systemctl restart apache2` or `sudo systemctl restart httpd`.

#### Vendor resources

For more information about ModSecurity configuration, refer to the following resources:
- [ModSecurity Integration | Elastic Docs](https://www.elastic.co/docs/reference/integrations/modsecurity)
- [ModSecurity v3 Reference Manual - GitHub](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x))

### Set up steps in Kibana

To set up the integration in Kibana, follow these steps:

1. In Kibana, navigate to **Management > Integrations**.
2. Search for and select **ModSecurity Audit**.
3. Click **Add ModSecurity Audit**.
4. Under the **Collect logs from modsecurity instances** input, configure the settings listed below.
5. Select the **Elastic Agent policy** to which you want to add this integration.
6. Click **Save and continue** and then **Add Elastic Agent to your hosts** if you have not already deployed an agent.

This integration supports the following configuration settings:
- Paths: Paths to the ModSecurity JSON audit log files. This must match the `SecAuditLog` path defined in your configuration. The default is `['/var/log/modsec-audit*']`.
- Preserve original event: If enabled, a raw copy of the original log is stored in the `event.original` field. The default is `false`.
- Timezone offset: Specify the timezone for log parsing. This accepts canonical IDs (such as `Europe/Amsterdam`), abbreviated IDs (such as `EST`), or HH:mm differentials (such as `-05:00`). The default is `local`.
- Tags: Custom tags for filtering ingested events. The default is `['modsec-audit']`.
- Processors: Optional processors to reduce fields or enhance metadata before parsing.

### Validation

To validate that the integration is working properly and data is flowing into Elasticsearch, follow these steps:

1. Trigger a security event by generating a request with a common malicious payload:
    ```bash
    curl "http://localhost/?id=1'%20OR%20'1'='1"
    ```
2. Attempt to access a sensitive system file to trigger local file inclusion rules:
    ```bash
    curl "http://localhost/../etc/passwd"
    ```
3. Verify that the log file is being updated locally on the host machine:
    ```bash
    tail -n 5 /var/log/modsec-audit.json
    ```
4. In Kibana, navigate to **Analytics > Discover**.
5. Select the `logs-*` data view.
6. Enter the following KQL filter in the search bar: `data_stream.dataset : "modsecurity.auditlog"`
7. Verify that events appear with recent timestamps. Expand an entry to confirm that fields such as `event.dataset`, `source.ip`, and `event.original` are populated correctly.

## Troubleshooting
> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

For help with Elastic ingest tools, check the [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems) documentation. If you encounter issues specific to the ModSecurity Audit integration, refer to the sections below.

### Common configuration issues

If you encounter issues while setting up or running this integration, refer to these common problems and their solutions:
- Logs aren't being parsed into fields: Make sure that `SecAuditLogFormat JSON` is enabled in your `modsecurity.conf` file. If logs are written in a different format, the integration won't be able to structure the data correctly.
- Permission denied errors: Check that the Elastic Agent has read permissions for the log files and execution permissions for the parent directories. You can grant access by running a command like `chmod 644 /var/log/modsec-audit.json` as needed.
- ModSecurity fails to start with an unknown directive error: If you get an error about `SecAuditLogFormat`, your version of ModSecurity might have been compiled without YAJL support. You'll need to reinstall or recompile ModSecurity with the YAJL library to enable JSON logging.
- Extremely large log lines causing ingestion failures: You should exclude part `K` (the list of all rules matched) from your `SecAuditLogParts` directive. Including this part can create log entries that exceed the agent's buffer limits. Try using `SecAuditLogParts ABDEFHIJZ` instead.
- Parsing errors like "cannot unmarshal": This usually happens if the log file contains data that isn't valid JSON. You can verify the file content by running the following command:
  ```bash
  jq . /var/log/modsec-audit.json
  ```
- Logs appear in the wrong time range: Check the timezone settings on your web server. You can adjust the `tz_offset` (Timezone Offset) variable in the integration settings to match your server's local time.

### Vendor resources

You can find more information about ModSecurity configuration and troubleshooting in the following resources:
- [ModSecurity GitHub Repository](https://github.com/owasp-modsecurity/ModSecurity)
- [OWASP Core Rule Set (CRS)](https://coreruleset.org/)
- [ModSecurity v3 Reference Manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29)
- [ModSecurity Integration Reference | Elastic Docs](https://www.elastic.co/docs/reference/integrations/modsecurity)

## Performance and scaling

This integration uses the Elastic Agent `logfile` input to monitor local audit logs. To ensure optimal performance in high-volume environments, you should consider the following adjustments:

- Setting `SecAuditLogType` to `Serial` improves performance by writing all audit events to a single file. The `Concurrent` logging method creates a separate file for every transaction and increases the risk of I/O becoming a bottleneck.
- To manage data volume and prevent ingestion failures, you must exclude `Part K` (the list of all rules matched) from the `SecAuditLogParts` directive. Including `Part K` can create excessively large log entries that exceed the maximum line size limits for parsing.
- You can significantly reduce storage overhead and ingestion noise by only logging relevant transactions. `SecAuditEngine RelevantOnly` ensures that only transactions that trigger a warning or error are logged. Alternatively, you can use `SecAuditLogRelevantStatus` to filter for specific HTTP codes.
- In distributed environments with multiple web server nodes, you should deploy an Elastic Agent on each node to collect logs locally rather than forwarding them over the network.
- In high-traffic environments, you'll need to ensure the Agent host has sufficient CPU and memory for real-time JSON parsing.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

This integration uses the following inputs:

These inputs can be used with this integration:
<details>
<summary>logfile</summary>

## Setup
For more details about the logfile input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-log).

### Collecting logs from logfile

To collect logs via logfile, select **Collect logs via the logfile input** and configure the following parameter:

- Paths: List of glob-based paths to crawl and fetch log files from. Supports glob patterns like
  `/var/log/*.log` or `/var/log/*/*.log` for subfolder matching. Each file found starts a
  separate harvester.
</details>


### Vendor documentation links

You can find more information about ModSecurity and its rulesets in the following resources:
- [ModSecurity GitHub Repository](https://github.com/owasp-modsecurity/ModSecurity) - Source code and community issue tracker.
- [OWASP Core Rule Set (CRS)](https://coreruleset.org/) - The standard rule set used with ModSecurity.
- [ModSecurity Integration Reference | Elastic Docs](https://www.elastic.co/docs/reference/integrations/modsecurity)
- [ModSecurity v3 Reference Manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29)
- [Elastic Agent Troubleshooting](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems)

### Data streams

This integration provides the following data stream:

#### auditlog

The `auditlog` data stream provides events from ModSecurity Audit logs of the following types: security audit logs. It captures detailed information about HTTP transactions that match rules, including request/response headers and bodies.

##### auditlog fields

The following table provides a list of all fields exported by the `auditlog` data stream:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.body.content | The full HTTP request body. | wildcard |
| http.request.body.content.text | Multi-field of `http.request.body.content`. | match_only_text |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.mime_type | Mime type of the body of the request. This value must only be populated based on the content of the request body, not on the `Content-Type` header. Comparing the mime type of a request with the request's Content-Type header can be helpful in detecting threats or misconfigured clients. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.content | The full HTTP response body. | wildcard |
| http.response.body.content.text | Multi-field of `http.response.body.content`. | match_only_text |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.mime_type | Mime type of the body of the response. This value must only be populated based on the content of the response body, not on the `Content-Type` header. Comparing the mime type of a response with the response's Content-Type header can be helpful in detecting misconfigured servers. | keyword |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| message | human-readable summary of the event | text |
| modsec.audit.connector | The name of the connector between the web server and libmodsecurity. | keyword |
| modsec.audit.details | Modsecurity audit details. | flattened |
| modsec.audit.messages | Modsecurity audit message. | keyword |
| modsec.audit.server | Modsecurity server name. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| transaction.id | Unique identifier of the transaction within the scope of its trace. A transaction is the highest level of work measured within a service, such as a request to a server. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


##### auditlog sample event

This is a sample event from the `auditlog` data stream:

An example event for `auditlog` looks as following:

```json
{
    "@timestamp": "2021-05-14T14:38:37.000+05:00",
    "agent": {
        "ephemeral_id": "1739e1e4-bab6-4445-968b-7726bd486433",
        "id": "a27141ba-9754-4dc0-9468-bd32f5cbe036",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.1"
    },
    "data_stream": {
        "dataset": "modsecurity.auditlog",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "a27141ba-9754-4dc0-9468-bd32f5cbe036",
        "snapshot": false,
        "version": "8.5.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "modsecurity.auditlog",
        "ingested": "2023-01-30T22:34:38Z",
        "kind": "event",
        "timezone": "+05:00",
        "type": [
            "access"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "75e38940166b4dbc90b6f5610e8e9c39",
        "ip": [
            "172.18.0.7"
        ],
        "mac": [
            "02-42-AC-12-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "http": {
        "request": {
            "method": "PUT"
        },
        "response": {
            "mime_type": "application/json; charset=utf-8",
            "status_code": 400
        },
        "version": "1.1"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/modsec-audit-tz.log"
        },
        "offset": 0
    },
    "modsec": {
        "audit": {
            "server": "nginx/1.14.0"
        }
    },
    "source": {
        "ip": "37.120.205.2",
        "port": 56047
    },
    "tags": [
        "modsec-audit"
    ],
    "url": {
        "domain": "www.test.com",
        "original": "https://www.test.com:443/orders/2734183/finish",
        "path": "/orders/2734183/finish",
        "port": 443,
        "scheme": "https"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "okhttp",
        "original": "okhttp/2.7.5",
        "version": "2.7.5"
    }
}
```
