# FreeIPA Integration

This integration collects security-relevant logs from FreeIPA (Red Hat IdM) identity management servers. It parses authentication events from the Kerberos KDC, LDAP operations from 389 Directory Server, PKI certificate lifecycle events from Dogtag CA, and high-level IAM operations from the FreeIPA JSON API. All data streams use filestream input to read log files directly from the server.

## Compatibility

Tested with FreeIPA 4.11 on Rocky Linux 9 and RHEL 9. Should work with FreeIPA 4.6 and later on any supported platform (RHEL 7+, CentOS, Rocky, Alma, Fedora). Red Hat IdM is the same software and produces the same log formats.

## Setup

Deploy one Elastic Agent per FreeIPA server. The agent reads log files directly, so it needs to run on the same host (or have the log directories mounted).

### File permissions

The Elastic Agent process needs read access to these log files:

| Log file | Default owner | Notes |
|----------|---------------|-------|
| `/var/log/krb5kdc.log` | root:root | Readable by root only by default |
| `/var/log/dirsrv/slapd-*/access` | dirsrv:dirsrv | |
| `/var/log/dirsrv/slapd-*/errors` | dirsrv:dirsrv | |
| `/var/log/pki/pki-tomcat/ca/signedAudit/ca_audit` | pkiuser:pkiuser | Only on CA replicas |
| `/var/log/httpd/error_log` | root:root | |


Add the `elastic-agent` user to the `dirsrv` and `pkiuser` groups, or use ACLs:

```bash
setfacl -m u:elastic-agent:r /var/log/krb5kdc.log
setfacl -m u:elastic-agent:rx /var/log/dirsrv/slapd-*
setfacl -m u:elastic-agent:r /var/log/dirsrv/slapd-*/access
setfacl -m u:elastic-agent:r /var/log/dirsrv/slapd-*/errors
setfacl -m u:elastic-agent:rx /var/log/pki/pki-tomcat/ca/signedAudit
setfacl -m u:elastic-agent:r /var/log/pki/pki-tomcat/ca/signedAudit/ca_audit
setfacl -m u:elastic-agent:r /var/log/httpd/error_log
```

### Logging configuration

FreeIPA enables most logging by default. Verify these settings:

**KDC logging** (`/etc/krb5.conf`):
```ini
[logging]
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log
```

**389ds access logging** (enabled by default, verify with):
```bash
dsconf slapd-YOUR-REALM config get nsslapd-accesslog-logging-enabled
```

**IPA API debug logging** (`/etc/ipa/default.conf`):
```ini
[global]
debug = True
```

Set `debug = True` to capture API operation details including execution time. Without this, only INFO-level lines are logged (command and result, no timing).

### Elastic Agent configuration

1. In Kibana, go to **Integrations** and search for "FreeIPA".
2. Add the integration and review the default log file paths for each data stream.
3. If your FreeIPA instance name differs from the default, update the 389ds log paths (replace `LAB-LOCAL` with your realm name, dots replaced by dashes).
4. Enable **Preserve Original Event** if you want the raw log line stored in `event.original`.
5. Deploy the policy to an Elastic Agent running on each FreeIPA server.

## Data Streams

### KDC

The `kdc` data stream collects Kerberos KDC authentication events from `/var/log/krb5kdc.log`. Each event represents a ticket request (AS_REQ for TGT, TGS_REQ for service ticket) with its outcome, client principal, service principal, source IP, and encryption types.

{{event "kdc"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "kdc"}}

### Directory Access

The `directory_access` data stream collects LDAP operation logs from 389 Directory Server (`/var/log/dirsrv/slapd-*/access`). Each line is one event — either an operation (BIND, SRCH, MOD, ADD, DEL) or a RESULT line with the outcome. Operations and results share `conn=N op=N` identifiers for correlation.

{{event "directory_access"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "directory_access"}}

### Directory Errors

The `directory_errors` data stream collects error and warning logs from 389 Directory Server (`/var/log/dirsrv/slapd-*/errors`). This includes replication failures, plugin errors, unindexed search warnings, and server lifecycle events.

{{event "directory_errors"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "directory_errors"}}

### CA Audit

The `ca_audit` data stream collects signed audit events from the Dogtag PKI Certificate Authority (`/var/log/pki/pki-tomcat/ca/signedAudit/ca_audit`). This includes certificate requests, issuances, revocations, CA authentication events, and session tracking. This data stream is only active on FreeIPA servers that run the CA role.

{{event "ca_audit"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "ca_audit"}}

### IPA API

The `ipa_api` data stream collects FreeIPA JSON API operation logs from the Apache error log (`/var/log/httpd/error_log`). Each event represents a high-level IPA command (user_add, group_add_member, cert_request, and others) with the acting principal, parameters, and result.

{{event "ipa_api"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "ipa_api"}}

## Alert rule templates

Alert rule templates provide pre-defined configurations for creating alert rules in Kibana. They are not enabled by default — navigate to **Stack Management > Rules** to review and activate them. Each template ships a sensible default threshold that you can adjust after activation.

Alert rule templates require Elastic Stack version 9.2.0 or later. On earlier versions the ES|QL queries can be used manually in **Stack Management > Rules** with the "Elasticsearch query" rule type.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

The following alert rule templates are available:

**[FreeIPA] Replication Errors**

Fires when replication agreement errors appear in the directory server error log. Replication failures between FreeIPA servers can cause split-brain conditions and data inconsistency across replicas. Groups alerts by agreement name and remote host.

**[FreeIPA] Unindexed LDAP Searches**

Fires when 5 or more unindexed LDAP searches are detected in a 15-minute window. Unindexed searches cause full table scans in the directory database, degrading performance for all LDAP clients including SSH logins, sudo rule evaluation, and HBAC checks.

**[FreeIPA] LDAP High Operation Latency**

Fires when the p95 LDAP operation latency exceeds 5 seconds (adjustable) across at least 10 operations in a 5-minute window. High LDAP latency directly impacts Kerberos authentication, sudo resolution, and HBAC evaluation on all enrolled clients.

**[FreeIPA] IPA API Error Spike**

Fires when 10 or more API errors occur in a 5-minute window. A spike in IPA API errors can indicate backend issues such as an unreachable LDAP server, a plugin failure, or a schema conflict after an upgrade.

**[FreeIPA] CA Subsystem Connection Failures**

Fires when the Dogtag CA cannot connect to its LDAP backend (connection refused errors). CA connection failures cause silent certificate renewal failures which can lead to expired IPA server certificates weeks later. Only relevant on servers running the CA role.
