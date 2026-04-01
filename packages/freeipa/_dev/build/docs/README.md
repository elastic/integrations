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

FreeIPA enables most logging by default. Verify these settings are in place:

<!-- vale off -->
**KDC logging** (krb5.conf):
```ini
[logging]
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log
```

**389ds access logging** (enabled by default, verify with the following command):
```bash
dsconf slapd-YOUR-REALM config get nsslapd-accesslog-logging-enabled
```

**IPA API logging** (default.conf):

No configuration required. API operations are logged at INFO level regardless of the `debug` setting. The `debug = True` option adds startup DEBUG messages (~700 lines per httpd restart) but does not affect API operation logging.

<!-- vale on -->
### Elastic Agent configuration

1. In Kibana, go to **Integrations** and search for "FreeIPA".
2. Add the integration and review the default log file paths for each data stream.
3. If your FreeIPA instance name differs from the default, update the 389ds log paths (replace `LAB-LOCAL` with your realm name, dots replaced by dashes).
4. Enable **Preserve Original Event** if you want the raw log line stored in `event.original`.
5. Deploy the policy to an Elastic Agent running on each FreeIPA server.

## Transforms

The integration includes optional transforms that enable cross-event correlation for advanced detection rules.

### latest_bind

Maintains a real-time lookup table mapping each LDAP `connection_id` to the authenticated `bind_dn` and `bind_method` from the corresponding BIND event. This enables detection rules to identify WHO performed an LDAP operation by joining RESULT or SRCH events with the bind context.

**Enables:** Anonymous LDAP enumeration detection, credential attribute search attribution, non-service account enumeration detection, sensitive DN modification attribution, LDAP configuration change attribution.

**Destination index:** `logs-freeipa_latest.dest_bind-1` (lookup mode, compatible with ES|QL LOOKUP JOIN).

**Refresh:** Every 30 seconds. **Retention:** 7 days.

### latest_connection

Maintains a lookup of connection metadata mapping each `connection_id` to `source.ip`, `destination.ip`, and SSL status. Enables correlation of LDAP operations with their network origin.

**Destination index:** `logs-freeipa_latest.dest_connection-1` (lookup mode).

**Refresh:** Every 30 seconds. **Retention:** 7 days.

### latest_auth

Tracks the most recent Kerberos authentication (TGT grant or failure) per `(client_principal, source_ip)` pair. Used by detection rules to identify authentication from new or unusual source IPs for known principals.

**Destination index:** `logs-freeipa_latest.dest_auth-1` (lookup mode).

**Refresh:** Every 30 seconds. **Retention:** 30 days.

### Activating transforms

Transforms are installed in a stopped state. The `kibana_system` user that Fleet uses to manage transforms does not have privileges on custom integration indices, so the transforms need to be started by a user with the right access.

The simplest approach is to run the update and start calls as a superuser (the `elastic` admin account or equivalent):

```
POST /_transform/logs-freeipa.latest_bind-default-<VERSION>/_update
{}

POST /_transform/logs-freeipa.latest_bind-default-<VERSION>/_start
```

The empty `_update` call reassigns the transform's stored credentials to the calling user. Repeat for `latest_connection` and `latest_auth`. Replace `<VERSION>` with the installed package version (for example, `0.1.0`).

For environments where using the admin account is not appropriate, create a dedicated role with read access to the source indices and write access to the destination indices:

```
PUT /_security/role/freeipa_transform
{
  "indices": [
    {
      "names": ["logs-freeipa.directory_access-*", "logs-freeipa.kdc-*"],
      "privileges": ["read", "view_index_metadata"]
    },
    {
      "names": ["logs-freeipa_latest.*"],
      "privileges": ["create_index", "delete", "index", "manage", "read"]
    }
  ]
}
```

Assign this role to a service account or API key, then run the `_update` and `_start` calls as that identity.

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
