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

An example event for `kdc` looks as following:

```json
{
    "@timestamp": "2026-03-13T07:27:42.000Z",
    "event": {
        "kind": "event",
        "module": "freeipa",
        "dataset": "freeipa.kdc",
        "category": [
            "authentication"
        ],
        "type": [
            "start"
        ],
        "action": "kdc_tgt_grant",
        "outcome": "success"
    },
    "freeipa": {
        "kdc": {
            "request_type": "AS_REQ",
            "client_principal": "host/ipa1.lab.local@LAB.LOCAL",
            "service_principal": "krbtgt/LAB.LOCAL@LAB.LOCAL",
            "encryption_type": "aes256-cts-hmac-sha384-192",
            "realm": "LAB.LOCAL",
            "authtime": "2026-03-10T21:27:42.000Z"
        }
    },
    "observer": {
        "hostname": "ipa1.lab.local"
    },
    "process": {
        "pid": 70110
    },
    "log": {
        "level": "info"
    },
    "source": {
        "ip": "172.30.0.60"
    },
    "user": {
        "name": "host/ipa1.lab.local",
        "domain": "LAB.LOCAL",
        "id": "host/ipa1.lab.local@LAB.LOCAL"
    },
    "related": {
        "user": [
            "host/ipa1.lab.local",
            "host/ipa1.lab.local@LAB.LOCAL"
        ],
        "ip": [
            "172.30.0.60"
        ]
    },
    "data_stream": {
        "type": "logs",
        "dataset": "freeipa.kdc",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "tags": [
        "freeipa-kdc"
    ]
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category for ECS compatibility. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| event.outcome | The outcome of the event (success or failure). | keyword |
| event.reason | Reason for the event outcome, typically an error message. | keyword |
| event.type | Event type for ECS compatibility. | keyword |
| freeipa.kdc.authtime | Authentication timestamp from the ticket. | date |
| freeipa.kdc.client_principal | Full client Kerberos principal (user@REALM). | keyword |
| freeipa.kdc.encryption_type | Reply encryption type used for the ticket. | keyword |
| freeipa.kdc.error_code | KDC status code for non-ISSUE responses. Set for all statuses except ISSUE, including NEEDED_PREAUTH which has event.outcome=success because it is a normal pre-authentication negotiation step, not a failure. | keyword |
| freeipa.kdc.realm | Kerberos realm. | keyword |
| freeipa.kdc.request_type | Kerberos request type (AS_REQ or TGS_REQ). | keyword |
| freeipa.kdc.s4u_client | S4U2Proxy delegated client principal (constrained delegation). | keyword |
| freeipa.kdc.service_principal | Full service principal being requested. | keyword |
| log.level | Log level of the event. | keyword |
| observer.hostname | Hostname of the FreeIPA server. | keyword |
| process.pid | Process ID of the KDC daemon. | long |
| related.ip | All IP addresses seen in this event. | ip |
| related.user | All user identifiers seen in this event. | keyword |
| source.ip | IP address of the Kerberos client. | ip |
| source.user.domain | Realm of the acting service in constrained delegation. | keyword |
| source.user.id | Full acting service principal in constrained delegation. | keyword |
| source.user.name | Acting service principal name in constrained delegation. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Kerberos realm. | keyword |
| user.id | Full Kerberos principal. | keyword |
| user.name | Short principal name (or target user for non-delegation events). | keyword |
| user.target.domain | Realm of the impersonated user in constrained delegation. | keyword |
| user.target.id | Full principal of the impersonated user in constrained delegation. | keyword |
| user.target.name | Impersonated user in constrained delegation (S4U2Proxy). | keyword |


### Directory Access

The `directory_access` data stream collects LDAP operation logs from 389 Directory Server (`/var/log/dirsrv/slapd-*/access`). Each line is one event — either an operation (BIND, SRCH, MOD, ADD, DEL) or a RESULT line with the outcome. Operations and results share `conn=N op=N` identifiers for correlation.

An example event for `directory_access` looks as following:

```json
{
    "@timestamp": "2026-03-13T07:57:42.206196Z",
    "event": {
        "kind": "event",
        "module": "freeipa",
        "dataset": "freeipa.directory_access",
        "category": [
            "database"
        ],
        "type": [
            "info"
        ],
        "action": "ldap_result",
        "outcome": "success",
        "duration": 3128975
    },
    "freeipa": {
        "directory": {
            "connection_id": 109,
            "operation_id": 7,
            "operation": "RESULT",
            "result_code": 0,
            "entries_returned": 0,
            "elapsed_time": 0.003128975,
            "tag_number": 101,
            "notes": "P"
        }
    },
    "related": {},
    "data_stream": {
        "type": "logs",
        "dataset": "freeipa.directory_access",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "tags": [
        "freeipa-directory-access"
    ]
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category for ECS compatibility. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.duration | Duration of the LDAP operation in nanoseconds. | long |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| event.outcome | The outcome of the event (success or failure). | keyword |
| event.reason | Reason for the event outcome, typically an LDAP error description. | keyword |
| event.type | Event type for ECS compatibility. | keyword |
| freeipa.directory.base_dn | Base DN for search operations. | keyword |
| freeipa.directory.bind_dn | DN used for BIND authentication. | keyword |
| freeipa.directory.bind_method | BIND method (SIMPLE or SASL/mechanism). | keyword |
| freeipa.directory.connection_id | LDAP connection number (conn=N). | long |
| freeipa.directory.elapsed_time | Elapsed time for the operation in seconds. | float |
| freeipa.directory.entries_returned | Number of entries returned by the operation. | long |
| freeipa.directory.ext_name | Human-readable name of the LDAP extended operation. | keyword |
| freeipa.directory.ext_oid | OID of the LDAP extended operation. | keyword |
| freeipa.directory.filter | LDAP search filter. | keyword |
| freeipa.directory.new_rdn | New relative distinguished name in MODRDN operations. | keyword |
| freeipa.directory.new_superior | New parent DN in MODRDN operations. | keyword |
| freeipa.directory.notes | Notes field from RESULT lines (P for paged, U for unindexed, A for all-ids threshold). | keyword |
| freeipa.directory.operation | LDAP operation type (BIND, SRCH, MOD, ADD, DEL, CMP, RESULT, CONNECTION, DISCONNECT). | keyword |
| freeipa.directory.operation_id | LDAP operation number within the connection (op=N). | long |
| freeipa.directory.result_code | LDAP result code (0 = success). | integer |
| freeipa.directory.scope | Search scope (base, one, sub). | keyword |
| freeipa.directory.ssl | Whether the connection uses SSL/TLS. | boolean |
| freeipa.directory.tag_number | LDAP protocol tag number from RESULT. | long |
| freeipa.directory.target_dn | Target DN for modify, add, delete, or compare operations. | keyword |
| freeipa.directory.target_op | Target operation ID being abandoned (ABANDON events only). | long |
| freeipa.directory.unindexed | Whether the operation required an unindexed search. | boolean |
| related.ip | All IP addresses seen in this event. | ip |
| related.user | All user identifiers seen in this event. | keyword |
| source.ip | IP address of the LDAP client. | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Full bind DN. | keyword |
| user.name | Username extracted from the bind DN. | keyword |


### Directory Errors

The `directory_errors` data stream collects error and warning logs from 389 Directory Server (`/var/log/dirsrv/slapd-*/errors`). This includes replication failures, plugin errors, unindexed search warnings, and server lifecycle events.

An example event for `directory_errors` looks as following:

```json
{
    "@timestamp": "2026-03-12T21:27:31.955Z",
    "event": {
        "kind": "event",
        "module": "freeipa",
        "dataset": "freeipa.directory_errors",
        "action": "directory_error",
        "category": [
            "database"
        ],
        "type": [
            "info"
        ]
    },
    "freeipa": {
        "directory_error": {
            "subsystem": "NSACLPlugin",
            "message": "acl_parse - The ACL target cn=vaults,cn=kra,dc=lab,dc=local does not exist"
        }
    },
    "log": {
        "level": "warn"
    },
    "data_stream": {
        "type": "logs",
        "dataset": "freeipa.directory_errors",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "tags": [
        "freeipa-directory-errors"
    ]
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category for ECS compatibility. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| event.type | Event type for ECS compatibility. | keyword |
| freeipa.directory_error.agreement | Replication agreement name. | keyword |
| freeipa.directory_error.ldap_error_code | LDAP error code from a replication operation. | integer |
| freeipa.directory_error.message | Full log message text after the subsystem prefix. | match_only_text |
| freeipa.directory_error.remote_host | Remote host in a replication agreement. | keyword |
| freeipa.directory_error.subsystem | Directory Server subsystem that produced the log entry. | keyword |
| log.level | Log level of the event. | keyword |
| related.hosts | All hostnames or FQDNs related to the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### CA Audit

The `ca_audit` data stream collects signed audit events from the Dogtag PKI Certificate Authority (`/var/log/pki/pki-tomcat/ca/signedAudit/ca_audit`). This includes certificate requests, issuances, revocations, CA authentication events, and session tracking. This data stream is only active on FreeIPA servers that run the CA role.

An example event for `ca_audit` looks as following:

```json
{
    "@timestamp": "2026-03-12T21:27:48.000Z",
    "event": {
        "kind": "event",
        "module": "freeipa",
        "dataset": "freeipa.ca_audit",
        "category": [
            "session"
        ],
        "type": [
            "start"
        ],
        "action": "ca_session_establish",
        "outcome": "success"
    },
    "freeipa": {
        "ca": {
            "event_type": "CLIENT_ACCESS_SESSION_ESTABLISH",
            "thread": "0.RetrieveModificationsTask",
            "server_host": "172.30.0.60",
            "server_port": 636,
            "serial_number": "8",
            "issuer_dn": "CN=Certificate Authority,O=LAB.LOCAL"
        }
    },
    "source": {
        "ip": "172.30.0.60"
    },
    "user": {
        "name": "CN=ipa1.lab.local,O=LAB.LOCAL",
        "id": "CN=ipa1.lab.local,O=LAB.LOCAL"
    },
    "related": {
        "user": [
            "CN=ipa1.lab.local,O=LAB.LOCAL"
        ],
        "ip": [
            "172.30.0.60"
        ]
    },
    "data_stream": {
        "type": "logs",
        "dataset": "freeipa.ca_audit",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "tags": [
        "freeipa-ca-audit"
    ]
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category for ECS compatibility. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| event.outcome | The outcome of the event (success or failure). | keyword |
| event.type | Event type for ECS compatibility. | keyword |
| freeipa.ca.acl_op | ACL operation from authorization events. | keyword |
| freeipa.ca.acl_resource | ACL resource name from authorization events. | keyword |
| freeipa.ca.approval | Approval status of certificate status change requests. | keyword |
| freeipa.ca.auth_manager | Authentication manager used for the request. | keyword |
| freeipa.ca.event_type | CA audit event type (for example, CLIENT_ACCESS_SESSION_ESTABLISH, CERT_REQUEST_PROCESSED). | keyword |
| freeipa.ca.info | Additional information from the audit event (can contain stack traces or long error messages). | match_only_text |
| freeipa.ca.issuer_dn | Certificate issuer distinguished name. | keyword |
| freeipa.ca.profile | Certificate profile ID used for the request. | keyword |
| freeipa.ca.request_id | Certificate request ID. | keyword |
| freeipa.ca.request_type | Certificate request type (for example, enrollment, renewal). | keyword |
| freeipa.ca.revocation_reason | Reason code for certificate revocation. | keyword |
| freeipa.ca.role | Role assumed in ROLE_ASSUME events. | keyword |
| freeipa.ca.scope | Scope of the configuration change. | keyword |
| freeipa.ca.serial_number | Certificate serial number. | keyword |
| freeipa.ca.server_host | Server hostname or IP from the audit event. | keyword |
| freeipa.ca.server_port | Server port from the audit event. | integer |
| freeipa.ca.subject_dn | Certificate subject distinguished name. | keyword |
| freeipa.ca.thread | Thread name from the CA audit log. | keyword |
| related.hosts | All hostnames seen in this event. | keyword |
| related.ip | All IP addresses seen in this event. | ip |
| related.user | All user identifiers seen in this event. | keyword |
| source.ip | IP address of the client. | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Subject ID from the audit event. | keyword |
| user.name | Subject identity from the audit event. | keyword |


### IPA API

The `ipa_api` data stream collects FreeIPA JSON API operation logs from the Apache error log (`/var/log/httpd/error_log`). Each event represents a high-level IPA command (user_add, group_add_member, cert_request, and others) with the acting principal, parameters, and result.

An example event for `ipa_api` looks as following:

```json
{
    "@timestamp": "2026-03-12T21:29:50.731Z",
    "event": {
        "kind": "event",
        "module": "freeipa",
        "dataset": "freeipa.ipa_api",
        "category": [
            "iam"
        ],
        "type": [
            "change"
        ],
        "action": "group_add_member",
        "outcome": "success"
    },
    "freeipa": {
        "api": {
            "command": "group_add_member",
            "parameters": "'testgroup', version='2.254', user=('testuser1,testuser2,testuser3',)",
            "server_class": "jsonserver_session",
            "result": "SUCCESS",
            "version": "1"
        }
    },
    "group": {
        "name": "testgroup"
    },
    "process": {
        "pid": 71201,
        "thread": {
            "id": 71423
        }
    },
    "source": {
        "ip": "172.30.0.60",
        "port": 55276
    },
    "user": {
        "name": "admin",
        "domain": "LAB.LOCAL",
        "id": "admin@LAB.LOCAL"
    },
    "related": {
        "user": [
            "admin",
            "admin@LAB.LOCAL"
        ],
        "ip": [
            "172.30.0.60"
        ]
    },
    "data_stream": {
        "type": "logs",
        "dataset": "freeipa.ipa_api",
        "namespace": "default"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "tags": [
        "freeipa-ipa-api"
    ]
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category for ECS compatibility. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.duration | Duration of the API call in nanoseconds. | long |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| event.outcome | The outcome of the event (success or failure). | keyword |
| event.reason | Reason for the event outcome when not SUCCESS. | keyword |
| event.type | Event type for ECS compatibility. | keyword |
| freeipa.api.command | IPA API command name (user_add, group_add_member, and others). | keyword |
| freeipa.api.parameters | Command parameters from the API call (can contain long values like CSRs). | match_only_text |
| freeipa.api.result | Raw result string from the API call (SUCCESS or error text). | keyword |
| freeipa.api.server_class | IPA server handler class (jsonserver_session, jsonserver_kerb). | keyword |
| freeipa.api.version | IPA API version used for the call. | keyword |
| group.name | Target group name for group commands. | keyword |
| host.name | Target host for host commands. | keyword |
| process.pid | Process ID of the httpd worker. | long |
| process.thread.id | Thread ID of the httpd worker. | long |
| related.hosts | All hostnames seen in this event. | keyword |
| related.ip | All IP addresses seen in this event. | ip |
| related.user | All user identifiers seen in this event. | keyword |
| source.ip | IP address of the API client. | ip |
| source.port | Source port of the API client. | long |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Kerberos realm of the principal. | keyword |
| user.id | Full Kerberos principal (user@REALM). | keyword |
| user.name | Short principal name (without realm). | keyword |
| user.target.name | Target user of the API command (the user being created, modified, or deleted). | keyword |


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
