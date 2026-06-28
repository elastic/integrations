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

An example event for `kdc` looks as following:

```json
{
    "process": {
        "pid": 379
    },
    "log": {
        "file": {
            "inode": "13949025",
            "path": "/var/log/krb5kdc.log",
            "device_id": "66306",
            "fingerprint": "ec0101bfb20272f986433e1d95695323827bdceb625e503936f02949c17d2fc2"
        },
        "offset": 11787845,
        "level": "info"
    },
    "source": {
        "ip": "10.89.0.2"
    },
    "freeipa": {
        "kdc": {
            "client_principal": "admin@EXAMPLE.TEST",
            "service_principal": "krbtgt/EXAMPLE.TEST@EXAMPLE.TEST",
            "request_type": "AS_REQ",
            "error_code": "NEEDED_PREAUTH",
            "realm": "EXAMPLE.TEST"
        }
    },
    "network": {
        "protocol": "kerberos",
        "transport": "udp"
    },
    "observer": {
        "hostname": "ipa.example.test",
        "product": "FreeIPA",
        "vendor": "Red Hat",
        "type": "kdc"
    },
    "@timestamp": "2026-04-01T18:49:29.000Z",
    "ecs": {
        "version": "8.0.0"
    },
    "related": {
        "ip": [
            "10.89.0.2"
        ],
        "user": [
            "admin",
            "admin@EXAMPLE.TEST"
        ]
    },
    "service": {
        "type": "freeipa"
    },
    "host": {
        "hostname": "ipa.example.test",
        "os": {
            "kernel": "6.18.18-1-lts",
            "codename": "Blue Onyx",
            "name": "Rocky Linux",
            "family": "redhat",
            "type": "linux",
            "version": "9.7 (Blue Onyx)",
            "platform": "rocky"
        },
        "containerized": false,
        "ip": [
            "10.89.0.2",
            "fe80::10d4:6fff:fe83:f407"
        ],
        "name": "ipa.example.test",
        "id": "39a2c6cdbd52ac815c089dc52ec548ba",
        "mac": [
            "12-D4-6F-83-F4-07"
        ],
        "architecture": "x86_64"
    },
    "client": {
        "ip": "10.89.0.2"
    },
    "event": {
        "agent_id_status": "verified",
        "reason": "Additional pre-authentication required",
        "ingested": "2026-04-01T18:49:43Z",
        "kind": "event",
        "action": "kdc_preauth_required",
        "category": [
            "authentication"
        ],
        "type": [
            "info"
        ],
        "outcome": "success"
    },
    "user": {
        "domain": "EXAMPLE.TEST",
        "name": "admin",
        "id": "admin@EXAMPLE.TEST"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.ip | IP address of the Kerberos client. | ip |
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
| network.protocol | Application protocol (kerberos). | keyword |
| network.transport | Transport protocol (udp). | keyword |
| observer.hostname | Hostname of the FreeIPA server. | keyword |
| observer.product | Product name of the observer. | keyword |
| observer.type | Type of the observer component. | keyword |
| observer.vendor | Vendor of the observer. | keyword |
| process.pid | Process ID of the KDC daemon. | long |
| related.ip | All IP addresses seen in this event. | ip |
| related.user | All user identifiers seen in this event. | keyword |
| service.type | Service type identifier. | keyword |
| source.as.number | Autonomous System Number from GeoIP ASN lookup. | long |
| source.as.organization.name | Organization name from GeoIP ASN lookup. | keyword |
| source.geo.city_name | City name from GeoIP lookup. | keyword |
| source.geo.continent_name | Continent name from GeoIP lookup. | keyword |
| source.geo.country_iso_code | Country ISO code from GeoIP lookup. | keyword |
| source.geo.country_name | Country name from GeoIP lookup. | keyword |
| source.geo.location | Longitude and latitude from GeoIP lookup. | geo_point |
| source.geo.region_iso_code | Region ISO code from GeoIP lookup. | keyword |
| source.geo.region_name | Region name from GeoIP lookup. | keyword |
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
    "log": {
        "file": {
            "inode": "14071730",
            "path": "/var/log/dirsrv/slapd-EXAMPLE-TEST/access",
            "device_id": "66306",
            "fingerprint": "c8af355f52f042f6bf41953f638c7762474a85f0c40b8977088a214f18b5c19e"
        },
        "offset": 46219203
    },
    "freeipa": {
        "directory": {
            "entries_returned": 1,
            "optime": 0.000467528,
            "connection_id": 1566,
            "wtime": 0.000146482,
            "elapsed_time": 0.000612577,
            "tag_number": 101,
            "operation_id": 2,
            "result_code": 4,
            "operation": "RESULT"
        }
    },
    "observer": {
        "product": "FreeIPA",
        "hostname": "ipa.example.test",
        "vendor": "Red Hat",
        "type": "directory-server"
    },
    "@timestamp": "2026-04-01T18:48:58.408Z",
    "ecs": {
        "version": "8.0.0"
    },
    "service": {
        "type": "freeipa"
    },
    "host": {
        "hostname": "ipa.example.test",
        "os": {
            "kernel": "6.18.18-1-lts",
            "codename": "Blue Onyx",
            "name": "Rocky Linux",
            "type": "linux",
            "family": "redhat",
            "version": "9.7 (Blue Onyx)",
            "platform": "rocky"
        },
        "containerized": false,
        "ip": [
            "10.89.0.2",
            "fe80::10d4:6fff:fe83:f407"
        ],
        "name": "ipa.example.test",
        "id": "39a2c6cdbd52ac815c089dc52ec548ba",
        "mac": [
            "12-D4-6F-83-F4-07"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "duration": 612577,
        "agent_id_status": "verified",
        "reason": "LDAP error code 4",
        "ingested": "2026-04-01T18:49:21Z",
        "kind": "event",
        "action": "ldap_result",
        "category": [
            "database"
        ],
        "type": [
            "info"
        ],
        "outcome": "failure"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.ip | IP address of the LDAP client. | ip |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.ip | IP address of the directory server. | ip |
| destination.port | Listening port of the directory server (389 or 636). | long |
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
| freeipa.directory.optime | Actual operation processing time, in seconds. | float |
| freeipa.directory.result_code | LDAP result code (0 = success). | integer |
| freeipa.directory.scope | Search scope (base, one, sub). | keyword |
| freeipa.directory.ssl | Whether the connection uses SSL/TLS. | boolean |
| freeipa.directory.tag_number | LDAP protocol tag number from RESULT. | long |
| freeipa.directory.target_dn | Target DN for modify, add, delete, or compare operations. | keyword |
| freeipa.directory.target_op | Target operation ID being abandoned (ABANDON events only). | long |
| freeipa.directory.unindexed | Whether the operation required an unindexed search. | boolean |
| freeipa.directory.wtime | Wait time before the operation was processed, in seconds. | float |
| network.protocol | Application protocol (ldap or ldaps). | keyword |
| network.transport | Transport protocol (tcp). | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.product | Product name of the observer. | keyword |
| observer.type | Type of the observer component. | keyword |
| observer.vendor | Vendor of the observer. | keyword |
| related.ip | All IP addresses seen in this event. | ip |
| related.user | All user identifiers seen in this event. | keyword |
| server.ip | IP address of the directory server. | ip |
| service.type | Service type identifier. | keyword |
| source.as.number | Autonomous System Number from GeoIP ASN lookup. | long |
| source.as.organization.name | Organization name from GeoIP ASN lookup. | keyword |
| source.geo.city_name | City name from GeoIP lookup. | keyword |
| source.geo.continent_name | Continent name from GeoIP lookup. | keyword |
| source.geo.country_iso_code | Country ISO code from GeoIP lookup. | keyword |
| source.geo.country_name | Country name from GeoIP lookup. | keyword |
| source.geo.location | Longitude and latitude from GeoIP lookup. | geo_point |
| source.geo.region_iso_code | Region ISO code from GeoIP lookup. | keyword |
| source.geo.region_name | Region name from GeoIP lookup. | keyword |
| source.ip | IP address of the LDAP client. | ip |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | TLS cipher suite used. | keyword |
| tls.client.x509.issuer.distinguished_name | Issuer DN of the client certificate. | keyword |
| tls.client.x509.subject.distinguished_name | Subject DN of the client certificate. | keyword |
| tls.version | TLS version negotiated. | keyword |
| tls.version_protocol | TLS version protocol component (tls). | keyword |
| user.id | Full bind DN. | keyword |
| user.name | Username extracted from the bind DN. | keyword |


### Directory Errors

The `directory_errors` data stream collects error and warning logs from 389 Directory Server (`/var/log/dirsrv/slapd-*/errors`). This includes replication failures, plugin errors, unindexed search warnings, and server lifecycle events.

An example event for `directory_errors` looks as following:

```json
{
    "log": {
        "file": {
            "inode": "14069469",
            "path": "/var/log/dirsrv/slapd-EXAMPLE-TEST/errors",
            "device_id": "66306",
            "fingerprint": "bfbaa773348a7449d0c5a3a9e16f41690633475870195d0eafc7e0f754180662"
        },
        "offset": 128457,
        "level": "err"
    },
    "freeipa": {
        "directory_error": {
            "subsystem": "NSACLPlugin",
            "message": "acl_access_allowed - Resetting aclpb_pblock 0x7f8702000000 to pblock addr 0x7f8700c00720"
        }
    },
    "observer": {
        "product": "FreeIPA",
        "hostname": "ipa.example.test",
        "vendor": "Red Hat",
        "type": "directory-server"
    },
    "@timestamp": "2026-04-01T09:19:16.890Z",
    "ecs": {
        "version": "8.0.0"
    },
    "host": {
        "hostname": "ipa.example.test",
        "os": {
            "kernel": "6.18.18-1-lts",
            "codename": "Blue Onyx",
            "name": "Rocky Linux",
            "type": "linux",
            "family": "redhat",
            "version": "9.7 (Blue Onyx)",
            "platform": "rocky"
        },
        "containerized": false,
        "ip": [
            "10.89.0.2",
            "fe80::10d4:6fff:fe83:f407"
        ],
        "name": "ipa.example.test",
        "id": "39a2c6cdbd52ac815c089dc52ec548ba",
        "mac": [
            "12-D4-6F-83-F4-07"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "agent_id_status": "verified",
        "reason": "acl_access_allowed - Resetting aclpb_pblock 0x7f8702000000 to pblock addr 0x7f8700c00720",
        "ingested": "2026-04-01T09:19:25Z",
        "kind": "event",
        "action": "directory_error",
        "category": [
            "database"
        ],
        "type": [
            "error"
        ],
        "outcome": "failure"
    }
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
| error.code | LDAP error code from replication failures. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category for ECS compatibility. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| event.outcome | The outcome of the event. | keyword |
| event.reason | Reason for the event outcome. | keyword |
| event.type | Event type for ECS compatibility. | keyword |
| freeipa.directory_error.agreement | Replication agreement name. | keyword |
| freeipa.directory_error.ldap_error_code | LDAP error code from a replication operation. | integer |
| freeipa.directory_error.message | Full log message text after the subsystem prefix. | match_only_text |
| freeipa.directory_error.remote_host | Remote host in a replication agreement. | keyword |
| freeipa.directory_error.subsystem | Directory Server subsystem that produced the log entry. | keyword |
| log.level | Log level of the event. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.product | Product name of the observer. | keyword |
| observer.type | Type of the observer component. | keyword |
| observer.vendor | Vendor of the observer. | keyword |
| related.hosts | All hostnames or FQDNs related to the event. | keyword |
| service.type | Service type identifier. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### CA Audit

The `ca_audit` data stream collects signed audit events from the Dogtag PKI Certificate Authority (`/var/log/pki/pki-tomcat/ca/signedAudit/ca_audit`). This includes certificate requests, issuances, revocations, CA authentication events, and session tracking. This data stream is only active on FreeIPA servers that run the CA role.

An example event for `ca_audit` looks as following:

```json
{
    "server": {
        "ip": "10.89.0.2"
    },
    "log": {
        "file": {
            "inode": "14070368",
            "path": "/var/log/pki/pki-tomcat/ca/signedAudit/ca_audit",
            "device_id": "66306",
            "fingerprint": "a04bc75ae3e18025de3dc6f0dc36c4e09a8db3f0c1ddafc3f5e33fe3f1554870"
        },
        "offset": 252717
    },
    "destination": {
        "port": 636,
        "ip": "10.89.0.2"
    },
    "source": {
        "ip": "10.89.0.2"
    },
    "freeipa": {
        "ca": {
            "issuer_dn": "CN=Certificate Authority,O=EXAMPLE.TEST",
            "event_type": "CLIENT_ACCESS_SESSION_TERMINATED",
            "server_host": "10.89.0.2",
            "server_port": 636,
            "serial_number": "8",
            "thread": "0.LDAPConnThread-5 ldaps://ipa.example.test:636",
            "info": "clientAlertReceived: CLOSE_NOTIFY"
        }
    },
    "observer": {
        "product": "FreeIPA",
        "hostname": "ipa.example.test",
        "vendor": "Red Hat",
        "type": "ca"
    },
    "@timestamp": "2026-04-01T10:19:23.000Z",
    "file": {
        "x509": {
            "serial_number": "8",
            "issuer": {
                "distinguished_name": "CN=Certificate Authority,O=EXAMPLE.TEST"
            }
        }
    },
    "ecs": {
        "version": "8.0.0"
    },
    "related": {
        "ip": [
            "10.89.0.2"
        ],
        "user": [
            "ipa.example.test",
            "CN=ipa.example.test,O=EXAMPLE.TEST"
        ]
    },
    "service": {
        "type": "freeipa"
    },
    "host": {
        "hostname": "ipa.example.test",
        "os": {
            "kernel": "6.18.18-1-lts",
            "codename": "Blue Onyx",
            "name": "Rocky Linux",
            "family": "redhat",
            "type": "linux",
            "version": "9.7 (Blue Onyx)",
            "platform": "rocky"
        },
        "containerized": false,
        "ip": [
            "10.89.0.2",
            "fe80::10d4:6fff:fe83:f407"
        ],
        "name": "ipa.example.test",
        "id": "39a2c6cdbd52ac815c089dc52ec548ba",
        "mac": [
            "12-D4-6F-83-F4-07"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2026-04-01T10:19:41Z",
        "kind": "event",
        "action": "ca_session_terminate",
        "category": [
            "session"
        ],
        "type": [
            "end"
        ],
        "outcome": "success"
    },
    "user": {
        "name": "ipa.example.test",
        "id": "CN=ipa.example.test,O=EXAMPLE.TEST"
    }
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
| destination.ip | IP address of the server (from ServerHost). | ip |
| destination.port | Port of the server (from ServerPort). | long |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category for ECS compatibility. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| event.outcome | The outcome of the event (success or failure). | keyword |
| event.type | Event type for ECS compatibility. | keyword |
| file.x509.issuer.distinguished_name | Certificate issuer distinguished name. | keyword |
| file.x509.serial_number | Certificate serial number. | keyword |
| file.x509.subject.distinguished_name | Certificate subject distinguished name. | keyword |
| freeipa.ca.acl_op | ACL operation from authorization events. | keyword |
| freeipa.ca.acl_resource | ACL resource name from authorization events. | keyword |
| freeipa.ca.approval | Approval status of certificate status change requests. | keyword |
| freeipa.ca.auth_manager | Authentication manager used for the request. | keyword |
| freeipa.ca.crl_number | CRL sequence number from CRL generation events. | keyword |
| freeipa.ca.crl_size | Number of entries in the generated CRL. | long |
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
| observer.hostname | Hostname of the observer. | keyword |
| observer.product | Product name of the observer. | keyword |
| observer.type | Type of the observer component. | keyword |
| observer.vendor | Vendor of the observer. | keyword |
| related.hosts | All hostnames seen in this event. | keyword |
| related.ip | All IP addresses seen in this event. | ip |
| related.user | All user identifiers seen in this event. | keyword |
| server.ip | IP address of the server. | ip |
| service.type | Service type identifier. | keyword |
| source.as.number | Autonomous System Number from GeoIP ASN lookup. | long |
| source.as.organization.name | Organization name from GeoIP ASN lookup. | keyword |
| source.geo.city_name | City name from GeoIP lookup. | keyword |
| source.geo.continent_name | Continent name from GeoIP lookup. | keyword |
| source.geo.country_iso_code | Country ISO code from GeoIP lookup. | keyword |
| source.geo.country_name | Country name from GeoIP lookup. | keyword |
| source.geo.location | Longitude and latitude from GeoIP lookup. | geo_point |
| source.geo.region_iso_code | Region ISO code from GeoIP lookup. | keyword |
| source.geo.region_name | Region name from GeoIP lookup. | keyword |
| source.ip | IP address of the client. | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Subject ID from the audit event. | keyword |
| user.name | Subject identity from the audit event. | keyword |


### IPA API

The `ipa_api` data stream collects FreeIPA JSON API operation logs from the Apache error log (`/var/log/httpd/error_log`). Each event represents a high-level IPA command (user_add, group_add_member, cert_request, and others) with the acting principal, parameters, and result.

An example event for `ipa_api` looks as following:

```json
{
    "process": {
        "pid": 7521,
        "thread": {
            "id": 7677
        }
    },
    "log": {
        "file": {
            "inode": "14070656",
            "path": "/var/log/httpd/error_log",
            "device_id": "66306",
            "fingerprint": "e7aeb518b4583988e24ceddd7f703603d63a4363ba08274f76314b4180f74906"
        },
        "offset": 1378531,
        "level": "INFO"
    },
    "source": {
        "port": 60456,
        "ip": "10.89.0.2"
    },
    "freeipa": {
        "api": {
            "result": "SUCCESS",
            "server_class": "jsonserver_kerb",
            "version": "1",
            "parameters": "None, sizelimit=1, version='2.254'",
            "command": "user_find"
        }
    },
    "url": {
        "path": "/ipa/json"
    },
    "network": {
        "protocol": "https",
        "transport": "tcp"
    },
    "observer": {
        "product": "FreeIPA",
        "hostname": "ipa.example.test",
        "vendor": "Red Hat",
        "type": "api-server"
    },
    "@timestamp": "2026-04-01T18:48:58.409Z",
    "ecs": {
        "version": "8.0.0"
    },
    "related": {
        "hosts": [
            "ipa.example.test"
        ],
        "ip": [
            "10.89.0.2"
        ],
        "user": [
            "admin",
            "admin@EXAMPLE.TEST"
        ]
    },
    "service": {
        "type": "freeipa"
    },
    "host": {
        "hostname": "ipa.example.test",
        "os": {
            "kernel": "6.18.18-1-lts",
            "codename": "Blue Onyx",
            "name": "Rocky Linux",
            "family": "redhat",
            "type": "linux",
            "version": "9.7 (Blue Onyx)",
            "platform": "rocky"
        },
        "containerized": false,
        "ip": [
            "10.89.0.2",
            "fe80::10d4:6fff:fe83:f407"
        ],
        "name": "ipa.example.test",
        "id": "39a2c6cdbd52ac815c089dc52ec548ba",
        "mac": [
            "12-D4-6F-83-F4-07"
        ],
        "architecture": "x86_64"
    },
    "http": {
        "request": {
            "method": "POST"
        }
    },
    "client": {
        "ip": "10.89.0.2"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2026-04-01T18:49:09Z",
        "kind": "event",
        "action": "user_find",
        "category": [
            "iam"
        ],
        "type": [
            "info"
        ],
        "outcome": "success"
    },
    "user": {
        "domain": "EXAMPLE.TEST",
        "name": "admin",
        "id": "admin@EXAMPLE.TEST"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.ip | IP address of the API client. | ip |
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
| http.request.method | HTTP request method (POST). | keyword |
| log.level | Log level of the IPA API message. | keyword |
| network.protocol | Application protocol (https). | keyword |
| network.transport | Transport protocol (tcp). | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.product | Product name of the observer. | keyword |
| observer.type | Type of the observer component. | keyword |
| observer.vendor | Vendor of the observer. | keyword |
| process.pid | Process ID of the httpd worker. | long |
| process.thread.id | Thread ID of the httpd worker. | long |
| related.hosts | All hostnames seen in this event. | keyword |
| related.ip | All IP addresses seen in this event. | ip |
| related.user | All user identifiers seen in this event. | keyword |
| rule.name | Target HBAC or sudo rule name. | keyword |
| service.type | Service type identifier. | keyword |
| source.as.number | Autonomous System Number from GeoIP ASN lookup. | long |
| source.as.organization.name | Organization name from GeoIP ASN lookup. | keyword |
| source.geo.city_name | City name from GeoIP lookup. | keyword |
| source.geo.continent_name | Continent name from GeoIP lookup. | keyword |
| source.geo.country_iso_code | Country ISO code from GeoIP lookup. | keyword |
| source.geo.country_name | Country name from GeoIP lookup. | keyword |
| source.geo.location | Longitude and latitude from GeoIP lookup. | geo_point |
| source.geo.region_iso_code | Region ISO code from GeoIP lookup. | keyword |
| source.geo.region_name | Region name from GeoIP lookup. | keyword |
| source.ip | IP address of the API client. | ip |
| source.port | Source port of the API client. | long |
| tags | List of keywords used to tag each event. | keyword |
| url.path | URL path of the IPA API endpoint. | keyword |
| user.domain | Kerberos realm of the principal. | keyword |
| user.id | Full Kerberos principal (user@REALM). | keyword |
| user.name | Short principal name (without realm). | keyword |
| user.target.name | Target user of the API command (the user being created, modified, or deleted). | keyword |


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
