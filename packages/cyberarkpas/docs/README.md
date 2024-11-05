# CyberArk Privileged Access Security

The CyberArk Privileged Access Security integration collects audit logs and monitoring data from [CyberArk's Vault](https://docs.cyberark.com/Product-Doc/OnlineHelp/Portal/Content/Resources/_TopNav/cc_Portal.htm) server.

## Data streams

The `audit` data stream receives Vault Audit logs for User and Safe activities over the syslog protocol.

It will also receive **monitoring** data from the server and route it to the `monitor` data stream (e.g. `logs-cyberarkpas.monitor-default`).

### Vault Configuration

Follow the steps under [Security Information and Event Management (SIEM) Applications](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PASIMP/DV-Integrating-with-SIEM-Applications.htm) documentation to setup the integration:

- Copy the [elastic-json-v1.0.xsl](https://raw.githubusercontent.com/elastic/beats/master/x-pack/filebeat/module/cyberarkpas/_meta/assets/elastic-json-v1.0.xsl) XSL Translator file to
the `Server\Syslog` folder.

- Sample syslog configuration for `DBPARM.ini`:

```ini
[SYSLOG]
UseLegacySyslogFormat=no
SyslogTranslatorFile=Syslog\elastic-json-v1.0.xsl
SyslogServerIP=<INSERT FILEBEAT IP HERE>
SyslogServerPort=<INSERT FILEBEAT PORT HERE>
SyslogServerProtocol=TCP
SendMonitoringMessage=yes
```

For proper timestamping of events, it's recommended to use the newer RFC5424 Syslog format
(`UseLegacySyslogFormat=No`). To avoid event loss, use `TCP` or `TLS` protocols instead of `UDP`.

The sample configuration above will include monitoring data. For more information about monitoring, see
[Monitor the Vault in SIEM Applications Using Syslog](https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/monitoring-the-vault-using-syslog.htm).

### Example audit event

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-03-04T17:27:14.000Z",
    "agent": {
        "ephemeral_id": "2e1e0d3f-9ac4-4f6a-816b-2b2b7400148a",
        "id": "5607d6f4-6e45-4c33-a087-2e07de5f0082",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.9.1"
    },
    "cyberarkpas": {
        "audit": {
            "action": "Logon",
            "desc": "Logon",
            "iso_timestamp": "2021-03-04T17:27:14Z",
            "issuer": "PVWAGWUser",
            "message": "Logon",
            "rfc5424": true,
            "severity": "Info",
            "station": "10.0.1.20",
            "timestamp": "Mar 04 09:27:14"
        }
    },
    "data_stream": {
        "dataset": "cyberarkpas.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5607d6f4-6e45-4c33-a087-2e07de5f0082",
        "snapshot": false,
        "version": "8.9.1"
    },
    "event": {
        "action": "authentication_success",
        "agent_id_status": "verified",
        "category": [
            "authentication",
            "session"
        ],
        "code": "7",
        "dataset": "cyberarkpas.audit",
        "ingested": "2023-08-29T14:16:49Z",
        "kind": "event",
        "outcome": "success",
        "severity": 2,
        "timezone": "+00:00",
        "type": [
            "start"
        ]
    },
    "host": {
        "name": "VAULT"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.21.0.4:38370"
        },
        "syslog": {
            "priority": 5
        }
    },
    "observer": {
        "hostname": "VAULT",
        "product": "Vault",
        "vendor": "Cyber-Ark",
        "version": "11.7.0000"
    },
    "related": {
        "ip": [
            "10.0.1.20"
        ],
        "user": [
            "PVWAGWUser"
        ]
    },
    "source": {
        "address": "10.0.1.20",
        "ip": "10.0.1.20"
    },
    "tags": [
        "cyberarkpas-audit",
        "forwarded"
    ],
    "user": {
        "name": "PVWAGWUser"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cyberarkpas.audit.action | A description of the audit record. | keyword |
| cyberarkpas.audit.ca_properties.address |  | keyword |
| cyberarkpas.audit.ca_properties.cpm_disabled |  | keyword |
| cyberarkpas.audit.ca_properties.cpm_error_details |  | keyword |
| cyberarkpas.audit.ca_properties.cpm_status |  | keyword |
| cyberarkpas.audit.ca_properties.creation_method |  | keyword |
| cyberarkpas.audit.ca_properties.customer |  | keyword |
| cyberarkpas.audit.ca_properties.database |  | keyword |
| cyberarkpas.audit.ca_properties.device_type |  | keyword |
| cyberarkpas.audit.ca_properties.dual_account_status |  | keyword |
| cyberarkpas.audit.ca_properties.group_name |  | keyword |
| cyberarkpas.audit.ca_properties.in_process |  | keyword |
| cyberarkpas.audit.ca_properties.index |  | keyword |
| cyberarkpas.audit.ca_properties.last_fail_date |  | keyword |
| cyberarkpas.audit.ca_properties.last_success_change |  | keyword |
| cyberarkpas.audit.ca_properties.last_success_reconciliation |  | keyword |
| cyberarkpas.audit.ca_properties.last_success_verification |  | keyword |
| cyberarkpas.audit.ca_properties.last_task |  | keyword |
| cyberarkpas.audit.ca_properties.logon_domain |  | keyword |
| cyberarkpas.audit.ca_properties.other |  | flattened |
| cyberarkpas.audit.ca_properties.policy_id |  | keyword |
| cyberarkpas.audit.ca_properties.port |  | keyword |
| cyberarkpas.audit.ca_properties.privcloud |  | keyword |
| cyberarkpas.audit.ca_properties.reset_immediately |  | keyword |
| cyberarkpas.audit.ca_properties.retries_count |  | keyword |
| cyberarkpas.audit.ca_properties.sequence_id |  | keyword |
| cyberarkpas.audit.ca_properties.tags |  | keyword |
| cyberarkpas.audit.ca_properties.user_dn |  | keyword |
| cyberarkpas.audit.ca_properties.user_name |  | keyword |
| cyberarkpas.audit.ca_properties.virtual_username |  | keyword |
| cyberarkpas.audit.category | The category name (for category-related operations). | keyword |
| cyberarkpas.audit.desc | A static value that displays a description of the audit codes. | keyword |
| cyberarkpas.audit.extra_details.ad_process_id |  | keyword |
| cyberarkpas.audit.extra_details.ad_process_name |  | keyword |
| cyberarkpas.audit.extra_details.application_type |  | keyword |
| cyberarkpas.audit.extra_details.command |  | keyword |
| cyberarkpas.audit.extra_details.connection_component_id |  | keyword |
| cyberarkpas.audit.extra_details.dst_host |  | keyword |
| cyberarkpas.audit.extra_details.logon_account |  | keyword |
| cyberarkpas.audit.extra_details.managed_account |  | keyword |
| cyberarkpas.audit.extra_details.other |  | flattened |
| cyberarkpas.audit.extra_details.process_id |  | keyword |
| cyberarkpas.audit.extra_details.process_name |  | keyword |
| cyberarkpas.audit.extra_details.protocol |  | keyword |
| cyberarkpas.audit.extra_details.psmid |  | keyword |
| cyberarkpas.audit.extra_details.session_duration |  | keyword |
| cyberarkpas.audit.extra_details.session_id |  | keyword |
| cyberarkpas.audit.extra_details.src_host |  | keyword |
| cyberarkpas.audit.extra_details.username |  | keyword |
| cyberarkpas.audit.file | The name of the target file. | keyword |
| cyberarkpas.audit.gateway_station | The IP of the web application machine (PVWA). | ip |
| cyberarkpas.audit.hostname | The hostname, in upper case. | keyword |
| cyberarkpas.audit.iso_timestamp | The timestamp, in ISO Timestamp format (RFC 3339). | date |
| cyberarkpas.audit.issuer | The Vault user who wrote the audit. This is usually the user who performed the operation. | keyword |
| cyberarkpas.audit.location | The target Location (for Location operations). | keyword |
| cyberarkpas.audit.message | A description of the audit records (same information as in the Desc field). | keyword |
| cyberarkpas.audit.message_id | The code ID of the audit records. | keyword |
| cyberarkpas.audit.product | A static value that represents the product. | keyword |
| cyberarkpas.audit.pvwa_details | Specific details of the PVWA audit records. | flattened |
| cyberarkpas.audit.raw | Raw XML for the original audit record. Only present when XSLT file has debugging enabled. | keyword |
| cyberarkpas.audit.reason | The reason entered by the user. | text |
| cyberarkpas.audit.rfc5424 | Whether the syslog format complies with RFC5424. | boolean |
| cyberarkpas.audit.safe | The name of the target Safe. | keyword |
| cyberarkpas.audit.severity | The severity of the audit records. | keyword |
| cyberarkpas.audit.source_user | The name of the Vault user who performed the operation. | keyword |
| cyberarkpas.audit.station | The IP from where the operation was performed. For PVWA sessions, this will be the real client machine IP. | ip |
| cyberarkpas.audit.target_user | The name of the Vault user on which the operation was performed. | keyword |
| cyberarkpas.audit.timestamp | The timestamp, in MMM DD HH:MM:SS format. | keyword |
| cyberarkpas.audit.vendor | A static value that represents the vendor. | keyword |
| cyberarkpas.audit.version | A static value that represents the version of the Vault. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Name of the module this data is coming from. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### Example monitor event

An example event for `monitor` looks as following:

```json
{
    "@timestamp": "2024-10-15T00:29:00.000Z",
    "agent": {
        "name": "elastic-agent-85013",
        "id": "0a6fa575-a3ed-463b-b47f-9c3e3a07e56f",
        "ephemeral_id": "c2d94886-0c83-475b-b25b-7e136a32240d",
        "type": "filebeat",
        "version": "8.14.3"
    },
    "cyberarkpas": {
        "monitor": {
            "syslog_queue_size": 0,
            "iso_timestamp": "2024-10-15T00:29:00Z",
            "drive_free_space_in_gb": 20,
            "drive_total_space_in_gb": 40,
            "max_parallel_tasks": 20,
            "transaction_count": 315,
            "memory_usage": 62,
            "average_queue_time": 0,
            "max_execution_time": 148,
            "version": "11.7.0029",
            "average_execution_time": 10,
            "max_queue_time": 37,
            "number_of_parallel_tasks": 1,
            "cpu_usage": 7,
            "timestamp": "Oct 15 00:29:00"
        }
    },
    "data_stream": {
        "namespace": "22830",
        "type": "logs",
        "dataset": "cyberarkpas.monitor"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0a6fa575-a3ed-463b-b47f-9c3e3a07e56f",
        "version": "8.14.3",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-10-21T07:32:45Z",
        "timezone": "+00:00",
        "kind": "metric",
        "dataset": "cyberarkpas.monitor"
    },
    "host": {
        "name": "VAULT",
        "cpu": {
            "usage": 0.07
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/monitor.log"
        },
        "offset": 15547
    },
    "observer": {
        "product": "VaultMonitor",
        "hostname": "VAULT",
        "vendor": "Cyber-Ark",
        "version": "11.7.0029"
    },
    "related": {
        "hosts": [
            "VAULT"
        ]
    },
    "tags": [
        "forwarded",
        "cyberarkpas-monitor"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cyberarkpas.monitor.average_execution_time | The average time it has taken the Vault to complete the execution of a transaction in the last minute, in milliseconds. | integer |
| cyberarkpas.monitor.average_queue_time | The average time that a transaction waited in the Vault's queue for execution in the last minute, in milliseconds. | integer |
| cyberarkpas.monitor.cpu_usage | Percent of CPU usage on the Vault machine. | integer |
| cyberarkpas.monitor.drive_free_space_in_gb | Number of GB available on the drive of the Vault installation folder. | integer |
| cyberarkpas.monitor.drive_total_space_in_gb | Total number of GB on the drive of the Vault installation folder. | integer |
| cyberarkpas.monitor.iso_timestamp | The timestamp, in ISO timestamp format (RFC 3339). | date |
| cyberarkpas.monitor.max_execution_time | The maximum time it has taken the Vault to complete the execution of a transaction, in the last minute, in milliseconds. | integer |
| cyberarkpas.monitor.max_parallel_tasks | The maximum number of Vault transactions that can run concurrently, based on the TasksCount parameter in DBParm.ini. | integer |
| cyberarkpas.monitor.max_queue_time | The maximum time that a transaction waited in the Vault's queue for execution in the last minute, in millisecond. | integer |
| cyberarkpas.monitor.memory_usage | Percent of used physical memory on the Vault machine. | integer |
| cyberarkpas.monitor.number_of_parallel_tasks | Number of Vault transactions that are currently running. | integer |
| cyberarkpas.monitor.raw | Raw XML for the original audit record. Only present when XSLT file has debugging enabled. | keyword |
| cyberarkpas.monitor.syslog_queue_size | The size of the syslog queue. | integer |
| cyberarkpas.monitor.timestamp | The timestamp, in MMM DD HH:MM:SS format. | keyword |
| cyberarkpas.monitor.transaction_count | Number of Vault transactions in the last minute. | integer |
| cyberarkpas.monitor.version | A static value that represents the version of the Vault. | version |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Name of the module this data is coming from. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |

