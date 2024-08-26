# Jamf Protect

The Jamf Protect integration collects and parses data received from [Jamf Protect](https://learn.jamf.com/bundle/jamf-protect-documentation/page/About_Jamf_Protect.html) using the following methods.

- HTTP Endpoint mode - Jamf Protect streams logs directly to an HTTP endpoint hosted by your Elastic Agent.
- AWS S3 polling mode - Jamf Protect forwards data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode - Jamf Protect writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

Use the Jamf Protect integration to collect logs from your machines.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

## Data streams

The Jamf Protect integration collects 4 types of events: alerts, telemetry, web threat events, and web traffic events.

[**Alerts**](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Alerts.html) help you keep a record of Alerts and Unified Logs happening on endpoints using Jamf Protect.

[**Telemetry**](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Creating_an_Action_Configuration.html) help you keep a record of audit events happening on endpoints using Jamf Protect.

[**Web threat events**](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Data_Streams_Overview.html) help you keep a record of web threat events happening on endpoints using Jamf Protect.

[**Web traffic events**](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Data_Streams_Overview.html) help you keep a record of content filtering and network requests happening on endpoints using Jamf Protect.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

To use this integration, you will also need to:
- Enable the integration in Elastic
- Configure Jamf Protect (macOS Security) to send logs to AWS S3 or the Elastic Agent (HTTP Endpoint)
    - Alerts
    - Unified Logs
    - Telemetry
- Configure Jamf Protect (Jamf Security Cloud) to send logs to AWS S3 or the Elastic Agent (HTTP Endpoint)
    - Threat Event Stream 
    - Network Traffic Stream


### Enable the integration in Elastic

For step-by-step instructions on how to set up an new integration in Elastic, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.
When setting up the integration, you will choose to collect logs via either S3 or HTTP Endpoint.

### Configure Jamf Protect using HTTP Endpoint

After validating settings, you can configure Jamf Protect to send events to Elastic.
For more information on configuring Jamf Protect, see 
- [Creating an Action Configuration](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Creating_an_Action_Configuration.html)
- [Configure Threat Event Stream](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Configuring_the_Network_Threat_Events_Stream_to_send_HTTP_Events.html)
- [Configure Network Traffic Stream](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Configuring_the_Network_Threat_Events_Stream_to_send_HTTP_Events.html)

Then, depending on which events you want to send to Elastic, configure one or multiple HTTP endpoints:

**Remote Alert Collection Endpoints**:
- In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Unified Logs Collection Endpoints**:
- In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Telemetry Collection Endpoints**:
- In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Threats Event Stream**:
- In the Server hostname or IP field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Network Traffic Stream**:
- In the Server hostname or IP field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.


### Configure Jamf Protect using AWS S3

After validating settings, you can configure Jamf Protect to send events to AWS S3.
For more information on configuring Jamf Protect, see 
- [Creating an Action Configuration](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Creating_an_Action_Configuration.html)
- [Enabling Data Forwarding to AWS S3](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Data_Forwarding_to_a_Third_Party_Storage_Solution.html#ariaid-title2)
- [Configure Threat Event Stream](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Configuring_the_Threat_Events_Stream_to_Send_Events_to_AWS_S3.html)

### To collect data from AWS SQS, follow the below steps:
1. If data forwarding to an AWS S3 Bucket hasn't been configured, then first setup an AWS S3 Bucket as mentioned in the above documentation.
2. Follow the steps below for each data stream that has been enabled:
     1. Create an SQS queue
         - To setup an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Amazon documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
         - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
     2. Setup event notification from the S3 bucket using the instructions [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html). Use the following settings:
        - Event type: `All object create events` (`s3:ObjectCreated:*`)
         - Destination: SQS Queue
         - Prefix (filter): enter the prefix for this data stream, e.g. `protect-/alerts/`
         - Select the SQS queue that has been created for this data stream

 **Note**:
  - A separate SQS queue and S3 bucket notification is required for each enabled data stream.
  - Permissions for the above AWS S3 bucket and SQS queues should be configured according to the [Filebeat S3 input documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#_aws_permissions_2)
  - Credentials for the above AWS S3 and SQS input types should be configured using the [link](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.


**Copyright (c) 2024, Jamf Software, LLC.  All rights reserved.**

## Logs reference

#### alerts

This is the `Alerts` dataset.

##### Example

An example event for `alerts` looks as following:

```json
{
    "@timestamp": "2024-06-12T21:15:48.751Z",
    "agent": {
        "ephemeral_id": "f61f65a0-cfe1-43bc-8b7e-b2bec2ad3fe1",
        "id": "8e815812-b6dc-4364-9622-da2462209a37",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.2"
    },
    "data_stream": {
        "dataset": "jamf_protect.alerts",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8e815812-b6dc-4364-9622-da2462209a37",
        "snapshot": false,
        "version": "8.13.2"
    },
    "event": {
        "action": "CustomURLHandlerCreation",
        "agent_id_status": "verified",
        "category": [
            "host",
            "file"
        ],
        "dataset": "jamf_protect.alerts",
        "id": "6bdb0697-6d07-47bc-a37d-6c3348a5d953",
        "ingested": "2024-06-12T21:15:58Z",
        "kind": "alert",
        "provider": "Jamf Protect",
        "reason": "Application that uses custom url handler created",
        "severity": 0,
        "start": "2023-11-21T11:32:44.184Z",
        "type": [
            "change"
        ]
    },
    "file": {
        "code_signature": {
            "status": "code object is not signed at all"
        },
        "gid": "0",
        "inode": "19478271",
        "mode": "16804",
        "path": "/Applications/.Microsoft Teams (work or school).app.installBackup",
        "size": 96,
        "uid": "0"
    },
    "group": {
        "id": "0",
        "name": "wheel"
    },
    "host": {
        "hostname": "LMAC-ZW0GTLVDL",
        "id": "32EC79C5-26DC-535A-85F7-986F063297E2",
        "ip": [
            "175.16.199.1"
        ],
        "os": {
            "family": "macos",
            "full": "Version 14.2 (Build 23C5030f)"
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "observer": {
        "product": "Jamf Protect",
        "vendor": "Jamf"
    },
    "process": {
        "args": [
            "/Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper",
            "XPC_SERVICE_NAME=com.microsoft.autoupdate.helper",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "XPC_FLAGS=1",
            "pfz=0x7ffffff12000",
            "stack_guard=0x94bec1a9eb9800ea",
            "malloc_entropy=0x7777a3bc060946c0,0x6f95455435250cbc",
            "ptr_munge=0x749c1515ccadfca",
            "main_stack=0x7ff7bf6da000,0x800000,0x7ff7bb6da000,0x4000000",
            "executable_file=0x1a01000009,0x12f5060",
            "dyld_file=0x1a01000009,0xfffffff000982f7",
            "executable_cdhash=262df85f4455ca182cb45671afb26c9ad9dff13b",
            "executable_boothash=1fc9ca7065a4d7a9c299cc51414c052e5d7025d7",
            "th_port=0x103"
        ],
        "code_signature": {
            "signing_id": "com.microsoft.autoupdate.helper",
            "status": "No error.",
            "team_id": "UBF8T346G9"
        },
        "entity_id": "b8cd6fa5-e8c3-4f05-88a0-68469d04806c",
        "executable": "/Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper",
        "group_leader": {
            "executable": "/Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper",
            "name": "com.microsoft.autoupdate.helper",
            "pid": 15910,
            "real_group": {
                "id": "0"
            },
            "real_user": {
                "id": "0"
            },
            "start": "2023-11-21T11:32:44Z",
            "user": {
                "id": "0"
            }
        },
        "hash": {
            "sha1": "5ddcd49004e66cead79ca82991f1b4d4a8ba52d9",
            "sha256": "8fd91d9d1ca53ef93921c8072e12ec082c9eba62bf93f0f900e71b6aa4fa0ed8"
        },
        "name": "com.microsoft.autoupdate.helper",
        "parent": {
            "pid": 15910
        },
        "pid": 15910,
        "real_group": {
            "id": "0"
        },
        "real_user": {
            "id": "0"
        },
        "start": "2023-11-21T11:32:44Z",
        "user": {
            "id": "0"
        }
    },
    "related": {
        "hash": [
            "5ddcd49004e66cead79ca82991f1b4d4a8ba52d9",
            "8fd91d9d1ca53ef93921c8072e12ec082c9eba62bf93f0f900e71b6aa4fa0ed8"
        ],
        "ip": [
            "175.16.199.1"
        ],
        "user": [
            "root"
        ]
    },
    "tags": [
        "Visibility"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Name of the dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| jamf_protect.alerts.timestamp_nanoseconds | The timestamp in Epoch nanoseconds. | date |
| log.offset | Log offset | long |
| volume.bus_type |  | keyword |
| volume.file_system_type |  | keyword |
| volume.nt_name |  | keyword |
| volume.product_id |  | keyword |
| volume.product_name |  | keyword |
| volume.removable |  | boolean |
| volume.serial_number |  | keyword |
| volume.size |  | long |
| volume.vendor_id |  | keyword |
| volume.vendor_name |  | keyword |
| volume.writable |  | boolean |


#### telemetry

This is the `Telemetry` dataset.

##### Example

An example event for `telemetry` looks as following:

```json
{
    "@timestamp": "2024-06-12T21:17:49.148Z",
    "agent": {
        "ephemeral_id": "693d67f8-0ad2-49d0-898d-eab743600cca",
        "id": "8e815812-b6dc-4364-9622-da2462209a37",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.2"
    },
    "data_stream": {
        "dataset": "jamf_protect.telemetry",
        "namespace": "ep",
        "type": "logs"
    },
    "elastic_agent": {
        "id": "8e815812-b6dc-4364-9622-da2462209a37",
        "snapshot": false,
        "version": "8.13.2"
    },
    "device": {
        "id": "123ABC456DJ",
        "manufacturer": "Apple"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "exec",
        "category": [
            "process"
        ],
        "code": "9",
        "id": "CDB31202-8CB4-4C72-A9C6-7F494CD5F598",
        "kind": "event",
        "provider": "Jamf Protect",
        "reason": "A new process has been executed",
        "sequence": 202,
        "start": "2024-05-31T09:47:12.436Z",
        "type": [
            "info",
            "start"
        ]
    },
    "host": {
        "hostname": "MacBookPro",
        "id": "00006030-001E301C0228001C",
        "ip": [
            "192.168.11.251",
            "192.168.64.1",
            "192.168.11.232"
        ],
        "os": {
            "family": "macos",
            "full": "14.5 (Build 23F79)",
            "name": "macOS",
            "type": "macos",
            "version": "14.5"
        }
    },
    "jamf_protect": {
        "telemetry": {
            "code_directory_hash": "23c70bd9b41017f9878af49bc2c46f7c8a70680b",
            "es_client": false,
            "event_allowed_by_esclient": false,
            "platform_binary": true
        }
    },
    "observer": {
        "product": "Jamf Protect",
        "type": "Endpoint Security",
        "vendor": "Jamf",
        "version": "5.5.0.6"
    },
    "process": {
        "args": [
            "/bin/zsh",
            "-c",
            "/var/folders/fm/j970swbn73dfnkjgsqjxxvj40000gp/T/eicar"
        ],
        "args_count": 3,
        "code_signature": {
            "signing_id": "com.apple.zsh"
        },
        "entity_id": "1278137C-15D6-53CE-AB0A-FC9499BC8E05",
        "env_vars": [
            "USER=jappleseed",
            "COMMAND_MODE=unix2003",
            "__CFBundleIdentifier=com.txhaflaire.JamfCheck",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "LOGNAME=jappleseed",
            "SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.Ah3WvMOC65/Listeners",
            "HOME=/Users/jappleseed",
            "SHELL=/bin/zsh",
            "TMPDIR=/var/folders/fm/j970swbn73dfnkjgsqjxxvj40000gp/T/",
            "__CF_USER_TEXT_ENCODING=0x1F6:0x0:0x0",
            "XPC_SERVICE_NAME=application.com.txhaflaire.JamfCheck.30852344.30852350",
            "XPC_FLAGS=0x0"
        ],
        "executable": "/bin/zsh",
        "group_leader": {
            "entity_id": "A7EDC884-C034-50E7-A3AA-2E281B3E0777",
            "pid": 64632,
            "real_group": {
                "id": "20"
            },
            "real_user": {
                "id": "502"
            },
            "user": {
                "id": "502"
            }
        },
        "interactive": false,
        "name": "zsh",
        "parent": {
            "entity_id": "A7EDC884-C034-50E7-A3AA-2E281B3E0777",
            "pid": 64632,
            "real_group": {
                "id": "20"
            },
            "real_user": {
                "id": "502"
            },
            "user": {
                "id": "502"
            }
        },
        "pid": 91306,
        "start": "2024-05-31T09:47:12.000Z",
        "thread": {
            "id": 5215860
        },
        "working_directory": "/"
    },
    "related": {
        "hash": [
            "23c70bd9b41017f9878af49bc2c46f7c8a70680b"
        ],
        "hosts": [
            "MacBookPro"
        ],
        "ip": [
            "192.168.11.251",
            "192.168.64.1",
            "192.168.11.232"
        ]
    },
    "user": {
        "effective": {
            "id": [
                "502"
            ]
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Name of the dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| jamf_protect.telemetry.account_type | Defines if it's a user or group | keyword |
| jamf_protect.telemetry.attribute_name | The name of the attribute that got set | keyword |
| jamf_protect.telemetry.attribute_value | The value of the attribute that got set | keyword |
| jamf_protect.telemetry.authentication_auto_unlock_type | Defines if Apple Watch is used to unlock the machine or approve an authorization prompt | keyword |
| jamf_protect.telemetry.authentication_method | Method used to authenticate | keyword |
| jamf_protect.telemetry.authentication_result_type | Defines the source address type | keyword |
| jamf_protect.telemetry.authentication_token_kerberos_principal | The associated kerberos principal username with the authentication event | keyword |
| jamf_protect.telemetry.authentication_touchid_mode | Defines if TouchID is used for verifying the user on the Lock Screen or Application or used for identification to peform a privileged action | keyword |
| jamf_protect.telemetry.authentication_type | Type of authentication used to authenticate the user | keyword |
| jamf_protect.telemetry.authorization_judgement_results | Results of the authorization judgement | object |
| jamf_protect.telemetry.authorization_petition_flags | Flags associated with the authorization petition | integer |
| jamf_protect.telemetry.authorization_petition_right_count | The count of rights in the authorization petition | integer |
| jamf_protect.telemetry.authorization_petition_rights | Rights associated with the authorization petition | keyword |
| jamf_protect.telemetry.bios_firmware_version | Version of the BIOS firmware | keyword |
| jamf_protect.telemetry.bios_system_firmware_version | Version of the system firmware in BIOS | keyword |
| jamf_protect.telemetry.btm_executable_path | Path to the executable in BTM | keyword |
| jamf_protect.telemetry.btm_item_app_url | URL of the app in BTM item | keyword |
| jamf_protect.telemetry.btm_item_is_legacy | Indicates if the BTM item is legacy | boolean |
| jamf_protect.telemetry.btm_item_is_managed | Indicates if the BTM item is managed | boolean |
| jamf_protect.telemetry.btm_item_type | Type of the BTM item | keyword |
| jamf_protect.telemetry.btm_item_url | URL of the BTM item | keyword |
| jamf_protect.telemetry.btm_item_user_uid | UID of the user associated with the BTM item | keyword |
| jamf_protect.telemetry.code_directory_hash | Code directory hash of a application bundle | keyword |
| jamf_protect.telemetry.env_count | Count of environment variables | integer |
| jamf_protect.telemetry.error_message | Contains the event specific error message | keyword |
| jamf_protect.telemetry.es_client | Set to true if the process is an Endpoint Security client | boolean |
| jamf_protect.telemetry.event_allowed_by_esclient | Value to indicate if the event was allowed or denied | boolean |
| jamf_protect.telemetry.existing_session | If an existing user session was attached to, this is true | boolean |
| jamf_protect.telemetry.failure_reason | The reason that contains why the outcome of the event failed | keyword |
| jamf_protect.telemetry.from_username | Username from which an action originated | keyword |
| jamf_protect.telemetry.graphical_authentication_username | The username used for authentication | keyword |
| jamf_protect.telemetry.graphical_session_id | ID of the graphical session | keyword |
| jamf_protect.telemetry.identifier | Identifier for an entity or action | keyword |
| jamf_protect.telemetry.log_entries | Log entries being collected in an event | object |
| jamf_protect.telemetry.platform_binary | This is set to true for all binaries that are shipped with macOS | boolean |
| jamf_protect.telemetry.profile_display_name | Display name of the profile | keyword |
| jamf_protect.telemetry.profile_identifier | Identifier of the profile | keyword |
| jamf_protect.telemetry.profile_install_source | Source from which the profile was installed | keyword |
| jamf_protect.telemetry.profile_is_updated | Indicates if the profile is updated | boolean |
| jamf_protect.telemetry.profile_organization | Organization associated with the profile | keyword |
| jamf_protect.telemetry.profile_scope | Scope of the profile | keyword |
| jamf_protect.telemetry.profile_uuid | UUID of the profile | keyword |
| jamf_protect.telemetry.record_name | Name of the record | keyword |
| jamf_protect.telemetry.record_type | Type of the record | keyword |
| jamf_protect.telemetry.session_username | Username of the loginwindow session | keyword |
| jamf_protect.telemetry.shell | Shell associated with the user or process | keyword |
| jamf_protect.telemetry.source_address_type | Defines the source address type | keyword |
| jamf_protect.telemetry.system_performance.bytes_received | Bytes received by the task | long |
| jamf_protect.telemetry.system_performance.bytes_received_per_s | Bytes received per second by the task | double |
| jamf_protect.telemetry.system_performance.bytes_sent | Bytes sent by the task | long |
| jamf_protect.telemetry.system_performance.bytes_sent_per_s | Bytes sent per second by the task | double |
| jamf_protect.telemetry.system_performance.cputime_ms_per_s | CPU time in milliseconds per second for the task | double |
| jamf_protect.telemetry.system_performance.cputime_ns | CPU time in nanoseconds for the task | long |
| jamf_protect.telemetry.system_performance.cputime_sample_ms_per_s | CPU sample time in milliseconds per second for the task | double |
| jamf_protect.telemetry.system_performance.cputime_userland_ratio | Userland CPU time ratio for the task | double |
| jamf_protect.telemetry.system_performance.diskio_bytesread | Bytes read by disk I/O for the task | long |
| jamf_protect.telemetry.system_performance.diskio_bytesread_per_s | Bytes read per second by disk I/O for the task | double |
| jamf_protect.telemetry.system_performance.diskio_byteswritten | Bytes written by disk I/O for the task | long |
| jamf_protect.telemetry.system_performance.diskio_byteswritten_per_s | Bytes written per second by disk I/O for the task | double |
| jamf_protect.telemetry.system_performance.energy_impact | Energy impact of the task | double |
| jamf_protect.telemetry.system_performance.energy_impact_per_s | Energy impact per second of the task | double |
| jamf_protect.telemetry.system_performance.idle_wakeups | Number of idle wakeups for the task | long |
| jamf_protect.telemetry.system_performance.interval_ns | Interval in nanoseconds | long |
| jamf_protect.telemetry.system_performance.intr_wakeups_per_s | Interrupt wakeups per second for the task | double |
| jamf_protect.telemetry.system_performance.name | Name of the task | keyword |
| jamf_protect.telemetry.system_performance.packets_received | Packets received by the task | long |
| jamf_protect.telemetry.system_performance.packets_received_per_s | Packets received per second by the task | double |
| jamf_protect.telemetry.system_performance.packets_sent | Packets sent by the task | long |
| jamf_protect.telemetry.system_performance.packets_sent_per_s | Packets sent per second by the task | double |
| jamf_protect.telemetry.system_performance.pageins | Page-ins by the task | long |
| jamf_protect.telemetry.system_performance.pageins_per_s | Page-ins per second by the task | double |
| jamf_protect.telemetry.system_performance.pid | Process ID of the task | long |
| jamf_protect.telemetry.system_performance.qos_background_ms_per_s | QoS background time in milliseconds per second for the task | double |
| jamf_protect.telemetry.system_performance.qos_background_ns | QoS background time in nanoseconds for the task | long |
| jamf_protect.telemetry.system_performance.qos_default_ms_per_s | QoS default time in milliseconds per second for the task | double |
| jamf_protect.telemetry.system_performance.qos_default_ns | QoS default time in nanoseconds for the task | long |
| jamf_protect.telemetry.system_performance.qos_disabled_ms_per_s | QoS disabled time in milliseconds per second for the task | double |
| jamf_protect.telemetry.system_performance.qos_disabled_ns | QoS disabled time in nanoseconds for the task | long |
| jamf_protect.telemetry.system_performance.qos_maintenance_ms_per_s | QoS maintenance time in milliseconds per second for the task | double |
| jamf_protect.telemetry.system_performance.qos_maintenance_ns | QoS maintenance time in nanoseconds for the task | long |
| jamf_protect.telemetry.system_performance.qos_user_initiated_ms_per_s | QoS user-initiated time in milliseconds per second for the task | double |
| jamf_protect.telemetry.system_performance.qos_user_initiated_ns | QoS user-initiated time in nanoseconds for the task | long |
| jamf_protect.telemetry.system_performance.qos_user_interactive_ms_per_s | QoS user-interactive time in milliseconds per second for the task | double |
| jamf_protect.telemetry.system_performance.qos_user_interactive_ns | QoS user-interactive time in nanoseconds for the task | long |
| jamf_protect.telemetry.system_performance.qos_utility_ms_per_s | QoS utility time in milliseconds per second for the task | double |
| jamf_protect.telemetry.system_performance.qos_utility_ns | QoS utility time in nanoseconds for the task | long |
| jamf_protect.telemetry.system_performance.started_abstime_ns | Absolute start time in nanoseconds for the task | long |
| jamf_protect.telemetry.system_performance.timer_wakeups.wakeups | Number of wakeups | long |
| jamf_protect.telemetry.to_username | Username to which an action is directed | keyword |
| jamf_protect.telemetry.tty | Software terminal device file that the process is associated with | keyword |
| log.offset | Log offset | long |
| volume.bus_type |  | keyword |
| volume.device_name |  | keyword |
| volume.file_system_type |  | keyword |
| volume.mount_name |  | keyword |
| volume.nt_name |  | keyword |
| volume.product_id |  | keyword |
| volume.product_name |  | keyword |
| volume.removable |  | boolean |
| volume.serial_number |  | keyword |
| volume.size |  | long |
| volume.vendor_id |  | keyword |
| volume.vendor_name |  | keyword |
| volume.writable |  | boolean |


#### threats event stream

This is the `Threats Event Stream` dataset.

##### Example

An example event for `web_threat_events` looks as following:

```json
{
    "@timestamp": "2024-06-12T21:21:39.714Z",
    "agent": {
        "ephemeral_id": "c0c550fc-7c58-4392-9ea9-b49f7a181825",
        "id": "8e815812-b6dc-4364-9622-da2462209a37",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.2"
    },
    "data_stream": {
        "dataset": "jamf_protect.web_threat_events",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "ip",
        "domain": "host",
        "port": 80
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8e815812-b6dc-4364-9622-da2462209a37",
        "snapshot": false,
        "version": "8.13.2"
    },
    "event": {
        "action": "Detected",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "jamf_protect.web_threat_events",
        "id": "013b15c9-8f62-4bf1-948a-d82367af2a10",
        "ingested": "2024-06-12T21:21:49Z",
        "kind": "alert",
        "provider": "Jamf Protect",
        "reason": "Sideloaded App",
        "severity": 6,
        "start": "2020-01-30T17:47:41.767Z",
        "url": "https://radar.wandera.com/security/events/detail/013b15c9-8f62-4bf1-948a-d82367af2a10.SIDE_LOADED_APP_IN_INVENTORY?createdUtcMs=1580406461767"
    },
    "file": {
        "hash": {
            "sha1": "16336078972773bc6c8cef69d722c8c093ba727ddc5bb31eb2",
            "sha256": "16336078978a306dc23b67dae9df18bc2a0205e3ff0cbf97c46e76fd670f93fd142d7042"
        },
        "name": "Books"
    },
    "host": {
        "geo": {
            "country_iso_code": "gb"
        },
        "hostname": "Apple iPhone 11",
        "id": "09f81436-de17-441e-a631-0461252c629b",
        "os": {
            "full": "IOS 11.2.5"
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "observer": {
        "product": "Jamf Protect",
        "type": "Endpoint Security",
        "vendor": "Jamf"
    },
    "organization": {
        "id": "fb4567b6-4ee2-3c4c-abb9-4c78ec463b25"
    },
    "rule": {
        "description": "Sideloaded App",
        "name": "SIDE_LOADED_APP_IN_INVENTORY"
    },
    "source": {
        "port": 3025
    },
    "tags": [
        "forwarded",
        "jamf_protect-web-threat-events"
    ],
    "user": {
        "email": "user@mail.com",
        "name": "John Doe"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Name of the dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| volume.bus_type |  | keyword |
| volume.file_system_type |  | keyword |
| volume.nt_name |  | keyword |
| volume.product_id |  | keyword |
| volume.product_name |  | keyword |
| volume.removable |  | boolean |
| volume.serial_number |  | keyword |
| volume.size |  | long |
| volume.vendor_id |  | keyword |
| volume.vendor_name |  | keyword |
| volume.writable |  | boolean |


#### network traffic stream

This is the `Network Traffic Stream` dataset.

##### Example

An example event for `web_traffic_events` looks as following:

```json
{
    "@timestamp": "2024-06-12T21:23:32.864Z",
    "agent": {
        "ephemeral_id": "82b058ea-7609-4a92-9ec4-8a9d84c83c69",
        "id": "8e815812-b6dc-4364-9622-da2462209a37",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.2"
    },
    "data_stream": {
        "dataset": "jamf_protect.web_traffic_events",
        "namespace": "ep",
        "type": "logs"
    },
    "dns": {
        "answers": {
            "ttl": 101,
            "type": "HTTPS"
        },
        "question": {
            "name": "s.youtube.com",
            "registered_domain": "youtube",
            "top_level_domain": "com"
        },
        "response_code": "NOERROR"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8e815812-b6dc-4364-9622-da2462209a37",
        "snapshot": false,
        "version": "8.13.2"
    },
    "event": {
        "action": "DNS Lookup",
        "agent_id_status": "verified",
        "category": [
            "host",
            "network"
        ],
        "dataset": "jamf_protect.web_traffic_events",
        "ingested": "2024-06-12T21:23:42Z",
        "kind": "event",
        "outcome": [
            "success"
        ],
        "provider": "Jamf Protect",
        "reason": "CLEAN",
        "start": "2024-02-02T06:26:04.273Z",
        "type": [
            "connection"
        ]
    },
    "host": {
        "id": "3453be41-0f2d-4d43-9ec2-a53f39fff93c",
        "os": {
            "type": [
                "ios"
            ]
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "observer": {
        "product": "Jamf Protect",
        "type": "Endpoint Security",
        "vendor": "Jamf"
    },
    "organization": {
        "id": "9608556b-0c3a-4a9c-9b4a-d714d8a028a1"
    },
    "rule": {
        "name": "DNS Lookup"
    },
    "tags": [
        "forwarded",
        "jamf_protect-web-traffic-events"
    ],
    "user": {
        "email": "hjilling@icloud.com",
        "name": "07a5a2ae-16de-4767-831e-0ea8b7c3abe4"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Name of the dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |

