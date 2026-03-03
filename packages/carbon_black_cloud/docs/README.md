# VMware Carbon Black Cloud

The VMware Carbon Black Cloud integration collects and parses data from the Carbon Black Cloud REST APIs and AWS S3 bucket.

## Version 1.21+ Update Disclaimer
Starting from version 1.21, if using multiple AWS data streams simultaneously configured to use AWS SQS, separate SQS queues should be configured per
data stream. The default values of file selector regexes have been commented out for this reason. The only reason the global queue now exists is to avoid
a breaking change while upgrading to version 1.21 and above. A separate SQS queue per data stream should help fix the data loss that's been occurring in the 
older versions.

## HTTPJSON vs CEL 
Version 2.0.0 introduces the use of the CEL input. The HTTPJSON input method has been marked as [Legacy], it will not receive enhancement changes and will not support the new `alert_v7` data stream.

## Note (Important)
1. Do not enable both the HTTPJSON and CEL input methods within a single data stream; having both enabled simultaneously can cause unexpected/duplicated results, as they operate on the same data streams.

## Compatibility
This module has been tested against `Alerts API (v7)`, `Audit Log Events (v3)` and `Vulnerability Assessment (v1)`.

## Requirements

### In order to ingest data from the AWS S3 bucket you must:
1. Configure the [Data Forwarder](https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/GUID-F68F63DD-2271-4088-82C9-71D675CD0535.html) to ingest data into an AWS S3 bucket.
2. Create an [AWS Access Keys and Secret Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys).
3. The default values of the "Bucket List Prefix" are listed below. However, users can set the parameter "Bucket List Prefix" according to their requirements.

  | Data Stream Name  | Bucket List Prefix     |
  | ----------------- | ---------------------- |
  | Alert_v7          | alert_logs_v7          |
  | Endpoint Event    | endpoint_event_logs    |
  | Watchlist Hit     | watchlist_hit_logs     |

### To collect data from AWS SQS, follow the below steps:
1. If data forwarding to an AWS S3 Bucket hasn't been configured, then first setup an AWS S3 Bucket as mentioned in the above documentation.
2. Follow the steps below for each data stream that has been enabled:
     1. Create an SQS queue
         - To setup an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Amazon documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
         - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
     2. Setup event notification from the S3 bucket using the instructions [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html). Use the following settings:
        - Event type: `All object create events` (`s3:ObjectCreated:*`)
         - Destination: SQS Queue
         - Prefix (filter): enter the prefix for this data stream, e.g. `alert_logs_v7/`
         - Select the SQS queue that has been created for this data stream

**Note**:
  - A separate SQS queue and S3 bucket notification is required for each enabled data stream.
  - Permissions for the above AWS S3 bucket and SQS queues should be configured according to the [Filebeat S3 input documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#_aws_permissions_2)
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.

### In order to ingest data from the APIs you must generate API keys and API Secret Keys:
1. In Carbon Black Cloud, On the left navigation pane, click **Settings > API Access**.
2. Click Add API Key.
3. Give the API key a unique name and description.
    - Select the appropriate access level type. Please check the required Access Levels & Permissions for integration in the table below.  
     **Note:** To use a custom access level, select Custom from the Access Level type drop-down menu and specify the Custom Access Level.
    - Optional: Add authorized IP addresses.
    - You can restrict the use of an API key to a specific set of IP addresses for security reasons.  
     **Note:** Authorized IP addresses are not available with Custom keys.
4. To apply the changes, click Save.

#### Access Levels & Permissions
- The following tables indicate which type of API Key access level is required. If the type is Custom then the permission that is required will also be included.

| Data stream                 | Access Level and Permissions               |
| --------------------------- | ------------------------------------------ |
| Audit                       | API                                        |
| Alert v7                    | Custom orgs.alerts (Read)                  |
| Asset Vulnerability Summary | Custom vulnerabilityAssessment.data (Read) |


## Logs

### Audit

This is the `audit` dataset.

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2022-02-10T16:04:30.263Z",
    "agent": {
        "ephemeral_id": "d9810f80-bccc-4900-886c-c14f1747369d",
        "id": "e535dae1-9d56-4f72-9e5b-bd456d3edb8f",
        "name": "elastic-agent-33765",
        "type": "filebeat",
        "version": "8.18.1"
    },
    "carbon_black_cloud": {
        "audit": {
            "flagged": false,
            "verbose": false
        }
    },
    "client": {
        "ip": "10.10.10.10",
        "user": {
            "domain": "demo.com",
            "email": "abc@demo.com",
            "id": "abc@demo.com",
            "name": "abc"
        }
    },
    "data_stream": {
        "dataset": "carbon_black_cloud.audit",
        "namespace": "18603",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e535dae1-9d56-4f72-9e5b-bd456d3edb8f",
        "snapshot": false,
        "version": "8.18.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "carbon_black_cloud.audit",
        "id": "2122f8ce8xxxxxxxxxxxxx",
        "ingested": "2025-06-02T15:02:56Z",
        "kind": "event",
        "original": "{\"clientIp\":\"10.10.10.10\",\"description\":\"Logged in successfully\",\"eventId\":\"2122f8ce8xxxxxxxxxxxxx\",\"eventTime\":1644509070263,\"flagged\":false,\"loginName\":\"abc@demo.com\",\"orgName\":\"cb-xxxx-xxxx.com\",\"requestUrl\":null,\"verbose\":false}",
        "outcome": "success",
        "reason": "Logged in successfully"
    },
    "input": {
        "type": "cel"
    },
    "organization": {
        "name": "cb-xxxx-xxxx.com"
    },
    "related": {
        "ip": [
            "10.10.10.10"
        ],
        "user": [
            "abc@demo.com",
            "abc"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "carbon_black_cloud-audit"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| carbon_black_cloud.audit.flagged | true if action is failed otherwise false. | boolean |
| carbon_black_cloud.audit.verbose | true if verbose audit log otherwise false. | boolean |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


### Alert

This is the `alert_v7` dataset.

An example event for `alert_v7` looks as following:

```json
{
    "@timestamp": "2024-03-13T08:02:36.578Z",
    "agent": {
        "ephemeral_id": "c2c6749d-d46f-46f3-a093-004c49de4b47",
        "id": "3089d948-58aa-4f94-a411-b2e5ad49775b",
        "name": "elastic-agent-84943",
        "type": "filebeat",
        "version": "8.18.1"
    },
    "carbon_black_cloud": {
        "alert": {
            "alert_notes_present": false,
            "backend_timestamp": "2024-03-13T08:03:29.540Z",
            "backend_update_timestamp": "2024-03-13T08:03:29.540Z",
            "category": "THREAT",
            "determination": {
                "change_timestamp": "2024-03-13T08:03:29.540Z",
                "changed_by": "ALERT_CREATION",
                "changed_by_type": "SYSTEM",
                "value": "NONE"
            },
            "device": {
                "external_ip": "75.98.230.194",
                "internal_ip": "172.16.100.140",
                "location": "UNKNOWN",
                "os": "WINDOWS",
                "policy": "default",
                "policy_id": 6525,
                "target_value": "MEDIUM"
            },
            "ioc": {
                "hit": "(fileless_scriptload_cmdline:Register-ScheduledTask OR fileless_scriptload_cmdline:New-ScheduledTask OR scriptload_content:Register-ScheduledTask OR scriptload_content:New-ScheduledTask) AND NOT (process_cmdline:windows\\\\ccm\\\\systemtemp OR crossproc_name:windows\\\\ccm\\\\ccmexec.exe OR (process_publisher:\"VMware, Inc.\" AND process_publisher_state:FILE_SIGNATURE_STATE_TRUSTED))",
                "id": "d1080521-e617-4e45-94e0-7a145c62c90a"
            },
            "is_updated": false,
            "mdr": {
                "alert": false,
                "alert_notes_present": false,
                "threat_notes_present": false
            },
            "ml_classification_final_verdict": "NOT_ANOMALOUS",
            "ml_classification_global_prevalence": "LOW",
            "ml_classification_org_prevalence": "LOW",
            "organization_key": "7DESJ9GN",
            "parent": {
                "cmdline": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
                "effective_reputation": "TRUSTED_WHITE_LIST",
                "guid": "7DESJ9GN-0064e5a7-0000077c-00000000-1da5ed7ec07b275",
                "hash": {
                    "md5": "145dcf6706eeea5b066885ee17964c09",
                    "sha256": "f13de58416730d210dab465b242e9c949fb0a0245eef45b07c381f0c6c8a43c3"
                },
                "name": "c:\\windows\\system32\\svchost.exe",
                "pid": 1916,
                "reputation": "TRUSTED_WHITE_LIST",
                "username": "NT AUTHORITY\\SYSTEM"
            },
            "policy_applied": "NOT_APPLIED",
            "primary_event_id": "re9M9hp8TbGLqyk6QXqQqA-0",
            "process": {
                "cmdline": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -EP Bypass \\\\eip.demo\\sysvol\\EIP.DEMO\\scripts\\Luminol.ps1",
                "effective_reputation": "TRUSTED_WHITE_LIST",
                "guid": "7DESJ9GN-0064e5a7-00001434-00000000-1da751c7354ebfe",
                "hash": {
                    "md5": "2e5a8590cf6848968fc23de3fa1e25f1",
                    "sha256": "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3"
                },
                "issuer": [
                    "Microsoft Windows Production PCA 2011"
                ],
                "name": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                "pid": 5172,
                "publisher": [
                    "Microsoft Windows"
                ],
                "reputation": "TRUSTED_WHITE_LIST",
                "username": "NT AUTHORITY\\SYSTEM"
            },
            "reason_code": "c21ca826-573a-3d97-8c1e-93c8471aab7f:8033b29d-81d2-3c47-82d2-f4a7f398b85d",
            "report": {
                "description": "Newer Powershell versions introduced built-in cmdlets to manage scheduled tasks natively without calling out to typical scheduled task processes like at.exe or schtasks.exe. This detection looks for behaviors related to the fileless execution of scheduled tasks. If you are responding to this alert, be sure to correlate the fileless scriptload events with events typically found in your environment Generally, attackers will create scheduled tasks with binaries that are located in user writable directories like AppData, Temp, or public folders.",
                "id": "LrKOC7DtQbm4g8w0UFruQg-d1080521-e617-4e45-94e0-7a145c62c90a",
                "link": "https://attack.mitre.org/techniques/T1053/",
                "name": "Execution - AMSI - New Fileless Scheduled Task Behavior Detected",
                "tags": [
                    "execution",
                    "privesc",
                    "persistence",
                    "t1053",
                    "windows",
                    "amsi",
                    "attack",
                    "attackframework"
                ]
            },
            "run_state": "RAN",
            "sensor_action": "ALLOW",
            "threat_id": "C21CA826573A8D974C1E93C8471AAB7F",
            "threat_notes_present": false,
            "type": "WATCHLIST",
            "url": "defense.conferdeploy.net/alerts?s[c][query_string]=id:1c6aba68-24cc-41e3-ad8e-4b545a587b55&orgKey=7DESJ9GN",
            "watchlists": [
                {
                    "id": "Ci7w5B4URg6HN60hatQMQ",
                    "name": "AMSI Threat Intelligence"
                }
            ],
            "workflow": {
                "change_timestamp": "2024-03-13T08:03:29.540Z",
                "changed_by": "ALERT_CREATION",
                "changed_by_type": "SYSTEM",
                "closure_reason": "NO_REASON",
                "status": "OPEN"
            }
        }
    },
    "data_stream": {
        "dataset": "carbon_black_cloud.alert_v7",
        "namespace": "16313",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "3089d948-58aa-4f94-a411-b2e5ad49775b",
        "snapshot": false,
        "version": "8.18.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "carbon_black_cloud.alert_v7",
        "end": "2024-03-13T08:00:09.894Z",
        "id": "1c6aba68-24cc-41e3-ad8e-4b545a587b55",
        "ingested": "2025-06-02T14:53:39Z",
        "kind": "alert",
        "original": "{\"alert_notes_present\":false,\"alert_url\":\"defense.conferdeploy.net/alerts?s[c][query_string]=id:1c6aba68-24cc-41e3-ad8e-4b545a587b55\\u0026orgKey=7DESJ9GN\",\"asset_group\":[],\"backend_timestamp\":\"2024-03-13T08:03:29.540Z\",\"backend_update_timestamp\":\"2024-03-13T08:03:29.540Z\",\"childproc_cmdline\":\"\",\"childproc_guid\":\"\",\"childproc_username\":\"\",\"detection_timestamp\":\"2024-03-13T08:02:36.578Z\",\"determination\":{\"change_timestamp\":\"2024-03-13T08:03:29.540Z\",\"changed_by\":\"ALERT_CREATION\",\"changed_by_type\":\"SYSTEM\",\"value\":\"NONE\"},\"device_external_ip\":\"75.98.230.194\",\"device_id\":6612391,\"device_internal_ip\":\"172.16.100.140\",\"device_location\":\"UNKNOWN\",\"device_name\":\"EIP\\\\WW-20002\",\"device_os\":\"WINDOWS\",\"device_os_version\":\"Windows 10 x64\",\"device_policy\":\"default\",\"device_policy_id\":6525,\"device_target_value\":\"MEDIUM\",\"device_uem_id\":\"\",\"device_username\":\"EIP\\\\Administrator\",\"first_event_timestamp\":\"2024-03-13T08:00:09.894Z\",\"id\":\"1c6aba68-24cc-41e3-ad8e-4b545a587b55\",\"ioc_hit\":\"(fileless_scriptload_cmdline:Register-ScheduledTask OR fileless_scriptload_cmdline:New-ScheduledTask OR scriptload_content:Register-ScheduledTask OR scriptload_content:New-ScheduledTask) AND NOT (process_cmdline:windows\\\\\\\\ccm\\\\\\\\systemtemp OR crossproc_name:windows\\\\\\\\ccm\\\\\\\\ccmexec.exe OR (process_publisher:\\\"VMware, Inc.\\\" AND process_publisher_state:FILE_SIGNATURE_STATE_TRUSTED))\",\"ioc_id\":\"d1080521-e617-4e45-94e0-7a145c62c90a\",\"is_updated\":false,\"last_event_timestamp\":\"2024-03-13T08:00:09.894Z\",\"mdr_alert\":false,\"mdr_alert_notes_present\":false,\"mdr_threat_notes_present\":false,\"ml_classification_anomalies\":[],\"ml_classification_final_verdict\":\"NOT_ANOMALOUS\",\"ml_classification_global_prevalence\":\"LOW\",\"ml_classification_org_prevalence\":\"LOW\",\"org_key\":\"7DESJ9GN\",\"parent_cmdline\":\"C:\\\\Windows\\\\system32\\\\svchost.exe -k netsvcs -p -s Schedule\",\"parent_effective_reputation\":\"TRUSTED_WHITE_LIST\",\"parent_guid\":\"7DESJ9GN-0064e5a7-0000077c-00000000-1da5ed7ec07b275\",\"parent_md5\":\"145dcf6706eeea5b066885ee17964c09\",\"parent_name\":\"c:\\\\windows\\\\system32\\\\svchost.exe\",\"parent_pid\":1916,\"parent_reputation\":\"TRUSTED_WHITE_LIST\",\"parent_sha256\":\"f13de58416730d210dab465b242e9c949fb0a0245eef45b07c381f0c6c8a43c3\",\"parent_username\":\"NT AUTHORITY\\\\SYSTEM\",\"policy_applied\":\"NOT_APPLIED\",\"primary_event_id\":\"re9M9hp8TbGLqyk6QXqQqA-0\",\"process_cmdline\":\"\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\" -EP Bypass \\\\\\\\eip.demo\\\\sysvol\\\\EIP.DEMO\\\\scripts\\\\Luminol.ps1\",\"process_effective_reputation\":\"TRUSTED_WHITE_LIST\",\"process_guid\":\"7DESJ9GN-0064e5a7-00001434-00000000-1da751c7354ebfe\",\"process_issuer\":[\"Microsoft Windows Production PCA 2011\"],\"process_md5\":\"2e5a8590cf6848968fc23de3fa1e25f1\",\"process_name\":\"c:\\\\windows\\\\system32\\\\windowspowershell\\\\v1.0\\\\powershell.exe\",\"process_pid\":5172,\"process_publisher\":[\"Microsoft Windows\"],\"process_reputation\":\"TRUSTED_WHITE_LIST\",\"process_sha256\":\"9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3\",\"process_username\":\"NT AUTHORITY\\\\SYSTEM\",\"reason\":\"Process powershell.exe was detected by the report \\\"Execution - AMSI - New Fileless Scheduled Task Behavior Detected\\\" in watchlist \\\"AMSI Threat Intelligence\\\"\",\"reason_code\":\"c21ca826-573a-3d97-8c1e-93c8471aab7f:8033b29d-81d2-3c47-82d2-f4a7f398b85d\",\"report_description\":\"Newer Powershell versions introduced built-in cmdlets to manage scheduled tasks natively without calling out to typical scheduled task processes like at.exe or schtasks.exe. This detection looks for behaviors related to the fileless execution of scheduled tasks. If you are responding to this alert, be sure to correlate the fileless scriptload events with events typically found in your environment Generally, attackers will create scheduled tasks with binaries that are located in user writable directories like AppData, Temp, or public folders.\",\"report_id\":\"LrKOC7DtQbm4g8w0UFruQg-d1080521-e617-4e45-94e0-7a145c62c90a\",\"report_link\":\"https://attack.mitre.org/techniques/T1053/\",\"report_name\":\"Execution - AMSI - New Fileless Scheduled Task Behavior Detected\",\"report_tags\":[\"execution\",\"privesc\",\"persistence\",\"t1053\",\"windows\",\"amsi\",\"attack\",\"attackframework\"],\"run_state\":\"RAN\",\"sensor_action\":\"ALLOW\",\"severity\":5,\"tags\":null,\"threat_id\":\"C21CA826573A8D974C1E93C8471AAB7F\",\"threat_notes_present\":false,\"type\":\"WATCHLIST\",\"user_update_timestamp\":null,\"watchlists\":[{\"id\":\"Ci7w5B4URg6HN60hatQMQ\",\"name\":\"AMSI Threat Intelligence\"}],\"workflow\":{\"change_timestamp\":\"2024-03-13T08:03:29.540Z\",\"changed_by\":\"ALERT_CREATION\",\"changed_by_type\":\"SYSTEM\",\"closure_reason\":\"NO_REASON\",\"status\":\"OPEN\"}}",
        "reason": "Process powershell.exe was detected by the report \"Execution - AMSI - New Fileless Scheduled Task Behavior Detected\" in watchlist \"AMSI Threat Intelligence\"",
        "severity": 5,
        "start": "2024-03-13T08:00:09.894Z"
    },
    "host": {
        "hostname": "WW-20002",
        "id": "6612391",
        "name": "WW-20002",
        "os": {
            "type": "windows",
            "version": "Windows 10 x64"
        }
    },
    "input": {
        "type": "cel"
    },
    "process": {
        "command_line": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -EP Bypass \\\\eip.demo\\sysvol\\EIP.DEMO\\scripts\\Luminol.ps1",
        "entity_id": "7DESJ9GN-0064e5a7-00001434-00000000-1da751c7354ebfe",
        "executable": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
        "hash": {
            "md5": "2e5a8590cf6848968fc23de3fa1e25f1",
            "sha256": "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3"
        },
        "name": "powershell.exe",
        "parent": {
            "command_line": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
            "entity_id": "7DESJ9GN-0064e5a7-0000077c-00000000-1da5ed7ec07b275",
            "executable": "c:\\windows\\system32\\svchost.exe",
            "hash": {
                "md5": "145dcf6706eeea5b066885ee17964c09",
                "sha256": "f13de58416730d210dab465b242e9c949fb0a0245eef45b07c381f0c6c8a43c3"
            },
            "name": "svchost.exe",
            "pid": 1916
        },
        "pid": 5172
    },
    "related": {
        "hash": [
            "f13de58416730d210dab465b242e9c949fb0a0245eef45b07c381f0c6c8a43c3",
            "145dcf6706eeea5b066885ee17964c09",
            "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3",
            "2e5a8590cf6848968fc23de3fa1e25f1"
        ],
        "hosts": [
            "WW-20002",
            "EIP"
        ],
        "user": [
            "Administrator"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "carbon_black_cloud-alert"
    ],
    "user": {
        "domain": "EIP",
        "name": "Administrator"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| carbon_black_cloud.alert.additional_events_present | Indicator to let API and forwarder users know that they should look up other associated events related to this alert. | boolean |
| carbon_black_cloud.alert.alert_notes_present | Indicates if notes are associated with the alert. | boolean |
| carbon_black_cloud.alert.attack_tactic | S tactic from the MITRE ATT&CK framework. | keyword |
| carbon_black_cloud.alert.attack_technique | Technique from the MITRE ATT&CK framework. | keyword |
| carbon_black_cloud.alert.backend_timestamp | Timestamp when the alert was first detected by the Carbon Black Cloud backend, it is a ISO 8601 UTC timestamp. | date |
| carbon_black_cloud.alert.backend_update_timestamp | The last time the alert was updated in Carbon Black Cloud, it is a ISO 8601 UTC timestamp. | date |
| carbon_black_cloud.alert.blocked_process.effective_reputation | Effective reputation of the blocked file or process; applied by the sensor at the time the block occurred. | keyword |
| carbon_black_cloud.alert.blocked_process.hash.md5 | MD5 hash of the child process binary; for any process terminated by the sensor. | keyword |
| carbon_black_cloud.alert.blocked_process.hash.sha256 | SHA-256 hash of the child process binary; for any process terminated by the sensor. | keyword |
| carbon_black_cloud.alert.blocked_process.name | Tokenized file path of the files blocked by sensor action. | keyword |
| carbon_black_cloud.alert.category | The category of the alert. | keyword |
| carbon_black_cloud.alert.childproc.cmdline | Command line executed by the child process. | keyword |
| carbon_black_cloud.alert.childproc.effective_reputation | Effective reputation of the child process hash. | keyword |
| carbon_black_cloud.alert.childproc.guid | Guid of the child process that has fired the alert. | keyword |
| carbon_black_cloud.alert.childproc.hash.md5 | MD5 hash of the child process. | keyword |
| carbon_black_cloud.alert.childproc.hash.sha256 | SHA-256 hash of the child process. | keyword |
| carbon_black_cloud.alert.childproc.name | Filesystem path of the child process binary. | keyword |
| carbon_black_cloud.alert.childproc.username | User context in which the child process was executed. | keyword |
| carbon_black_cloud.alert.connection_type | The type of network connection (e.g., EGRESS, INGRESS). | keyword |
| carbon_black_cloud.alert.determination.change_timestamp | Timestamp of the determination change | date |
| carbon_black_cloud.alert.determination.changed_by | Entity that changed the determination | keyword |
| carbon_black_cloud.alert.determination.changed_by_type | Type of entity that changed the determination | keyword |
| carbon_black_cloud.alert.determination.value | Value of the determination | keyword |
| carbon_black_cloud.alert.device.external_ip | IP address of the endpoint according to the Carbon Black Cloud; can differ from device_internal_ip due to network proxy or NAT. | keyword |
| carbon_black_cloud.alert.device.internal_ip | IP address of the endpoint reported by the sensor. | keyword |
| carbon_black_cloud.alert.device.location | Whether the device was on or off premises when the alert started, based on the current IP address and the device’s registered DNS domain suffix. | keyword |
| carbon_black_cloud.alert.device.os | OS of the device. | keyword |
| carbon_black_cloud.alert.device.policy | The name of the device policy associated with the device at the time of the alert. | keyword |
| carbon_black_cloud.alert.device.policy_id | The identifier for the device policy associated with the device at the time of the alert. | integer |
| carbon_black_cloud.alert.device.target_value | Target value assigned to the device, set from the policy. | keyword |
| carbon_black_cloud.alert.device.uem_id | Device correlation with WS1/EUC, required for our Workspace ONE Intelligence integration to function. | keyword |
| carbon_black_cloud.alert.egress_group_id | The unique identifier of the egress group associated with the event. | keyword |
| carbon_black_cloud.alert.egress_group_name | The name of the egress group associated with the event. | keyword |
| carbon_black_cloud.alert.ioc.field | The field the indicator of comprise (IOC) hit contains. | keyword |
| carbon_black_cloud.alert.ioc.hit | IOC field value or IOC query that matches. | keyword |
| carbon_black_cloud.alert.ioc.id | The identifier of the IOC that cause the hit. | keyword |
| carbon_black_cloud.alert.ip_reputation | The reputation score of the IP address associated with the event. | integer |
| carbon_black_cloud.alert.is_updated | Set to true if this is an updated copy of the alert initiated by the Carbon Black Cloud backend. | boolean |
| carbon_black_cloud.alert.k8s_cluster | The Kubernetes cluster associated with the event. | keyword |
| carbon_black_cloud.alert.k8s_kind | The type of Kubernetes resource associated with the event (e.g., Pod, DaemonSet). | keyword |
| carbon_black_cloud.alert.k8s_namespace | The Kubernetes namespace associated with the event. | keyword |
| carbon_black_cloud.alert.k8s_pod_name | The name of the Kubernetes pod associated with the event. | keyword |
| carbon_black_cloud.alert.k8s_policy | The name of the Kubernetes policy associated with the event. | keyword |
| carbon_black_cloud.alert.k8s_policy_id | The unique identifier of the Kubernetes policy associated with the event. | keyword |
| carbon_black_cloud.alert.k8s_rule | The name of the Kubernetes rule associated with the event. | keyword |
| carbon_black_cloud.alert.k8s_rule_id | The unique identifier of the Kubernetes rule associated with the event. | keyword |
| carbon_black_cloud.alert.k8s_workload_name | The name of the Kubernetes workload associated with the event. | keyword |
| carbon_black_cloud.alert.mdr.alert | Is the alert eligible for review by Carbon Black MDR Analysts. | boolean |
| carbon_black_cloud.alert.mdr.alert_notes_present | Customer visible notes at the alert level that were added by a MDR analyst. | boolean |
| carbon_black_cloud.alert.mdr.classification.change_timestamp | WWhen the last MDR classification change occurred, it is a ISO 8601 UTC timestamp. | date |
| carbon_black_cloud.alert.mdr.determination.change_timestamp | When the last MDR classification change occurred, it is a ISO 8601 UTC timestamp. | date |
| carbon_black_cloud.alert.mdr.determination.value | A record that identifies the whether the alert was determined to represent a likely or unlikely threat. | keyword |
| carbon_black_cloud.alert.mdr.threat_notes_present | Customer visible notes at the threat level that were added by a MDR analyst. | boolean |
| carbon_black_cloud.alert.mdr.workflow.change_timestamp | WWhen the last MDR status change occurred, it is a ISO 8601 UTC timestamp. | date |
| carbon_black_cloud.alert.mdr.workflow.is_assigned | If the workflow is assigned or not. | boolean |
| carbon_black_cloud.alert.mdr.workflow.status | Primary value used to capture status change during MD Analyst's alert triage. | boolean |
| carbon_black_cloud.alert.ml_classification_anomalies | An list of anomalies detected by the machine learning classification. | keyword |
| carbon_black_cloud.alert.ml_classification_final_verdict | Final verdict of the alert, based on the ML models that were used to make the prediction. | keyword |
| carbon_black_cloud.alert.ml_classification_global_prevalence | Categories (low/medium/high) used to describe the prevalence of alerts across all regional organizations. | keyword |
| carbon_black_cloud.alert.ml_classification_org_prevalence | TCategories (low/medium/high) used to describe the prevalence of alerts within an organization. | keyword |
| carbon_black_cloud.alert.netconn.local_ip | IP address of the local side of the network connection. | ip |
| carbon_black_cloud.alert.netconn.local_ipv4 | IPv4 address of the local side of the network connection. | ip |
| carbon_black_cloud.alert.netconn.local_ipv6 | IPv6 address of the local side of the network connection. | ip |
| carbon_black_cloud.alert.netconn.local_port | TCP or UDP port used by the local side of the network connection. | integer |
| carbon_black_cloud.alert.netconn.protocol | Network protocol of the network connection. | keyword |
| carbon_black_cloud.alert.netconn.remote_domain | Domain name (FQDN) associated with the remote end of the network connection. | keyword |
| carbon_black_cloud.alert.netconn.remote_ip | IP address of the remote side of the network connection. | ip |
| carbon_black_cloud.alert.netconn.remote_ipv4 | IPv4 address of the remote side of the network connection. | ip |
| carbon_black_cloud.alert.netconn.remote_ipv6 | IPv6 address of the remote side of the network connection. | ip |
| carbon_black_cloud.alert.netconn.remote_port | TCP or UDP port used by the remote side of the network connection; same as netconn_port and event_network_remote_port. | integer |
| carbon_black_cloud.alert.org_feature_entitlement | The feature entitlement of the organization. | keyword |
| carbon_black_cloud.alert.organization_key | The unique identifier for the organization associated with the alert. | keyword |
| carbon_black_cloud.alert.parent.cmdline | Command line executed by the parent process. | keyword |
| carbon_black_cloud.alert.parent.effective_reputation | Effective reputation of the parent hash. | keyword |
| carbon_black_cloud.alert.parent.guid | Guid of the parent process that has fired the alert. | keyword |
| carbon_black_cloud.alert.parent.hash.md5 | MD5 hash of the parent process. | keyword |
| carbon_black_cloud.alert.parent.hash.sha256 | SHA-256 hash of the parent process. | keyword |
| carbon_black_cloud.alert.parent.name | Filesystem path of the parent process binary. | keyword |
| carbon_black_cloud.alert.parent.pid | PID of the parent process that has fired the alert. | long |
| carbon_black_cloud.alert.parent.reputation | Reputation of the parent process; applied when event is processed by the Carbon Black Cloud. | keyword |
| carbon_black_cloud.alert.parent.username | User context in which the parent process was executed. | keyword |
| carbon_black_cloud.alert.policy_applied | Whether a policy was applied. | keyword |
| carbon_black_cloud.alert.primary_event_id | ID of the primary event in the alert. | keyword |
| carbon_black_cloud.alert.process.cmdline | Command line executed by the actor process. | keyword |
| carbon_black_cloud.alert.process.effective_reputation | Effective reputation of the actor hash. | keyword |
| carbon_black_cloud.alert.process.guid | Guid of the process that has fired the alert. | keyword |
| carbon_black_cloud.alert.process.hash.md5 | MD5 hash of the process. | keyword |
| carbon_black_cloud.alert.process.hash.sha256 | SHA-256 hash of the process. | keyword |
| carbon_black_cloud.alert.process.issuer | The certificate authority associated with the process's certificate. | keyword |
| carbon_black_cloud.alert.process.name | Filesystem path of the actor process binary. | keyword |
| carbon_black_cloud.alert.process.pid | PID of the process that has fired the alert. | long |
| carbon_black_cloud.alert.process.publisher | Publisher name on the certificate used to sign the Windows or macOS process binary. | keyword |
| carbon_black_cloud.alert.process.reputation | Reputation of the actor process; applied when event is processed by the Carbon Black Cloud. | keyword |
| carbon_black_cloud.alert.process.username | User context in which the actor process was executed. | keyword |
| carbon_black_cloud.alert.product_id | The hexadecimal id of the USB device's product. | keyword |
| carbon_black_cloud.alert.product_name | The name of the USB device's vendor. | keyword |
| carbon_black_cloud.alert.reason | A spoken language written explanation of the what and why the alert occurred and any action taken. | keyword |
| carbon_black_cloud.alert.reason_code | Shorthand enum for the full-text reason. | keyword |
| carbon_black_cloud.alert.remote_is_private | Indicates whether the remote IP address is private or not. | boolean |
| carbon_black_cloud.alert.report.description | Description of the IOC report associated with the alert. | keyword |
| carbon_black_cloud.alert.report.id | The identifier of the report that contains the IOC. | keyword |
| carbon_black_cloud.alert.report.link | Link of reports that contained the IOC that caused a hit. | keyword |
| carbon_black_cloud.alert.report.name | The name of the report that contains the IOC. | keyword |
| carbon_black_cloud.alert.report.tags | Tags associated with the IOC report. | keyword |
| carbon_black_cloud.alert.rule_category_id | ID representing the category of the rule_id for certain alert types. | keyword |
| carbon_black_cloud.alert.rule_config_id | ID of the rule configuration that triggered an alert. | keyword |
| carbon_black_cloud.alert.rule_config_name | Name of the rule configuration that triggered an alert. | keyword |
| carbon_black_cloud.alert.rule_config_type | Type of the rule configuration that triggered an alert. | keyword |
| carbon_black_cloud.alert.rule_id | ID of the rule that triggered an alert. | keyword |
| carbon_black_cloud.alert.run_state | Whether the threat in the alert ran. | keyword |
| carbon_black_cloud.alert.sensor_action | The action taken by the sensor, according to the rule of the policy. | keyword |
| carbon_black_cloud.alert.serial_number | The serial number of the USB device. | keyword |
| carbon_black_cloud.alert.status | status of alert. | keyword |
| carbon_black_cloud.alert.tags | Tags associated with the alert. | keyword |
| carbon_black_cloud.alert.threat_category | Categories of threats which we were able to take action on. | keyword |
| carbon_black_cloud.alert.threat_id | The identifier of a threat which this alert belongs. Threats are comprised of a combination of factors that can be repeated across devices. | keyword |
| carbon_black_cloud.alert.threat_name | Name of the threat. | keyword |
| carbon_black_cloud.alert.threat_notes_present | Indicates if notes are associated with the threat_id. | boolean |
| carbon_black_cloud.alert.tms_rule_id | Threat intrusion detection id. | keyword |
| carbon_black_cloud.alert.ttps | Other potential malicious activities involved in a threat. | keyword |
| carbon_black_cloud.alert.type | Type of alert. | keyword |
| carbon_black_cloud.alert.url | Link to the alerts page for this alert. Does not vary by alert type. | keyword |
| carbon_black_cloud.alert.user_update_timestamp | Timestamp of the last property of an alert changed by a user, such as the alert workflow or determination, it is a ISO 8601 UTC timestamp. | date |
| carbon_black_cloud.alert.vendor_id | The hexadecimal id of the USB device's vendor. | keyword |
| carbon_black_cloud.alert.vendor_name | The name of the USB device's vendor. | keyword |
| carbon_black_cloud.alert.version | The version of the schema being emitted. | keyword |
| carbon_black_cloud.alert.watchlists.id | Identifier of the watchlist. | keyword |
| carbon_black_cloud.alert.watchlists.name | Name of the watchlist. | keyword |
| carbon_black_cloud.alert.workflow.change_timestamp | The last change/update time of workflow. | date |
| carbon_black_cloud.alert.workflow.changed_by | The name of process which changed the workflow. | keyword |
| carbon_black_cloud.alert.workflow.changed_by_autoclose_rule_id | The rule id that auto closed the workflow. | keyword |
| carbon_black_cloud.alert.workflow.changed_by_type | The type of user who changed the workflow. | keyword |
| carbon_black_cloud.alert.workflow.closure_reason | Reason for which the workflow was closed. | keyword |
| carbon_black_cloud.alert.workflow.status | The status of the workflow. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


### Endpoint Event

This is the `endpoint_event` dataset.

An example event for `endpoint_event` looks as following:

```json
{
    "carbon_black_cloud": {
        "endpoint_event": {
            "backend": {
                "timestamp": "2022-02-10 11:52:50 +0000 UTC"
            },
            "device": {
                "external_ip": "67.43.156.12",
                "os": "WINDOWS",
                "timestamp": "2022-02-10 11:51:35.0684097 +0000 UTC"
            },
            "event_origin": "EDR",
            "organization_key": "XXXXXXXX",
            "process": {
                "duration": 2,
                "parent": {
                    "reputation": "REP_RESOLVING"
                },
                "publisher": [
                    {
                        "name": "Microsoft Windows",
                        "state": [
                            "FILE_SIGNATURE_STATE_SIGNED",
                            "FILE_SIGNATURE_STATE_VERIFIED",
                            "FILE_SIGNATURE_STATE_TRUSTED",
                            "FILE_SIGNATURE_STATE_OS",
                            "FILE_SIGNATURE_STATE_CATALOG_SIGNED"
                        ]
                    }
                ],
                "reputation": "REP_RESOLVING",
                "terminated": true,
                "username": "NT AUTHORITY\\SYSTEM"
            },
            "schema": 1,
            "sensor_action": "ACTION_ALLOW",
            "target_cmdline": "\"route.exe\" print",
            "type": "endpoint.event.procend"
        }
    },
    "data_stream": {
        "dataset": "carbon_black_cloud.endpoint_event",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "3b20ea47-9610-412d-97e3-47cd19b7e4d5",
        "snapshot": true,
        "version": "8.0.0"
    },
    "event": {
        "action": "ACTION_PROCESS_TERMINATE",
        "orignal": "{\"type\":\"endpoint.event.procend\",\"process_guid\":\"XXXXXXXX-003d902d-00001310-00000000-1d81e748c4adb37\",\"parent_guid\":\"XXXXXXXX-003d902d-00000694-00000000-1d7540221dedd62\",\"backend_timestamp\":\"2022-02-10 11:52:50 +0000 UTC\",\"org_key\":\"XXXXXXXX\",\"device_id\":\"4034605\",\"device_name\":\"client-cb2\",\"device_external_ip\":\"67.43.156.13\",\"device_os\":\"WINDOWS\",\"device_group\":\"\",\"action\":\"ACTION_PROCESS_TERMINATE\",\"schema\":1,\"device_timestamp\":\"2022-02-10 11:51:35.0684097 +0000 UTC\",\"process_terminated\":true,\"process_duration\":2,\"process_reputation\":\"REP_RESOLVING\",\"parent_reputation\":\"REP_RESOLVING\",\"process_pid\":4880,\"parent_pid\":1684,\"process_publisher\":[{\"name\":\"Microsoft Windows\",\"state\":\"FILE_SIGNATURE_STATE_SIGNED | FILE_SIGNATURE_STATE_VERIFIED | FILE_SIGNATURE_STATE_TRUSTED | FILE_SIGNATURE_STATE_OS | FILE_SIGNATURE_STATE_CATALOG_SIGNED\"}],\"process_path\":\"c:\\\\windows\\\\system32\\\\route.exe\",\"parent_path\":\"c:\\\\windowsazure\\\\guestagent_2.7.41491.1010_2021-05-11_233023\\\\guestagent\\\\windowsazureguestagent.exe\",\"process_hash\":[\"2498272dc48446891182747428d02a30\",\"9e9c7696859b94b1c33a532fa4d5c648226cf3361121dd899e502b8949fb11a6\"],\"parent_hash\":[\"03dd698da2671383c9b4f868c9931879\",\"44a1975b2197484bb22a0eb673e67e7ee9ec20265e9f6347f5e06b6447ac82c5\"],\"process_cmdline\":\"\\\"route.exe\\\" print\",\"parent_cmdline\":\"C:\\\\WindowsAzure\\\\GuestAgent_2.7.41491.1010_2021-05-11_233023\\\\GuestAgent\\\\WindowsAzureGuestAgent.exe\",\"process_username\":\"NT AUTHORITY\\\\SYSTEM\",\"sensor_action\":\"ACTION_ALLOW\",\"event_origin\":\"EDR\",\"target_cmdline\":\"\\\"route.exe\\\" print\"}"
    },
    "host": {
        "hostname": "client-cb2",
        "id": "4034605",
        "ip": [
            "67.43.156.13"
        ],
        "os": {
            "type": "windows"
        }
    },
    "input": {
        "type": "aws-s3"
    },
    "process": {
        "command_line": "\"route.exe\" print",
        "entity_id": "XXXXXXXX-003d902d-00001310-00000000-1d81e748c4adb37",
        "executable": "c:\\windows\\system32\\route.exe",
        "hash": {
            "md5": "2498272dc48446891182747428d02a30",
            "sha256": "9e9c7696859b94b1c33a532fa4d5c648226cf3361121dd899e502b8949fb11a6"
        },
        "parent": {
            "command_line": "C:\\WindowsAzure\\GuestAgent_2.7.41491.1010_2021-05-11_233023\\GuestAgent\\WindowsAzureGuestAgent.exe",
            "entity_id": "XXXXXXXX-003d902d-00000694-00000000-1d7540221dedd62",
            "executable": "c:\\windowsazure\\guestagent_2.7.41491.1010_2021-05-11_233023\\guestagent\\windowsazureguestagent.exe",
            "hash": {
                "md5": "03dd698da2671383c9b4f868c9931879",
                "sha256": "44a1975b2197484bb22a0eb673e67e7ee9ec20265e9f6347f5e06b6447ac82c5"
            },
            "pid": 1684
        },
        "pid": 4880
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "carbon_black_cloud-endpoint-event"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| carbon_black_cloud.endpoint_event.alert_id | The ID of the Alert this event is associated with. | keyword |
| carbon_black_cloud.endpoint_event.backend.timestamp | Time when the backend received the batch of events. | keyword |
| carbon_black_cloud.endpoint_event.childproc.guid | Unique ID of the child process. | keyword |
| carbon_black_cloud.endpoint_event.childproc.hash.md5 | Cryptographic MD5 hashes of the executable file backing the child process. | keyword |
| carbon_black_cloud.endpoint_event.childproc.hash.sha256 | Cryptographic SHA256 hashes of the executable file backing the child process. | keyword |
| carbon_black_cloud.endpoint_event.childproc.name | Full path to the target of the crossproc event on the device's local file system. | keyword |
| carbon_black_cloud.endpoint_event.childproc.pid | OS-reported Process ID of the child process. | long |
| carbon_black_cloud.endpoint_event.childproc.publisher.name | The name of the publisher. | keyword |
| carbon_black_cloud.endpoint_event.childproc.publisher.state | The state of the publisher. | keyword |
| carbon_black_cloud.endpoint_event.childproc.reputation | Carbon Black Cloud Reputation string for the childproc. | keyword |
| carbon_black_cloud.endpoint_event.childproc.username | The username associated with the user context that the child process was started under. | keyword |
| carbon_black_cloud.endpoint_event.create_time | The time at which the event was ingested in carbon black cloud. | keyword |
| carbon_black_cloud.endpoint_event.crossproc.action | The action taken on cross-process. | keyword |
| carbon_black_cloud.endpoint_event.crossproc.api | Name of the operating system API called by the actor process. | keyword |
| carbon_black_cloud.endpoint_event.crossproc.guid | Unique ID of the cross process. | keyword |
| carbon_black_cloud.endpoint_event.crossproc.hash.md5 | Cryptographic MD5 hashes of the target of the crossproc event. | keyword |
| carbon_black_cloud.endpoint_event.crossproc.hash.sha256 | Cryptographic SHA256 hashes of the target of the crossproc event. | keyword |
| carbon_black_cloud.endpoint_event.crossproc.name | Full path to the target of the crossproc event on the device's local file system. | keyword |
| carbon_black_cloud.endpoint_event.crossproc.publisher.name | The name of the publisher. | keyword |
| carbon_black_cloud.endpoint_event.crossproc.publisher.state | The state of the publisher. | keyword |
| carbon_black_cloud.endpoint_event.crossproc.reputation | Carbon Black Cloud Reputation string for the crossproc. | keyword |
| carbon_black_cloud.endpoint_event.crossproc.target | True if the process was the target of the cross-process event; false if the process was the actor. | boolean |
| carbon_black_cloud.endpoint_event.device.external_ip | External IP of the device. | ip |
| carbon_black_cloud.endpoint_event.device.internal_ip | Internal IP of the device. | ip |
| carbon_black_cloud.endpoint_event.device.os | Os name. | keyword |
| carbon_black_cloud.endpoint_event.device.timestamp | Time seen on sensor. | keyword |
| carbon_black_cloud.endpoint_event.event_origin | Indicates which product the event came from. "EDR" indicates the event originated from Enterprise EDR. "NGAV" indicates the event originated from Endpoint Standard. | keyword |
| carbon_black_cloud.endpoint_event.fileless_scriptload.cmdline | Deobfuscated script content run in a fileless context by the process. | keyword |
| carbon_black_cloud.endpoint_event.fileless_scriptload.cmdline_length | Character count of the deobfuscated script content run in a fileless context. | keyword |
| carbon_black_cloud.endpoint_event.fileless_scriptload.hash.md5 | MD5 hash of the deobfuscated script content run by the process in a fileless context. | keyword |
| carbon_black_cloud.endpoint_event.fileless_scriptload.hash.sha256 | SHA-256 hash of the deobfuscated script content run by the process in a fileless context. | keyword |
| carbon_black_cloud.endpoint_event.modload.count | Count of modload events reported by the sensor since last initialization. | long |
| carbon_black_cloud.endpoint_event.modload.effective_reputation | Effective reputation(s) of the loaded module(s); applied by the sensor when the event occurred. | keyword |
| carbon_black_cloud.endpoint_event.modload.publisher.name | The name of the publisher. | keyword |
| carbon_black_cloud.endpoint_event.modload.publisher.state | The state of the publisher. | keyword |
| carbon_black_cloud.endpoint_event.netconn.proxy.domain | DNS name associated with the "proxy" end of this network connection; may be empty if the name cannot be inferred or the connection is made direct to/from a proxy IP address. | keyword |
| carbon_black_cloud.endpoint_event.netconn.proxy.ip | IPv4 or IPv6 address in string format associated with the "proxy" end of this network connection. | ip |
| carbon_black_cloud.endpoint_event.netconn.proxy.port | UDP/TCP port number associated with the "proxy" end of this network connection. | keyword |
| carbon_black_cloud.endpoint_event.organization_key | The organization key associated with the console instance. | keyword |
| carbon_black_cloud.endpoint_event.process.duration | The time difference in seconds between the process start and process terminate event. | long |
| carbon_black_cloud.endpoint_event.process.parent.reputation | Reputation of the parent process; applied when event is processed by the Carbon Black Cloud i.e. after sensor delivers event to the cloud. | keyword |
| carbon_black_cloud.endpoint_event.process.publisher.name | The name of the publisher. | keyword |
| carbon_black_cloud.endpoint_event.process.publisher.state | The state of the publisher. | keyword |
| carbon_black_cloud.endpoint_event.process.reputation | Reputation of the actor process; applied when event is processed by the Carbon Black Cloud i.e. after sensor delivers event to the cloud. | keyword |
| carbon_black_cloud.endpoint_event.process.terminated | True if process was terminated elase false. | boolean |
| carbon_black_cloud.endpoint_event.process.username | The username associated with the user context that this process was started under. | keyword |
| carbon_black_cloud.endpoint_event.schema | The schema version. The current schema version is "1". This schema version will only be incremented if the field definitions are changed in a backwards-incompatible way. | long |
| carbon_black_cloud.endpoint_event.scriptload.count | Count of scriptload events across all processes reported by the sensor since last initialization. | long |
| carbon_black_cloud.endpoint_event.scriptload.effective_reputation | Effective reputation(s) of the script file(s) loaded at process launch; applied by the sensor when the event occurred. | keyword |
| carbon_black_cloud.endpoint_event.scriptload.hash.md5 | Cryptographic MD5 hashes of the target of the scriptload event. | keyword |
| carbon_black_cloud.endpoint_event.scriptload.hash.sha256 | Cryptographic SHA256 hashes of the target of the scriptload event. | keyword |
| carbon_black_cloud.endpoint_event.scriptload.name | Full path to the target of the crossproc event on the device's local file system. | keyword |
| carbon_black_cloud.endpoint_event.scriptload.publisher.name | The name of the publisher. | keyword |
| carbon_black_cloud.endpoint_event.scriptload.publisher.state | The state of the publisher. | keyword |
| carbon_black_cloud.endpoint_event.scriptload.reputation | Carbon Black Cloud Reputation string for the scriptload. | keyword |
| carbon_black_cloud.endpoint_event.sensor_action | The sensor action taken on event. | keyword |
| carbon_black_cloud.endpoint_event.target_cmdline | Process command line associated with the target process. | keyword |
| carbon_black_cloud.endpoint_event.type | The event type. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


### Watchlist Hit

This is the `watchlist_hit` dataset.

An example event for `watchlist_hit` looks as following:

```json
{
    "agent": {
        "id": "e0d5f508-9616-400f-b26b-bb1aa6638b80",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "carbon_black_cloud": {
        "watchlist_hit": {
            "device": {
                "external_ip": "67.43.156.12",
                "internal_ip": "10.10.156.12",
                "os": "WINDOWS"
            },
            "ioc": {
                "hit": "((process_name:sc.exe -parent_name:svchost.exe) AND process_cmdline:query) -enriched:true",
                "id": "565571-0"
            },
            "organization_key": "xxxxxxxx",
            "process": {
                "parent": {
                    "publisher": [
                        {
                            "name": "Microsoft Windows",
                            "state": [
                                "FILE_SIGNATURE_STATE_SIGNED",
                                "FILE_SIGNATURE_STATE_VERIFIED",
                                "FILE_SIGNATURE_STATE_TRUSTED",
                                "FILE_SIGNATURE_STATE_OS",
                                "FILE_SIGNATURE_STATE_CATALOG_SIGNED"
                            ]
                        }
                    ],
                    "reputation": "REP_WHITE",
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                "publisher": [
                    {
                        "name": "Microsoft Windows",
                        "state": [
                            "FILE_SIGNATURE_STATE_SIGNED",
                            "FILE_SIGNATURE_STATE_VERIFIED",
                            "FILE_SIGNATURE_STATE_TRUSTED",
                            "FILE_SIGNATURE_STATE_OS",
                            "FILE_SIGNATURE_STATE_CATALOG_SIGNED"
                        ]
                    }
                ],
                "reputation": "REP_WHITE",
                "username": "NT AUTHORITY\\SYSTEM"
            },
            "report": {
                "id": "CFnKBKLTv6hUkBGFobRdg-565571",
                "name": "Discovery - System Service Discovery Detected",
                "tags": [
                    "attack",
                    "attackframework",
                    "threathunting",
                    "hunting",
                    "t1007",
                    "recon",
                    "discovery",
                    "windows"
                ]
            },
            "schema": 1,
            "type": "watchlist.hit",
            "watchlists": [
                {
                    "id": "P5f9AW29TGmTOvBW156Cig",
                    "name": "ATT&CK Framework"
                }
            ]
        }
    },
    "data_stream": {
        "dataset": "carbon_black_cloud.watchlist_hit",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "carbon_black_cloud.watchlist_hit",
        "ingested": "2022-02-17T07:23:31Z",
        "kind": "event",
        "original": "{\"schema\":1,\"create_time\":\"2022-02-10T23:54:32.449Z\",\"device_external_ip\":\"205.234.30.196\",\"device_id\":4467271,\"device_internal_ip\":\"10.33.4.214\",\"device_name\":\"Carbonblack-win1\",\"device_os\":\"WINDOWS\",\"ioc_hit\":\"((process_name:sc.exe -parent_name:svchost.exe) AND process_cmdline:query) -enriched:true\",\"ioc_id\":\"565571-0\",\"org_key\":\"7DESJ9GN\",\"parent_cmdline\":\"C:\\\\WINDOWS\\\\system32\\\\cmd.exe /c \\\"sc query aella_conf | findstr RUNNING \\u003e null\\\"\",\"parent_guid\":\"7DESJ9GN-00442a47-00000fec-00000000-1d81ed87d4655d1\",\"parent_hash\":[\"d0fce3afa6aa1d58ce9fa336cc2b675b\",\"4d89fc34d5f0f9babd022271c585a9477bf41e834e46b991deaa0530fdb25e22\"],\"parent_path\":\"c:\\\\windows\\\\syswow64\\\\cmd.exe\",\"parent_pid\":4076,\"parent_publisher\":[{\"name\":\"Microsoft Windows\",\"state\":\"FILE_SIGNATURE_STATE_SIGNED | FILE_SIGNATURE_STATE_VERIFIED | FILE_SIGNATURE_STATE_TRUSTED | FILE_SIGNATURE_STATE_OS | FILE_SIGNATURE_STATE_CATALOG_SIGNED\"}],\"parent_reputation\":\"REP_WHITE\",\"parent_username\":\"NT AUTHORITY\\\\SYSTEM\",\"process_cmdline\":\"sc  query aella_conf \",\"process_guid\":\"7DESJ9GN-00442a47-00001d5c-00000000-1d81ed87d63d2c6\",\"process_hash\":[\"d9d7684b8431a0d10d0e76fe9f5ffec8\",\"4fe6d9eb8109fb79ff645138de7cff37906867aade589bd68afa503a9ab3cfb2\"],\"process_path\":\"c:\\\\windows\\\\syswow64\\\\sc.exe\",\"process_pid\":7516,\"process_publisher\":[{\"name\":\"Microsoft Windows\",\"state\":\"FILE_SIGNATURE_STATE_SIGNED | FILE_SIGNATURE_STATE_VERIFIED | FILE_SIGNATURE_STATE_TRUSTED | FILE_SIGNATURE_STATE_OS | FILE_SIGNATURE_STATE_CATALOG_SIGNED\"}],\"process_reputation\":\"REP_WHITE\",\"process_username\":\"NT AUTHORITY\\\\SYSTEM\",\"report_id\":\"CFnKBKLTv6hUkBGFobRdg-565571\",\"report_name\":\"Discovery - System Service Discovery Detected\",\"report_tags\":[\"attack\",\"attackframework\",\"threathunting\",\"hunting\",\"t1007\",\"recon\",\"discovery\",\"windows\"],\"severity\":3,\"type\":\"watchlist.hit\",\"watchlists\":[{\"id\":\"P5f9AW29TGmTOvBW156Cig\",\"name\":\"ATT\\u0026CK Framework\"}]}",
        "severity": 3
    },
    "host": {
        "hostname": "Carbonblack-win1",
        "id": "4467271",
        "ip": [
            "10.10.156.12",
            "67.43.156.12"
        ],
        "os": {
            "type": "windows"
        }
    },
    "input": {
        "type": "aws-s3"
    },
    "process": {
        "command_line": "sc  query aella_conf ",
        "entity_id": "7DESJ9GN-00442a47-00001d5c-00000000-1d81ed87d63d2c6",
        "executable": "c:\\windows\\syswow64\\sc.exe",
        "hash": {
            "md5": "d9d7684b8431a0d10d0e76fe9f5ffec8",
            "sha256": "4fe6d9eb8109fb79ff645138de7cff37906867aade589bd68afa503a9ab3cfb2"
        },
        "parent": {
            "command_line": "C:\\WINDOWS\\system32\\cmd.exe /c \"sc query aella_conf | findstr RUNNING > null\"",
            "entity_id": "7DESJ9GN-00442a47-00000fec-00000000-1d81ed87d4655d1",
            "executable": "c:\\windows\\syswow64\\cmd.exe",
            "hash": {
                "md5": "d0fce3afa6aa1d58ce9fa336cc2b675b",
                "sha256": "4d89fc34d5f0f9babd022271c585a9477bf41e834e46b991deaa0530fdb25e22"
            },
            "pid": 4076
        },
        "pid": 7516
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "carbon_black_cloud-watchlist-hit"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| carbon_black_cloud.watchlist_hit.device.external_ip | External IP of the device. | ip |
| carbon_black_cloud.watchlist_hit.device.internal_ip | Internal IP of the device. | ip |
| carbon_black_cloud.watchlist_hit.device.os | OS Type of device (Windows/OSX/Linux). | keyword |
| carbon_black_cloud.watchlist_hit.ioc.field | Field the IOC hit contains. | keyword |
| carbon_black_cloud.watchlist_hit.ioc.hit | IOC field value, or IOC query that matches. | keyword |
| carbon_black_cloud.watchlist_hit.ioc.id | ID of the IOC that caused the hit. | keyword |
| carbon_black_cloud.watchlist_hit.organization_key | The organization key associated with the console instance. | keyword |
| carbon_black_cloud.watchlist_hit.process.parent.publisher.name | The name of the publisher. | keyword |
| carbon_black_cloud.watchlist_hit.process.parent.publisher.state | The state of the publisher. | keyword |
| carbon_black_cloud.watchlist_hit.process.parent.reputation | Reputation of the actor process; applied when event is processed by the Carbon Black Cloud i.e. after sensor delivers event to the cloud. | keyword |
| carbon_black_cloud.watchlist_hit.process.parent.username | The username associated with the user context that this process was started under. | keyword |
| carbon_black_cloud.watchlist_hit.process.publisher.name | The name of the publisher. | keyword |
| carbon_black_cloud.watchlist_hit.process.publisher.state | The state of the publisher. | keyword |
| carbon_black_cloud.watchlist_hit.process.reputation | Reputation of the actor process; applied when event is processed by the Carbon Black Cloud i.e. after sensor delivers event to the cloud. | keyword |
| carbon_black_cloud.watchlist_hit.process.username | The username associated with the user context that this process was started under. | keyword |
| carbon_black_cloud.watchlist_hit.report.id | ID of the watchlist report(s) that detected a hit on the process. | keyword |
| carbon_black_cloud.watchlist_hit.report.name | Name of the watchlist report(s) that detected a hit on the process. | keyword |
| carbon_black_cloud.watchlist_hit.report.tags | List of tags associated with the report(s) that detected a hit on the process. | keyword |
| carbon_black_cloud.watchlist_hit.schema | Schema version. | long |
| carbon_black_cloud.watchlist_hit.type | The watchlist hit type. | keyword |
| carbon_black_cloud.watchlist_hit.watchlists.id | The ID of the watchlists. | keyword |
| carbon_black_cloud.watchlist_hit.watchlists.name | The name of the watchlists. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


### Asset Vulnerability Summary

This is the `asset_vulnerability_summary` dataset.

An example event for `asset_vulnerability_summary` looks as following:

```json
{
    "@timestamp": "2025-06-02T14:58:13.698Z",
    "agent": {
        "ephemeral_id": "cec373bd-24d4-48f5-9a22-d7630b36e420",
        "id": "afe3350e-e0ea-4c70-8249-090c14d9d593",
        "name": "elastic-agent-11440",
        "type": "filebeat",
        "version": "8.18.1"
    },
    "carbon_black_cloud": {
        "asset_vulnerability_summary": {
            "last_sync": {
                "timestamp": "2022-01-17T08:33:37.384Z"
            },
            "os_info": {
                "os_arch": "64-bit"
            },
            "sync": {
                "status": "COMPLETED",
                "type": "SCHEDULED"
            },
            "type": "ENDPOINT",
            "vuln_count": 1770
        }
    },
    "data_stream": {
        "dataset": "carbon_black_cloud.asset_vulnerability_summary",
        "namespace": "93728",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "afe3350e-e0ea-4c70-8249-090c14d9d593",
        "snapshot": false,
        "version": "8.18.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "carbon_black_cloud.asset_vulnerability_summary",
        "ingested": "2025-06-02T14:58:16Z",
        "kind": "state",
        "original": "{\"cve_ids\":null,\"device_id\":8,\"highest_risk_score\":10,\"host_name\":\"DESKTOP-008\",\"last_sync_ts\":\"2022-01-17T08:33:37.384932Z\",\"name\":\"DESKTOP-008KK\",\"os_info\":{\"os_arch\":\"64-bit\",\"os_name\":\"Microsoft Windows 10 Education\",\"os_type\":\"WINDOWS\",\"os_version\":\"10.0.17763\"},\"severity\":\"CRITICAL\",\"sync_status\":\"COMPLETED\",\"sync_type\":\"SCHEDULED\",\"type\":\"ENDPOINT\",\"vm_id\":\"\",\"vm_name\":\"\",\"vuln_count\":1770}"
    },
    "host": {
        "hostname": "DESKTOP-008",
        "id": "8",
        "name": "DESKTOP-008KK",
        "os": {
            "name": "Microsoft Windows 10 Education",
            "type": "windows",
            "version": "10.0.17763"
        }
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hosts": [
            "DESKTOP-008"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "carbon_black_cloud-asset_vulnerability_summary"
    ],
    "vulnerability": {
        "score": {
            "base": 10
        },
        "severity": "CRITICAL"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| carbon_black_cloud.asset_vulnerability_summary.last_sync.timestamp | The identifier is for the Last sync time. | date |
| carbon_black_cloud.asset_vulnerability_summary.os_info.os_arch | The identifier is for the Operating system architecture. | keyword |
| carbon_black_cloud.asset_vulnerability_summary.sync.status | The identifier is for the Device sync status. | keyword |
| carbon_black_cloud.asset_vulnerability_summary.sync.type | The identifier is for the Whether a manual sync was triggered for the device, or if it was a scheduled sync. | keyword |
| carbon_black_cloud.asset_vulnerability_summary.type | The identifier is for the Device type. | keyword |
| carbon_black_cloud.asset_vulnerability_summary.vm.id | The identifier is for the Virtual Machine ID. | keyword |
| carbon_black_cloud.asset_vulnerability_summary.vm.name | The identifier is for the Virtual Machine name. | keyword |
| carbon_black_cloud.asset_vulnerability_summary.vuln_count | The identifier is for the Number of vulnerabilities at this level. | integer |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |

