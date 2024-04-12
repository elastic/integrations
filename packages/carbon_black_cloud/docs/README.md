# VMware Carbon Black Cloud

The VMware Carbon Black Cloud integration collects and parses data from the Carbon Black Cloud REST APIs and AWS S3 bucket.

## Version 2.0.0+ Update Disclaimer
Carbon Black Cloud `Alerts API (v6)` [will be deactivated on July 31, 2024](https://developer.carbonblack.com/reference/carbon-black-cloud/api-migration/#migration-summary). After this, the current alert data stream will become unusable. To enable a smooth transition we have introduced a new data stream named `alert_v7` based on the major `Alerts API (v7)` schema changes and `Data Forwarder 2.0` schema changes. This data stream has significant changes compared to the original data stream and is only available for our new `CEL input` which is currently tagged as `[Beta]`. Please consult the official docs [Alerts v7](https://developer.carbonblack.com/reference/carbon-black-cloud/guides/api-migration/alerts-migration) and [Data Forwarder 2.0](https://developer.carbonblack.com/reference/carbon-black-cloud/data-forwarder/schema/latest/alert-2.0.0/) for further info. After July 31, 2024, the old alerts v6 data stream will be deprecated and removed from the HTTPJSON input and only the new `alert_v7` data stream will exist under the `CEL input`.

## Version 1.21+ Update Disclaimer
Starting from version 1.21, if using multiple AWS data streams simultaneously configured to use AWS SQS, separate SQS queues should be configured per
data stream. The default values of file selector regexes have been commented out for this reason. The only reason the global queue now exists is to avoid
a breaking change while upgrading to version 1.21 and above. A separate SQS queue per data stream should help fix the data loss that's been occurring in the 
older versions.

## HTTPJSON vs CEL 
Version 2.0.0 introduces the use of the CEL input. This input method is currently marked as [Beta] while the older HTTPJSON input method has been
marked as [Legacy]. The HTTPJSON input method will not receive enhancement changes and will not support the new `alert_v7` data stream.

## Note (Important)
1. Do not enable both the HTTPJSON and CEL input methods within a single data stream; having both enabled simultaneously can cause unexpected/duplicated results, as they operate on the same data streams.

2. When using the AWS-S3 input, use either the old alert data stream or the new [Beta] alert_v7 data stream that supports the Data Forwarder 2.0 schema.

3. The `alert_v7` data stream is supported by our new `Alert V7` dashboards. The old `Alert` dashboards will not reflect the new changes.


## Compatibility
This module has been tested against `Alerts API (v7) [Beta]`, `Alerts API (v6)`, `Audit Log Events (v3)` and `Vulnerability Assessment (v1)`.

## Requirements

### In order to ingest data from the AWS S3 bucket you must:
1. Configure the [Data Forwarder](https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/GUID-F68F63DD-2271-4088-82C9-71D675CD0535.html) to ingest data into an AWS S3 bucket.
2. Create an [AWS Access Keys and Secret Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys).
3. The default value of the "Bucket List Prefix" is listed below. However, the user can set the parameter "Bucket List Prefix" according to the requirement.

  | Data Stream Name  | Bucket List Prefix     |
  | ----------------- | ---------------------- |
  | Alert_v7          | alert_logs_v7          |
  | Alert             | alert_logs             |
  | Endpoint Event    | endpoint_event_logs    |
  | Watchlist Hit     | watchlist_hit_logs     |

### To collect data from AWS SQS, follow the below steps:
1. If data forwarding to an AWS S3 Bucket hasn't been configured, then first setup an AWS S3 Bucket as mentioned in the above documentation.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
  - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
3. Set up event notification for an S3 bucket. Follow this [Link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - The user has to perform Step 3 for all the data streams individually, and each time prefix parameter should be set the same as the S3 Bucket List Prefix as created earlier. (for example, `alert_logs/` for the alert data stream.)
  - For all the event notifications that have been created, select the event type as s3:ObjectCreated:*, select the destination type SQS Queue, and select the queue that has been created in Step 2.

**Note**:
  - Credentials for the above AWS S3 and SQS input types should be configured using the [link](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.
  - When configuring SQS queues, separate queues should be used for each data stream instead of the global SQS queue from version 1.21 onwards to avoid data 
    loss. File selectors should not be used to filter out data stream logs using the global queue as it was in versions prior.

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
| Audit   	                  | API                                        |
| Alert                       | Custom orgs.alerts (Read)                  |
| Asset Vulnerability Summary | Custom vulnerabilityAssessment.data (Read) |


## Note

- The alert data stream has a 15-minute delay to ensure that no occurrences are missed.

## Logs

### Audit

This is the `audit` dataset.

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2022-02-10T16:04:30.263Z",
    "agent": {
        "ephemeral_id": "a820562f-e713-4f48-81bc-7f329f192335",
        "id": "45e49275-eb7d-4b20-a8af-d084fb2551c7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.0"
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
            "id": "abc@demo.com"
        }
    },
    "data_stream": {
        "dataset": "carbon_black_cloud.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "45e49275-eb7d-4b20-a8af-d084fb2551c7",
        "snapshot": true,
        "version": "8.8.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-04-19T16:30:46.573Z",
        "dataset": "carbon_black_cloud.audit",
        "id": "2122f8ce8xxxxxxxxxxxxx",
        "ingested": "2023-04-19T16:30:50Z",
        "kind": "event",
        "original": "{\"clientIp\":\"10.10.10.10\",\"description\":\"Logged in successfully\",\"eventId\":\"2122f8ce8xxxxxxxxxxxxx\",\"eventTime\":1644509070263,\"flagged\":false,\"loginName\":\"abc@demo.com\",\"orgName\":\"cb-xxxx-xxxx.com\",\"requestUrl\":null,\"verbose\":false}",
        "outcome": "success",
        "reason": "Logged in successfully"
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "name": "cb-xxxx-xxxx.com"
    },
    "related": {
        "ip": [
            "10.10.10.10"
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
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.user.id | Unique identifier of the user. | keyword |
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.mac | Host mac addresses. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| organization.name | Organization name. | keyword |
| organization.name.text | Multi-field of `organization.name`. | match_only_text |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |


### Alert

This is the `alert` dataset.

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2020-11-17T22:05:13.000Z",
    "agent": {
        "ephemeral_id": "0c34bcbb-0fe1-4219-a711-8a44cb9e8b75",
        "id": "c073dde3-4d37-4b40-8161-a008a04d551f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.0"
    },
    "carbon_black_cloud": {
        "alert": {
            "category": "warning",
            "device": {
                "location": "UNKNOWN",
                "os": "WINDOWS"
            },
            "last_update_time": "2020-11-17T22:05:13.000Z",
            "legacy_alert_id": "C8EB7306-AF26-4A9A-B677-814B3AF69720",
            "organization_key": "ABCD6X3T",
            "policy": {
                "applied": "APPLIED",
                "id": 6997287,
                "name": "Standard"
            },
            "product_id": "0x5406",
            "product_name": "U3 Cruzer Micro",
            "reason_code": "6D578342-9DE5-4353-9C25-1D3D857BFC5B:DCAEB1FA-513C-4026-9AB6-37A935873FBC",
            "run_state": "DID_NOT_RUN",
            "sensor_action": "DENY",
            "serial_number": "0875920EF7C2A304",
            "target_value": "MEDIUM",
            "threat_cause": {
                "cause_event_id": "FCEE2AF0-D832-4C9F-B988-F11B46028C9E",
                "threat_category": "NON_MALWARE",
                "vector": "REMOVABLE_MEDIA"
            },
            "threat_id": "t5678",
            "type": "DEVICE_CONTROL",
            "vendor_id": "0x0781",
            "vendor_name": "SanDisk",
            "workflow": {
                "changed_by": "Carbon Black",
                "last_update_time": "2020-11-17T22:02:16.000Z",
                "state": "OPEN"
            }
        }
    },
    "data_stream": {
        "dataset": "carbon_black_cloud.alert",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c073dde3-4d37-4b40-8161-a008a04d551f",
        "snapshot": true,
        "version": "8.8.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-04-19T16:35:34.619Z",
        "dataset": "carbon_black_cloud.alert",
        "end": "2020-11-17T22:02:16.000Z",
        "id": "test1",
        "ingested": "2023-04-19T16:35:38Z",
        "kind": "alert",
        "original": "{\"category\":\"WARNING\",\"create_time\":\"2020-11-17T22:05:13Z\",\"device_id\":2,\"device_location\":\"UNKNOWN\",\"device_name\":\"DESKTOP-002\",\"device_os\":\"WINDOWS\",\"device_os_version\":\"Windows 10 x64\",\"device_username\":\"test34@demo.com\",\"first_event_time\":\"2020-11-17T22:02:16Z\",\"id\":\"test1\",\"last_event_time\":\"2020-11-17T22:02:16Z\",\"last_update_time\":\"2020-11-17T22:05:13Z\",\"legacy_alert_id\":\"C8EB7306-AF26-4A9A-B677-814B3AF69720\",\"org_key\":\"ABCD6X3T\",\"policy_applied\":\"APPLIED\",\"policy_id\":6997287,\"policy_name\":\"Standard\",\"product_id\":\"0x5406\",\"product_name\":\"U3 Cruzer Micro\",\"reason\":\"Access attempted on unapproved USB device SanDisk U3 Cruzer Micro (SN: 0875920EF7C2A304). A Deny Policy Action was applied.\",\"reason_code\":\"6D578342-9DE5-4353-9C25-1D3D857BFC5B:DCAEB1FA-513C-4026-9AB6-37A935873FBC\",\"run_state\":\"DID_NOT_RUN\",\"sensor_action\":\"DENY\",\"serial_number\":\"0875920EF7C2A304\",\"severity\":3,\"target_value\":\"MEDIUM\",\"threat_cause_cause_event_id\":\"FCEE2AF0-D832-4C9F-B988-F11B46028C9E\",\"threat_cause_threat_category\":\"NON_MALWARE\",\"threat_cause_vector\":\"REMOVABLE_MEDIA\",\"threat_id\":\"t5678\",\"type\":\"DEVICE_CONTROL\",\"vendor_id\":\"0x0781\",\"vendor_name\":\"SanDisk\",\"workflow\":{\"changed_by\":\"Carbon Black\",\"comment\":\"\",\"last_update_time\":\"2020-11-17T22:02:16Z\",\"remediation\":\"\",\"state\":\"OPEN\"}}",
        "reason": "Access attempted on unapproved USB device SanDisk U3 Cruzer Micro (SN: 0875920EF7C2A304). A Deny Policy Action was applied.",
        "severity": 3,
        "start": "2020-11-17T22:02:16.000Z"
    },
    "host": {
        "hostname": "DESKTOP-002",
        "id": "2",
        "name": "DESKTOP-002",
        "os": {
            "type": "windows",
            "version": "Windows 10 x64"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "hosts": [
            "DESKTOP-002"
        ],
        "user": [
            "test34@demo.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "carbon_black_cloud-alert"
    ],
    "user": {
        "name": "test34@demo.com"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| carbon_black_cloud.alert.blocked_threat_category | The category of threat which we were able to take action on. | keyword |
| carbon_black_cloud.alert.category | The category of the alert. | keyword |
| carbon_black_cloud.alert.count |  | long |
| carbon_black_cloud.alert.created_by_event_id | Event identifier that initiated the alert. | keyword |
| carbon_black_cloud.alert.device.location | The Location of device. | keyword |
| carbon_black_cloud.alert.device.os | OS of the device. | keyword |
| carbon_black_cloud.alert.document_guid | Unique ID of document. | keyword |
| carbon_black_cloud.alert.ioc.field | The field the indicator of comprise (IOC) hit contains. | keyword |
| carbon_black_cloud.alert.ioc.hit | IOC field value or IOC query that matches. | keyword |
| carbon_black_cloud.alert.ioc.id | The identifier of the IOC that cause the hit. | keyword |
| carbon_black_cloud.alert.kill_chain_status | The stage within the Cyber Kill Chain sequence most closely associated with the attributes of the alert. | keyword |
| carbon_black_cloud.alert.last_update_time | The last time the alert was updated as an ISO 8601 UTC timestamp. | date |
| carbon_black_cloud.alert.legacy_alert_id | The legacy identifier for the alert. | keyword |
| carbon_black_cloud.alert.not_blocked_threat_category | Other potentially malicious activity involved in the threat that we weren't able to take action on (either due to policy config, or not having a relevant rule). | keyword |
| carbon_black_cloud.alert.notes_present | Indicates if notes are associated with the threat_id. | boolean |
| carbon_black_cloud.alert.organization_key | The unique identifier for the organization associated with the alert. | keyword |
| carbon_black_cloud.alert.policy.applied | Whether a policy was applied. | keyword |
| carbon_black_cloud.alert.policy.id | The identifier for the policy associated with the device at the time of the alert. | long |
| carbon_black_cloud.alert.policy.name | The name of the policy associated with the device at the time of the alert. | keyword |
| carbon_black_cloud.alert.product_id | The hexadecimal id of the USB device's product. | keyword |
| carbon_black_cloud.alert.product_name | The name of the USB device’s vendor. | keyword |
| carbon_black_cloud.alert.reason_code | Shorthand enum for the full-text reason. | keyword |
| carbon_black_cloud.alert.report.id | The identifier of the report that contains the IOC. | keyword |
| carbon_black_cloud.alert.report.name | The name of the report that contains the IOC. | keyword |
| carbon_black_cloud.alert.run_state | Whether the threat in the alert ran. | keyword |
| carbon_black_cloud.alert.sensor_action | The action taken by the sensor, according to the rule of the policy. | keyword |
| carbon_black_cloud.alert.serial_number | The serial number of the USB device. | keyword |
| carbon_black_cloud.alert.status | status of alert. | keyword |
| carbon_black_cloud.alert.tags | Tags associated with the alert. | keyword |
| carbon_black_cloud.alert.target_value | The priority of the device assigned by the policy. | keyword |
| carbon_black_cloud.alert.threat_activity.c2 | Whether the alert involved a command and control (c2) server. | keyword |
| carbon_black_cloud.alert.threat_activity.dlp | Whether the alert involved data loss prevention (DLP). | keyword |
| carbon_black_cloud.alert.threat_activity.phish | Whether the alert involved phishing. | keyword |
| carbon_black_cloud.alert.threat_cause.actor.md5 | MD5 of the threat cause actor. | keyword |
| carbon_black_cloud.alert.threat_cause.actor.name | The name can be one of the following: process commandline, process name, or analytic matched threat. Analytic matched threats are Exploit, Malware, PUP, or Trojan. | keyword |
| carbon_black_cloud.alert.threat_cause.actor.process_pid | Process identifier (PID) of the actor process. | keyword |
| carbon_black_cloud.alert.threat_cause.actor.sha256 | SHA256 of the threat cause actor. | keyword |
| carbon_black_cloud.alert.threat_cause.cause_event_id | ID of the Event that triggered the threat. | keyword |
| carbon_black_cloud.alert.threat_cause.process.guid | The global unique identifier of the process. | keyword |
| carbon_black_cloud.alert.threat_cause.process.parent.guid | The global unique identifier of the process. | keyword |
| carbon_black_cloud.alert.threat_cause.reputation | Reputation of the threat cause. | keyword |
| carbon_black_cloud.alert.threat_cause.threat_category | Category of the threat cause. | keyword |
| carbon_black_cloud.alert.threat_cause.vector | The source of the threat cause. | keyword |
| carbon_black_cloud.alert.threat_id | The identifier of a threat which this alert belongs. Threats are comprised of a combination of factors that can be repeated across devices. | keyword |
| carbon_black_cloud.alert.threat_indicators.process_name | Process name associated with threat. | keyword |
| carbon_black_cloud.alert.threat_indicators.sha256 | Sha256 associated with threat. | keyword |
| carbon_black_cloud.alert.threat_indicators.ttps | Tactics, techniques and procedures associated with threat. | keyword |
| carbon_black_cloud.alert.type | Type of alert. | keyword |
| carbon_black_cloud.alert.vendor_id | The hexadecimal id of the USB device's vendor. | keyword |
| carbon_black_cloud.alert.vendor_name | The name of the USB device’s vendor. | keyword |
| carbon_black_cloud.alert.watchlists.id | The identifier of watchlist. | keyword |
| carbon_black_cloud.alert.watchlists.name | The name of the watchlist. | keyword |
| carbon_black_cloud.alert.workflow.changed_by | The name of user who changed the workflow. | keyword |
| carbon_black_cloud.alert.workflow.comment | Comment associated with workflow. | keyword |
| carbon_black_cloud.alert.workflow.last_update_time | The last update time of workflow. | date |
| carbon_black_cloud.alert.workflow.remediation | N/A. | keyword |
| carbon_black_cloud.alert.workflow.state | The state of workflow. | keyword |
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.mac | Host mac addresses. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


### Alert

This is the `alert_v7` dataset.

An example event for `alert_v7` looks as following:

```json
{
    "@timestamp": "2024-03-13T08:02:36.578Z",
    "agent": {
        "ephemeral_id": "9c46ff77-c269-4593-a3d8-efd89fbdca66",
        "id": "db2930ff-774e-4541-bcd4-1a6a1d656167",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
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
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "db2930ff-774e-4541-bcd4-1a6a1d656167",
        "snapshot": false,
        "version": "8.12.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "carbon_black_cloud.alert_v7",
        "end": "2024-03-13T08:00:09.894Z",
        "id": "1c6aba68-24cc-41e3-ad8e-4b545a587b55",
        "ingested": "2024-04-10T09:06:02Z",
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.mac | Host mac addresses. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.parent.command_line.text | Multi-field of `process.parent.command_line`. | match_only_text |
| process.parent.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.hash.md5 | MD5 hash. | keyword |
| process.parent.hash.sha256 | SHA256 hash. | keyword |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


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
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
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
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| dll.hash.md5 | MD5 hash. | keyword |
| dll.hash.sha256 | SHA256 hash. | keyword |
| dll.path | Full file path of the library. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.mac | Host mac addresses. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.parent.command_line.text | Multi-field of `process.parent.command_line`. | match_only_text |
| process.parent.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.hash.md5 | MD5 hash. | keyword |
| process.parent.hash.sha256 | SHA256 hash. | keyword |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| registry.path | Full path, including hive, key and value | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |


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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.mac | Host mac addresses. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.parent.command_line.text | Multi-field of `process.parent.command_line`. | match_only_text |
| process.parent.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.hash.md5 | MD5 hash. | keyword |
| process.parent.hash.sha256 | SHA256 hash. | keyword |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |


### Asset Vulnerability Summary

This is the `asset_vulnerability_summary` dataset.

An example event for `asset_vulnerability_summary` looks as following:

```json
{
    "@timestamp": "2023-04-19T16:29:52.808Z",
    "agent": {
        "ephemeral_id": "7a1f920f-4945-405b-9e1f-67f8a3601fdb",
        "id": "45e49275-eb7d-4b20-a8af-d084fb2551c7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.0"
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
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "45e49275-eb7d-4b20-a8af-d084fb2551c7",
        "snapshot": true,
        "version": "8.8.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-04-19T16:29:52.808Z",
        "dataset": "carbon_black_cloud.asset_vulnerability_summary",
        "ingested": "2023-04-19T16:29:56Z",
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
        "type": "httpjson"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.mac | Host mac addresses. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| vulnerability.score.base | Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Base scores cover an assessment for exploitability metrics (attack vector, complexity, privileges, and user interaction), impact metrics (confidentiality, integrity, and availability), and scope. For example (https://www.first.org/cvss/specification-document) | float |
| vulnerability.severity | The severity of the vulnerability can help with metrics and internal prioritization regarding remediation. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |
