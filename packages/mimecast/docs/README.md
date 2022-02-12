# Mimecast Integration

The Mimecast integration collects events from the Mimecast API.

## Configuration

Authorization parameters for the Mimecast API (`Application Key`, `Application ID`, `Access Key`, and `Secret Key`), should be provided by a Mimecast representative for this integration.
Under `Advanced options` you can set the time interval between two API requests as well as the API URL. A Mimecast representative should also be able to give you with this information in case you need to change the defaults. 

Note that rate limit quotas may require you to set up different credentials for the different available log types.

## Logs

### Audit Events

This is the `mimecast.audit_events` dataset. These logs contain Mimecast audit events with the following details: audit type, event category and detailed information about the event. More information about these logs [here] (https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-audit-events/).

An example event for `audit_events` looks as following:

```json
{
    "@timestamp": "2021-11-16T12:01:37.000Z",
    "agent": {
        "ephemeral_id": "57841034-22ed-4fcd-bcfd-0a9518249e2d",
        "hostname": "docker-fleet-agent",
        "id": "eb7f38a3-c00c-4d87-9c69-fddb3d650fab",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.0"
    },
    "client": {
        "as": {
            "number": 15169,
            "organization": {
                "name": "Google LLC"
            }
        },
        "geo": {
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 37.751,
                "lon": -97.822
            }
        },
        "ip": "8.8.8.8"
    },
    "data_stream": {
        "dataset": "mimecast.audit_events",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "eb7f38a3-c00c-4d87-9c69-fddb3d650fab",
        "snapshot": true,
        "version": "7.16.0"
    },
    "event": {
        "action": "case-action",
        "agent_id_status": "verified",
        "created": "2021-11-16T12:01:37.000Z",
        "dataset": "mimecast.audit_events",
        "id": "eNqrVipOTS4tSs1MUbJSskwzjDIMyDRKLinNSEl1c0pOqXLJyQlL89c2DXZ1C3eP9AyvijKL9I7Rd_WOzC0ztMg2dzFM1M73s6w09CqoDA1T0lFKLE3JLMnJTwcZaGxoaWFsYmhkrqOUXFpckp-bWpScn5IKtMnZxMzR3BSovCy1qDgzP0_JyrAWAE_sLAI",
        "ingested": "2021-11-24T15:39:11Z",
        "original": "{\"auditType\":\"Case Action\",\"category\":\"case_review_logs\",\"eventInfo\":\"Viewed Case - Case: GDPR/CCPA, Date: 2021-11-16, Time: 12:01:37+0000, IP: 8.8.8.8, Application: mimecast-case-review\",\"eventTime\":\"2021-11-16T12:01:37+0000\",\"id\":\"eNqrVipOTS4tSs1MUbJSskwzjDIMyDRKLinNSEl1c0pOqXLJyQlL89c2DXZ1C3eP9AyvijKL9I7Rd_WOzC0ztMg2dzFM1M73s6w09CqoDA1T0lFKLE3JLMnJTwcZaGxoaWFsYmhkrqOUXFpckp-bWpScn5IKtMnZxMzR3BSovCy1qDgzP0_JyrAWAE_sLAI\",\"user\":\"johndoe@example.com\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "mimecast": {
        "application": "mimecast-case-review",
        "category": "case_review_logs",
        "eventInfo": "Viewed Case - Case: GDPR/CCPA, Date: 2021-11-16, Time: 12:01:37+0000, IP: 8.8.8.8, Application: mimecast-case-review"
    },
    "related": {
        "ip": [
            "8.8.8.8"
        ],
        "user": [
            "johndoe",
            "johndoe@example.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-audit-events"
    ],
    "user": {
        "domain": "example.com",
        "email": "johndoe@example.com",
        "name": "johndoe"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.as.asn | Client ASN number. | long |
| client.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| client.as.organization.name | Organization name. | keyword |
| client.as.organization_name | Client Organization name. | keyword |
| client.geo.city_name | City name. | keyword |
| client.geo.continent_name | Name of the continent. | keyword |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.geo.region_iso_code | Region ISO code. | keyword |
| client.geo.region_name | Region name. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
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
| email.from.address | Stores the from email address from the RFC5322 From - header field. | keyword |
| email.origination_timestamp | The date and time the email message was composed. Many email clients will fill this in automatically when the message is sent by a user. | date |
| email.subject | A brief summary of the topic of the message | keyword |
| email.to.address | The email address(es) of the message recipient(s) | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| mimecast.application | The Mimecast unique id of the event. | keyword |
| mimecast.category | The category of the event. | keyword |
| mimecast.email.address | Email address from event info. | keyword |
| mimecast.email.metadata | The email meta data from audit info. | keyword |
| mimecast.eventInfo | The detailed event information. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.name | Short name or login of the user. | keyword |


### DLP Logs

This is the `mimecast.dlp_logs` dataset. These logs contain information about messages that triggered a DLP or Content Examination policy. More information about these logs [here] (https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-dlp-logs/). 

An example event for `dlp` looks as following:

```json
{
    "@timestamp": "2021-11-18T21:41:18.000Z",
    "agent": {
        "ephemeral_id": "1aef981f-3448-4d12-bd5a-723ac1cdcc81",
        "hostname": "docker-fleet-agent",
        "id": "eb7f38a3-c00c-4d87-9c69-fddb3d650fab",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.0"
    },
    "data_stream": {
        "dataset": "mimecast.dlp_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "eb7f38a3-c00c-4d87-9c69-fddb3d650fab",
        "snapshot": true,
        "version": "7.16.0"
    },
    "email": {
        "direction": "inbound",
        "from": {
            "address": "\u003c\u003e"
        },
        "message_id": "\u003c20211118214115.B346F10021D@mail.emailsec.ninja\u003e",
        "subject": "Undelivered Mail Returned to Sender",
        "to": {
            "address": "johndoe@example.com"
        }
    },
    "event": {
        "action": "notification",
        "agent_id_status": "verified",
        "created": "2021-11-18T21:41:18+0000",
        "dataset": "mimecast.dlp_logs",
        "ingested": "2021-11-24T15:39:49Z",
        "original": "{\"action\":\"notification\",\"eventTime\":\"2021-11-18T21:41:18+0000\",\"messageId\":\"\\u003c20211118214115.B346F10021D@mail.emailsec.ninja\\u003e\",\"policy\":\"Content Inspection - Watermark\",\"recipientAddress\":\"johndoe@example.com\",\"route\":\"inbound\",\"senderAddress\":\"\\u003c\\u003e\",\"subject\":\"Undelivered Mail Returned to Sender\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "rule": {
        "name": "Content Inspection - Watermark"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-dlp-logs"
    ]
}
```

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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.direction | Direction of the message based on the sending and receiving domains | keyword |
| email.from.address | Stores the from email address from the RFC5322 From - header field. | keyword |
| email.message_id | Identifier from the RFC5322 Message-ID - header field that refers to a particular version of a particular message. | wildcard |
| email.subject | A brief summary of the topic of the message | keyword |
| email.to.address | The email address(es) of the message recipient(s) | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| mimecast.action | The action taken against the message. | keyword |
| mimecast.messageId | The message-id value of the message. | keyword |
| mimecast.policy | The name of a DLP or Content Examination configuration that triggered the message. | keyword |
| mimecast.recipientAddress | Email address of the recipient. | keyword |
| mimecast.route | The message direction. Possible values are inbound, outbound or internal. | keyword |
| mimecast.senderAddress | Email address of the sender. | keyword |
| mimecast.subject | The message subject. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### SIEM Logs

This is the `mimecast.siem_logs` dataset. These logs contain information about messages that contains MTA logs (MTA = message transfer agent) – all Inbound, outbound and internal messages. More about these logs [here](https://integrations.mimecast.com/documentation/tutorials/understanding-siem-logs/).

An example event for `siem` looks as following:

```json
{
    "@timestamp": "2021-10-18T08:02:43.000Z",
    "ecs": {
        "version": "1.12.0"
    },
    "event": {
        "reason": "Spm",
        "action": "Hld",
        "ingested": "2021-11-25T11:34:11.459620200Z",
        "original": "{\"Act\":\"Hld\",\"AttCnt\":0,\"AttNames\":null,\"AttSize\":0,\"Content-Disposition\":\"attachment; filename=\\\"process_20211018093329655.json\\\"\",\"Hld\":\"Spm\",\"MsgId\":\"\\u003cINX.164dae0719be95da77068c7d264.3e915.e7719.c78c.17c926a3231ace@newsletter.77onlineshop.eu\\u003e\",\"MsgSize\":157436,\"Sender\":\"bounce_9244+cdaahhimyaaaaagaad5ekqaaaaaaaaeribenpq@newsletter.77onlineshop.eu\",\"Subject\":\"Hi Sandra! Neue Styles eingetroffen! – Finde deinen Lieblings-Look!\",\"aCode\":\"HhuwRf_AOcuJZINE2ZgcKw\",\"acc\":\"ABC123\",\"datetime\":\"2021-10-18T09:02:43+0100\"}",
        "created": "2021-10-18T09:02:43+0100",
        "outcome": "unknown"
    },
    "email": {
        "message_id": "\u003cINX.164dae0719be95da77068c7d264.3e915.e7719.c78c.17c926a3231ace@newsletter.77onlineshop.eu\u003e",
        "from": {
            "address": "bounce_9244+cdaahhimyaaaaagaad5ekqaaaaaaaaeribenpq@newsletter.77onlineshop.eu"
        },
        "attachments": {
            "file": {
                "size": 0
            }
        },
        "local_id": "HhuwRf_AOcuJZINE2ZgcKw",
        "subject": "Hi Sandra! Neue Styles eingetroffen! – Finde deinen Lieblings-Look!",
        "message_size": 157436
    },
    "tags": [
        "preserve_original_event"
    ],
    "mimecast": {
        "acc": "ABC123",
        "log_type": "process",
        "AttCnt": 0
    }
}
```

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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.attachments.file.extension | Attachment file extension, excluding the leading dot. | keyword |
| email.attachments.file.mime_type | MIME type of the attachment file. | keyword |
| email.attachments.file.name | Name of the attachment file including the extension. | keyword |
| email.attachments.file.size | Attachment file size in bytes. | long |
| email.attachments.hash.md5 | MD5 hash of the file attachment. | keyword |
| email.attachments.hash.sha1 | SHA-1 hash of the file attachment. | keyword |
| email.attachments.hash.sha256 | SHA-256 hash of the file attachment. | keyword |
| email.direction | Direction of the message based on the sending and receiving domains. | keyword |
| email.from.address | Stores the from email address from the RFC5322 From - header field. | keyword |
| email.header_from | The sender address found in the from header of the email. | keyword |
| email.local_id | Unique identifier given to the email by the source (MTA, gateway, etc.) that created the event and is not persistent across hops (for example, the X-MS-Exchange-Organization-Network-Message-Id id). | keyword |
| email.message_id | Identifier from the RFC5322 Message-ID - header field that refers to a particular version of a particular message. | wildcard |
| email.message_size | The total size of the email.The total size of the email. | long |
| email.subject | A brief summary of the topic of the message | keyword |
| email.to.address | The email address(es) of the message recipient(s). | keyword |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | match_only_text |
| error.type | The type of the error, for example the class name of the exception. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| mimecast.AttCnt | The number of attachments on the email. | long |
| mimecast.AttNames | The filenames of all attachments on the email. | keyword |
| mimecast.Attempt | The count of attempts that the Mimecast MTA has made to deliver the email. | long |
| mimecast.CustomName | The message has matched a custom name. | keyword |
| mimecast.CustomThreatDictionary | The content of the email was detected to contain words in a custom threat dictionary. | keyword |
| mimecast.CustomerIP | The source IP is one of the accounts authorised IPs or one of the authorised IPs belonging to an Umbrella Account, if the Account uses an Umbrella Account. | keyword |
| mimecast.Hits | Number of items flagged for the message. | keyword |
| mimecast.IPInternalName | For emails subject to Targeted Threat Protection - Impersonation Protect, if the email was detected to be from an internal user name. | keyword |
| mimecast.IPNewDomain | For emails subject to Targeted Threat Protection - Impersonation Protect, if the email was detected to be from a new domain. | keyword |
| mimecast.IPReplyMismatch | For emails subject to Targeted Threat Protection - Impersonation Protect, if the email was detetced to have a mismatch in the reply to address. | keyword |
| mimecast.IPSimilarDomain | For emails subject to Targeted Threat Protection - Impersonation Protect, if the email was detetced to be from a similar domain to any domain you have registered as an Internal Domain. | keyword |
| mimecast.IPThreadDict | For emails subject to Targeted Threat Protection - Impersonation Protect, if the content of the email was detected to contain words in the Mimecast threat dictionary. | keyword |
| mimecast.InternalName | The email was detected to be from an internal user name. | keyword |
| mimecast.Latency | The time in milliseconds that the delivery attempt took. | long |
| mimecast.MimecastIP | The source IP is one of the Mimecast' IPs e.g. Mimecast Personal Portal. | keyword |
| mimecast.MsgId | The internet message id of the email. | keyword |
| mimecast.MsgSize | The total size of the email. | long |
| mimecast.RcptActType | Action after reception. | keyword |
| mimecast.RcptHdrType | Type of the receipt header. | keyword |
| mimecast.ReceiptAck | The receipt acknowledgment message received by Mimecast from the receiving mail server. | keyword |
| mimecast.ReplyMismatch | The reply address does not correspond to the senders address. | keyword |
| mimecast.ScanResultInfo | The reason that the click was blocked. | keyword |
| mimecast.SenderDomainInternal | The sender domain is a registered internal domain. | keyword |
| mimecast.SimilarCustomExternalDomain | The senders domain is similar to a custom external domain list. | keyword |
| mimecast.SimilarInternalDomain | The senders domain is similar to a registered internal domain. | keyword |
| mimecast.SimilarMimecastExternalDomain | The senders domain is similar to a Mimecast managed list of domains. | keyword |
| mimecast.Snt | The amount of data in bytes that were delivered. | long |
| mimecast.SpamInfo | Information from Mimecast Spam scanners for messages found to be Spam. | keyword |
| mimecast.SpamLimit | The Spam limit defined for the given sender and recipient. | long |
| mimecast.SpamProcessingDetail | The Spam processing details for DKIM, SPF, DMARC. | keyword |
| mimecast.SpamScore | The Spam score the email was given. | long |
| mimecast.Subject | The subject of the email, limited to 150 characters. | keyword |
| mimecast.TaggedExternal | The message has been tagged as originating from a external source. | keyword |
| mimecast.TaggedMalicious | The message has been tagged as malicious. | keyword |
| mimecast.ThreatDictionary | The content of the email was detected to contain words in the Mimecast threat dictionary. | keyword |
| mimecast.UrlCategory | The category of the URL that was clicked. | keyword |
| mimecast.Virus | The name of the virus found on the email, if applicable. | keyword |
| mimecast.acc | The Mimecast account code for your account. | keyword |
| mimecast.credentialTheft | The info about credential theft. | keyword |
| mimecast.log_type | String to get type of SIEM log. | keyword |
| mimecast.msgid | The internet message id of the email. | keyword |
| mimecast.urlCategory | The category of the URL that was clicked. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| source.domain | Source domain. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.established | Boolean flag indicating if the TLS negotiation was successful and transitioned to an encrypted tunnel. | boolean |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| user.email | User email address. | keyword |


### TTP Impersonation Logs

This is the `mimecast.ttp_ip_logs` dataset. These logs contain information about messages containing information flagged by an Impersonation Protection configuration. Learn more about these logs [here] (https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-impersonation-protect-logs/). 

An example event for `ttp_ip` looks as following:

```json
{
    "@timestamp": "2021-10-15T17:10:46.000Z",
    "ecs": {
        "version": "1.12.0"
    },
    "related": {
        "ip": "8.8.8.8"
    },
    "rule": {
        "name": "IP - 1 hit (Tag email)"
    },
    "source": {
        "ip": "8.8.8.8"
    },
    "event": {
        "action": "none",
        "ingested": "2021-11-19T14:42:59.823940200Z",
        "original": "{\"id\":\"MTOKEN:eNqrVkouLS7Jz00tSs5PSVWyUnI2MXM0N1XSUcpMUbIyMjU1NjIw1FEqSy0qzszPU7ICskvywAoNDAyVagFirRIG\",\"senderAddress\":\"smtp@example.com\",\"recipientAddress\":\"johndoe@example.com\",\"subject\":\"Requested File\",\"definition\":\"IP - 1 hit (Tag email)\",\"hits\":1,\"identifiers\":[\"internal_user_name\"],\"action\":\"none\",\"taggedExternal\":false,\"taggedMalicious\":true,\"senderIpAddress\":\"8.8.8.8\",\"eventTime\":\"2021-10-15T17:10:46+0000\",\"impersonationResults\":[{\"impersonationDomainSource\":\"internal_user_name\",\"similarDomain\":\"John Doe Jr \u003cjohndoejr@example.com\u003e\",\"stringSimilarToDomain\":\"John Doe Jr\",\"checkerResult\":\"hit\"}],\"messageId\":\"\u003cEE7E97EA-1926-4A90-9399-D049A98893F4@emailsec.ninja\u003e\"}",
        "id": "MTOKEN:eNqrVkouLS7Jz00tSs5PSVWyUnI2MXM0N1XSUcpMUbIyMjU1NjIw1FEqSy0qzszPU7ICskvywAoNDAyVagFirRIG",
        "created": "2021-10-15T17:10:46+0000"
    },
    "email": {
        "from": {
            "address": "smtp@example.com"
        },
        "message_id": "\u003cEE7E97EA-1926-4A90-9399-D049A98893F4@emailsec.ninja\u003e",
        "to": {
            "address": "johndoe@example.com"
        },
        "subject": "Requested File"
    },
    "tags": [
        "preserve_original_event"
    ],
    "mimecast": {
        "hits": 1,
        "impersonationResults": [
            {
                "checkerResult": "hit",
                "impersonationDomainSource": "internal_user_name",
                "stringSimilarToDomain": "John Doe Jr",
                "similarDomain": "John Doe Jr \u003cjohndoejr@example.com\u003e"
            }
        ],
        "taggedMalicious": true,
        "taggedExternal": false,
        "identifiers": [
            "internal_user_name"
        ]
    }
}
```

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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.from.address | Stores the from email address from the RFC5322 From - header field. | keyword |
| email.message_id | Identifier from the RFC5322 Message-ID - header field that refers to a particular version of a particular message. | wildcard |
| email.subject | A brief summary of the topic of the message | keyword |
| email.to.address | The email address(es) of the message recipient(s) | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| mimecast.action | The action triggered by the email. | keyword |
| mimecast.definition | The name of the policy definition that triggered the log. | keyword |
| mimecast.hits | The number of identifiers that the message triggered. | long |
| mimecast.id | A token that can be used to retrieve this log again. | keyword |
| mimecast.identifiers | The properties of the message that triggered the action - similar_internal_domain, newly_observed_domain, internal_user_name, reply_address_mismatch, and/or targeted_threat_dictionary. | keyword |
| mimecast.impersonationResults.checkerResult | Result checker. | keyword |
| mimecast.impersonationResults.impersonationDomainSource | Impersonation domain source. | keyword |
| mimecast.impersonationResults.similarDomain | Similar domain. | keyword |
| mimecast.impersonationResults.stringSimilarToDomain | The string that is suspiciously similar to a known value within the Mimecast configuration. Multiple triggers will be comma-separated. | keyword |
| mimecast.messageId | The message-id of the identified message. | keyword |
| mimecast.recipientAddress | The email address of the recipient of the email. | keyword |
| mimecast.senderAddress | The email address of the sender of the message. | keyword |
| mimecast.senderIpAddress | The source IP address of the message. | keyword |
| mimecast.subject | The subject of the email. | keyword |
| mimecast.taggedExternal | Whether the message was tagged as coming from an external address. | boolean |
| mimecast.taggedMalicious | Whether the message was tagged as malicious. | boolean |
| related.ip | All of the IPs seen on your event. | ip |
| rule.name | The name of the rule or signature generating the event. | keyword |
| source.domain | Source domain. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |


### TTP Attachment Logs

This is the `mimecast.ttp_ap_logs` dataset. These logs contain Mimecast TTP attachment protection logs with the following details: result of attachment analysis (if it is malicious or not etc.), date when file is released, sender and recipient address, filename and type, action triggered for the attachment, the route of the original email containing the attachment and details. Learn more about these logs [here] (https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-attachment-protection-logs/).

An example event for `ttp_ap` looks as following:

```json
{
    "@timestamp": "2021-10-14T18:54:32.000Z",
    "ecs": {
        "version": "1.12.0"
    },
    "related": {
        "hash": "eaeef09b60a59b913e9bfc0a4373e25d6182beff388957473fba517cc09345e3"
    },
    "rule": {
        "name": "Inbound - Safe file with On-Demand Sandbox"
    },
    "event": {
        "action": "user_release_none",
        "ingested": "2021-11-19T14:40:07.263592900Z",
        "original": "{\"senderAddress\":\"\u003c\u003e\",\"recipientAddress\":\"johndoe@example.com\",\"fileName\":\"numbers.pdf\",\"fileType\":\"application\\/pdf\",\"result\":\"safe\",\"actionTriggered\":\"user release, none\",\"date\":\"2021-10-14T18:54:32+0000\",\"details\":\"Safe                                              \\r\\nTime taken: 0 hrs, 0 min, 4 sec\",\"route\":\"inbound\",\"messageId\":\"\u003c20200806044148.F35F813B435@mail.brianjthronton.com\u003e\",\"subject\":\"Important Updated Numbers from the Center for Disease Control\",\"fileHash\":\"eaeef09b60a59b913e9bfc0a4373e25d6182beff388957473fba517cc09345e3\",\"definition\":\"Inbound - Safe file with On-Demand Sandbox\"}",
        "created": "2021-10-14T18:54:32+0000"
    },
    "email": {
        "from": {
            "address": "\u003c\u003e"
        },
        "message_id": "\u003c20200806044148.F35F813B435@mail.brianjthronton.com\u003e",
        "attachments": {
            "hash": "eaeef09b60a59b913e9bfc0a4373e25d6182beff388957473fba517cc09345e3",
            "file": {
                "name": "numbers.pdf",
                "mime_type": "application/pdf",
                "extension": "pdf"
            }
        },
        "to": {
            "address": "johndoe@example.com"
        },
        "subject": "Important Updated Numbers from the Center for Disease Control",
        "direction": "inbound"
    },
    "tags": [
        "preserve_original_event"
    ],
    "mimecast": {
        "result": "safe",
        "details": "Safe                                              \r\nTime taken: 0 hrs, 0 min, 4 sec"
    }
}
```

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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.attachments.file.extension | Attachment file extension, excluding the leading dot. | keyword |
| email.attachments.file.mime_type | MIME type of the attachment file. | keyword |
| email.attachments.file.name | Name of the attachment file including the extension. | keyword |
| email.attachments.hash | File hash. | keyword |
| email.direction | Direction of the message based on the sending and receiving domains | keyword |
| email.from.address | Stores the from email address from the RFC5322 From - header field. | keyword |
| email.message_id | Identifier from the RFC5322 Message-ID - header field that refers to a particular version of a particular message. | wildcard |
| email.subject | A brief summary of the topic of the message | keyword |
| email.to.address | The email address(es) of the message recipient(s) | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| mimecast.actionTriggered | The action triggered for the attachment. | keyword |
| mimecast.definition | The definition. | keyword |
| mimecast.details | Detailed output of the attachment sandbox processing. | keyword |
| mimecast.fileHash | The hash of the attachment. | keyword |
| mimecast.fileName | The file name of the original attachment. | keyword |
| mimecast.fileType | The file type of the attachment. | keyword |
| mimecast.messageId | The internet message id of the email. | keyword |
| mimecast.recipientAddress | The address of the user that received the attachment. | keyword |
| mimecast.result | The result of the attachment analysis - clean, malicious, unknown, or timeout. | keyword |
| mimecast.route | The route of the original email containing the attachment, either - inbound, outbound, internal, or external. | keyword |
| mimecast.senderAddress | The sender of the attachment. | keyword |
| mimecast.subject | The subject of the email. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### TTP URL Logs

This is the `mimecast.ttp_url_logs` dataset. These logs contain Mimecast TTP attachment protection logs with the following details: the category of the URL clicked, the email address of the user who clicked the link, the url clicked, the action taken by the user if user awareness was applied, the route of the email that contained the link, the action defined by the administrator for the URL, the date that the URL was clicked, url scan result, the action that was taken for the click, the description of the definition that triggered the URL to be rewritten by Mimecast, the action requested by the user, an array of components of the message where the URL was found. More about these logs [here](https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-url-logs/). 

An example event for `ttp_url` looks as following:

```json
{
    "rule": {
        "name": "Inbound URL 'Aggressive'"
    },
    "source": {
        "ip": "8.8.8.8"
    },
    "url": {
        "original": "https://click.emailinfo2.bestbuy.com/?qs=5c47c91aeb44fac857370c26ddf09c3f484431e1ccfa636fc64e26e40dd87efdb43d4deeeab8c2e727ebfa079e8cf1404c095c511152e4b09e7d00bf8377f32d"
    },
    "tags": [
        "preserve_original_event"
    ],
    "@timestamp": "2021-10-16T14:45:34.000Z",
    "ecs": {
        "version": "1.12.0"
    },
    "related": {
        "user": [
            "johndoe",
            "johndoe@example.com"
        ],
        "ip": [
            "8.8.8.8"
        ]
    },
    "event": {
        "action": "Continue",
        "ingested": "2021-11-24T14:39:10.084705200Z",
        "original": "{\"userEmailAddress\": \"johndoe@example.com\", \"fromUserEmailAddress\": \"bestbuyinfo@emailinfo.bestbuy.com\", \"url\": \"https://click.emailinfo2.bestbuy.com/?qs=5c47c91aeb44fac857370c26ddf09c3f484431e1ccfa636fc64e26e40dd87efdb43d4deeeab8c2e727ebfa079e8cf1404c095c511152e4b09e7d00bf8377f32d\", \"ttpDefinition\": \"Inbound URL 'Aggressive'\", \"subject\": \"Today only: Save $100 on Tineco Pure One S12 smart cordless stick vacuum, plus more.\", \"action\": \"allow\", \"adminOverride\": \"N/A\", \"userOverride\": \"None\", \"scanResult\": \"clean\", \"category\": \"Business\", \"sendingIp\": \"8.8.8.8\", \"userAwarenessAction\": \"Continue\", \"date\": \"2021-10-16T14:45:34+0000\", \"actions\": \"Allow\", \"route\": \"inbound\", \"creationMethod\": \"User Click\", \"emailPartsDescription\": [ \"Body\" ], \"messageId\": \"\u003c31b43097-94f9-4f64-8e37-8ad23650c692@ind1s01mta1292.xt.local\u003e\" }",
        "created": "2021-10-16T14:45:34+0000"
    },
    "user": {
        "name": "johndoe",
        "email": "johndoe@example.com",
        "domain": "example.com"
    },
    "email": {
        "message_id": "\u003c31b43097-94f9-4f64-8e37-8ad23650c692@ind1s01mta1292.xt.local\u003e",
        "from": {
            "address": "bestbuyinfo@emailinfo.bestbuy.com"
        },
        "subject": "Today only: Save $100 on Tineco Pure One S12 smart cordless stick vacuum, plus more.",
        "direction": "inbound"
    },
    "mimecast": {
        "userOverride": "None",
        "action": "allow",
        "adminOverride": "N/A",
        "scanResult": "clean",
        "category": "Business",
        "actions": "Allow",
        "creationMethod": "User Click",
        "emailPartsDescription": [
            "Body"
        ]
    }
}
```

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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.direction | Direction of the message based on the sending and receiving domains | keyword |
| email.from.address | Stores the from email address from the RFC5322 From - header field. | keyword |
| email.message_id | Identifier from the RFC5322 Message-ID - header field that refers to a particular version of a particular message. | wildcard |
| email.subject | A brief summary of the topic of the message | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| mimecast.action | The action that was taken for the click. | keyword |
| mimecast.actions | The actions that were taken. | keyword |
| mimecast.adminOverride | The action defined by the administrator for the URL. | keyword |
| mimecast.category | The category of the URL clicked. | keyword |
| mimecast.creationMethod | The description how event occurred. | keyword |
| mimecast.emailPartsDescription | An array of components of the messge where the URL was found. | keyword |
| mimecast.fromUserEmailAddress | The email of user who triggers the event. | keyword |
| mimecast.messageId | The message-id value of the message. | keyword |
| mimecast.route | The route of the email that contained the link. | keyword |
| mimecast.scanResult | The result of the URL scan. | keyword |
| mimecast.sendingIP | The IP of user who triggers the event. | keyword |
| mimecast.subject | The subject of the email. | keyword |
| mimecast.ttpDefinition | The description of the definition that triggered the URL to be rewritten by Mimecast. | keyword |
| mimecast.url | The url clicked. | keyword |
| mimecast.userAwarenessAction | The action taken by the user if user awareness was applied. | keyword |
| mimecast.userEmailAddress | The email address of the user who clicked the link. | keyword |
| mimecast.userOverride | The action requested by the user. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.name | Short name or login of the user. | keyword |


### Threat Intel Feed Malware: Customer

This is the `mimecast.threat_intel_malware_customer` dataset. These logs contain information about messages that return identified malware threats at a customer level. More about these logs [here](https://integrations.mimecast.com/documentation/endpoint-reference/threat-intel/get-feed/). 

An example event for `threat_intel_malware_customer` looks as following:

```json
{
    "@timestamp": "2021-10-29T15:07:26.653Z",
    "ecs": {
        "version": "1.12"
    },
    "related": {
        "hash": "c20d551424f2df6312f7fa700ed97cd199c3d5c8a0f4dfd683627f18913096de"
    },
    "threat": {
        "indicator": {
            "first_seen": "2021-10-29T15:07:26.653Z",
            "file": {
                "hash": {
                    "sha256": "c20d551424f2df6312f7fa700ed97cd199c3d5c8a0f4dfd683627f18913096de"
                }
            },
            "modified_at": "2021-10-29T15:07:26.653Z",
            "type": "file"
        }
    },
    "event": {
        "ingested": "2021-11-17T13:42:34.324885300Z",
        "original": "{ \"Content-Disposition\":\"attachment; filename=\\\"malware_customer_stix_20211028161801144.stix\\\"\",\"type\": \"indicator\", \"id\": \"indicator--18c62174-0d31-4653-afe6-d104c57b6b2c\", \"created\": \"2021-10-29T15:07:26.653Z\", \"modified\": \"2021-10-29T15:07:26.653Z\", \"labels\": [ \"malicious-activity\" ], \"pattern\": \"[file:hashes.'SHA-256' = 'c20d551424f2df6312f7fa700ed97cd199c3d5c8a0f4dfd683627f18913096de']\", \"valid_from\": \"2021-10-29T15:07:26.653Z\" }",
        "category": "threat",
        "type": "indicator",
        "kind": "enrichment"
    },
    "tags": [
        "preserve_original_event",
        "malicious-activity"
    ],
    "mimecast": {
        "pattern": "[file:hashes.'SHA-256' = 'c20d551424f2df6312f7fa700ed97cd199c3d5c8a0f4dfd683627f18913096de']",
        "log_type": "malware_customer",
        "id": "indicator--18c62174-0d31-4653-afe6-d104c57b6b2c",
        "type": "indicator",
        "labels": [
            "malicious-activity"
        ]
    }
}
```

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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| mimecast.created | When the indicator was last created. | date |
| mimecast.hashtype | The hash type. | keyword |
| mimecast.id | The ID of the indicator. | keyword |
| mimecast.labels | The labels related to the indicator. | keyword |
| mimecast.log_type | String to get type of Threat intel feed. | keyword |
| mimecast.modified | When the indicator was last modified. | date |
| mimecast.name | Name of the file. | keyword |
| mimecast.pattern | The pattern. | keyword |
| mimecast.relationship_type | Type of the relationship. | keyword |
| mimecast.source_ref | Source of the reference. | keyword |
| mimecast.target_ref | Reference target. | keyword |
| mimecast.type | The indicator type, can for example be "domain, email, FileHash-SHA256". | keyword |
| mimecast.valid_from | The valid from date. | date |
| mimecast.value | The value of the indicator. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. Recommended values:   \* autonomous-system   \* artifact   \* directory   \* domain-name   \* email-addr   \* file   \* ipv4-addr   \* ipv6-addr   \* mac-addr   \* mutex   \* port   \* process   \* software   \* url   \* user-account   \* windows-registry-key   \* x509-certificate | keyword |


### Threat Intel Feed Malware: Grid

This is the `mimecast.threat_intel_malware_grid` dataset. These logs contain information about messages that return identified malware threats at a regional grid level. More about these logs [here](https://integrations.mimecast.com/documentation/endpoint-reference/threat-intel/get-feed/). 

An example event for `threat_intel_malware_grid` looks as following:

```json
{
    "@timestamp": "2021-10-29T15:07:26.653Z",
    "ecs": {
        "version": "1.12"
    },
    "related": {
        "hash": "c20d551424f2df6312f7fa700ed97cd199c3d5c8a0f4dfd683627f18913096de"
    },
    "threat": {
        "indicator": {
            "first_seen": "2021-10-29T15:07:26.653Z",
            "file": {
                "hash": {
                    "sha256": "c20d551424f2df6312f7fa700ed97cd199c3d5c8a0f4dfd683627f18913096de"
                }
            },
            "modified_at": "2021-10-29T15:07:26.653Z",
            "type": "file"
        }
    },
    "event": {
        "ingested": "2021-11-17T13:42:35.248902200Z",
        "original": "{ \"Content-Disposition\":\"attachment; filename=\\\"malware_grid_stix_20211028161801144.stix\\\"\",\"type\": \"indicator\", \"id\": \"indicator--18c62174-0d31-4653-afe6-d104c57b6b2c\", \"created\": \"2021-10-29T15:07:26.653Z\", \"modified\": \"2021-10-29T15:07:26.653Z\", \"labels\": [ \"malicious-activity\" ], \"pattern\": \"[file:hashes.'SHA-256' = 'c20d551424f2df6312f7fa700ed97cd199c3d5c8a0f4dfd683627f18913096de']\", \"valid_from\": \"2021-10-29T15:07:26.653Z\" }",
        "category": "threat",
        "kind": "enrichment"
    },
    "tags": [
        "preserve_original_event",
        "malicious-activity"
    ],
    "mimecast": {
        "pattern": "[file:hashes.'SHA-256' = 'c20d551424f2df6312f7fa700ed97cd199c3d5c8a0f4dfd683627f18913096de']",
        "log_type": "malware_grid",
        "id": "indicator--18c62174-0d31-4653-afe6-d104c57b6b2c",
        "type": "indicator",
        "labels": [
            "malicious-activity"
        ]
    }
}
```

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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| mimecast.created | When the indicator was last created. | date |
| mimecast.hashtype | The hash type. | keyword |
| mimecast.id | The ID of the indicator. | keyword |
| mimecast.labels | The labels related to the indicator. | keyword |
| mimecast.log_type | String to get type of Threat intel feed. | keyword |
| mimecast.modified | When the indicator was last modified. | date |
| mimecast.name | Name of the file. | keyword |
| mimecast.pattern | The pattern. | keyword |
| mimecast.relationship_type | Type of the relationship. | keyword |
| mimecast.source_ref | Source of the reference. | keyword |
| mimecast.target_ref | Reference target. | keyword |
| mimecast.type | The indicator type, can for example be "domain, email, FileHash-SHA256". | keyword |
| mimecast.valid_from | The valid from date. | date |
| mimecast.value | The value of the indicator. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. Recommended values:   \* autonomous-system   \* artifact   \* directory   \* domain-name   \* email-addr   \* file   \* ipv4-addr   \* ipv6-addr   \* mac-addr   \* mutex   \* port   \* process   \* software   \* url   \* user-account   \* windows-registry-key   \* x509-certificate | keyword |
