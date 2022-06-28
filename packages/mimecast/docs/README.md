# Mimecast Integration

The Mimecast integration collects events from the Mimecast API.

## Configuration

Authorization parameters for the Mimecast API (`Application Key`, `Application
ID`, `Access Key`, and `Secret Key`) should be provided by a Mimecast
representative for this integration. Under `Advanced options` you can set the
time interval between two API requests as well as the API URL. A Mimecast
representative should also be able to give you this information in case you need
to change the defaults.

Note that rate limit quotas may require you to set up different credentials for
the different available log types.

## Logs

### Audit Events

This is the `mimecast.audit_events` dataset. These logs contain Mimecast audit
events with the following details: audit type, event category, and detailed
information about the event. More information about these logs [here]
(https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-audit-events/).

An example event for `audit_events` looks as following:

```json
{
    "@timestamp": "2021-11-16T12:01:37.000Z",
    "agent": {
        "ephemeral_id": "a52ffcd4-9b76-4efd-bc6d-4afebe1b20d6",
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "mimecast.audit_events",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "action": "search-action",
        "agent_id_status": "verified",
        "created": "2022-05-09T10:21:38.573Z",
        "dataset": "mimecast.audit_events",
        "id": "eNqrVipOTS4tSs1MUbJSSg_xMDJPNkisSDdISQ00j0gzz44wDAtL89c2DXZ1C3eP9AyvijKL9I7Rd_WOzC0ztMg2dzFM1M73s6w09CqoDA1T0lFKLE3JLMnJTwcZaGxoaWFsYmhkoaOUXFpckp-bWpScn5IKtMnZxMzR3BSovCy1qDgzP0_JyrAWAAjKK1o",
        "ingested": "2022-05-09T10:21:39Z",
        "original": "{\"auditType\":\"Search Action\",\"category\":\"case_review_logs\",\"eventInfo\":\"Inspected Review Set Messages - Source: Review Set - Supervision - hot words, Case - GDPR/CCPA, Message Status: Pending, Date: 2021-11-16, Time: 12:01:37+0000, IP: 8.8.8.8, Application: mimecast-case-review\",\"eventTime\":\"2021-11-16T12:01:37+0000\",\"id\":\"eNqrVipOTS4tSs1MUbJSSg_xMDJPNkisSDdISQ00j0gzz44wDAtL89c2DXZ1C3eP9AyvijKL9I7Rd_WOzC0ztMg2dzFM1M73s6w09CqoDA1T0lFKLE3JLMnJTwcZaGxoaWFsYmhkoaOUXFpckp-bWpScn5IKtMnZxMzR3BSovCy1qDgzP0_JyrAWAAjKK1o\",\"user\":\"johndoe@example.com\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "mimecast": {
        "category": "case_review_logs",
        "eventInfo": "Inspected Review Set Messages - Source: Review Set - Supervision - hot words, Case - GDPR/CCPA, Message Status: Pending, Date: 2021-11-16, Time: 12:01:37+0000, IP: 8.8.8.8, Application: mimecast-case-review"
    },
    "related": {
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
| client.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| client.as.organization.name | Organization name. | keyword |
| client.as.organization.name.text | Multi-field of `client.as.organization.name`. | match_only_text |
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
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.origination_timestamp | The date and time the email message was composed. Many email clients will fill in this value automatically when the message is sent by a user. | date |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| mimecast.2FA | Info about two-factor authentication. | keyword |
| mimecast.application | The Mimecast unique id of the event. | keyword |
| mimecast.category | The category of the event. | keyword |
| mimecast.email.address | Email address from event info. | keyword |
| mimecast.email.metadata | The email meta data from audit info. | keyword |
| mimecast.eventInfo | The detailed event information. | keyword |
| mimecast.method | Method which triggers audit events. | keyword |
| mimecast.remote | Info about remote IP trying to access the API. | keyword |
| mimecast.remote_ip | Remote IP. | ip |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


### DLP Logs

This is the `mimecast.dlp_logs` dataset. These logs contain information about
messages that triggered a DLP or Content Examination policy. More information
about these logs [here]
(https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-dlp-logs/).

An example event for `dlp` looks as following:

```json
{
    "@timestamp": "2021-11-18T21:41:18.000Z",
    "agent": {
        "ephemeral_id": "0461fb9e-2359-4960-9036-461e4763582d",
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "mimecast.dlp_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "snapshot": false,
        "version": "8.2.0"
    },
    "email": {
        "direction": "inbound",
        "from": {
            "address": [
                "\u003c\u003e"
            ]
        },
        "message_id": "\u003c20211118214115.B346F10021D@mail.emailsec.ninja\u003e",
        "subject": "Undelivered Mail Returned to Sender",
        "to": {
            "address": [
                "johndoe@example.com"
            ]
        }
    },
    "event": {
        "action": "notification",
        "agent_id_status": "verified",
        "created": "2021-11-18T21:41:18+0000",
        "dataset": "mimecast.dlp_logs",
        "ingested": "2022-05-09T10:22:29Z",
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
| email.direction | The direction of the message based on the sending and receiving domains. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.message_id | Identifier from the RFC 5322 `Message-ID:` email header that refers to a particular email message. | wildcard |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| rule.name | The name of the rule or signature generating the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### SIEM Logs

This is the `mimecast.siem_logs` dataset. These logs contain information about
messages that contains MTA (message transfer agent) log – all inbound,
outbound, and internal messages. More about these logs
[here](https://integrations.mimecast.com/documentation/tutorials/understanding-siem-logs/).

An example event for `siem` looks as following:

```json
{
    "@timestamp": "2021-11-12T12:15:46.000Z",
    "agent": {
        "ephemeral_id": "d683003b-9e59-4e3d-91fe-3b3411c5946f",
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "mimecast.siem_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "snapshot": false,
        "version": "8.2.0"
    },
    "email": {
        "direction": "internal",
        "from": {
            "address": [
                "johndoe@example.com"
            ]
        },
        "local_id": "fjihpfEgM_iRwemxhe3t_w",
        "to": {
            "address": "o365_service_account@example.com"
        }
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2021-11-12T12:15:46+0000",
        "dataset": "mimecast.siem_logs",
        "ingested": "2022-05-09T10:23:21Z",
        "original": "{\"Content-Disposition\":\"attachment; filename=\\\"jrnl_20211018093329655.json\\\"\",\"Dir\":\"Internal\",\"Rcpt\":\"o365_service_account@example.com\",\"RcptActType\":\"Jnl\",\"RcptHdrType\":\"Unknown\",\"Sender\":\"johndoe@example.com\",\"aCode\":\"fjihpfEgM_iRwemxhe3t_w\",\"acc\":\"ABC123\",\"datetime\":\"2021-11-12T12:15:46+0000\"}",
        "outcome": "unknown"
    },
    "input": {
        "type": "httpjson"
    },
    "mimecast": {
        "RcptActType": "Jnl",
        "RcptHdrType": "Unknown",
        "acc": "ABC123",
        "log_type": "jrnl"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-siem-logs"
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
| email.attachments.file.extension | Attachment file extension, excluding the leading dot. | keyword |
| email.attachments.file.hash.md5 | MD5 hash. | keyword |
| email.attachments.file.hash.sha1 | SHA1 hash. | keyword |
| email.attachments.file.hash.sha256 | SHA256 hash. | keyword |
| email.attachments.file.mime_type | The MIME media type of the attachment. This value will typically be extracted from the `Content-Type` MIME header field. | keyword |
| email.attachments.file.name | Name of the attachment file including the file extension. | keyword |
| email.attachments.file.size | Attachment file size in bytes. | long |
| email.direction | The direction of the message based on the sending and receiving domains. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.local_id | Unique identifier given to the email by the source that created the event. Identifier is not persistent across hops. | keyword |
| email.message_id | Identifier from the RFC 5322 `Message-ID:` email header that refers to a particular email message. | wildcard |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | match_only_text |
| error.type | The type of the error, for example the class name of the exception. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
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
| mimecast.Route | Email route. | keyword |
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
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.established | Boolean flag indicating if the TLS negotiation was successful and transitioned to an encrypted tunnel. | boolean |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| user.email | User email address. | keyword |


### Threat Intel Feed Malware: Customer

This is the `mimecast.threat_intel_malware_customer` dataset. These logs contain
information about messages that return identified malware threats at a customer
level. More about these logs
[here](https://integrations.mimecast.com/documentation/endpoint-reference/threat-intel/get-feed/).

An example event for `threat_intel_malware_customer` looks as following:

```json
{
    "@timestamp": "2021-11-19T01:28:37.099Z",
    "agent": {
        "ephemeral_id": "11e300ff-bc6a-4674-9452-d4fb167b7d59",
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "mimecast.threat_intel_malware_customer",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "threat",
        "created": "2022-05-09T10:24:11.849Z",
        "dataset": "mimecast.threat_intel_malware_customer",
        "ingested": "2022-05-09T10:24:12Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2021-11-19T01:28:37.099Z\",\"id\":\"indicator--456ac916-4c4e-43be-b7a9-6678f6a845cd\",\"labels\":[\"malicious-activity\"],\"modified\":\"2021-11-19T01:28:37.099Z\",\"pattern\":\"[file:hashes.'SHA-256' = 'ec5a6c52acdc187fc6c1187f14cd685c686c2b283503a023c4a9d3a977b491be']\",\"type\":\"indicator\",\"valid_from\":\"2021-11-19T01:28:37.099Z\"}",
        "type": "indicator"
    },
    "input": {
        "type": "httpjson"
    },
    "mimecast": {
        "id": "indicator--456ac916-4c4e-43be-b7a9-6678f6a845cd",
        "labels": [
            "malicious-activity"
        ],
        "pattern": "[file:hashes.'SHA-256' = 'ec5a6c52acdc187fc6c1187f14cd685c686c2b283503a023c4a9d3a977b491be']",
        "type": "indicator"
    },
    "related": {
        "hash": [
            "ec5a6c52acdc187fc6c1187f14cd685c686c2b283503a023c4a9d3a977b491be"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-threat-intel-feed-malware-customer",
        "malicious-activity"
    ],
    "threat": {
        "indicator": {
            "file": {
                "hash": {
                    "sha256": "ec5a6c52acdc187fc6c1187f14cd685c686c2b283503a023c4a9d3a977b491be"
                }
            },
            "first_seen": "2021-11-19T01:28:37.099Z",
            "modified_at": "2021-11-19T01:28:37.099Z",
            "type": "file"
        }
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
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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

This is the `mimecast.threat_intel_malware_grid` dataset. These logs contain
information about messages that return identified malware threats at a regional
grid level. More about these logs
[here](https://integrations.mimecast.com/documentation/endpoint-reference/threat-intel/get-feed/).

An example event for `threat_intel_malware_grid` looks as following:

```json
{
    "@timestamp": "2021-11-19T01:28:37.099Z",
    "agent": {
        "ephemeral_id": "d4b2c0c8-5d78-4482-9e6b-4b5a6d55e652",
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "mimecast.threat_intel_malware_grid",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "threat",
        "created": "2022-05-09T10:25:08.535Z",
        "dataset": "mimecast.threat_intel_malware_grid",
        "ingested": "2022-05-09T10:25:09Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2021-11-19T01:28:37.099Z\",\"id\":\"indicator--456ac916-4c4e-43be-b7a9-6678f6a845cd\",\"labels\":[\"malicious-activity\"],\"modified\":\"2021-11-19T01:28:37.099Z\",\"pattern\":\"[file:hashes.'SHA-256' = 'ec5a6c52acdc187fc6c1187f14cd685c686c2b283503a023c4a9d3a977b491be']\",\"type\":\"indicator\",\"valid_from\":\"2021-11-19T01:28:37.099Z\"}",
        "type": "indicator"
    },
    "input": {
        "type": "httpjson"
    },
    "mimecast": {
        "id": "indicator--456ac916-4c4e-43be-b7a9-6678f6a845cd",
        "labels": [
            "malicious-activity"
        ],
        "pattern": "[file:hashes.'SHA-256' = 'ec5a6c52acdc187fc6c1187f14cd685c686c2b283503a023c4a9d3a977b491be']",
        "type": "indicator"
    },
    "related": {
        "hash": [
            "ec5a6c52acdc187fc6c1187f14cd685c686c2b283503a023c4a9d3a977b491be"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-threat-intel-feed-malware-grid",
        "malicious-activity"
    ],
    "threat": {
        "indicator": {
            "file": {
                "hash": {
                    "sha256": "ec5a6c52acdc187fc6c1187f14cd685c686c2b283503a023c4a9d3a977b491be"
                }
            },
            "first_seen": "2021-11-19T01:28:37.099Z",
            "modified_at": "2021-11-19T01:28:37.099Z",
            "type": "file"
        }
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
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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


### TTP Attachment Logs

This is the `mimecast.ttp_ap_logs` dataset. These logs contain Mimecast TTP
attachment protection logs with the following details: result of attachment
analysis (if it is malicious or not etc.), date when file is released, sender
and recipient address, filename and type, action triggered for the attachment,
the route of the original email containing the attachment and details. Learn
more about these logs [here]
(https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-attachment-protection-logs/).

An example event for `ttp_ap` looks as following:

```json
{
    "@timestamp": "2021-11-24T11:54:27.000Z",
    "agent": {
        "ephemeral_id": "04641c23-428a-4181-9f85-c2533f734177",
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "mimecast.ttp_ap_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "snapshot": false,
        "version": "8.2.0"
    },
    "email": {
        "attachments": {
            "file": {
                "extension": "pdf",
                "hash": {
                    "sha256": "cabd7cb6e1822fd9e1fc9bcf144ee26ee6bfc855c4574ca967dd53dcc36a1254"
                },
                "mime_type": "application/pdf",
                "name": "Datasheet_Mimecast Targeted Threat Protection + Internal Email Protect (2).pdf"
            }
        },
        "direction": "inbound",
        "from": {
            "address": [
                "\u003c\u003e"
            ]
        },
        "message_id": "\u003cCAKUQxhimsCd1bvWQVs14Amuh1+Hnw_bmSuA7ot8hy4eDa9_ziQ@mail.gmail.com\u003e",
        "subject": "Test Files",
        "to": {
            "address": [
                "johndoe@emample.com"
            ]
        }
    },
    "event": {
        "action": "user_release_none",
        "agent_id_status": "verified",
        "created": "2021-11-24T11:54:27+0000",
        "dataset": "mimecast.ttp_ap_logs",
        "ingested": "2022-05-09T10:26:02Z",
        "original": "{\"actionTriggered\":\"user release, none\",\"date\":\"2021-11-24T11:54:27+0000\",\"definition\":\"Inbound - Safe file with On-Demand Sandbox\",\"details\":\"Safe                                              \\r\\nTime taken: 0 hrs, 0 min, 7 sec\",\"fileHash\":\"cabd7cb6e1822fd9e1fc9bcf144ee26ee6bfc855c4574ca967dd53dcc36a1254\",\"fileName\":\"Datasheet_Mimecast Targeted Threat Protection + Internal Email Protect (2).pdf\",\"fileType\":\"application/pdf\",\"messageId\":\"\\u003cCAKUQxhimsCd1bvWQVs14Amuh1+Hnw_bmSuA7ot8hy4eDa9_ziQ@mail.gmail.com\\u003e\",\"recipientAddress\":\"johndoe@emample.com\",\"result\":\"safe\",\"route\":\"inbound\",\"senderAddress\":\"\\u003c\\u003e\",\"subject\":\"Test Files\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "mimecast": {
        "details": "Safe                                              \r\nTime taken: 0 hrs, 0 min, 7 sec",
        "result": "safe"
    },
    "related": {
        "hash": [
            "cabd7cb6e1822fd9e1fc9bcf144ee26ee6bfc855c4574ca967dd53dcc36a1254"
        ]
    },
    "rule": {
        "name": "Inbound - Safe file with On-Demand Sandbox"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-ttp-ap"
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
| email.attachments.file.extension | Attachment file extension, excluding the leading dot. | keyword |
| email.attachments.file.hash.sha256 | SHA256 hash. | keyword |
| email.attachments.file.mime_type | The MIME media type of the attachment. This value will typically be extracted from the `Content-Type` MIME header field. | keyword |
| email.attachments.file.name | Name of the attachment file including the file extension. | keyword |
| email.direction | The direction of the message based on the sending and receiving domains. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.message_id | Identifier from the RFC 5322 `Message-ID:` email header that refers to a particular email message. | wildcard |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
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


### TTP Impersonation Logs

This is the `mimecast.ttp_ip_logs` dataset. These logs contain information about
messages containing information flagged by an Impersonation Protection
configuration. Learn more about these logs [here]
(https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-impersonation-protect-logs/).

An example event for `ttp_ip` looks as following:

```json
{
    "@timestamp": "2021-11-12T15:27:04.000Z",
    "agent": {
        "ephemeral_id": "e8d74ee7-38ba-4ce5-ae3a-035bfeb01d97",
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "mimecast.ttp_ip_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "snapshot": false,
        "version": "8.2.0"
    },
    "email": {
        "from": {
            "address": [
                "johndoe@example.com"
            ]
        },
        "message_id": "\u003cMN2PR16MB2719879CA4DB60C265F7FD8FB0959@MN2PR16MB2719.namprd16.prod.outlook.com\u003e",
        "subject": "Don't read, just fill out!",
        "to": {
            "address": [
                "johndoe@example.com"
            ]
        }
    },
    "event": {
        "action": "none",
        "agent_id_status": "verified",
        "created": "2021-11-12T15:27:04+0000",
        "dataset": "mimecast.ttp_ip_logs",
        "id": "MTOKEN:eNqrVkouLS7Jz00tSs5PSVWyUnI2MXM0N1XSUcpMUbIyMjM3MzAw0FEqSy0qzszPU7Iy1FEqyQMrNDAwV6oFAGMiEg8",
        "ingested": "2022-05-09T10:26:50Z",
        "original": "{\"action\":\"none\",\"definition\":\"IP - 1 hit (Tag email)\",\"eventTime\":\"2021-11-12T15:27:04+0000\",\"hits\":1,\"id\":\"MTOKEN:eNqrVkouLS7Jz00tSs5PSVWyUnI2MXM0N1XSUcpMUbIyMjM3MzAw0FEqSy0qzszPU7Iy1FEqyQMrNDAwV6oFAGMiEg8\",\"identifiers\":[\"internal_user_name\"],\"impersonationResults\":[{\"checkerResult\":\"hit\",\"impersonationDomainSource\":\"internal_user_name\",\"similarDomain\":\"John Doe \\u003cjohndoe_cdw@example.com\\u003e\",\"stringSimilarToDomain\":\"John Doe\"}],\"messageId\":\"\\u003cMN2PR16MB2719879CA4DB60C265F7FD8FB0959@MN2PR16MB2719.namprd16.prod.outlook.com\\u003e\",\"recipientAddress\":\"johndoe@example.com\",\"senderAddress\":\"johndoe@example.com\",\"senderIpAddress\":\"8.8.8.8\",\"subject\":\"Don't read, just fill out!\",\"taggedExternal\":false,\"taggedMalicious\":true}"
    },
    "input": {
        "type": "httpjson"
    },
    "mimecast": {
        "hits": 1,
        "identifiers": [
            "internal_user_name"
        ],
        "impersonationResults": [
            {
                "checkerResult": "hit",
                "impersonationDomainSource": "internal_user_name",
                "similarDomain": "John Doe \u003cjohndoe_cdw@example.com\u003e",
                "stringSimilarToDomain": "John Doe"
            }
        ],
        "taggedExternal": false,
        "taggedMalicious": true
    },
    "related": {
        "ip": [
            "8.8.8.8"
        ]
    },
    "rule": {
        "name": "IP - 1 hit (Tag email)"
    },
    "source": {
        "ip": "8.8.8.8"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-ttp-ip"
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
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.message_id | Identifier from the RFC 5322 `Message-ID:` email header that refers to a particular email message. | wildcard |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
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
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |


### TTP URL Logs

This is the `mimecast.ttp_url_logs` dataset. These logs contain Mimecast TTP
attachment protection logs with the following details: the category of the URL
clicked, the email address of the user who clicked the link, the url clicked,
the action taken by the user if user awareness was applied, the route of the
email that contained the link, the action defined by the administrator for the
URL, the date that the URL was clicked, url scan result, the action that was
taken for the click, the description of the definition that triggered the URL to
be rewritten by Mimecast, the action requested by the user, an array of
components of the message where the URL was found. More about these logs
[here](https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-url-logs/).

An example event for `ttp_url` looks as following:

```json
{
    "@timestamp": "2021-11-10T03:49:53.000Z",
    "agent": {
        "ephemeral_id": "fbfd6110-bdd7-4230-b13b-4768be6ad132",
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "mimecast.ttp_url_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "2f28c80b-ffde-4202-a4bd-938a8ce174ad",
        "snapshot": false,
        "version": "8.2.0"
    },
    "email": {
        "direction": "inbound",
        "from": {
            "address": [
                "googlealerts-noreply@google.com"
            ]
        },
        "message_id": "\u003c000000000000a02a0a05d0671c06@google.com\u003e",
        "subject": "Google Alert - china",
        "to": {
            "address": [
                "johndoe@example.com"
            ]
        }
    },
    "event": {
        "action": "Continue",
        "agent_id_status": "verified",
        "created": "2021-11-10T03:49:53+0000",
        "dataset": "mimecast.ttp_url_logs",
        "ingested": "2022-05-09T10:27:40Z",
        "original": "{\"action\":\"allow\",\"actions\":\"Allow\",\"adminOverride\":\"N/A\",\"category\":\"Search Engines \\u0026 Portals\",\"creationMethod\":\"User Click\",\"date\":\"2021-11-10T03:49:53+0000\",\"emailPartsDescription\":[\"Body\"],\"fromUserEmailAddress\":\"googlealerts-noreply@google.com\",\"messageId\":\"\\u003c000000000000a02a0a05d0671c06@google.com\\u003e\",\"route\":\"inbound\",\"scanResult\":\"clean\",\"sendingIp\":\"8.8.8.8\",\"subject\":\"Google Alert - china\",\"ttpDefinition\":\"Inbound URL 'Aggressive'\",\"url\":\"https://www.google.co.za/alerts/share?hl=en\\u0026gl=US\\u0026ru=https://www.wsj.com/articles/u-s-tests-israels-iron-dome-in-guam-as-defense-against-chinese-cruise-missiles-11636455224\\u0026ss=tw\\u0026rt=U.S.+Tests+Israel%27s+Iron+Dome+in+Guam+as+Defense+Against+Chinese+Cruise+Missiles+-+WSJ\\u0026cd=KhQxNzg2NTc5NDQ3ODIzODUyNjI5NzIcZmQ4N2VjYzkxMGIxMWE4Yzpjby56YTplbjpVUw\\u0026ssp=AMJHsmW3CCK1S4TNPifSXszcyaNMwd6TDg\",\"userAwarenessAction\":\"Continue\",\"userEmailAddress\":\"johndoe@example.com\",\"userOverride\":\"None\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "mimecast": {
        "action": "allow",
        "actions": "Allow",
        "adminOverride": "N/A",
        "category": "Search Engines \u0026 Portals",
        "creationMethod": "User Click",
        "emailPartsDescription": [
            "Body"
        ],
        "scanResult": "clean",
        "userOverride": "None"
    },
    "related": {
        "ip": [
            "8.8.8.8"
        ],
        "user": [
            "johndoe@example.com"
        ]
    },
    "rule": {
        "name": "Inbound URL 'Aggressive'"
    },
    "source": {
        "ip": "8.8.8.8"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-ttp-url"
    ],
    "url": {
        "original": "https://www.google.co.za/alerts/share?hl=en\u0026gl=US\u0026ru=https://www.wsj.com/articles/u-s-tests-israels-iron-dome-in-guam-as-defense-against-chinese-cruise-missiles-11636455224\u0026ss=tw\u0026rt=U.S.+Tests+Israel%27s+Iron+Dome+in+Guam+as+Defense+Against+Chinese+Cruise+Missiles+-+WSJ\u0026cd=KhQxNzg2NTc5NDQ3ODIzODUyNjI5NzIcZmQ4N2VjYzkxMGIxMWE4Yzpjby56YTplbjpVUw\u0026ssp=AMJHsmW3CCK1S4TNPifSXszcyaNMwd6TDg"
    },
    "user": {
        "email": [
            "johndoe@example.com"
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
| email.direction | The direction of the message based on the sending and receiving domains. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.message_id | Identifier from the RFC 5322 `Message-ID:` email header that refers to a particular email message. | wildcard |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
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
| url.original.text | Multi-field of `url.original`. | match_only_text |
| user.email | User email address. | keyword |

