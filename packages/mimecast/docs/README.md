# Mimecast Integration

The Mimecast integration collects events from the [Mimecast API](https://integrations.mimecast.com/documentation/).

## Configuration

Authorization parameters for the Mimecast API (`Application Key`, `Application
ID`, `Access Key`, and `Secret Key`) should be provided by a Mimecast
representative for this integration. Under `Advanced options` you can set the
time interval between two API requests as well as the API URL. A Mimecast
representative should also be able to give you this information in case you need
to change the defaults.

> Note: Rate limit quotas may require you to set up different credentials for the different available log types.

## Logs

### Archive Search Logs

This is the `mimecast.archive_search_logs` dataset. These logs contain Mimecast archive
search logs with the following details: search source, description and detailed
information about the search performed. More information about these logs is available [here](
https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-archive-search-logs/).

An example event for `archive_search` looks as following:

```json
{
    "@timestamp": "2021-03-18T18:35:49.000Z",
    "agent": {
        "ephemeral_id": "33b422bb-ff57-4039-80c8-23c64e5f54d7",
        "id": "5e5700e6-bb04-40f9-b6fc-e5adb94ec6b5",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "mimecast.archive_search_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f81bb806-77be-4e89-9f08-d426b37fd611",
        "snapshot": false,
        "version": "8.8.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "created": "2021-03-18T18:35:49.000Z",
        "dataset": "mimecast.archive_search_logs",
        "ingested": "2023-09-11T06:48:05Z",
        "kind": "event",
        "original": "{\"createTime\":\"2021-03-18T18:35:49+0000\",\"description\":\"Message Tracking Search\",\"emailAddr\":\"admin_dhamilton@hapi1.hamilton321.net\",\"searchReason\":\"\",\"searchText\":\"\",\"source\":\"archive\"}",
        "type": [
            "admin"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "mimecast": {
        "search_details": {
            "description": "Message Tracking Search",
            "source": "archive"
        }
    },
    "related": {
        "user": [
            "admin_dhamilton",
            "admin_dhamilton@hapi1.hamilton321.net"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-archive-search-logs"
    ],
    "user": {
        "domain": "hapi1.hamilton321.net",
        "email": "admin_dhamilton@hapi1.hamilton321.net",
        "name": "admin_dhamilton"
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
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| mimecast.email.address | The email address of the user who performed the search. | keyword |
| mimecast.search_details.description | The description of the search if any. | keyword |
| mimecast.search_details.path | The search path if any. | keyword |
| mimecast.search_details.reason | The search reason entered when the search was executed if any. | keyword |
| mimecast.search_details.source | The search source context | keyword |
| mimecast.search_details.text | The text used in the search. | keyword |


### Audit Events

This is the `mimecast.audit_events` dataset. These logs contain Mimecast audit
events with the following details: audit type, event category and detailed
information about the event. More information about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-audit-events/).

An example event for `audit_events` looks as following:

```json
{
    "@timestamp": "2021-11-16T12:01:37.000Z",
    "agent": {
        "ephemeral_id": "6a9d8a15-f4d3-4d1f-af91-06d4e08a7d24",
        "id": "ce5d0823-b60f-46d4-9710-b48a3ed212d3",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "mimecast.audit_events",
        "namespace": "90117",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ce5d0823-b60f-46d4-9710-b48a3ed212d3",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "search-action",
        "agent_id_status": "verified",
        "created": "2024-07-02T04:21:54.038Z",
        "dataset": "mimecast.audit_events",
        "id": "eNqrVipOTS4tSs1MUbJSSg_xMDJPNkisSDdISQ00j0gzz44wDAtL89c2DXZ1C3eP9AyvijKL9I7Rd_WOzC0ztMg2dzFM1M73s6w09CqoDA1T0lFKLE3JLMnJTwcZaGxoaWFsYmhkoaOUXFpckp-bWpScn5IKtMnZxMzR3BSovCy1qDgzP0_JyrAWAAjKK2o",
        "ingested": "2024-07-02T04:22:04Z",
        "original": "{\"auditType\":\"Search Action\",\"category\":\"case_review_logs\",\"eventInfo\":\"Inspected Review Set Messages - Source: Review Set - Supervision - hot words, Case - GDPR/CCPA, Message Status: Pending, Date: 2021-11-16, Time: 12:01:37+0000, IP: 8.8.8.8, Application: mimecast-case-review\",\"eventTime\":\"2021-11-16T12:01:37+0000\",\"id\":\"eNqrVipOTS4tSs1MUbJSSg_xMDJPNkisSDdISQ00j0gzz44wDAtL89c2DXZ1C3eP9AyvijKL9I7Rd_WOzC0ztMg2dzFM1M73s6w09CqoDA1T0lFKLE3JLMnJTwcZaGxoaWFsYmhkoaOUXFpckp-bWpScn5IKtMnZxMzR3BSovCy1qDgzP0_JyrAWAAjKK2o\",\"user\":\"johndoe@example.com\"}"
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
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
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


### DLP Logs

This is the `mimecast.dlp_logs` dataset. These logs contain information about
messages that triggered a DLP or Content Examination policy. More information
about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-dlp-logs/). 

An example event for `dlp` looks as following:

```json
{
    "@timestamp": "2021-11-18T21:41:18.000Z",
    "agent": {
        "ephemeral_id": "b3630060-e536-4953-a9b4-74f78c6ac6c1",
        "id": "c0ee214c-57e5-4a60-80ba-e4dc247eb02e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.9.0"
    },
    "data_stream": {
        "dataset": "mimecast.dlp_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c0ee214c-57e5-4a60-80ba-e4dc247eb02e",
        "snapshot": false,
        "version": "8.9.0"
    },
    "email": {
        "direction": "inbound",
        "from": {
            "address": [
                "<>"
            ]
        },
        "message_id": "<20211118214115.B346F10021D-2@mail.emailsec.ninja>",
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
        "ingested": "2023-07-27T14:57:41Z",
        "original": "{\"action\":\"notification\",\"eventTime\":\"2021-11-18T21:41:18+0000\",\"messageId\":\"\\u003c20211118214115.B346F10021D-2@mail.emailsec.ninja\\u003e\",\"policy\":\"Content Inspection - Watermark\",\"recipientAddress\":\"johndoe@example.com\",\"route\":\"inbound\",\"senderAddress\":\"\\u003c\\u003e\",\"subject\":\"Undelivered Mail Returned to Sender\"}"
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
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


### SIEM Logs

This is the `mimecast.siem_logs` dataset. These logs contain information about
messages that contains MTA (message transfer agent) log – all inbound,
outbound, and internal messages. More about [these logs](
https://integrations.mimecast.com/documentation/tutorials/understanding-siem-logs/).

An example event for `siem` looks as following:

```json
{
    "@timestamp": "2021-11-12T12:15:46.000Z",
    "agent": {
        "ephemeral_id": "9e414d8d-fe0d-4db1-a95f-aed984c0eef9",
        "id": "a26821e0-e36a-4513-a137-0df112893aba",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "mimecast.siem_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a26821e0-e36a-4513-a137-0df112893aba",
        "snapshot": false,
        "version": "8.12.1"
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
            "address": [
                "o365_service_account@example.com"
            ]
        }
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2021-11-12T12:15:46+0000",
        "dataset": "mimecast.siem_logs",
        "ingested": "2024-04-07T21:50:35Z",
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
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
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
| mimecast.MimecastIP | The source IP is one of the Mimecast' IPs e.g. Mimecast Personal Portal. | keyword |
| mimecast.MsgId | The internet message id of the email. | keyword |
| mimecast.MsgSize | The total size of the email. | long |
| mimecast.RcptActType | Action after reception. | keyword |
| mimecast.RcptHdrType | Type of the receipt header. | keyword |
| mimecast.ReceiptAck | The receipt acknowledgment message received by Mimecast from the receiving mail server. | keyword |
| mimecast.Recipient | The recipient of the original message. | keyword |
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
| mimecast.SpamProcessingDetail | The Spam processing details for DKIM, SPF, DMARC. | flattened |
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


### Threat Intel Feed Malware: Customer

This is the `mimecast.threat_intel_malware_customer` dataset. These logs contain
information about messages that return identified malware threats at a customer
level.  Learn more about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/threat-intel/get-feed/).

An example event for `threat_intel_malware_customer` looks as following:

```json
{
    "@timestamp": "2021-11-19T01:28:37.099Z",
    "agent": {
        "ephemeral_id": "1cb33560-ee01-4d6d-b63c-4d33848115e0",
        "id": "c0ee214c-57e5-4a60-80ba-e4dc247eb02e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.9.0"
    },
    "data_stream": {
        "dataset": "mimecast.threat_intel_malware_customer",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c0ee214c-57e5-4a60-80ba-e4dc247eb02e",
        "snapshot": false,
        "version": "8.9.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2023-07-27T15:00:16.307Z",
        "dataset": "mimecast.threat_intel_malware_customer",
        "ingested": "2023-07-27T15:00:17Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2021-11-19T01:28:37.099Z\",\"id\":\"indicator--456ac916-4c4e-43be-b7a9-6678f6a845cd\",\"labels\":[\"malicious-activity\"],\"modified\":\"2021-11-19T01:28:37.099Z\",\"pattern\":\"[file:hashes.'SHA-256' = 'ec5a6c52acdc187fc6c1187f14cd685c686c2b283503a023c4a9d3a977b491be']\",\"type\":\"indicator\",\"valid_from\":\"2021-11-19T01:28:37.099Z\"}",
        "type": [
            "indicator"
        ]
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
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
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


### Threat Intel Feed Malware: Grid

This is the `mimecast.threat_intel_malware_grid` dataset. These logs contain
information about messages that return identified malware threats at a regional 
grid level. More about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/threat-intel/get-feed/).

An example event for `threat_intel_malware_grid` looks as following:

```json
{
    "@timestamp": "2021-11-19T01:28:37.099Z",
    "agent": {
        "ephemeral_id": "f13ad74b-0d24-4bb8-b0f9-b72fc70a980a",
        "id": "c0ee214c-57e5-4a60-80ba-e4dc247eb02e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.9.0"
    },
    "data_stream": {
        "dataset": "mimecast.threat_intel_malware_grid",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c0ee214c-57e5-4a60-80ba-e4dc247eb02e",
        "snapshot": false,
        "version": "8.9.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2023-07-27T15:01:03.091Z",
        "dataset": "mimecast.threat_intel_malware_grid",
        "ingested": "2023-07-27T15:01:04Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2021-11-19T01:28:37.099Z\",\"id\":\"indicator--456ac916-4c4e-43be-b7a9-6678f6a845cd\",\"labels\":[\"malicious-activity\"],\"modified\":\"2021-11-19T01:28:37.099Z\",\"pattern\":\"[file:hashes.'SHA-256' = 'ec5a6c52acdc187fc6c1187f14cd685c686c2b283503a023c4a9d3a977b491be']\",\"type\":\"indicator\",\"valid_from\":\"2021-11-19T01:28:37.099Z\"}",
        "type": [
            "indicator"
        ]
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
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
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


### TTP Attachment Logs

This is the `mimecast.ttp_ap_logs` dataset. These logs contain Mimecast TTP
attachment protection logs with the following details: result of attachment
analysis (if it is malicious or not etc.), date when file is released, sender 
and recipient address, filename and type, action triggered for the attachment, 
the route of the original email containing the attachment and details. 
Learn more about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-attachment-protection-logs/).

An example event for `ttp_ap` looks as following:

```json
{
    "@timestamp": "2021-11-24T11:54:27.000Z",
    "agent": {
        "ephemeral_id": "f1e4b7e5-19a3-41bf-9ad5-c80de2f36ac9",
        "id": "c0ee214c-57e5-4a60-80ba-e4dc247eb02e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.9.0"
    },
    "data_stream": {
        "dataset": "mimecast.ttp_ap_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c0ee214c-57e5-4a60-80ba-e4dc247eb02e",
        "snapshot": false,
        "version": "8.9.0"
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
                "<>"
            ]
        },
        "message_id": "<1-CAKUQxhimsCd1bvWQVs14Amuh1+Hnw_bmSuA7ot8hy4eDa9_ziQ@mail.gmail.com>",
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
        "ingested": "2023-07-27T15:03:13Z",
        "original": "{\"actionTriggered\":\"user release, none\",\"date\":\"2021-11-24T11:54:27+0000\",\"definition\":\"Inbound - Safe file with On-Demand Sandbox\",\"details\":\"Safe\\r\\nTime taken: 0 hrs, 0 min, 7 sec\",\"fileHash\":\"cabd7cb6e1822fd9e1fc9bcf144ee26ee6bfc855c4574ca967dd53dcc36a1254\",\"fileName\":\"Datasheet_Mimecast Targeted Threat Protection + Internal Email Protect (2).pdf\",\"fileType\":\"application/pdf\",\"messageId\":\"\\u003c1-CAKUQxhimsCd1bvWQVs14Amuh1+Hnw_bmSuA7ot8hy4eDa9_ziQ@mail.gmail.com\\u003e\",\"recipientAddress\":\"johndoe@emample.com\",\"result\":\"safe\",\"route\":\"inbound\",\"senderAddress\":\"\\u003c\\u003e\",\"subject\":\"Test Files\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "mimecast": {
        "details": "Safe\r\nTime taken: 0 hrs, 0 min, 7 sec",
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
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
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


### TTP Impersonation Logs

This is the `mimecast.ttp_ip_logs` dataset. These logs contain information about
messages containing information flagged by an Impersonation Protection
configuration. Learn more about [these logs]
(https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-impersonation-protect-logs/).

An example event for `ttp_ip` looks as following:

```json
{
    "@timestamp": "2021-11-12T15:27:04.000Z",
    "agent": {
        "ephemeral_id": "2c26c85b-6378-46cd-a2b8-222d87230852",
        "id": "c0ee214c-57e5-4a60-80ba-e4dc247eb02e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.9.0"
    },
    "data_stream": {
        "dataset": "mimecast.ttp_ip_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c0ee214c-57e5-4a60-80ba-e4dc247eb02e",
        "snapshot": false,
        "version": "8.9.0"
    },
    "email": {
        "from": {
            "address": [
                "johndoe@example.com"
            ]
        },
        "message_id": "<20-MN2PR16MB2719879CA4DB60C265F7FD8FB0959@MN2PR16MB2719.namprd16.prod.outlook.com>",
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
        "ingested": "2023-07-27T15:04:20Z",
        "original": "{\"action\":\"none\",\"definition\":\"IP - 1 hit (Tag email)\",\"eventTime\":\"2021-11-12T15:27:04+0000\",\"hits\":1,\"id\":\"MTOKEN:eNqrVkouLS7Jz00tSs5PSVWyUnI2MXM0N1XSUcpMUbIyMjM3MzAw0FEqSy0qzszPU7Iy1FEqyQMrNDAwV6oFAGMiEg8\",\"identifiers\":[\"internal_user_name\"],\"impersonationResults\":[{\"checkerResult\":\"hit\",\"impersonationDomainSource\":\"internal_user_name\",\"similarDomain\":\"John Doe \\u003cjohndoe_cdw@example.com\\u003e\",\"stringSimilarToDomain\":\"John Doe\"}],\"messageId\":\"\\u003c20-MN2PR16MB2719879CA4DB60C265F7FD8FB0959@MN2PR16MB2719.namprd16.prod.outlook.com\\u003e\",\"recipientAddress\":\"johndoe@example.com\",\"senderAddress\":\"johndoe@example.com\",\"senderIpAddress\":\"8.8.8.8\",\"subject\":\"Don't read, just fill out!\",\"taggedExternal\":false,\"taggedMalicious\":true}"
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
                "similarDomain": "John Doe <johndoe_cdw@example.com>",
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
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
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


### TTP URL Logs

This is the `mimecast.ttp_url_logs` dataset. These logs contain Mimecast TTP
attachment protection logs with the following details: the category of the URL
clicked, the email address of the user who clicked the link, the url clicked,
the action taken by the user if user awareness was applied, the route of the
email that contained the link, the action defined by the administrator for the
URL, the date that the URL was clicked, url scan result, the action that was
taken for the click, the description of the definition that triggered the URL to
be rewritten by Mimecast, the action requested by the user, an array of
components of the message where the URL was found. More about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-url-logs/).

An example event for `ttp_url` looks as following:

```json
{
    "@timestamp": "2021-11-10T03:49:53.000Z",
    "agent": {
        "ephemeral_id": "ffba6f04-a3d6-4e55-8cbc-293b129d88d5",
        "id": "c0ee214c-57e5-4a60-80ba-e4dc247eb02e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.9.0"
    },
    "data_stream": {
        "dataset": "mimecast.ttp_url_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c0ee214c-57e5-4a60-80ba-e4dc247eb02e",
        "snapshot": false,
        "version": "8.9.0"
    },
    "email": {
        "direction": "inbound",
        "from": {
            "address": [
                "googlealerts-noreply@google.com"
            ]
        },
        "message_id": "<20-000000000000a02a0a05d0671c06@google.com>",
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
        "ingested": "2023-07-27T15:05:14Z",
        "original": "{\"action\":\"allow\",\"actions\":\"Allow\",\"adminOverride\":\"N/A\",\"category\":\"Search Engines \\u0026 Portals\",\"creationMethod\":\"User Click\",\"date\":\"2021-11-10T03:49:53+0000\",\"emailPartsDescription\":[\"Body\"],\"fromUserEmailAddress\":\"googlealerts-noreply@google.com\",\"messageId\":\"\\u003c20-000000000000a02a0a05d0671c06@google.com\\u003e\",\"route\":\"inbound\",\"scanResult\":\"clean\",\"sendingIp\":\"8.8.8.8\",\"subject\":\"Google Alert - china\",\"ttpDefinition\":\"Inbound URL 'Aggressive'\",\"url\":\"https://www.google.co.za/alerts/share?hl=en\\u0026gl=US\\u0026ru=https://www.wsj.com/articles/u-s-tests-israels-iron-dome-in-guam-as-defense-against-chinese-cruise-missiles-11636455224\\u0026ss=tw\\u0026rt=U.S.+Tests+Israel%27s+Iron+Dome+in+Guam+as+Defense+Against+Chinese+Cruise+Missiles+-+WSJ\\u0026cd=KhQxNzg2NTc5NDQ3ODIzODUyNjI5NzIcZmQ4N2VjYzkxMGIxMWE4Yzpjby56YTplbjpVUw\\u0026ssp=AMJHsmW3CCK1S4TNPifSXszcyaNMwd6TDg\",\"userAwarenessAction\":\"Continue\",\"userEmailAddress\":\"johndoe@example.com\",\"userOverride\":\"None\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "mimecast": {
        "action": "allow",
        "actions": "Allow",
        "adminOverride": "N/A",
        "category": "Search Engines & Portals",
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
        "original": "https://www.google.co.za/alerts/share?hl=en&gl=US&ru=https://www.wsj.com/articles/u-s-tests-israels-iron-dome-in-guam-as-defense-against-chinese-cruise-missiles-11636455224&ss=tw&rt=U.S.+Tests+Israel%27s+Iron+Dome+in+Guam+as+Defense+Against+Chinese+Cruise+Missiles+-+WSJ&cd=KhQxNzg2NTc5NDQ3ODIzODUyNjI5NzIcZmQ4N2VjYzkxMGIxMWE4Yzpjby56YTplbjpVUw&ssp=AMJHsmW3CCK1S4TNPifSXszcyaNMwd6TDg"
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
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
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
| mimecast.sendingIp | The IP of user who triggers the event. | keyword |
| mimecast.subject | The subject of the email. | keyword |
| mimecast.ttpDefinition | The description of the definition that triggered the URL to be rewritten by Mimecast. | keyword |
| mimecast.url | The url clicked. | keyword |
| mimecast.userAwarenessAction | The action taken by the user if user awareness was applied. | keyword |
| mimecast.userEmailAddress | The email address of the user who clicked the link. | keyword |
| mimecast.userOverride | The action requested by the user. | keyword |

