# Mimecast Integration

The Mimecast integration collects events from the [Mimecast API](https://integrations.mimecast.com/documentation/).

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Configuration

### v1 API Endpoints

Authorization parameters for the Mimecast API (`Application Key`, `Application
ID`, `Access Key`, and `Secret Key`) should be provided by a Mimecast
representative for this integration. Under `Advanced options` you can set the
time interval between two API requests as well as the API URL. A Mimecast
representative should also be able to give you this information in case you need
to change the defaults.

> Note: Rate limit quotas may require you to set up different credentials for the different available log types.

### v2 API Endpoints

Authorization parameters for the Mimecast API (`Client ID` and `Client Key`) should
be provided by a Mimecast representative for this integration. Under `Advanced options`
you can set the time interval between two API requests as well as the API URL. A Mimecast
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
        "ephemeral_id": "7a63b865-3dc4-403b-8cd4-54e99b744e0e",
        "id": "79e1ec7c-5d51-4db4-a363-df2e810d3411",
        "name": "elastic-agent-28365",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.archive_search_logs",
        "namespace": "34707",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "79e1ec7c-5d51-4db4-a363-df2e810d3411",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "created": "2021-03-18T18:35:49.000Z",
        "dataset": "mimecast.archive_search_logs",
        "ingested": "2025-12-16T10:32:04Z",
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
        "ephemeral_id": "36061bf9-f838-404c-b724-28267b5bcd86",
        "id": "d6fa0f89-1fb9-474b-b2f3-0c52080145f6",
        "name": "elastic-agent-75872",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.audit_events",
        "namespace": "46653",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d6fa0f89-1fb9-474b-b2f3-0c52080145f6",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "action": "search-action",
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2025-12-16T10:34:04.141Z",
        "dataset": "mimecast.audit_events",
        "id": "eNqrVipOTS4tSs1MUbJSSg_xMDJPNkisSDdISQ00j0gzz44wDAtL89c2DXZ1C3eP9AyvijKL9I7Rd_WOzC0ztMg2dzFM1M73s6w09CqoDA1T0lFKLE3JLMnJTwcZaGxoaWFsYmhkoaOUXFpckp-bWpScn5IKtMnZxMzR3BSovCy1qDgzP0_JyrAWAAjKK2o",
        "ingested": "2025-12-16T10:34:05Z",
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
| mimecast.timezone | Timezone reported in the event message. | keyword |


### Cloud Integrated Logs

This is the `mimecast.cloud_integrated_logs` dataset. These logs contain Mimecast
threats and security events with the following details: entities, mail flows and URL
protected events. More information about [these logs](
https://developer.services.mimecast.com/docs/threatssecurityeventsanddataforci/1/routes/siem/v1/batch/events/ci/get).

An example event for `cloud_integrated` looks as following:

```json
{
    "@timestamp": "2024-11-21T18:03:26.960Z",
    "agent": {
        "ephemeral_id": "7ea63455-2f5b-420f-87e2-7a33d3f86299",
        "id": "2934863c-8548-4f64-b43e-d42a5265e942",
        "name": "elastic-agent-43281",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "mimecast.cloud_integrated_logs",
        "namespace": "25198",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2934863c-8548-4f64-b43e-d42a5265e942",
        "snapshot": false,
        "version": "8.16.0"
    },
    "email": {
        "message_id": "<2ae37333-38e7-89ff-dc36-c8d48c6e3df3@demovation-ci.b41.one>"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2024-11-21T18:03:26.960Z",
        "dataset": "mimecast.cloud_integrated_logs",
        "ingested": "2025-07-08T12:53:17Z",
        "module": "mimecast",
        "original": "{\"_offset\":1803841,\"_partition\":53,\"accountId\":\"AUS2474\",\"aggregateId\":\"4XvR1B4m7BzFB8L-qk59b4szrgayciaagczc977rzb_1732212206\",\"authResults\":[{\"aligned\":true,\"result\":\"pass\",\"type\":\"SPF\"},{\"aligned\":false,\"result\":\"none\",\"type\":\"DKIM\"},{\"aligned\":null,\"result\":\"pass\",\"type\":\"DMARC\"}],\"messageId\":\"\\u003c2ae37333-38e7-89ff-dc36-c8d48c6e3df3@demovation-ci.b41.one\\u003e\",\"processingId\":\"c40337e6860db0301575d8d09362bff214c0b010d6c4d41da9d770759ff54d10_1732212206\",\"subtype\":null,\"timestamp\":1732212206960,\"type\":\"mailflow\"}"
    },
    "input": {
        "type": "cel"
    },
    "mimecast": {
        "accountId": "AUS2474",
        "aggregateId": "4XvR1B4m7BzFB8L-qk59b4szrgayciaagczc977rzb_1732212206",
        "authResults": {
            "aligned": [
                true,
                false
            ],
            "result": [
                "pass",
                "none",
                "pass"
            ],
            "type": [
                "SPF",
                "DKIM",
                "DMARC"
            ]
        },
        "log_type": "mailflow",
        "processingId": "c40337e6860db0301575d8d09362bff214c0b010d6c4d41da9d770759ff54d10_1732212206"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-cloud-integrated-logs"
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
| mimecast.accountId | The Mimecast account code for your account. | keyword |
| mimecast.action | The action taken for this message. | keyword |
| mimecast.aggregateId | Unique identifier that allows you to correlate/group related events. | keyword |
| mimecast.attachments | The filenames of all attachments on the emai. | keyword |
| mimecast.authResults.aligned |  | boolean |
| mimecast.authResults.result |  | keyword |
| mimecast.authResults.type |  | keyword |
| mimecast.direction | The direction of the email based on the sending and receiving domains. | keyword |
| mimecast.historicalMail | Identifies whether the scan was from historical email (prior to Mimecast). | boolean |
| mimecast.log_type |  | keyword |
| mimecast.messageId | The internet message id of the email. | keyword |
| mimecast.originalUrl | The original URL Clicked. | keyword |
| mimecast.policiesApplied.action |  | keyword |
| mimecast.policiesApplied.mode |  | keyword |
| mimecast.policiesApplied.name |  | keyword |
| mimecast.processingId | Unique identifier that allows you to correlate/group related events. | keyword |
| mimecast.recipients | The recipient of the email. | keyword |
| mimecast.redirectUrl | The redirect URL, following original URL click. | keyword |
| mimecast.senderEnvelope | The sender of the email. | keyword |
| mimecast.senderHeader | The sender address found in the from header of the email. | keyword |
| mimecast.senderIp | The source IP of the sending mail server. | keyword |
| mimecast.source |  | keyword |
| mimecast.sourceIp | The source IP of the original message. | keyword |
| mimecast.subject | The subject of the email, limited to 150 characters. | keyword |
| mimecast.subtype |  | keyword |
| mimecast.tags | The determination if the email was untrustworthy. | keyword |
| mimecast.threatState | The action taken. | keyword |
| mimecast.threatType | The type of threat identified where applicable. no detections= allowed. | keyword |
| mimecast.timestamp | The date and time of event. | keyword |


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
        "ephemeral_id": "b24eb4af-c762-48f8-8330-820a19c3ff92",
        "id": "4d775e70-07f7-47c6-824a-405828fce806",
        "name": "elastic-agent-36544",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.dlp_logs",
        "namespace": "10826",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "4d775e70-07f7-47c6-824a-405828fce806",
        "snapshot": false,
        "version": "8.19.4"
    },
    "email": {
        "direction": "inbound",
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
        "category": [
            "email"
        ],
        "created": "2021-11-18T21:41:18+0000",
        "dataset": "mimecast.dlp_logs",
        "ingested": "2025-12-16T10:36:16Z",
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


### Message Release Logs

This is the `mimecast.message_release_logs` dataset. These logs contain information about
messages that were either released to the recipient, with details about the user that
processed the release. More information about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-message-release-logs/). 

An example event for `message_release` looks as following:

```json
{
    "@timestamp": "2024-10-28T14:16:51.000Z",
    "agent": {
        "ephemeral_id": "6f44afc9-d958-4ef8-80d9-1fa4488ee06c",
        "id": "93f79b0f-4dfe-430e-a155-e3bc5ea1f4c6",
        "name": "elastic-agent-66267",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "mimecast.message_release_logs",
        "namespace": "80489",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "93f79b0f-4dfe-430e-a155-e3bc5ea1f4c6",
        "snapshot": false,
        "version": "8.16.0"
    },
    "email": {
        "direction": "inbound",
        "from": {
            "address": [
                "yahoo-delivers@evaluation-fuzz.b41.one"
            ]
        },
        "local_id": "eNoNjt0KgjAYQN9ltwlNMVZBF...",
        "subject": "Yahoo! Newsletter, November 2001",
        "to": {
            "address": [
                "monika.causholli@demo-int.elastic.mime-api.com"
            ]
        }
    },
    "event": {
        "action": "rejected",
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "dataset": "mimecast.message_release_logs",
        "id": "eNoNjt0KgjAYQN9ltwlNMVZBF...",
        "ingested": "2025-07-08T12:55:56Z",
        "kind": "alert",
        "module": "mimecast",
        "original": "{\"attachments\":true,\"detectionLevel\":\"relaxed\",\"fromEnv\":{\"emailAddress\":\"yahoo-delivers@evaluation-fuzz.b41.one\"},\"fromHdr\":{\"emailAddress\":\"yahoo-delivers@evaluation-fuzz.b41.one\"},\"heldReason\":\"Default Spam Scanning Definition\",\"id\":\"eNoNjt0KgjAYQN9ltwlNMVZBF...\",\"messageInfo\":\"Graymail\",\"operator\":{\"emailAddress\":\"monika.causholli@demo-int.elastic.mime-api.com\"},\"policy\":\"Default Spam Scanning Definition\",\"rejectReason\":\"Message goes against email policies\",\"released\":\"2024-10-28T14:16:51+0000\",\"route\":\"inbound\",\"size\":3670056,\"spamProcessingDetail\":{\"dkim\":{\"allow\":true,\"info\":\"unknown\"},\"dmarc\":{\"allow\":true,\"info\":\"allow\"},\"greyEmail\":false,\"managedSender\":{\"allow\":true,\"info\":\"unknown\"},\"permittedSender\":{\"allow\":true,\"info\":\"none\"},\"rbl\":{\"allow\":true,\"info\":\"\"},\"spf\":{\"allow\":true,\"info\":\"allow\"},\"verdict\":{\"categories\":[{\"name\":\"spam\",\"risk\":\"high\",\"subcategories\":[{\"augmentations\":[],\"name\":\"technology_feed\",\"risk\":\"high\"},{\"augmentations\":[{\"name\":\"body\",\"risk\":\"negligible\"}],\"name\":\"content\",\"risk\":\"negligible\"}]},{\"name\":\"graymail\",\"risk\":\"negligible\",\"subcategories\":[]}],\"decision\":\"spam\",\"description\":\"\",\"risk\":\"high\"}},\"spamScore\":20,\"status\":\"rejected\",\"subject\":\"Yahoo! Newsletter, November 2001\",\"to\":[{\"emailAddress\":\"monika.causholli@demo-int.elastic.mime-api.com\"}]}",
        "reason": "Message goes against email policies",
        "risk_score": 20,
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "mimecast": {
        "message_release_logs": {
            "attachments": true,
            "detectionLevel": "relaxed",
            "fromEnv": {
                "emailAddress": "yahoo-delivers@evaluation-fuzz.b41.one"
            },
            "fromHdr": {
                "emailAddress": "yahoo-delivers@evaluation-fuzz.b41.one"
            },
            "heldReason": "Default Spam Scanning Definition",
            "id": "eNoNjt0KgjAYQN9ltwlNMVZBF...",
            "messageInfo": "Graymail",
            "operator": "monika.causholli@demo-int.elastic.mime-api.com",
            "policy": "Default Spam Scanning Definition",
            "rejectReason": "Message goes against email policies",
            "released": "2024-10-28T14:16:51+0000",
            "route": "inbound",
            "size": 3670056,
            "spamProcessingDetail": {
                "dkim": {
                    "allow": true,
                    "info": "unknown"
                },
                "dmarc": {
                    "allow": true,
                    "info": "allow"
                },
                "greyEmail": false,
                "managedSender": {
                    "allow": true,
                    "info": "unknown"
                },
                "permittedSender": {
                    "allow": true,
                    "info": "none"
                },
                "rbl": {
                    "allow": true
                },
                "spamVerdict": {
                    "categories": [
                        {
                            "name": "spam",
                            "risk": "high",
                            "subcategories": [
                                {
                                    "name": "technology_feed",
                                    "risk": "high"
                                },
                                {
                                    "augmentations": [
                                        {
                                            "name": "body",
                                            "risk": "negligible"
                                        }
                                    ],
                                    "name": "content",
                                    "risk": "negligible"
                                }
                            ]
                        },
                        {
                            "name": "graymail",
                            "risk": "negligible"
                        }
                    ],
                    "decision": "spam",
                    "risk": "high"
                },
                "spf": {
                    "allow": true,
                    "info": "allow"
                }
            },
            "spamScore": 20,
            "status": "rejected",
            "subject": "Yahoo! Newsletter, November 2001",
            "to": {
                "emailAddress": "monika.causholli@demo-int.elastic.mime-api.com"
            }
        }
    },
    "related": {
        "hosts": [
            "demo-int.elastic.mime-api.com",
            "evaluation-fuzz.b41.one"
        ],
        "user": [
            "monika.causholli",
            "monika.causholli@demo-int.elastic.mime-api.com",
            "yahoo-delivers",
            "yahoo-delivers@evaluation-fuzz.b41.one"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-message-release-logs"
    ],
    "user": {
        "email": "monika.causholli@demo-int.elastic.mime-api.com"
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
| mimecast.message_release_logs.attachments | Indicates whether the message contains attachments. | boolean |
| mimecast.message_release_logs.detectionLevel | Spam detection level, if held by a spam policy. Possible values are: relaxed, moderate, aggressive, cluster or whitelisted_cluster. | keyword |
| mimecast.message_release_logs.fromEnv.displayableName | Display name of the user address from the "from" envelope. If none exists, this field will be empty. | keyword |
| mimecast.message_release_logs.fromEnv.emailAddress | The routable email address of the user from the "from" envelope. | keyword |
| mimecast.message_release_logs.fromHdr.displayableName | Display name of the user address from the "from" header. If none exists, this field will be empty. | keyword |
| mimecast.message_release_logs.fromHdr.emailAddress | The routable email address of the user from the "from" header. | keyword |
| mimecast.message_release_logs.heldGroup | The recipient group of the held message, if message was sent to a group. | keyword |
| mimecast.message_release_logs.heldReason | Detail around the reason the message was initially held. If held by a specific policy definition, this will be the name of the policy definition that triggered the message to be held. | keyword |
| mimecast.message_release_logs.id | The Mimecast secure ID of the specific message release log. | keyword |
| mimecast.message_release_logs.messageInfo | Additional information around the release reason. | text |
| mimecast.message_release_logs.operator | Email address of the user that released the message. | keyword |
| mimecast.message_release_logs.policy | Name of the policy definition that triggered the message to be held. | keyword |
| mimecast.message_release_logs.rejectReason | Detail on the reason a message was rejected, if message was rejected. | keyword |
| mimecast.message_release_logs.released | Timestamp of the message release action in ISO 8601 format. | keyword |
| mimecast.message_release_logs.route | Message direction. Possible values are: inbound or outbound. | keyword |
| mimecast.message_release_logs.size | Total size of the message, in bytes. | long |
| mimecast.message_release_logs.spamProcessingDetail.dkim.allow | Indicates checks for whether the message passed DKIM checks are performed. | boolean |
| mimecast.message_release_logs.spamProcessingDetail.dkim.info | Details about the check result. | keyword |
| mimecast.message_release_logs.spamProcessingDetail.dmarc.allow | Indicates checks for whether the message passed DMARC checks are performed. | boolean |
| mimecast.message_release_logs.spamProcessingDetail.dmarc.info | Details about the check result. | keyword |
| mimecast.message_release_logs.spamProcessingDetail.grayEmail | Indicates with the spam was classified as graymail or bulk. Note that this API uses graymail and greymail interchangeably. | boolean |
| mimecast.message_release_logs.spamProcessingDetail.greyEmail | Indicates with the spam was classified as graymail or bulk. Note that this API uses graymail and greymail interchangeably. | boolean |
| mimecast.message_release_logs.spamProcessingDetail.managedSender.allow | Indicates checks for whether the sender has been permitted by a Managed Sender entry are performed. | boolean |
| mimecast.message_release_logs.spamProcessingDetail.managedSender.info | Details about the check result. | keyword |
| mimecast.message_release_logs.spamProcessingDetail.permittedSender.allow | Indicates checks for whether the sender has been permitted by policy are performed. | boolean |
| mimecast.message_release_logs.spamProcessingDetail.permittedSender.info | Details about the check result. | keyword |
| mimecast.message_release_logs.spamProcessingDetail.rbl.allow | Indicates checks for whether the message passed RBL checks are performed. | boolean |
| mimecast.message_release_logs.spamProcessingDetail.rbl.info | Details about the check result. | keyword |
| mimecast.message_release_logs.spamProcessingDetail.spamVerdict.categories | Spam detection type categories. | flattened |
| mimecast.message_release_logs.spamProcessingDetail.spamVerdict.decision | Indicating what the ultimate verdict was for the message. | keyword |
| mimecast.message_release_logs.spamProcessingDetail.spamVerdict.description | Description of the spam verdict decision. | keyword |
| mimecast.message_release_logs.spamProcessingDetail.spamVerdict.risk | Identified risk level within the spam detection. Possible values are: negligible, low, high. | keyword |
| mimecast.message_release_logs.spamProcessingDetail.spf.allow | Indicates checks for whether the message passed SPF checks are performed. | boolean |
| mimecast.message_release_logs.spamProcessingDetail.spf.info | Details about the check result. | keyword |
| mimecast.message_release_logs.spamScore | The message spam score, based on the applied spam scanning policy definition. | double |
| mimecast.message_release_logs.status | Status of the message. Possible values are released or rejected. | keyword |
| mimecast.message_release_logs.subject | The released message's subject line. | keyword |
| mimecast.message_release_logs.to.displayableName | Display name of the user address from the "to" header. If none exists, this field will be empty. | keyword |
| mimecast.message_release_logs.to.emailAddress | The routable email address of the user from the "to" header. | keyword |


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
        "ephemeral_id": "209054e3-c38a-4e5a-bb6c-e771a044eb63",
        "id": "561734f3-9650-4135-bc74-cf4d379801c5",
        "name": "elastic-agent-56189",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.siem_logs",
        "namespace": "85570",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "561734f3-9650-4135-bc74-cf4d379801c5",
        "snapshot": false,
        "version": "8.19.4"
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
        "category": [
            "email"
        ],
        "created": "2021-11-12T12:15:46+0000",
        "dataset": "mimecast.siem_logs",
        "ingested": "2025-12-16T05:32:04Z",
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
| mimecast.CustomThreatDictionary | The content of the email was detected to contain words in a custom threat dictionary. | keyword |
| mimecast.CustomerIP | The source IP is one of the accounts authorised IPs or one of the authorised IPs belonging to an Umbrella Account, if the Account uses an Umbrella Account. | keyword |
| mimecast.Hits | Number of items flagged for the message. | keyword |
| mimecast.Hostname |  | keyword |
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
| mimecast.ThreatDictionary | The content of the email was detected to contain words in the Mimecast threat dictionary. | keyword |
| mimecast.UrlCategory | The category of the URL that was clicked. | keyword |
| mimecast.Virus | The name of the virus found on the email, if applicable. | keyword |
| mimecast.acc | The Mimecast account code for your account. | keyword |
| mimecast.accountId | The Mimecast account code for your account | keyword |
| mimecast.action | The action taken at the receipt stage. Receipt logs:(Rej; Acc; Ign; Bnc), Process logs:(Acc; Hld; Bnc; Sdbx; Rty), Impersonation Protect logs:(None; Hold), URL Protect logs:(Block). | keyword |
| mimecast.aggregateId | Unique identifier that allows you to correlate/group related events. | keyword |
| mimecast.analysis | The senders domain is similar to a custom external domain list. | keyword |
| mimecast.attachments | The filenames of all attachments on the email | keyword |
| mimecast.blockReason | The reason click was blocked. (Unknown; File Detected; Clean; Malicious; Suspicious) | keyword |
| mimecast.credentialTheft | The info about credential theft. | keyword |
| mimecast.customNameMatch | The message has matched a custom name.  True; False | keyword |
| mimecast.customThreatDictionary | The content of the email was detected to contain words in the client custom threat dictionary. (True; False) | keyword |
| mimecast.customerIp | The source IP is one of the accounts authorised IPs or one of the authorised IPs belonging to an Umbrella Account, if the Account uses an Umbrella Account. | keyword |
| mimecast.delivered | \* If the email was delivered successfully or not. False; True | keyword |
| mimecast.delivery | Attempts  The count of attempts that the Mimecast MTA has made to deliver the email. | keyword |
| mimecast.deliveryAttempts |  | keyword |
| mimecast.deliveryErrors | Information about any errors that occurred on the delivery attempt. | keyword |
| mimecast.deliveryTime | The time in milliseconds that the delivery attempt took. | keyword |
| mimecast.destinationIp | The destination IP address for the delivery attempt. | keyword |
| mimecast.direction | The direction of the email based on the sending and receiving domains. (Inbound; Outbound; Internal; External) | keyword |
| mimecast.emailSize | The amount of data in bytes that were delivered. | keyword |
| mimecast.fileExtension | The file extension. | keyword |
| mimecast.fileName | The name of file. | keyword |
| mimecast.holdReason | The reason the email was held for review (quarantined), if applicable. (Spm; Att; RcptLimit; Exp; Imp; Sbx; Oth; Url; Ctnt; Dpp; RBL; (absent)) | keyword |
| mimecast.internalUserName | The email was detected to be from an internal user name. (Hit; No Hit) | keyword |
| mimecast.ipNewDomain | For emails subject to Targeted Threat Protection: Impersonation Protect, if the email was detected to be from a new domain. | keyword |
| mimecast.ipReplyMismatch | For emails subject to Targeted Threat Protection: Impersonation Protect, if the email was detetced to have a mismatch in the reply to address. | keyword |
| mimecast.ipSimilarDomain | For emails subject to Targeted Threat Protection: Impersonation Protect, if the email was detetced to be from a similar domain to any domain you have registered as an Internal Domain. | keyword |
| mimecast.ipThreatDictionary | For emails subject to Targeted Threat Protection: Impersonation Protect, if the content of the email was detected to contain words in the Mimecast threat dictionary. | keyword |
| mimecast.ipUserName | For emails subject to Targeted Threat Protection: Impersonation Protect, if the email was detected to be from an internal user name. | keyword |
| mimecast.itemsDetected | Number of items flagged for the message. | keyword |
| mimecast.log_type | String to get type of SIEM log. | keyword |
| mimecast.md5 | MD5 Hash. | keyword |
| mimecast.messageId | The internet message id of the email. | keyword |
| mimecast.mimecastThreatDictionary | The content of the email was detected to contain words in the Mimecast threat dictionary. (True; False) | keyword |
| mimecast.monitoredDomainSource | the source of the URL match based on Mimecast's heuristic scanning techniques | keyword |
| mimecast.msgid | The internet message id of the email. | keyword |
| mimecast.newDomain | The email was detected to be from a new domain (True; False) | keyword |
| mimecast.numberAttachments | The number of attachments on the email. | keyword |
| mimecast.policyDefinition | The definition of policy triggered. | keyword |
| mimecast.processingId | Unique identifier that allows you to correlate/group related events. | keyword |
| mimecast.receiptErrors | Information about any errors that occurred during receipt. | keyword |
| mimecast.recipients | The recipient of the email. | keyword |
| mimecast.rejectionCode | The rejection code, for messages rejected by the receiving mail server. | keyword |
| mimecast.rejectionInfo | The rejection information if the email was rejected at the receipt stage. | keyword |
| mimecast.rejectionType | The rejection type, for messages rejected by the receiving mail server. | keyword |
| mimecast.replyMismatch | The reply address does not correspond to the senders address. (True; False) | keyword |
| mimecast.route | The route of the message. (Inbound; Outbound; Internal; External) | keyword |
| mimecast.scanResults | The reason that the click was blocked. | keyword |
| mimecast.senderDomain | The sender domain. | keyword |
| mimecast.senderDomainInternal | The sender domain is a registered internal domain. | keyword |
| mimecast.senderEnvelope | The sender of the email. | keyword |
| mimecast.senderHeader | Sender address found in the from header of the email. | keyword |
| mimecast.senderIp | The source IP of the original message or sending mail server. | keyword |
| mimecast.sha1 | SHA1 hash. | keyword |
| mimecast.sha256 | SHA256 hash. | keyword |
| mimecast.similarCustomExternalDomain | The senders domain is similar to a custom external domain list. (True; False) | keyword |
| mimecast.similarDomain | The domain is similar to a registered domain. | keyword |
| mimecast.similarInternalDomain | The senders domain is similar to a registered internal domain. (True; False) | keyword |
| mimecast.similarMimecastExternalDomain | The senders domain is similar to a Mimecast managed list of domains. (True; False) | keyword |
| mimecast.similarMimecastExternalDomainResults | Advanced phishing detection results from scanners | keyword |
| mimecast.sizeAttachment | The size (in bytes) of the malicious file. | keyword |
| mimecast.sourceIp | The source IP of the original message. | keyword |
| mimecast.spamDetectionLevel | The detection level defined for the given sender and recipient. | keyword |
| mimecast.spamInfo | Information from Mimecast Spam scanners for messages found to be Spam. | keyword |
| mimecast.spamProcessingDetail | The Spam processing details for DKIM, SPF, DMARC | keyword |
| mimecast.spamScore | The metric that measures the likelihood of the event being considered spam. | keyword |
| mimecast.subject | The subject of the email. | keyword |
| mimecast.subtype |  | keyword |
| mimecast.taggedExternal | The message has been tagged as originating from a external source. (True; False) | boolean |
| mimecast.taggedMalicious | The message has been tagged as malicious. (True; False) | boolean |
| mimecast.timestamp | The date and time of event. | keyword |
| mimecast.tlsCipher | The TLS Cipher used if the email was delivered or received using TLS. | keyword |
| mimecast.tlsUsed | If the message was delivered using TLS or not. (Yes; No) | keyword |
| mimecast.tlsVersion | The TLS version used if the email was delivered or received using TLS. | keyword |
| mimecast.totalSizeAttachments | The total size of all attachments on the email. | keyword |
| mimecast.url | URL Clicked | keyword |
| mimecast.urlCategory | The category of the URL that was clicked. | keyword |
| mimecast.virusFound | The name or signature of the virus found on the email, if applicable. | keyword |


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
        "ephemeral_id": "62b45a46-b430-4a60-8d39-150102c2cf5f",
        "id": "4fbcd1c3-faac-4981-863e-cee2d3dfc5b2",
        "name": "elastic-agent-38980",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.threat_intel_malware_customer",
        "namespace": "64794",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "4fbcd1c3-faac-4981-863e-cee2d3dfc5b2",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat",
            "email",
            "malware"
        ],
        "created": "2025-12-16T05:35:55.350Z",
        "dataset": "mimecast.threat_intel_malware_customer",
        "ingested": "2025-12-16T05:35:56Z",
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
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


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
        "ephemeral_id": "d897aeba-64c6-493c-abca-30b90eb0ffda",
        "id": "d6f54d61-9d99-4de7-a4d1-e20a59ca7044",
        "name": "elastic-agent-16610",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.threat_intel_malware_grid",
        "namespace": "24530",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d6f54d61-9d99-4de7-a4d1-e20a59ca7044",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat",
            "email",
            "malware"
        ],
        "created": "2025-12-16T05:37:55.074Z",
        "dataset": "mimecast.threat_intel_malware_grid",
        "ingested": "2025-12-16T05:37:56Z",
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
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


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
        "ephemeral_id": "b02029a2-8693-492f-b399-70a52affb601",
        "id": "4d94529c-4879-4740-8c99-9661e034dff9",
        "name": "elastic-agent-34716",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.ttp_ap_logs",
        "namespace": "29066",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "4d94529c-4879-4740-8c99-9661e034dff9",
        "snapshot": false,
        "version": "8.19.4"
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
        "category": [
            "email"
        ],
        "created": "2021-11-24T11:54:27+0000",
        "dataset": "mimecast.ttp_ap_logs",
        "ingested": "2025-12-16T10:38:25Z",
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
        "ephemeral_id": "33a85920-cac6-40c1-8eb1-f10d7fe336e8",
        "id": "9ae2237c-6df6-4642-8866-f4baeb8378ef",
        "name": "elastic-agent-30931",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.ttp_ip_logs",
        "namespace": "24821",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9ae2237c-6df6-4642-8866-f4baeb8378ef",
        "snapshot": false,
        "version": "8.19.4"
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
        "category": [
            "email"
        ],
        "created": "2021-11-12T15:27:04+0000",
        "dataset": "mimecast.ttp_ip_logs",
        "id": "MTOKEN:eNqrVkouLS7Jz00tSs5PSVWyUnI2MXM0N1XSUcpMUbIyMjM3MzAw0FEqSy0qzszPU7Iy1FEqyQMrNDAwV6oFAGMiEg8",
        "ingested": "2025-12-16T10:23:35Z",
        "kind": "alert",
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
        "ephemeral_id": "e16fc88d-c17b-446c-91bf-ab2f69c24a3a",
        "id": "739d0562-8a1e-4e77-97d0-08327ffab55b",
        "name": "elastic-agent-24838",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.ttp_url_logs",
        "namespace": "81022",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "739d0562-8a1e-4e77-97d0-08327ffab55b",
        "snapshot": false,
        "version": "8.19.4"
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
        "category": [
            "email"
        ],
        "created": "2021-11-10T03:49:53+0000",
        "dataset": "mimecast.ttp_url_logs",
        "ingested": "2025-12-16T10:27:15Z",
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
            "googlealerts-noreply@google.com",
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
        "domain": "www.google.co.za",
        "original": "https://www.google.co.za/alerts/share?hl=en&gl=US&ru=https://www.wsj.com/articles/u-s-tests-israels-iron-dome-in-guam-as-defense-against-chinese-cruise-missiles-11636455224&ss=tw&rt=U.S.+Tests+Israel%27s+Iron+Dome+in+Guam+as+Defense+Against+Chinese+Cruise+Missiles+-+WSJ&cd=KhQxNzg2NTc5NDQ3ODIzODUyNjI5NzIcZmQ4N2VjYzkxMGIxMWE4Yzpjby56YTplbjpVUw&ssp=AMJHsmW3CCK1S4TNPifSXszcyaNMwd6TDg",
        "path": "/alerts/share",
        "query": "hl=en&gl=US&ru=https://www.wsj.com/articles/u-s-tests-israels-iron-dome-in-guam-as-defense-against-chinese-cruise-missiles-11636455224&ss=tw&rt=U.S.+Tests+Israel's+Iron+Dome+in+Guam+as+Defense+Against+Chinese+Cruise+Missiles+-+WSJ&cd=KhQxNzg2NTc5NDQ3ODIzODUyNjI5NzIcZmQ4N2VjYzkxMGIxMWE4Yzpjby56YTplbjpVUw&ssp=AMJHsmW3CCK1S4TNPifSXszcyaNMwd6TDg",
        "scheme": "https"
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
| mimecast.tagMap.DangerousFileExt.ContentCheck_ContentScannersBlocked |  | keyword |
| mimecast.tagMap.DangerousFileExt.ContentCheck_DangerousExtsUrlFileDownload |  | keyword |
| mimecast.tagMap.DangerousFileExt.ContentCheck_DangerousMimetypesUrlFileDownload |  | keyword |
| mimecast.tagMap.DangerousFileExt.Inspect_FileExts |  | keyword |
| mimecast.tagMap.DangerousFileExt.Inspect_MimeTypes |  | keyword |
| mimecast.tagMap.DangerousFileExt.Status |  | keyword |
| mimecast.tagMap.UrlReputationScan.Status |  | keyword |
| mimecast.tagMap.UrlReputationScan.Type |  | keyword |
| mimecast.tagMap.UrlReputationScan.Url |  | keyword |
| mimecast.tagMap.UrlReputationScan.UrlBlock |  | keyword |
| mimecast.ttpDefinition | The description of the definition that triggered the URL to be rewritten by Mimecast. | keyword |
| mimecast.url | The url clicked. | keyword |
| mimecast.userAwarenessAction | The action taken by the user if user awareness was applied. | keyword |
| mimecast.userEmailAddress | The email address of the user who clicked the link. | keyword |
| mimecast.userOverride | The action requested by the user. | keyword |

