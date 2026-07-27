# Mimecast Integration

The Mimecast integration collects events from the [Mimecast API](https://developer.services.mimecast.com/apis).

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Configuration

### v2 API Endpoints

Authorization parameters for the Mimecast API (`Client ID` and `Client Secret`) should
be provided by a Mimecast representative for this integration. Under `Advanced options`
you can set the time interval between two API requests as well as the API URL. A Mimecast
representative should also be able to give you this information in case you need
to change the defaults.

> Note: Rate limit quotas may require you to set up different credentials for the different available log types.

### v1 API Endpoints (deprecated)

> **Deprecated:** Mimecast API 1.0 is [end-of-life](https://mimecastsupport.zendesk.com/hc/en-us/articles/43572890309651-API-Integrations-API-1-0-End-of-Life-Project-Extension-Aug-2025).
> New installations should use the v2 API. Existing v1 configurations continue
> to work but will stop functioning when Mimecast retires API 1.0 application
> credentials. See the [API 1.0 to 2.0 Migration Guide](https://developer.services.mimecast.com/api-1-0-to-2-0-migration-guide)
> for details on provisioning v2 API credentials.

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
    "@timestamp": "2024-11-12T16:21:27.000Z",
    "agent": {
        "ephemeral_id": "c28fe82d-b778-437e-8bca-cd19f65ce426",
        "id": "774a7e89-0464-43ea-870d-42c8a6304863",
        "name": "elastic-agent-68546",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.archive_search_logs",
        "namespace": "78572",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "774a7e89-0464-43ea-870d-42c8a6304863",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "created": "2024-11-12T16:21:27.000Z",
        "dataset": "mimecast.archive_search_logs",
        "ingested": "2026-07-27T21:30:21Z",
        "kind": "event",
        "original": "{\"createTime\":\"2024-11-12T16:21:27+0000\",\"description\":\"Message Tracking Search\",\"emailAddr\":\"\\u003c\\u003e\",\"searchReason\":\"\",\"searchText\":\"[User : user1@example.net]\",\"source\":\"archive\"}",
        "type": [
            "admin"
        ]
    },
    "input": {
        "type": "cel"
    },
    "mimecast": {
        "search_details": {
            "description": "Message Tracking Search",
            "source": "archive",
            "text": "[User : user1@example.net]"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-archive-search-logs"
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
    "@timestamp": "2024-10-17T02:06:50.000Z",
    "agent": {
        "ephemeral_id": "7b2346a4-f48b-4dd0-8526-1c95c9bec91c",
        "id": "b8edebe1-b5f6-43b8-9eae-992861cc32e6",
        "name": "elastic-agent-26155",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "client": {
        "as": {
            "number": 64501,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Amsterdam",
            "continent_name": "Europe",
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "location": {
                "lat": 52.37404,
                "lon": 4.88969
            },
            "region_iso_code": "NL-NH",
            "region_name": "North Holland"
        },
        "ip": "198.51.100.44"
    },
    "data_stream": {
        "dataset": "mimecast.audit_events",
        "namespace": "47381",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "b8edebe1-b5f6-43b8-9eae-992861cc32e6",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "action": "api-application-updated",
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2024-10-17T02:06:50.000Z",
        "dataset": "mimecast.audit_events",
        "id": "eNoVzk0PgiAAgOH_wrUO4SizrYOasxUzs6jWLYURfqEg6Wr99-z-bs_7AZplRjFBwQp4E3y5t3G7w1SVz9KxwxtJj7mVNripeP7WV3N2-3AohNUFGw0DmMY2aqOeq7MZfCKqyME1jeUMv_qAdVub6MJdnprZIYz2PS3u-bNuB54kfA2m4GGo6ErJ_zZCi4UD51OQGd3JiqlMUjYu-eTkIdey0di_mNJC1mAFvz-isz1f",
        "ingested": "2026-07-27T21:32:10Z",
        "original": "{\"auditType\":\"API Application Updated\",\"category\":\"account_logs\",\"eventInfo\":\"API Gateway Application testing Updated. Application Program Interface Addendum (22 September 2022) acknowledged, Date: 2024-10-17, Time: 02:06:50+0000, IP: 198.51.100.44, Application: Administration Console\",\"eventTime\":\"2024-10-17T02:06:50+0000\",\"id\":\"eNoVzk0PgiAAgOH_wrUO4SizrYOasxUzs6jWLYURfqEg6Wr99-z-bs_7AZplRjFBwQp4E3y5t3G7w1SVz9KxwxtJj7mVNripeP7WV3N2-3AohNUFGw0DmMY2aqOeq7MZfCKqyME1jeUMv_qAdVub6MJdnprZIYz2PS3u-bNuB54kfA2m4GGo6ErJ_zZCi4UD51OQGd3JiqlMUjYu-eTkIdey0di_mNJC1mAFvz-isz1f\",\"user\":\"user.name@example.com\"}"
    },
    "input": {
        "type": "cel"
    },
    "mimecast": {
        "application": "Administration Console",
        "category": "account_logs",
        "eventInfo": "API Gateway Application testing Updated. Application Program Interface Addendum (22 September 2022) acknowledged, Date: 2024-10-17, Time: 02:06:50+0000, IP: 198.51.100.44, Application: Administration Console"
    },
    "related": {
        "ip": [
            "198.51.100.44"
        ],
        "user": [
            "user.name",
            "user.name@example.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-audit-events"
    ],
    "user": {
        "domain": "example.com",
        "email": "user.name@example.com",
        "name": "user.name"
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
        "ephemeral_id": "f4436d4b-4588-4855-b8d0-a1b40d365790",
        "id": "5ae7b2ce-717c-4d4a-b112-6739f55dc239",
        "name": "elastic-agent-36980",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.cloud_integrated_logs",
        "namespace": "26086",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5ae7b2ce-717c-4d4a-b112-6739f55dc239",
        "snapshot": false,
        "version": "8.19.4"
    },
    "email": {
        "message_id": "<2ae37333-38e7-89ff-dc36-c8d48c6e3df3@mail.example.org>"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2024-11-21T18:03:26.960Z",
        "dataset": "mimecast.cloud_integrated_logs",
        "ingested": "2026-07-27T21:33:04Z",
        "original": "{\"_offset\":1803841,\"_partition\":53,\"accountId\":\"AUS2474\",\"aggregateId\":\"4XvR1B4m7BzFB8L-qk59b4szrgayciaagczc977rzb_1732212206\",\"authResults\":[{\"aligned\":true,\"result\":\"pass\",\"type\":\"SPF\"},{\"aligned\":false,\"result\":\"none\",\"type\":\"DKIM\"},{\"aligned\":null,\"result\":\"pass\",\"type\":\"DMARC\"}],\"messageId\":\"\\u003c2ae37333-38e7-89ff-dc36-c8d48c6e3df3@mail.example.org\\u003e\",\"processingId\":\"c40337e6860db0301575d8d09362bff214c0b010d6c4d41da9d770759ff54d10_1732212206\",\"subtype\":null,\"timestamp\":1732212206960,\"type\":\"mailflow\"}"
    },
    "input": {
        "type": "cel"
    },
    "mimecast": {
        "accountId": "AUS2474",
        "aggregateId": "4XvR1B4m7BzFB8L-qk59b4szrgayciaagczc977rzb_1732212206",
        "authResults": [
            {
                "aligned": true,
                "result": "pass",
                "type": "SPF"
            },
            {
                "aligned": false,
                "result": "none",
                "type": "DKIM"
            },
            {
                "result": "pass",
                "type": "DMARC"
            }
        ],
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
| email.attachments | A list of objects describing the attachment files sent along with an email message. | nested |
| email.attachments.file.name | Name of the attachment file including the file extension. | keyword |
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
    "@timestamp": "2024-11-17T19:47:39.000Z",
    "agent": {
        "ephemeral_id": "7a20afc6-bf6d-4a71-83e9-69e8c0a251c6",
        "id": "d6ee16c4-81eb-43f0-8b84-47854a597170",
        "name": "elastic-agent-84675",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.dlp_logs",
        "namespace": "85443",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d6ee16c4-81eb-43f0-8b84-47854a597170",
        "snapshot": false,
        "version": "8.19.4"
    },
    "email": {
        "direction": "inbound",
        "from": {
            "address": [
                "webmaster@example.org"
            ]
        },
        "message_id": "<ae9f2f0678ed116f-152138@mail.example.net>",
        "subject": "New CERA.com Coming Soon! - CERA Alert",
        "to": {
            "address": [
                "vkamins@example.com"
            ]
        }
    },
    "event": {
        "action": "hold",
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2024-11-17T19:47:39+0000",
        "dataset": "mimecast.dlp_logs",
        "ingested": "2026-07-27T21:34:50Z",
        "original": "{\"action\":\"hold\",\"eventTime\":\"2024-11-17T19:47:39+0000\",\"messageId\":\"\\u003cae9f2f0678ed116f-152138@mail.example.net\\u003e\",\"policy\":\"Confidential\",\"recipientAddress\":\"vkamins@example.com\",\"route\":\"inbound\",\"senderAddress\":\"webmaster@example.org\",\"subject\":\"New CERA.com Coming Soon! - CERA Alert\"}"
    },
    "input": {
        "type": "cel"
    },
    "rule": {
        "name": "Confidential"
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
        "ephemeral_id": "2d1b712e-504c-4cd7-b474-9181085c82b6",
        "id": "fbdcd635-f38b-43ec-b3c2-df54c9c6c41d",
        "name": "elastic-agent-69652",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.message_release_logs",
        "namespace": "95418",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "fbdcd635-f38b-43ec-b3c2-df54c9c6c41d",
        "snapshot": false,
        "version": "8.19.4"
    },
    "email": {
        "direction": "inbound",
        "from": {
            "address": [
                "yahoo-delivers@example.org"
            ]
        },
        "local_id": "eNoNjt0KgjAYQN9ltwlNMVZBF...",
        "subject": "Yahoo! Newsletter, November 2001",
        "to": {
            "address": [
                "monika.causholli@example.com"
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
        "ingested": "2026-07-27T21:35:40Z",
        "kind": "alert",
        "original": "{\"attachments\":true,\"detectionLevel\":\"relaxed\",\"fromEnv\":{\"emailAddress\":\"yahoo-delivers@example.org\"},\"fromHdr\":{\"emailAddress\":\"yahoo-delivers@example.org\"},\"heldReason\":\"Default Spam Scanning Definition\",\"id\":\"eNoNjt0KgjAYQN9ltwlNMVZBF...\",\"messageInfo\":\"Graymail\",\"operator\":{\"emailAddress\":\"monika.causholli@example.com\"},\"policy\":\"Default Spam Scanning Definition\",\"rejectReason\":\"Message goes against email policies\",\"released\":\"2024-10-28T14:16:51+0000\",\"route\":\"inbound\",\"size\":3670056,\"spamProcessingDetail\":{\"dkim\":{\"allow\":true,\"info\":\"unknown\"},\"dmarc\":{\"allow\":true,\"info\":\"allow\"},\"greyEmail\":false,\"managedSender\":{\"allow\":true,\"info\":\"unknown\"},\"permittedSender\":{\"allow\":true,\"info\":\"none\"},\"rbl\":{\"allow\":true,\"info\":\"\"},\"spf\":{\"allow\":true,\"info\":\"allow\"},\"verdict\":{\"categories\":[{\"name\":\"spam\",\"risk\":\"high\",\"subcategories\":[{\"augmentations\":[],\"name\":\"technology_feed\",\"risk\":\"high\"},{\"augmentations\":[{\"name\":\"body\",\"risk\":\"negligible\"}],\"name\":\"content\",\"risk\":\"negligible\"}]},{\"name\":\"graymail\",\"risk\":\"negligible\",\"subcategories\":[]}],\"decision\":\"spam\",\"description\":\"\",\"risk\":\"high\"}},\"spamScore\":20,\"status\":\"rejected\",\"subject\":\"Yahoo! Newsletter, November 2001\",\"to\":[{\"emailAddress\":\"monika.causholli@example.com\"}]}",
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
                "emailAddress": "yahoo-delivers@example.org"
            },
            "fromHdr": {
                "emailAddress": "yahoo-delivers@example.org"
            },
            "heldReason": "Default Spam Scanning Definition",
            "id": "eNoNjt0KgjAYQN9ltwlNMVZBF...",
            "messageInfo": "Graymail",
            "operator": "monika.causholli@example.com",
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
            "to": [
                {
                    "emailAddress": "monika.causholli@example.com"
                }
            ]
        }
    },
    "related": {
        "hosts": [
            "example.com",
            "example.org"
        ],
        "user": [
            "monika.causholli",
            "monika.causholli@example.com",
            "yahoo-delivers",
            "yahoo-delivers@example.org"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-message-release-logs"
    ],
    "user": {
        "email": [
            "monika.causholli@example.com"
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
    "@timestamp": "2024-11-12T18:52:07.130Z",
    "agent": {
        "ephemeral_id": "0b763c82-ffca-4953-af86-7bf79ab57bd0",
        "id": "3d392d70-5a2b-4c45-97a7-e5b156050a28",
        "name": "elastic-agent-30190",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.siem_logs",
        "namespace": "91723",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "3d392d70-5a2b-4c45-97a7-e5b156050a28",
        "snapshot": false,
        "version": "8.19.4"
    },
    "email": {
        "direction": "outbound",
        "from": {
            "address": [
                "sender@example.com"
            ]
        },
        "message_id": "<23b9843f48f8d349-99325@mail.example.net>",
        "subject": "Out of office",
        "to": {
            "address": [
                "recipient@example.net"
            ]
        }
    },
    "event": {
        "action": "Acc",
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2024-11-12T18:52:07.130Z",
        "dataset": "mimecast.siem_logs",
        "ingested": "2026-07-27T21:37:21Z",
        "original": "{\"_offset\":70595,\"_partition\":60,\"accountId\":\"CUSB4A274\",\"action\":\"Acc\",\"aggregateId\":\"q1h3LjgrN46b12GlX0By9Q_1731437523\",\"direction\":\"Outbound\",\"messageId\":\"\\u003c23b9843f48f8d349-99325@mail.example.net\\u003e\",\"numberAttachments\":\"0\",\"processingId\":\"X7OQopo8177ryv7KXWXxytbksk3qv0Ct8NSYWcQkhJM_1731437523\",\"receiptErrors\":null,\"recipients\":\"recipient@example.net\",\"rejectionCode\":null,\"rejectionInfo\":null,\"rejectionType\":null,\"senderEnvelope\":\"sender@example.com\",\"senderHeader\":\"sender@example.com\",\"senderIp\":\"198.51.100.18\",\"spamDetectionLevel\":\"28\",\"spamInfo\":\"[]\",\"spamProcessingDetail\":null,\"spamScore\":\"0\",\"subject\":\"Out of office\",\"subtype\":\"Acc\",\"timestamp\":1731437527130,\"tlsCipher\":\"TLS_AES_256_GCM_SHA384\",\"tlsVersion\":\"TLSv1.3\",\"type\":\"receipt\",\"virusFound\":null}",
        "outcome": "unknown"
    },
    "input": {
        "type": "cel"
    },
    "mimecast": {
        "accountId": "CUSB4A274",
        "aggregateId": "q1h3LjgrN46b12GlX0By9Q_1731437523",
        "log_type": "receipt",
        "numberAttachments": "0",
        "processingId": "X7OQopo8177ryv7KXWXxytbksk3qv0Ct8NSYWcQkhJM_1731437523",
        "senderHeader": "sender@example.com",
        "spamDetectionLevel": "28",
        "spamInfo": "[]",
        "spamScore": "0",
        "subtype": "Acc",
        "tlsVersion": "TLSv1.3"
    },
    "related": {
        "user": [
            "sender@example.com",
            "recipient@example.net"
        ]
    },
    "source": {
        "as": {
            "number": 64501,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Amsterdam",
            "continent_name": "Europe",
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "location": {
                "lat": 52.37404,
                "lon": 4.88969
            },
            "region_iso_code": "NL-NH",
            "region_name": "North Holland"
        },
        "ip": "198.51.100.18"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-siem-logs"
    ],
    "tls": {
        "cipher": "TLS_AES_256_GCM_SHA384"
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
| email.attachments | A list of objects describing the attachment files sent along with an email message. | nested |
| email.attachments.file.extension | Attachment file extension, excluding the leading dot. | keyword |
| email.attachments.file.hash.md5 | MD5 hash. | keyword |
| email.attachments.file.hash.sha1 | SHA1 hash. | keyword |
| email.attachments.file.hash.sha256 | SHA256 hash. | keyword |
| email.attachments.file.mime_type | The MIME media type of the attachment. This value will typically be extracted from the `Content-Type` MIME header field. | keyword |
| email.attachments.file.name | Name of the attachment file including the file extension. | keyword |
| email.attachments.file.size | Attachment file size in bytes. | long |
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
| mimecast.senderDomainInternal | Whether the sender domain is a registered internal domain. | keyword |
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
    "@timestamp": "2024-11-18T16:08:00.000Z",
    "agent": {
        "ephemeral_id": "1fe461ea-1dbc-4674-bff8-4c9ac095f607",
        "id": "40a830ad-e58f-4e72-a8ca-9fd4c517e038",
        "name": "elastic-agent-71745",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.threat_intel_malware_customer",
        "namespace": "45715",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "40a830ad-e58f-4e72-a8ca-9fd4c517e038",
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
        "dataset": "mimecast.threat_intel_malware_customer",
        "ingested": "2026-07-27T21:39:01Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2024-11-18T16:08Z\",\"id\":\"indicator--366fad17-1142-4f18-a488-802b2127b30c\",\"labels\":[\"malicious-activity\"],\"modified\":\"2024-11-18T16:08Z\",\"pattern\":\"[file:hashes.'SHA-256' = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f']\",\"type\":\"indicator\",\"valid_from\":\"2024-11-18T16:08Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "mimecast": {
        "id": "indicator--366fad17-1142-4f18-a488-802b2127b30c",
        "labels": [
            "malicious-activity"
        ],
        "pattern": "[file:hashes.'SHA-256' = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f']",
        "type": "indicator"
    },
    "related": {
        "hash": [
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
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
                    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                }
            },
            "first_seen": "2024-11-18T16:08:00.000Z",
            "modified_at": "2024-11-18T16:08:00.000Z",
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
| email.attachments | A list of objects describing the attachment files sent along with an email message. | nested |
| email.attachments.file.extension | Attachment file extension, excluding the leading dot. | keyword |
| email.attachments.file.name | Name of the attachment file including the file extension. | keyword |
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
    "@timestamp": "2024-11-18T23:45:00.000Z",
    "agent": {
        "ephemeral_id": "1ce8a3d0-6a85-4038-8b63-a70b76ae4f4e",
        "id": "97ebdfa3-58b7-4cdc-8892-e3faf047717a",
        "name": "elastic-agent-10317",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.threat_intel_malware_grid",
        "namespace": "14663",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "97ebdfa3-58b7-4cdc-8892-e3faf047717a",
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
        "dataset": "mimecast.threat_intel_malware_grid",
        "ingested": "2026-07-27T21:40:41Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2024-11-18T23:45Z\",\"id\":\"indicator--46e1c0cf-a90c-413d-94b2-7fa889e79fe7\",\"labels\":[\"malicious-activity\"],\"modified\":\"2024-11-18T23:45Z\",\"pattern\":\"[file:hashes.'SHA-256' = 'f4cbcb0b434a2376bf50ba8949dd83bc866dab481fe49595983bba1f76044670']\",\"type\":\"indicator\",\"valid_from\":\"2024-11-18T23:45Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "mimecast": {
        "id": "indicator--46e1c0cf-a90c-413d-94b2-7fa889e79fe7",
        "labels": [
            "malicious-activity"
        ],
        "pattern": "[file:hashes.'SHA-256' = 'f4cbcb0b434a2376bf50ba8949dd83bc866dab481fe49595983bba1f76044670']",
        "type": "indicator"
    },
    "related": {
        "hash": [
            "f4cbcb0b434a2376bf50ba8949dd83bc866dab481fe49595983bba1f76044670"
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
                    "sha256": "f4cbcb0b434a2376bf50ba8949dd83bc866dab481fe49595983bba1f76044670"
                }
            },
            "first_seen": "2024-11-18T23:45:00.000Z",
            "modified_at": "2024-11-18T23:45:00.000Z",
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
| email.attachments | A list of objects describing the attachment files sent along with an email message. | nested |
| email.attachments.file.extension | Attachment file extension, excluding the leading dot. | keyword |
| email.attachments.file.name | Name of the attachment file including the file extension. | keyword |
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
    "@timestamp": "2024-11-17T00:52:30.000Z",
    "agent": {
        "ephemeral_id": "6c35dc2e-0998-4c38-ab0f-4c724b471421",
        "id": "6d90727b-56a3-4d70-852c-4c594dd67e21",
        "name": "elastic-agent-84142",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.ttp_ap_logs",
        "namespace": "77305",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "6d90727b-56a3-4d70-852c-4c594dd67e21",
        "snapshot": false,
        "version": "8.19.4"
    },
    "email": {
        "attachments": {
            "file": {
                "extension": "xlsx",
                "hash": {
                    "sha256": "168dde02cf41aed3bf31ad831b75d8ee0b738304baa6957c40e29b2487f15116"
                },
                "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "name": "Sandbox Test.xlsx"
            }
        },
        "direction": "internal",
        "from": {
            "address": [
                "eric.boyt@example.com"
            ]
        },
        "message_id": "<675ddc8ccedda6a7-363046@mail.example.net>",
        "subject": "RE",
        "to": {
            "address": [
                "charles.weldon@example.com"
            ]
        }
    },
    "event": {
        "action": "none",
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2024-11-17T00:52:30+0000",
        "dataset": "mimecast.ttp_ap_logs",
        "ingested": "2026-07-27T21:42:31Z",
        "kind": "alert",
        "original": "{\"actionTriggered\":\"none\",\"date\":\"2024-11-17T00:52:30+0000\",\"definition\":\"Default Internal Attachment Protect Definition\",\"details\":\"Malicious                                         \\r\\nTime taken: 0 hrs, 0 min, 1 sec\",\"fileHash\":\"168dde02cf41aed3bf31ad831b75d8ee0b738304baa6957c40e29b2487f15116\",\"fileName\":\"Sandbox Test.xlsx\",\"fileType\":\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\",\"messageId\":\"\\u003c675ddc8ccedda6a7-363046@mail.example.net\\u003e\",\"recipientAddress\":\"charles.weldon@example.com\",\"result\":\"malicious\",\"route\":\"internal\",\"senderAddress\":\"eric.boyt@example.com\",\"subject\":\"RE\"}"
    },
    "input": {
        "type": "cel"
    },
    "mimecast": {
        "details": "Malicious                                         \r\nTime taken: 0 hrs, 0 min, 1 sec",
        "result": "malicious"
    },
    "related": {
        "hash": [
            "168dde02cf41aed3bf31ad831b75d8ee0b738304baa6957c40e29b2487f15116"
        ]
    },
    "rule": {
        "name": "Default Internal Attachment Protect Definition"
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
| email.attachments | A list of objects describing the attachment files sent along with an email message. | nested |
| email.attachments.file.extension | Attachment file extension, excluding the leading dot. | keyword |
| email.attachments.file.hash.sha256 | SHA256 hash. | keyword |
| email.attachments.file.mime_type | The MIME media type of the attachment. This value will typically be extracted from the `Content-Type` MIME header field. | keyword |
| email.attachments.file.name | Name of the attachment file including the file extension. | keyword |
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
    "@timestamp": "2021-11-12T15:27:14.000Z",
    "agent": {
        "ephemeral_id": "7836d37b-77c8-46f3-a57f-b71673ea32de",
        "id": "50458d13-e7ba-49fa-9205-baae2462b578",
        "name": "elastic-agent-22398",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.ttp_ip_logs",
        "namespace": "24544",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "50458d13-e7ba-49fa-9205-baae2462b578",
        "snapshot": false,
        "version": "8.19.4"
    },
    "email": {
        "from": {
            "address": [
                "johndoe@example.com"
            ]
        },
        "message_id": "<2-MN2PR16MB2719879CA4DB60C265F7FD8FB0959@MN2PR16MB2719.namprd16.example.outlook.com>",
        "subject": "Don't read, just fill out!",
        "to": {
            "address": [
                "johndoejr@exampple.com"
            ]
        }
    },
    "event": {
        "action": "none",
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2021-11-12T15:27:14+0000",
        "dataset": "mimecast.ttp_ip_logs",
        "id": "MTOKEN:eNqrVkouLS7Jz00tSs5PSVWyUnI2MXM0N1XSUcpMUbIyMjM3MzCw0FEqSy0qzszPU7Iy1FEqyQMrNDAwV6oFAGP7Ehc",
        "ingested": "2026-07-27T21:45:16Z",
        "kind": "alert",
        "original": "{\"action\":\"none\",\"definition\":\"IP - 1 hit (Tag email)\",\"eventTime\":\"2021-11-12T15:27:14+0000\",\"hits\":1,\"id\":\"MTOKEN:eNqrVkouLS7Jz00tSs5PSVWyUnI2MXM0N1XSUcpMUbIyMjM3MzCw0FEqSy0qzszPU7Iy1FEqyQMrNDAwV6oFAGP7Ehc\",\"identifiers\":[\"internal_user_name\"],\"impersonationResults\":[{\"checkerResult\":\"hit\",\"impersonationDomainSource\":\"internal_user_name\",\"similarDomain\":\"John Doe \\u003cjohndoe_nu@example.com\\u003e\",\"stringSimilarToDomain\":\"John Doe\"}],\"messageId\":\"\\u003c2-MN2PR16MB2719879CA4DB60C265F7FD8FB0959@MN2PR16MB2719.namprd16.example.outlook.com\\u003e\",\"recipientAddress\":\"johndoejr@exampple.com\",\"senderAddress\":\"johndoe@example.com\",\"senderIpAddress\":\"8.8.8.8\",\"subject\":\"Don't read, just fill out!\",\"taggedExternal\":false,\"taggedMalicious\":true}"
    },
    "input": {
        "type": "cel"
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
                "similarDomain": "John Doe <johndoe_nu@example.com>",
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
    "@timestamp": "2024-11-13T13:03:11.000Z",
    "agent": {
        "ephemeral_id": "b7d9f19d-7919-43ed-86fa-31ac220ebd1d",
        "id": "073b3ca7-4566-4379-8ddb-1024cb115517",
        "name": "elastic-agent-93533",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "mimecast.ttp_url_logs",
        "namespace": "89520",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "073b3ca7-4566-4379-8ddb-1024cb115517",
        "snapshot": false,
        "version": "8.19.4"
    },
    "email": {
        "direction": "inbound",
        "from": {
            "address": [
                "gregoryhunt@example.org"
            ]
        },
        "message_id": "<cc11f61d32d018de-152846@mail.example.net>",
        "subject": "Re",
        "to": {
            "address": [
                "mike.a.roberts@example.com"
            ]
        }
    },
    "event": {
        "action": "N/A",
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2024-11-13T13:03:11+0000",
        "dataset": "mimecast.ttp_url_logs",
        "ingested": "2026-07-27T21:46:51Z",
        "kind": "alert",
        "original": "{\"action\":\"warn\",\"actions\":\"Block\",\"adminOverride\":\"N/A\",\"category\":\"Dangerous file extension\",\"creationMethod\":\"Entry Scan\",\"date\":\"2024-11-13T13:03:11+0000\",\"emailPartsDescription\":[\"Attachment\"],\"fromUserEmailAddress\":\"gregoryhunt@example.org\",\"messageId\":\"\\u003ccc11f61d32d018de-152846@mail.example.net\\u003e\",\"route\":\"inbound\",\"scanResult\":\"malicious\",\"sendingIp\":\"203.0.113.42\",\"subject\":\"Re\",\"tagMap\":{\"DangerousFileExt\":{\"ContentCheck:ContentScannersBlocked\":[\".exe\"],\"ContentCheck:DangerousExtsUrlFileDownload\":[\"dll\"],\"ContentCheck:DangerousMimetypesUrlFileDownload\":[\"application/x-msdownload\"],\"Inspect:FileExts\":[\"[exe]\"],\"Inspect:MimeTypes\":[\"[]\"],\"Status\":[\"CustomerSpecific\",\"VerdictBlock\"]}},\"ttpDefinition\":\"Default Inbound URL Protect Definition\",\"url\":\"https://oneclient.sfx.ms/Win/Preview/OneDriveSetup.exe\",\"userAwarenessAction\":\"N/A\",\"userEmailAddress\":\"mike.a.roberts@example.com\",\"userOverride\":\"None\"}"
    },
    "input": {
        "type": "cel"
    },
    "mimecast": {
        "action": "warn",
        "actions": "Block",
        "adminOverride": "N/A",
        "category": "Dangerous file extension",
        "creationMethod": "Entry Scan",
        "emailPartsDescription": [
            "Attachment"
        ],
        "scanResult": "malicious",
        "tagMap": {
            "DangerousFileExt": {
                "ContentCheck_ContentScannersBlocked": [
                    ".exe"
                ],
                "ContentCheck_DangerousExtsUrlFileDownload": [
                    "dll"
                ],
                "ContentCheck_DangerousMimetypesUrlFileDownload": [
                    "application/x-msdownload"
                ],
                "Inspect_FileExts": [
                    "[exe]"
                ],
                "Inspect_MimeTypes": [
                    "[]"
                ],
                "Status": [
                    "CustomerSpecific",
                    "VerdictBlock"
                ]
            }
        },
        "userOverride": "None"
    },
    "related": {
        "ip": [
            "203.0.113.42"
        ],
        "user": [
            "gregoryhunt@example.org",
            "mike.a.roberts@example.com"
        ]
    },
    "rule": {
        "name": "Default Inbound URL Protect Definition"
    },
    "source": {
        "ip": "203.0.113.42"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mimecast-ttp-url"
    ],
    "url": {
        "domain": "oneclient.sfx.ms",
        "extension": "exe",
        "original": "https://oneclient.sfx.ms/Win/Preview/OneDriveSetup.exe",
        "path": "/Win/Preview/OneDriveSetup.exe",
        "scheme": "https"
    },
    "user": {
        "email": [
            "mike.a.roberts@example.com"
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

