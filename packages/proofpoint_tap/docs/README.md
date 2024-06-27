# Proofpoint TAP

The Proofpoint TAP integration collects and parses data from the Proofpoint TAP REST APIs.

## Compatibility

This module has been tested against `SIEM API v2`.

## Configurations

The service principal and secret are used to authenticate to the SIEM API. To generate TAP Service Credentials please follow the following steps.  
1. Log in to the [_TAP dashboard_](https://threatinsight.proofpoint.com).  
2. Navigate to **Settings > Connected Applications**.  
3. Click **Create New Credential**.  
4. Name the new credential set and click **Generate**.  
5. Copy the **Service Principal** and **Secret** and save them for later use.  
For the more information on generating TAP credentials please follow the steps mentioned in the link [_Generate TAP Service Credentials_](https://ptr-docs.proofpoint.com/ptr-guides/integrations-files/ptr-tap/#generate-tap-service-credentials).


## Logs

### Clicks Blocked

This is the `clicks_blocked` dataset.

NOTE: For the `clicks_blocked` dataset, `source.ip` corresponds to the Proofpoint `senderIP` — the IP of the email sender — and `destination.ip` corresponds to `clickIP` — the IP of the click destination.

An example event for `clicks_blocked` looks as following:

```json
{
    "@timestamp": "2022-03-30T10:11:12.000Z",
    "agent": {
        "ephemeral_id": "ae779a95-f06b-4c4b-b5ef-85bd0374ec45",
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "proofpoint_tap.clicks_blocked",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.112"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "snapshot": false,
        "version": "8.10.1"
    },
    "email": {
        "from": {
            "address": [
                "abc123@example.com"
            ]
        },
        "message_id": "12345678912345.12345.mail@example.com",
        "to": {
            "address": [
                "9c52aa64228824247c48df69b066e5a7@example.com"
            ]
        }
    },
    "event": {
        "action": [
            "denied"
        ],
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2023-09-22T17:31:59.691Z",
        "dataset": "proofpoint_tap.clicks_blocked",
        "id": "a5c9f8bb-1234-1234-1234-dx9xxx2xx9xxx",
        "ingested": "2023-09-22T17:32:02Z",
        "kind": "event",
        "original": "{\"GUID\":\"ZcxxxxVxyxFxyxLxxxDxVxx4xxxxx\",\"campaignId\":\"46x01x8x-x899-404x-xxx9-111xx393d1x7\",\"classification\":\"malware\",\"clickIP\":\"89.160.20.112\",\"clickTime\":\"2022-03-30T10:11:12.000Z\",\"id\":\"a5c9f8bb-1234-1234-1234-dx9xxx2xx9xxx\",\"messageID\":\"12345678912345.12345.mail@example.com\",\"recipient\":\"9c52aa64228824247c48df69b066e5a7@example.com\",\"sender\":\"abc123@example.com\",\"senderIP\":\"81.2.69.143\",\"threatID\":\"502b7xxxx0x5x1x3xb6xcxexbxxxxxxxcxxexc6xbxxxxxxdx7fxcx6x9xxxx9xdxxxxxxxx5f\",\"threatStatus\":\"active\",\"threatTime\":\"2022-03-21T14:40:31.000Z\",\"threatURL\":\"https://threatinsight.proofpoint.com/a2abc123-1234-1234-1234-babcded1234/threat/email/502xxxxxxxxxcebxxxxxxxxxxa04277xxxxx5dxc6xxxxxxxxx5f\",\"url\":\"https://www.example.com/abcdabcd123?query=0\",\"userAgent\":\"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/199.0.427504638 Mobile/15E148 Safari/604.1\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "proofpoint_tap": {
        "clicks_blocked": {
            "campaign_id": "46x01x8x-x899-404x-xxx9-111xx393d1x7",
            "classification": "malware",
            "threat": {
                "id": "502b7xxxx0x5x1x3xb6xcxexbxxxxxxxcxxexc6xbxxxxxxdx7fxcx6x9xxxx9xdxxxxxxxx5f",
                "status": "active",
                "time": "2022-03-21T14:40:31.000Z",
                "url": "https://threatinsight.proofpoint.com/a2abc123-1234-1234-1234-babcded1234/threat/email/502xxxxxxxxxcebxxxxxxxxxxa04277xxxxx5dxc6xxxxxxxxx5f"
            }
        },
        "guid": "ZcxxxxVxyxFxyxLxxxDxVxx4xxxxx"
    },
    "related": {
        "ip": [
            "81.2.69.143",
            "89.160.20.112"
        ]
    },
    "source": {
        "ip": "81.2.69.143"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "proofpoint_tap-clicks_blocked"
    ],
    "url": {
        "domain": "www.example.com",
        "full": "https://www.example.com/abcdabcd123?query=0",
        "path": "/abcdabcd123",
        "query": "query=0",
        "scheme": "https"
    },
    "user_agent": {
        "device": {
            "name": "iPhone"
        },
        "name": "Google",
        "original": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/199.0.427504638 Mobile/15E148 Safari/604.1",
        "os": {
            "full": "iOS 14.6",
            "name": "iOS",
            "version": "14.6"
        },
        "version": "199.0.427504638"
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
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| proofpoint_tap.clicks_blocked.campaign_id | An identifier for the campaign of which the threat is a member, if available at the time of the query. Threats can be linked to campaigns even after these events are retrieved. | keyword |
| proofpoint_tap.clicks_blocked.classification | The threat category of the malicious URL. | keyword |
| proofpoint_tap.clicks_blocked.click_time | The time the user clicked on the URL. | date |
| proofpoint_tap.clicks_blocked.sender_ip | The IP address of the sender. | ip |
| proofpoint_tap.clicks_blocked.threat.id | The unique identifier associated with this threat. It can be used to query the forensics and campaign endpoints. | keyword |
| proofpoint_tap.clicks_blocked.threat.status | The current state of the threat. | keyword |
| proofpoint_tap.clicks_blocked.threat.time | Proofpoint identified the URL as a threat at this time. | date |
| proofpoint_tap.clicks_blocked.threat.url | A link to the entry on the TAP Dashboard for the particular threat. | keyword |
| proofpoint_tap.guid | The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique. | keyword |


### Clicks Permitted

This is the `clicks_permitted` dataset.

NOTE: For the `clicks_permitted` dataset, `source.ip` corresponds to the Proofpoint `senderIP` — the IP of the email sender — and `destination.ip` corresponds to `clickIP` — the IP of the click destination.

An example event for `clicks_permitted` looks as following:

```json
{
    "@timestamp": "2022-03-21T20:39:37.000Z",
    "agent": {
        "ephemeral_id": "9ed6d678-8adf-4976-bd88-2df7b0511246",
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "proofpoint_tap.clicks_permitted",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.112"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "snapshot": false,
        "version": "8.10.1"
    },
    "email": {
        "from": {
            "address": [
                "abc123@example.com"
            ]
        },
        "message_id": "12345678912345.12345.mail@example.com",
        "to": {
            "address": [
                "abc@example.com"
            ]
        }
    },
    "event": {
        "action": [
            "allowed"
        ],
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2023-09-22T17:32:59.985Z",
        "dataset": "proofpoint_tap.clicks_permitted",
        "id": "de7eef56-1234-1234-1234-5xxfx7xxxdxxxx",
        "ingested": "2023-09-22T17:33:02Z",
        "kind": "event",
        "original": "{\"GUID\":\"cTxxxxxxzx7xxxxxxxxxx8x4xwxx\",\"campaignId\":\"46x01x8x-x899-404x-xxx9-111xx393d1x7\",\"classification\":\"phish\",\"clickIP\":\"89.160.20.112\",\"clickTime\":\"2022-03-21T20:39:37.000Z\",\"id\":\"de7eef56-1234-1234-1234-5xxfx7xxxdxxxx\",\"messageID\":\"12345678912345.12345.mail@example.com\",\"recipient\":\"abc@example.com\",\"sender\":\"abc123@example.com\",\"senderIP\":\"81.2.69.143\",\"threatID\":\"92c17aaxxxxxxxxxx07xx7xxxx9xexcx3x3xxxxxx8xx3xxxx\",\"threatStatus\":\"active\",\"threatTime\":\"2022-03-30T10:05:57.000Z\",\"threatURL\":\"https://threatinsight.proofpoint.com/a2abc123-1234-1234-1234-babcded1234/threat/email/92c17aaxxxxxxxxxx07xx7xxxx9xexcx3x3xxxxxx8xx3xxxx\",\"url\":\"https://example.com/collab/?id=x4x3x6xsx1xxxx8xEdxexnxxxaxX\",\"userAgent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36 Edg/99.0.1150.46\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "proofpoint_tap": {
        "clicks_permitted": {
            "campaign_id": "46x01x8x-x899-404x-xxx9-111xx393d1x7",
            "classification": "phish",
            "threat": {
                "id": "92c17aaxxxxxxxxxx07xx7xxxx9xexcx3x3xxxxxx8xx3xxxx",
                "status": "active",
                "time": "2022-03-30T10:05:57.000Z",
                "url": "https://threatinsight.proofpoint.com/a2abc123-1234-1234-1234-babcded1234/threat/email/92c17aaxxxxxxxxxx07xx7xxxx9xexcx3x3xxxxxx8xx3xxxx"
            }
        },
        "guid": "cTxxxxxxzx7xxxxxxxxxx8x4xwxx"
    },
    "related": {
        "ip": [
            "81.2.69.143",
            "89.160.20.112"
        ]
    },
    "source": {
        "ip": "81.2.69.143"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "proofpoint_tap-clicks_permitted"
    ],
    "url": {
        "domain": "example.com",
        "full": "https://example.com/collab/?id=x4x3x6xsx1xxxx8xEdxexnxxxaxX",
        "path": "/collab/",
        "query": "id=x4x3x6xsx1xxxx8xEdxexnxxxaxX",
        "scheme": "https"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Edge",
        "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36 Edg/99.0.1150.46",
        "os": {
            "full": "Windows 10",
            "name": "Windows",
            "version": "10"
        },
        "version": "99.0.1150.46"
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
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| proofpoint_tap.clicks_permitted.campaign_id | An identifier for the campaign of which the threat is a member, if available at the time of the query. Threats can be linked to campaigns even after these events are retrieved. | keyword |
| proofpoint_tap.clicks_permitted.classification | The threat category of the malicious URL. | keyword |
| proofpoint_tap.clicks_permitted.click_time | The time the user clicked on the URL. | date |
| proofpoint_tap.clicks_permitted.sender_ip | The IP address of the sender. | ip |
| proofpoint_tap.clicks_permitted.threat.id | The unique identifier associated with this threat. It can be used to query the forensics and campaign endpoints. | keyword |
| proofpoint_tap.clicks_permitted.threat.status | The current state of the threat. | keyword |
| proofpoint_tap.clicks_permitted.threat.time | Proofpoint identified the URL as a threat at this time. | date |
| proofpoint_tap.clicks_permitted.threat.url | A link to the entry on the TAP Dashboard for the particular threat. | keyword |
| proofpoint_tap.guid | The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique. | keyword |


### Message Blocked 

This is the `message_blocked` dataset.

An example event for `message_blocked` looks as following:

```json
{
    "@timestamp": "2021-11-25T09:10:00.050Z",
    "agent": {
        "ephemeral_id": "2738078c-875f-4284-984f-5858cbba75c9",
        "id": "633dac72-aecd-41d9-88df-dd066a3b83ea",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "proofpoint_tap.message_blocked",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "633dac72-aecd-41d9-88df-dd066a3b83ea",
        "snapshot": false,
        "version": "8.13.0"
    },
    "email": {
        "attachments": [
            {
                "file": {
                    "hash": {
                        "md5": "b10a8db164e0754105b7a99be72e3fe5",
                        "sha256": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
                    },
                    "mime_type": "text/plain",
                    "name": "text.txt"
                }
            },
            {
                "file": {
                    "hash": {
                        "md5": "b10a8db164e0754105b7a99be72e3fe5",
                        "sha256": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
                    },
                    "mime_type": "application/pdf",
                    "name": "text.pdf"
                }
            }
        ],
        "cc": {
            "address": [
                "abc@example.com"
            ]
        },
        "delivery_timestamp": "2021-11-25T09:10:00.050Z",
        "from": {
            "address": [
                "abc@example.com"
            ]
        },
        "message_id": "12345678912345.12345.mail@example.com",
        "sender": {
            "address": "x99x7x5580193x6x51x597xx2x0210@example.com"
        },
        "subject": "Please find a totally safe invoice attached.",
        "to": {
            "address": [
                "example.abc@example.com",
                "hey.hello@example.com"
            ]
        },
        "x_mailer": "Spambot v2.5"
    },
    "event": {
        "action": [
            "denied"
        ],
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2024-04-03T23:27:42.516Z",
        "dataset": "proofpoint_tap.message_blocked",
        "ingested": "2024-04-03T23:27:46Z",
        "kind": "event",
        "original": "{\"GUID\":\"x11xxxx1-12f9-111x-x12x-1x1x123456xx\",\"QID\":\"x2XXxXXX111111\",\"ccAddresses\":[\"abc@example.com\"],\"clusterId\":\"pharmtech_hosted\",\"completelyRewritten\":\"true\",\"fromAddress\":\"abc@example.com\",\"headerCC\":\"\\\"Example Abc\\\" \\u003cabc@example.com\\u003e\",\"headerFrom\":\"\\\"A. Bc\\\" \\u003cabc@example.com\\u003e\",\"headerReplyTo\":null,\"headerTo\":\"\\\"Aa Bb\\\" \\u003caa.bb@example.com\\u003e; \\\"Hey Hello\\\" \\u003chey.hello@example.com\\u003e\",\"impostorScore\":0,\"malwareScore\":100,\"messageID\":\"12345678912345.12345.mail@example.com\",\"messageParts\":[{\"contentType\":\"text/plain\",\"disposition\":\"inline\",\"filename\":\"text.txt\",\"md5\":\"b10a8db164e0754105b7a99be72e3fe5\",\"oContentType\":\"text/plain\",\"sandboxStatus\":\"unsupported\",\"sha256\":\"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e\"},{\"contentType\":\"application/pdf\",\"disposition\":\"attached\",\"filename\":\"text.pdf\",\"md5\":\"b10a8db164e0754105b7a99be72e3fe5\",\"oContentType\":\"application/pdf\",\"sandboxStatus\":\"threat\",\"sha256\":\"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e\"}],\"messageTime\":\"2021-11-25T09:10:00.050Z\",\"modulesRun\":[\"pdr\",\"sandbox\",\"spam\",\"urldefense\"],\"phishScore\":46,\"policyRoutes\":[\"default_inbound\",\"executives\"],\"quarantineFolder\":\"Attachment Defense\",\"quarantineRule\":\"module.sandbox.threat\",\"recipient\":[\"example.abc@example.com\",\"hey.hello@example.com\"],\"replyToAddress\":null,\"sender\":\"x99x7x5580193x6x51x597xx2x0210@example.com\",\"senderIP\":\"175.16.199.1\",\"spamScore\":4,\"subject\":\"Please find a totally safe invoice attached.\",\"threatsInfoMap\":[{\"campaignId\":\"46x01x8x-x899-404x-xxx9-111xx393d1x7\",\"classification\":\"MALWARE\",\"threat\":\"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e\",\"threatId\":\"2xxx740f143fc1aa4c1cd0146d334x5593b1428x6x062b2c406e5efe8xxx95xx\",\"threatStatus\":\"active\",\"threatTime\":\"2021-11-25T09:10:00.050Z\",\"threatType\":\"ATTACHMENT\",\"threatUrl\":\"https://www.example.com/?name=john\"},{\"campaignId\":\"46x01x8x-x899-404x-xxx9-111xx393d1x7\",\"classification\":\"MALWARE\",\"threat\":\"example.com\",\"threatId\":\"3xx97xx852c66a7xx761450xxxxxx9f4ffab74715b591294f78b5e37a76481xx\",\"threatTime\":\"2021-07-20T05:00:00.050Z\",\"threatType\":\"URL\",\"threatUrl\":\"https://www.example.com/?name=john\"}],\"toAddresses\":[\"example.abc@example.com\",\"hey.hello@example.com\"],\"xmailer\":\"Spambot v2.5\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "proofpoint_tap": {
        "guid": "x11xxxx1-12f9-111x-x12x-1x1x123456xx",
        "message_blocked": {
            "completely_rewritten": "true",
            "header": {
                "cc": "\"Example Abc\" <abc@example.com>",
                "from": "\"A. Bc\" abc@example.com",
                "to": "\"Aa Bb\" <aa.bb@example.com>; \"Hey Hello\" <hey.hello@example.com>"
            },
            "impostor_score": 0,
            "malware_score": 100,
            "message_parts": [
                {
                    "disposition": "inline",
                    "o_content_type": "text/plain",
                    "sandbox_status": "unsupported"
                },
                {
                    "disposition": "attached",
                    "o_content_type": "application/pdf",
                    "sandbox_status": "threat"
                }
            ],
            "modules_run": [
                "pdr",
                "sandbox",
                "spam",
                "urldefense"
            ],
            "phish_score": 46,
            "policy_routes": [
                "default_inbound",
                "executives"
            ],
            "qid": "x2XXxXXX111111",
            "quarantine": {
                "folder": "Attachment Defense",
                "rule": "module.sandbox.threat"
            },
            "recipient": [
                "example.abc@example.com",
                "hey.hello@example.com"
            ],
            "spam_score": 4,
            "threat_info_map": [
                {
                    "campaign_id": "46x01x8x-x899-404x-xxx9-111xx393d1x7",
                    "classification": "MALWARE",
                    "threat": {
                        "artifact": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
                        "id": "2xxx740f143fc1aa4c1cd0146d334x5593b1428x6x062b2c406e5efe8xxx95xx",
                        "status": "active",
                        "time": "2021-11-25T09:10:00.050Z",
                        "type": "ATTACHMENT",
                        "url": "https://www.example.com/?name=john"
                    }
                },
                {
                    "campaign_id": "46x01x8x-x899-404x-xxx9-111xx393d1x7",
                    "classification": "MALWARE",
                    "threat": {
                        "artifact": "example.com",
                        "id": "3xx97xx852c66a7xx761450xxxxxx9f4ffab74715b591294f78b5e37a76481xx",
                        "time": "2021-07-20T05:00:00.050Z",
                        "type": "URL",
                        "url": "https://www.example.com/?name=john"
                    }
                }
            ],
            "to_addresses": [
                "example.abc@example.com",
                "hey.hello@example.com"
            ]
        }
    },
    "related": {
        "hash": [
            "b10a8db164e0754105b7a99be72e3fe5",
            "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        ],
        "ip": [
            "175.16.199.1"
        ]
    },
    "source": {
        "geo": {
            "city_name": "Changchun",
            "continent_name": "Asia",
            "country_iso_code": "CN",
            "country_name": "China",
            "location": {
                "lat": 43.88,
                "lon": 125.3228
            },
            "region_iso_code": "CN-22",
            "region_name": "Jilin Sheng"
        },
        "ip": "175.16.199.1"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "proofpoint_tap-message_blocked"
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
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| proofpoint_tap.guid | The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique. | keyword |
| proofpoint_tap.message_blocked.cluster | The name of the PPS cluster which processed the message. | keyword |
| proofpoint_tap.message_blocked.completely_rewritten | The rewrite status of the message. If value is 'true', all instances of URL threats within the message were successfully rewritten. If the value is 'false', at least one instance of the a threat URL was not rewritten. If the value is 'na', the message did not contain any URL-based threats. | keyword |
| proofpoint_tap.message_blocked.header.cc |  | keyword |
| proofpoint_tap.message_blocked.header.from | The full content of the From: header, including any friendly name. | keyword |
| proofpoint_tap.message_blocked.header.replyto | If present, the full content of the Reply-To: header, including any friendly names. | keyword |
| proofpoint_tap.message_blocked.header.to |  | keyword |
| proofpoint_tap.message_blocked.impostor_score | The impostor score of the message. Higher scores indicate higher certainty. | double |
| proofpoint_tap.message_blocked.malware_score | The malware score of the message. Higher scores indicate higher certainty. | long |
| proofpoint_tap.message_blocked.message_parts.disposition | If the value is 'inline,' the messagePart is a message body. If the value is 'attached,' the messagePart is an attachment. | keyword |
| proofpoint_tap.message_blocked.message_parts.o_content_type | The declared Content-Type of the messagePart. | keyword |
| proofpoint_tap.message_blocked.message_parts.sandbox_status | The verdict returned by the sandbox during the scanning process. If the value is 'unsupported', the messagePart is not supported by Attachment Defense and was not scanned. If the value is 'clean', the sandbox returned a clean verdict. If the value is 'threat', the sandbox returned a malicious verdict. If the value is 'prefilter', the messagePart contained no active content, and was therefore not sent to the sandboxing service. If the value is 'uploaded,' the message was uploaded by PPS to the sandboxing service, but did not yet have a verdict at the time the message was processed. If the value is 'inprogress,' the attachment had been uploaded and was awaiting scanning at the time the message was processed. If the verdict is 'uploaddisabled,' the attachment was eligible for scanning, but was not uploaded because of PPS policy. | keyword |
| proofpoint_tap.message_blocked.message_size | The size in bytes of the message, including headers and attachments. | long |
| proofpoint_tap.message_blocked.modules_run | The list of PPS modules which processed the message. | keyword |
| proofpoint_tap.message_blocked.phish_score | The phish score of the message. Higher scores indicate higher certainty. | long |
| proofpoint_tap.message_blocked.policy_routes | The policy routes that the message matched during processing by PPS. | keyword |
| proofpoint_tap.message_blocked.qid | The queue ID of the message within PPS. It can be used to identify the message in PPS and is not unique. | keyword |
| proofpoint_tap.message_blocked.quarantine.folder | The name of the folder which contains the quarantined message. This appears only for messagesBlocked. | keyword |
| proofpoint_tap.message_blocked.quarantine.rule | The name of the rule which quarantined the message. This appears only for messagesBlocked events. | keyword |
| proofpoint_tap.message_blocked.recipient | An array containing the email addresses of the SMTP (envelope) recipients. | keyword |
| proofpoint_tap.message_blocked.spam_score | The spam score of the message. Higher scores indicate higher certainty. | long |
| proofpoint_tap.message_blocked.threat_info_map.campaign_id | An identifier for the campaign of which the threat is a member, if available at the time of the query. Threats can be linked to campaigns even after these events are retrieved. | keyword |
| proofpoint_tap.message_blocked.threat_info_map.classification | The category of threat found in the message. | keyword |
| proofpoint_tap.message_blocked.threat_info_map.threat.artifact | The artifact which was condemned by Proofpoint. The malicious URL, hash of the attachment threat, or email address of the impostor sender. | keyword |
| proofpoint_tap.message_blocked.threat_info_map.threat.id | The unique identifier associated with this threat. It can be used to query the forensics and campaign endpoints. | keyword |
| proofpoint_tap.message_blocked.threat_info_map.threat.status | The current state of the threat. | keyword |
| proofpoint_tap.message_blocked.threat_info_map.threat.time | Proofpoint assigned the threatStatus at this time. | date |
| proofpoint_tap.message_blocked.threat_info_map.threat.type | Whether the threat was an attachment, URL, or message type. | keyword |
| proofpoint_tap.message_blocked.threat_info_map.threat.url | A link to the entry about the threat on the TAP Dashboard. | keyword |
| proofpoint_tap.message_blocked.to_addresses | A list of email addresses contained within the To: header, excluding friendly names. | keyword |


### Message Delivered 

This is the `message_delivered` dataset.

An example event for `message_delivered` looks as following:

```json
{
    "@timestamp": "2022-01-01T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "f01ebff4-ea3a-4827-ac33-e7af925ed197",
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "proofpoint_tap.message_delivered",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "snapshot": false,
        "version": "8.10.1"
    },
    "email": {
        "delivery_timestamp": "2022-01-01T00:00:00.000Z",
        "to": {
            "address": [
                "fxxxxhxsxxvxbcx2xx5xxx6x3xx26@example.com"
            ]
        }
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "created": "2023-09-22T17:35:00.037Z",
        "dataset": "proofpoint_tap.message_delivered",
        "id": "2hsvbU-i8abc123-12345-xxxxx12",
        "ingested": "2023-09-22T17:35:03Z",
        "kind": "event",
        "original": "{\"GUID\":\"NxxxsxvxbxUxixcx2xxxxx5x6xWxBxOxxxxxjxx\",\"QID\":null,\"ccAddresses\":null,\"cluster\":\"pharmtech_hosted\",\"completelyRewritten\":true,\"fromAddress\":null,\"headerFrom\":null,\"headerReplyTo\":null,\"id\":\"2hsvbU-i8abc123-12345-xxxxx12\",\"impostorScore\":0,\"malwareScore\":0,\"messageID\":\"\",\"messageParts\":null,\"messageSize\":0,\"messageTime\":\"2022-01-01T00:00:00.000Z\",\"modulesRun\":null,\"phishScore\":0,\"policyRoutes\":null,\"quarantineFolder\":null,\"quarantineRule\":null,\"recipient\":[\"fxxxxhxsxxvxbcx2xx5xxx6x3xx26@example.com\"],\"replyToAddress\":null,\"sender\":\"\",\"senderIP\":\"89.160.20.112\",\"spamScore\":0,\"subject\":null,\"threatsInfoMap\":[{\"campaignID\":null,\"classification\":\"spam\",\"threat\":\"http://zbcd123456x0.example.com\",\"threatID\":\"b7exxxxxxxx0d10xxxxxxe2xxxxxxxxxxxx81cxxxxxx034ac9cxxxxxxxxxxxxb\",\"threatStatus\":\"active\",\"threatTime\":\"2021-11-25T13:02:58.640Z\",\"threatType\":\"url\",\"threatUrl\":\"https://threatinsight.proofpoint.com/aaabcdef-1234-b1abcdefghe/threat/email/b7exxxxxxxx0d10xxxxxxe2xxxxxxxxxxxx81cxxxxxx034ac9cxxxxxxxxxxxxb\"},{\"campaignID\":null,\"classification\":\"phish\",\"threat\":\"http://zbcd123456x0.example.com\",\"threatID\":\"aaabcdefg123456f009971a9c193abcdefg123456bf5abcdefg1234566\",\"threatStatus\":\"active\",\"threatTime\":\"2021-07-19T10:28:15.100Z\",\"threatType\":\"url\",\"threatUrl\":\"https://threatinsight.proofpoint.com/aaabcdef-1234-b1abcdefghe/threat/email/b7exxxxxxxx0d10xxxxxxe2xxxxxxxxxxxx81cxxxxxx034ac9cxxxxxxxxxxxxb\"}],\"toAddresses\":null,\"xmailer\":null}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "proofpoint_tap": {
        "guid": "NxxxsxvxbxUxixcx2xxxxx5x6xWxBxOxxxxxjxx",
        "message_delivered": {
            "cluster": "pharmtech_hosted",
            "completely_rewritten": "true",
            "impostor_score": 0,
            "malware_score": 0,
            "message_size": 0,
            "phish_score": 0,
            "recipient": [
                "fxxxxhxsxxvxbcx2xx5xxx6x3xx26@example.com"
            ],
            "spam_score": 0,
            "threat_info_map": [
                {
                    "classification": "spam",
                    "threat": {
                        "artifact": "http://zbcd123456x0.example.com",
                        "id": "b7exxxxxxxx0d10xxxxxxe2xxxxxxxxxxxx81cxxxxxx034ac9cxxxxxxxxxxxxb",
                        "status": "active",
                        "time": "2021-11-25T13:02:58.640Z",
                        "type": "url",
                        "url": "https://threatinsight.proofpoint.com/aaabcdef-1234-b1abcdefghe/threat/email/b7exxxxxxxx0d10xxxxxxe2xxxxxxxxxxxx81cxxxxxx034ac9cxxxxxxxxxxxxb"
                    }
                },
                {
                    "classification": "phish",
                    "threat": {
                        "artifact": "http://zbcd123456x0.example.com",
                        "id": "aaabcdefg123456f009971a9c193abcdefg123456bf5abcdefg1234566",
                        "status": "active",
                        "time": "2021-07-19T10:28:15.100Z",
                        "type": "url",
                        "url": "https://threatinsight.proofpoint.com/aaabcdef-1234-b1abcdefghe/threat/email/b7exxxxxxxx0d10xxxxxxe2xxxxxxxxxxxx81cxxxxxx034ac9cxxxxxxxxxxxxb"
                    }
                }
            ]
        }
    },
    "related": {
        "ip": [
            "89.160.20.112"
        ]
    },
    "source": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.112"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "proofpoint_tap-message_delivered"
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
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| proofpoint_tap.guid | The ID of the message within PPS. It can be used to identify the message in PPS and is guaranteed to be unique. | keyword |
| proofpoint_tap.message_delivered.cluster | The name of the PPS cluster which processed the message. | keyword |
| proofpoint_tap.message_delivered.completely_rewritten | The rewrite status of the message. If value is 'true', all instances of URL threats within the message were successfully rewritten. If the value is 'false', at least one instance of the a threat URL was not rewritten. If the value is 'na', the message did not contain any URL-based threats. | keyword |
| proofpoint_tap.message_delivered.header.from | The full content of the From: header, including any friendly name. | keyword |
| proofpoint_tap.message_delivered.header.replyto | If present, the full content of the Reply-To: header, including any friendly names. | keyword |
| proofpoint_tap.message_delivered.impostor_score | The impostor score of the message. Higher scores indicate higher certainty. | double |
| proofpoint_tap.message_delivered.malware_score | The malware score of the message. Higher scores indicate higher certainty. | long |
| proofpoint_tap.message_delivered.message_parts.disposition | If the value is 'inline,' the messagePart is a message body. If the value is 'attached,' the messagePart is an attachment. | keyword |
| proofpoint_tap.message_delivered.message_parts.o_content_type | The declared Content-Type of the messagePart. | keyword |
| proofpoint_tap.message_delivered.message_parts.sandbox_status | The verdict returned by the sandbox during the scanning process. If the value is 'unsupported', the messagePart is not supported by Attachment Defense and was not scanned. If the value is 'clean', the sandbox returned a clean verdict. If the value is 'threat', the sandbox returned a malicious verdict. If the value is 'prefilter', the messagePart contained no active content, and was therefore not sent to the sandboxing service. If the value is 'uploaded,' the message was uploaded by PPS to the sandboxing service, but did not yet have a verdict at the time the message was processed. If the value is 'inprogress,' the attachment had been uploaded and was awaiting scanning at the time the message was processed. If the verdict is 'uploaddisabled,' the attachment was eligible for scanning, but was not uploaded because of PPS policy. | keyword |
| proofpoint_tap.message_delivered.message_size | The size in bytes of the message, including headers and attachments. | long |
| proofpoint_tap.message_delivered.modules_run | The list of PPS modules which processed the message. | keyword |
| proofpoint_tap.message_delivered.phish_score | The phish score of the message. Higher scores indicate higher certainty. | long |
| proofpoint_tap.message_delivered.policy_routes | The policy routes that the message matched during processing by PPS. | keyword |
| proofpoint_tap.message_delivered.qid | The queue ID of the message within PPS. It can be used to identify the message in PPS and is not unique. | keyword |
| proofpoint_tap.message_delivered.quarantine.folder | The name of the folder which contains the quarantined message. This appears only for messagesBlocked. | keyword |
| proofpoint_tap.message_delivered.quarantine.rule | The name of the rule which quarantined the message. This appears only for messagesBlocked events. | keyword |
| proofpoint_tap.message_delivered.recipient | An array containing the email addresses of the SMTP (envelope) recipients. | keyword |
| proofpoint_tap.message_delivered.spam_score | The spam score of the message. Higher scores indicate higher certainty. | long |
| proofpoint_tap.message_delivered.threat_info_map.campaign_id | An identifier for the campaign of which the threat is a member, if available at the time of the query. Threats can be linked to campaigns even after these events are retrieved. | keyword |
| proofpoint_tap.message_delivered.threat_info_map.classification | The category of threat found in the message. | keyword |
| proofpoint_tap.message_delivered.threat_info_map.threat.artifact | The artifact which was condemned by Proofpoint. The malicious URL, hash of the attachment threat, or email address of the impostor sender. | keyword |
| proofpoint_tap.message_delivered.threat_info_map.threat.id | The unique identifier associated with this threat. It can be used to query the forensics and campaign endpoints. | keyword |
| proofpoint_tap.message_delivered.threat_info_map.threat.status | The current state of the threat. | keyword |
| proofpoint_tap.message_delivered.threat_info_map.threat.time | Proofpoint assigned the threatStatus at this time. | date |
| proofpoint_tap.message_delivered.threat_info_map.threat.type | Whether the threat was an attachment, URL, or message type. | keyword |
| proofpoint_tap.message_delivered.threat_info_map.threat.url | A link to the entry about the threat on the TAP Dashboard. | keyword |
| proofpoint_tap.message_delivered.to_addresses | A list of email addresses contained within the To: header, excluding friendly names. | keyword |

