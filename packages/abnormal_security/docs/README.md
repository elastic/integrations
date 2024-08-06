# Abnormal Security

Abnormal Security is a behavioral AI-based email security platform that learns the behavior of every identity in a cloud email environment and analyzes the risk of every event to block even the most sophisticated attacks.

The Abnormal Security integration collects data for AI Security Mailbox (formerly known as Abuse Mailbox), Audit, Case, and Threat logs using REST API.

## Data streams

The Abnormal Security integration collects four types of logs:

**[AI Security Mailbox](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/AI%20Security%20Mailbox%20(formerly%20known%20as%20Abuse%20Mailbox))** - Get details of AI Security Mailbox.

**[Audit](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Audit%20Logs)** - Get details of Audit logs for Portal.

**[Case](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Cases)** - Get details of Abnormal Cases.

**[Threat](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Threats)** - Get details of Abnormal Threat Logs.

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#_minimum_requirements).

## Setup

### To collect data from the Abnormal Security Client API:

#### Step 1: Go to Portal
* Visit the [Abnormal Security Portal](https://portal.abnormalsecurity.com/home/settings/integrations) and click on the `Abnormal REST API` setting.

#### Step 2: Generating the authentication token
* Retrieve your authentication token. This token will be used further in the Elastic integration setup to authenticate and access different Abnormal Security Logs.

#### Step 3: IP allowlisting
* Abnormal Security requires you to restrict API access based on source IP. So in order for the integration to work, user needs to update the IP allowlisting to include the external source IP of the endpoint running the integration via Elastic Agent.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Abnormal Security.
3. Click on the "Abnormal Security" integration from the search results.
4. Click on the "Add Abnormal Security" button to add the integration.
5. Add all the required integration configuration parameters, including Access Token, Interval, Initial Interval and Page Size to enable data collection.
6. Click on "Save and continue" to save the integration.

**Note**: By default, the URL is set to `https://api.abnormalplatform.com`. We have observed that Abnormal Security Base URL changes based on location so find your own base URL.

## Logs reference

### AI Security Mailbox

This is the `ai_security_mailbox` dataset.

#### Example

An example event for `ai_security_mailbox` looks as following:

```json
{
    "@timestamp": "2024-07-26T10:30:06.000Z",
    "abnormal_security": {
        "ai_security_mailbox": {
            "attack": {
                "type": "Attack Type: Graymail"
            },
            "campaign_id": "fff51768-c446-34e1-97a8-9802c29c3ebd",
            "first_reported": "2024-07-26T10:30:06.000Z",
            "from": {
                "address": "bob@example.com",
                "name": "bob@example.com"
            },
            "judgement_status": "Safe",
            "last_reported": "2024-07-26T10:30:06.000Z",
            "message_id": "7063250485337877109",
            "overall_status": "No Action Needed",
            "recipient": {
                "address": "john@example.com",
                "name": "john"
            },
            "subject": "Days of Understanding 2024"
        }
    },
    "agent": {
        "ephemeral_id": "becef71f-2db4-4fa6-92f2-773b45c2f1bc",
        "id": "7aaba523-565c-4597-bc42-59135436336b",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "abnormal_security.ai_security_mailbox",
        "namespace": "72265",
        "type": "logs"
    },
    "destination": {
        "user": {
            "name": "john"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7aaba523-565c-4597-bc42-59135436336b",
        "snapshot": false,
        "version": "8.13.0"
    },
    "email": {
        "from": {
            "address": [
                "bob@example.com"
            ]
        },
        "subject": "Days of Understanding 2024",
        "to": {
            "address": [
                "john@example.com"
            ]
        }
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "abnormal_security.ai_security_mailbox",
        "id": "7063250485337877109",
        "ingested": "2024-08-06T09:40:30Z",
        "kind": "event",
        "original": "{\"attackType\":\"Attack Type: Graymail\",\"campaignId\":\"fff51768-c446-34e1-97a8-9802c29c3ebd\",\"firstReported\":\"2024-07-26T10:30:06Z\",\"fromAddress\":\"bob@example.com\",\"fromName\":\"bob@example.com\",\"judgementStatus\":\"Safe\",\"lastReported\":\"2024-07-26T10:30:06Z\",\"messageId\":\"7063250485337877109\",\"overallStatus\":\"No Action Needed\",\"recipientAddress\":\"john@example.com\",\"recipientName\":\"john\",\"subject\":\"Days of Understanding 2024\"}"
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Inbound Email Security",
        "vendor": "Abnormal"
    },
    "related": {
        "user": [
            "bob@example.com",
            "john@example.com",
            "john"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "abnormal_security-ai_security_mailbox"
    ],
    "threat": {
        "technique": {
            "name": [
                "Attack Type: Graymail"
            ]
        }
    },
    "user": {
        "email": "bob@example.com"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abnormal_security.ai_security_mailbox.attack.type | The type of threat the message represents. | keyword |
| abnormal_security.ai_security_mailbox.campaign_id | An ID which maps to an abuse campaign. | keyword |
| abnormal_security.ai_security_mailbox.first_reported | Date abuse campaign was first reported. | date |
| abnormal_security.ai_security_mailbox.from.address | The email address of the sender. | keyword |
| abnormal_security.ai_security_mailbox.from.name | The display name of the sender. | keyword |
| abnormal_security.ai_security_mailbox.judgement_status | Judgement status of message. | keyword |
| abnormal_security.ai_security_mailbox.last_reported | Date abuse campaign was last reported. | date |
| abnormal_security.ai_security_mailbox.message_id | A unique identifier for the first message in the abuse campaign. | keyword |
| abnormal_security.ai_security_mailbox.overall_status | Overall status of message. | keyword |
| abnormal_security.ai_security_mailbox.recipient.address | The email address of the recipient. | keyword |
| abnormal_security.ai_security_mailbox.recipient.name | The name of the recipient. | keyword |
| abnormal_security.ai_security_mailbox.subject | Subject of the first email in the abuse campaign. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Audit

This is the `audit` dataset.

#### Example

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2024-07-17T15:39:32.141Z",
    "abnormal_security": {
        "audit": {
            "action": "update_remediation_status",
            "action_details": {
                "request_url": "/v1.0/search_v2/666/purge_messages/"
            },
            "category": "search-and-respond-notifications",
            "source_ip": "81.2.69.142",
            "status": "SUCCESS",
            "timestamp": "2024-07-17T15:39:32.141Z",
            "user": {
                "email": "bob@example.com"
            }
        }
    },
    "agent": {
        "ephemeral_id": "40cced4d-2587-4880-a6ad-3fe697d9ca7f",
        "id": "7aaba523-565c-4597-bc42-59135436336b",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "abnormal_security.audit",
        "namespace": "19380",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7aaba523-565c-4597-bc42-59135436336b",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "update_remediation_status",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "abnormal_security.audit",
        "ingested": "2024-08-06T09:41:39Z",
        "kind": "event",
        "original": "{\"action\":\"update_remediation_status\",\"actionDetails\":{\"providedReason\":\"null\",\"requestUrl\":\"/v1.0/search_v2/666/purge_messages/\"},\"category\":\"search-and-respond-notifications\",\"sourceIp\":\"81.2.69.142\",\"status\":\"SUCCESS\",\"tenantName\":\"\",\"timestamp\":\"2024-07-17 15:39:32.141000+00:00\",\"user\":{\"email\":\"bob@example.com\"}}",
        "outcome": "success",
        "type": [
            "info",
            "change"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Inbound Email Security",
        "vendor": "Abnormal"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ],
        "user": [
            "bob@example.com"
        ]
    },
    "source": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.142"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "abnormal_security-audit"
    ],
    "url": {
        "extension": "0/search_v2/666/purge_messages/",
        "original": "/v1.0/search_v2/666/purge_messages/",
        "path": "/v1.0/search_v2/666/purge_messages/"
    },
    "user": {
        "email": "bob@example.com"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abnormal_security.audit.action | The specific action performed during the event. This field is optional and may not be present. | keyword |
| abnormal_security.audit.action_details.message_id | ID of the message on which an action was performed. | keyword |
| abnormal_security.audit.action_details.provided_reason | Reason provided for performing the action. | keyword |
| abnormal_security.audit.action_details.request_url | URL for the request. | keyword |
| abnormal_security.audit.category | The category of the performed action. | keyword |
| abnormal_security.audit.source_ip | The IP address of the device that caused the event. | ip |
| abnormal_security.audit.status | The result of the event. Returned as either SUCCESS or FAILURE. | keyword |
| abnormal_security.audit.tenant_name | Name of the tenant the user has access to. | keyword |
| abnormal_security.audit.timestamp | Date/time when the event occurred in UTC. | date |
| abnormal_security.audit.user.email | Email address of the user. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Case

This is the `case` dataset.

#### Example

An example event for `case` looks as following:

```json
{
    "@timestamp": "2024-08-06T09:42:32.438Z",
    "abnormal_security": {
        "case": {
            "affected_employee": "john@example.com",
            "analysis": "SIGN_IN",
            "customer_visible_time": "2024-01-05T12:33:25.000Z",
            "first_observed": "2024-01-05T12:33:25.000Z",
            "id": "1234",
            "remediation_status": "Not remediated",
            "severity": "Account Takeover",
            "severity_level": "LOW",
            "status": "Acknowledged (Attack resolved)"
        }
    },
    "agent": {
        "ephemeral_id": "d459a481-d0b8-4f26-afd1-ceed8531465a",
        "id": "7aaba523-565c-4597-bc42-59135436336b",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "abnormal_security.case",
        "namespace": "48573",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7aaba523-565c-4597-bc42-59135436336b",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "sign_in",
        "agent_id_status": "verified",
        "dataset": "abnormal_security.case",
        "id": "1234",
        "ingested": "2024-08-06T09:42:44Z",
        "kind": "event",
        "original": "{\"affectedEmployee\":\"john@example.com\",\"analysis\":\"SIGN_IN\",\"caseId\":1234,\"case_status\":\"Acknowledged (Attack resolved)\",\"customerVisibleTime\":\"2024-01-05T12:33:25+00:00\",\"firstObserved\":\"2024-01-05T12:33:25+00:00\",\"remediation_status\":\"Not remediated\",\"severity\":\"Account Takeover\",\"severity_level\":\"LOW\",\"threatIds\":[]}",
        "severity": 1,
        "start": "2024-01-05T12:33:25.000Z",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Inbound Email Security",
        "vendor": "Abnormal"
    },
    "related": {
        "user": [
            "john@example.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "abnormal_security-case"
    ],
    "user": {
        "email": "john@example.com"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abnormal_security.case.affected_employee | Which employee this case pertains to. | keyword |
| abnormal_security.case.analysis |  | keyword |
| abnormal_security.case.customer_visible_time |  | date |
| abnormal_security.case.description |  | keyword |
| abnormal_security.case.first_observed | First time suspicious behavior was observed. | date |
| abnormal_security.case.id | A unique identifier for this case. | keyword |
| abnormal_security.case.remediation_status |  | keyword |
| abnormal_security.case.severity | Description of the severity level for this case. | keyword |
| abnormal_security.case.severity_level |  | keyword |
| abnormal_security.case.status |  | keyword |
| abnormal_security.case.threat_ids | Threats related to Case. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Threat

This is the `threat` dataset.

#### Example

An example event for `threat` looks as following:

```json
{
    "@timestamp": "2024-07-17T23:25:38.000Z",
    "abnormal_security": {
        "threat": {
            "abx_message_id": "2260288475997441000",
            "abx_portal_url": "https://portal.abnormalsecurity.com/home/threat-center/remediation-history/3456765434567654",
            "attachment_count": 0,
            "attack": {
                "strategy": "Unknown Sender",
                "type": "Spam",
                "vector": "Link"
            },
            "attacked_party": "Employee (Other)",
            "auto_remediated": true,
            "from_address": "john@example.com",
            "from_name": "john",
            "id": "bf255f2d-a2ad-3f50-5075-fdcc24308bbd",
            "impersonated_party": "None / Others",
            "internet_message_id": "<AZz8NUMEST-qmuz77_koic@example>",
            "is_read": false,
            "post_remediated": false,
            "received_time": "2024-07-17T23:25:38.000Z",
            "recipient_address": "bob@example.com",
            "remediation_status": "Auto-Remediated",
            "remediation_timestamp": "2024-07-17T23:25:45.735Z",
            "return_path": "bounce-bob_H181S7GUCF@example.com",
            "sender_domain": "example.com",
            "sender_ip_address": "81.2.69.142",
            "sent_time": "2024-07-17T23:25:29.000Z",
            "subject": "YoU.have.𝗪𝟬0𝗡𝗡 a K0baIt 215-piece_ToooI_Set_Noo0wW..#GBOB",
            "summary_insights": [
                "Abnormal Email Body HTML",
                "Invisible characters found in Email",
                "Suspicious Link",
                "Unusual Sender",
                "Unusual Sender Domain"
            ],
            "to_addresses": [
                "bob@example.com"
            ],
            "url_count": 1,
            "urls": [
                "https://www.example.com/"
            ]
        }
    },
    "agent": {
        "ephemeral_id": "7a47e772-7565-4c03-be8a-43a442be5c92",
        "id": "7aaba523-565c-4597-bc42-59135436336b",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "abnormal_security.threat",
        "namespace": "63490",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7aaba523-565c-4597-bc42-59135436336b",
        "snapshot": false,
        "version": "8.13.0"
    },
    "email": {
        "delivery_timestamp": "2024-07-17T23:25:38.000Z",
        "from": {
            "address": [
                "john@example.com"
            ]
        },
        "message_id": "<AZz8NUMEST-qmuz77_koic@example>",
        "origination_timestamp": "2024-07-17T23:25:29.000Z",
        "subject": "YoU.have.𝗪𝟬0𝗡𝗡 a K0baIt 215-piece_ToooI_Set_Noo0wW..#GBOB",
        "to": {
            "address": [
                "bob@example.com"
            ]
        }
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat",
            "email"
        ],
        "dataset": "abnormal_security.threat",
        "id": "2260288475997441000",
        "ingested": "2024-08-06T09:43:49Z",
        "kind": "enrichment",
        "original": "{\"abxMessageId\":2260288475997441000,\"abxPortalUrl\":\"https://portal.abnormalsecurity.com/home/threat-center/remediation-history/3456765434567654\",\"attachmentCount\":0,\"attachmentNames\":[],\"attackStrategy\":\"Unknown Sender\",\"attackType\":\"Spam\",\"attackVector\":\"Link\",\"attackedParty\":\"Employee (Other)\",\"autoRemediated\":true,\"ccEmails\":[],\"fromAddress\":\"john@example.com\",\"fromName\":\"john\",\"impersonatedParty\":\"None / Others\",\"internetMessageId\":\"\\u003cAZz8NUMEST-qmuz77_koic@example\\u003e\",\"isRead\":false,\"postRemediated\":false,\"receivedTime\":\"2024-07-17T23:25:38Z\",\"recipientAddress\":\"bob@example.com\",\"remediationStatus\":\"Auto-Remediated\",\"remediationTimestamp\":\"2024-07-17T23:25:45.73564Z\",\"replyToEmails\":[],\"returnPath\":\"bounce-bob_H181S7GUCF@example.com\",\"senderDomain\":\"example.com\",\"senderIpAddress\":\"81.2.69.142\",\"sentTime\":\"2024-07-17T23:25:29Z\",\"subject\":\"YoU.have.𝗪𝟬0𝗡𝗡 a K0baIt 215-piece_ToooI_Set_Noo0wW..#GBOB\",\"summaryInsights\":[\"Abnormal Email Body HTML\",\"Invisible characters found in Email\",\"Suspicious Link\",\"Unusual Sender\",\"Unusual Sender Domain\"],\"threatId\":\"bf255f2d-a2ad-3f50-5075-fdcc24308bbd\",\"toAddresses\":[\"bob@example.com\"],\"urlCount\":1,\"urls\":[\"https://www.example.com/\"]}",
        "reference": "https://portal.abnormalsecurity.com/home/threat-center/remediation-history/3456765434567654",
        "type": [
            "indicator",
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Inbound Email Security",
        "vendor": "Abnormal"
    },
    "related": {
        "hosts": [
            "example.com"
        ],
        "ip": [
            "81.2.69.142"
        ],
        "user": [
            "john@example.com",
            "john",
            "bob@example.com",
            "bounce-bob_H181S7GUCF@example.com"
        ]
    },
    "source": {
        "domain": "example.com",
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.142"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "abnormal_security-threat"
    ],
    "threat": {
        "indicator": {
            "email": {
                "address": "john@example.com"
            },
            "reference": "https://portal.abnormalsecurity.com/home/threat-center/remediation-history/3456765434567654",
            "type": "email-addr"
        },
        "tactic": {
            "name": [
                "Spam"
            ]
        },
        "technique": {
            "name": [
                "Unknown Sender"
            ]
        }
    },
    "user": {
        "name": "john"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abnormal_security.threat.abx_message_id | A unique identifier for an individual message within a threat (i.e email campaign). | keyword |
| abnormal_security.threat.abx_portal_url | The URL at which the specific message details are viewable in Abnormal Security's Portal web interface. | keyword |
| abnormal_security.threat.attachment_count | Number of attachments in email (only available for IESS customers). | long |
| abnormal_security.threat.attachment_names | List of attachment names, if any. | keyword |
| abnormal_security.threat.attack.strategy |  | keyword |
| abnormal_security.threat.attack.type | The type of threat the message represents. | keyword |
| abnormal_security.threat.attack.vector | The attack medium. | keyword |
| abnormal_security.threat.attacked_party | The party that was targeted by an attack. | keyword |
| abnormal_security.threat.auto_remediated | Indicates whether Abnormal has automatically detected and remediated the message from the user's Inbox. Note : Abnormal has retained this field and the postRemediated field to support prior integrations, but in newly created integrations, you should capture this information from the remediationStatus field. | boolean |
| abnormal_security.threat.cc_emails | List of email addresses CC'ed. | keyword |
| abnormal_security.threat.from_address | The email address of the sender. | keyword |
| abnormal_security.threat.from_name | The display name of the sender. | keyword |
| abnormal_security.threat.id | An ID which maps to a threat campaign. A threat campaign might be received by multiple users. | keyword |
| abnormal_security.threat.impersonated_party | Impersonated party, if any. | keyword |
| abnormal_security.threat.internet_message_id | The internet message ID, per RFC 822. | keyword |
| abnormal_security.threat.is_read | Whether an email has been read. | boolean |
| abnormal_security.threat.post_remediated | Indicates whether Abnormal remediated the campaign at a later time, after landing in the user's Inbox. Note``:`` Abnormal has retained this field and the autoRemediated field to support prior integrations, but in newly created integrations, you should capture this information from the remediationStatus field. | boolean |
| abnormal_security.threat.received_time | The timestamp at which this message arrived. | date |
| abnormal_security.threat.recipient_address | the email address of the user who actually received the message. | keyword |
| abnormal_security.threat.remediation_status | The remediation status of the email threat. | keyword |
| abnormal_security.threat.remediation_timestamp | The timestamp at which this message was remediated, or empty if it has not been remediated. | date |
| abnormal_security.threat.reply_to_emails | The 'reply-to' list of emails. | keyword |
| abnormal_security.threat.return_path |  | keyword |
| abnormal_security.threat.sender_domain | Email domain of sender (only available for IESS customers). | keyword |
| abnormal_security.threat.sender_ip_address | IP address of sender. | ip |
| abnormal_security.threat.sent_time | The timestamp at which this message was sent. | date |
| abnormal_security.threat.subject | The email subject. | keyword |
| abnormal_security.threat.summary_insights | A summary of insights into this attack. | keyword |
| abnormal_security.threat.to_addresses | All the email addresses to which the message was sent, comma-separated & truncated at 255 chars. | keyword |
| abnormal_security.threat.url_count | Number of urls in email (only available for IESS customers). | long |
| abnormal_security.threat.urls | URLs present in the email body, if any. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |

