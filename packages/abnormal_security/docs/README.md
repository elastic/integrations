# Abnormal Security

Abnormal Security is a behavioral AI-based email security platform that learns the behavior of every identity in a cloud email environment and analyzes the risk of every event to block even the most sophisticated attacks.

The Abnormal Security integration collects data for AI Security Mailbox (formerly known as Abuse Mailbox), Audit, Case, and Threat logs using REST API.

## Data streams

The Abnormal Security integration collects four types of logs:

**[AI Security Mailbox](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/AI%20Security%20Mailbox%20(formerly%20known%20as%20Abuse%20Mailbox))** - Get details of an AI Security Mailbox.

**[Audit](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Audit%20Logs)** - Get details of an Audit logs for Portal.

**[Case](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Cases)** - Get details of an Abnormal Cases.

**[Threat](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3#/Threats)** - Get details of an Abnormal Threat Log.

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
* It ensures that API access is only possible from IP addresses (of Elastic Agent).

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Abnormal Security.
3. Click on the "Abnormal Security" integration from the search results.
4. Click on the "Add Abnormal Security" button to add the integration.
5. Add all the required integration configuration parameters, including Access Token, Interval, Initial Interval and Page Size to enable data collection.
6. Click on "Save and continue" to save the integration.

**Note**: By default, the URL is set to `https://api.abnormalplatform.com`. We have observed that Abnormal Security Base URL get change as per location so find your own base URL.

## Logs reference

### AI Security Mailbox

This is the `ai_security_mailbox` dataset.

#### Example

An example event for `ai_security_mailbox` looks as following:

```json
{
    "@timestamp": "2020-11-11T21:11:40.000Z",
    "abnormal_security": {
        "ai_security_mailbox": {
            "attack": {
                "type": "Malicious: Phishing"
            },
            "campaign_id": "fff51768-c446-34e1-97a8-9802c29c3ebd",
            "first_reported": "2020-11-11T21:11:40.000Z",
            "from": {
                "address": "support@secure-reply.org",
                "name": "Support"
            },
            "judgement_status": "Malicious",
            "last_reported": "2020-11-11T21:11:40.000Z",
            "message_id": "-1234567891011121314",
            "overall_status": "Could not find original message",
            "recipient": {
                "address": "example@example.com",
                "name": "Tom"
            },
            "subject": "Fwd: This is spam"
        }
    },
    "agent": {
        "ephemeral_id": "d920f395-656b-4fc0-9a6a-ae2d65bd6334",
        "id": "8c034622-b60b-4a13-b690-590c44774a4c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "abnormal_security.ai_security_mailbox",
        "namespace": "55664",
        "type": "logs"
    },
    "destination": {
        "user": {
            "name": "Tom"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8c034622-b60b-4a13-b690-590c44774a4c",
        "snapshot": false,
        "version": "8.13.0"
    },
    "email": {
        "from": {
            "address": [
                "support@secure-reply.org"
            ]
        },
        "subject": "Fwd: This is spam",
        "to": {
            "address": [
                "example@example.com"
            ]
        }
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "dataset": "abnormal_security.ai_security_mailbox",
        "id": "-1234567891011121314",
        "ingested": "2024-07-26T12:39:08Z",
        "kind": "event",
        "original": "{\"attackType\":\"Malicious: Phishing\",\"campaignId\":\"fff51768-c446-34e1-97a8-9802c29c3ebd\",\"firstReported\":\"2020-11-11T13:11:40-08:00\",\"fromAddress\":\"support@secure-reply.org\",\"fromName\":\"Support\",\"judgementStatus\":\"Malicious\",\"lastReported\":\"2020-11-11T13:11:40-08:00\",\"messageId\":\"-1234567891011121314\",\"overallStatus\":\"Could not find original message\",\"recipientAddress\":\"example@example.com\",\"recipientName\":\"Tom\",\"subject\":\"Fwd: This is spam\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Abnormal Security",
        "vendor": "Abnormal"
    },
    "related": {
        "user": [
            "support@secure-reply.org",
            "Support",
            "example@example.com",
            "Tom"
        ]
    },
    "source": {
        "user": {
            "name": "Support"
        }
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
                "Malicious: Phishing"
            ]
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abnormal_security.ai_security_mailbox.attack.type | The type of threat the message represents. | keyword |
| abnormal_security.ai_security_mailbox.campaign_id | An id which maps to an abuse campaign. | keyword |
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
    "@timestamp": "2024-07-18T18:41:37.467Z",
    "abnormal_security": {
        "audit": {
            "action": "view_message_content",
            "action_details": {
                "message_id": "-8674108407491446899",
                "provided_reason": "Reason",
                "request_url": "/v2.1/messages/email_content/"
            },
            "category": "threat_log",
            "source_ip": "2a02:cf40::",
            "status": "FAILURE",
            "tenant_name": "mock_tenant",
            "timestamp": "2024-07-18T18:41:37.467Z",
            "user": {
                "email": "johan@example.com"
            }
        }
    },
    "agent": {
        "ephemeral_id": "f481f3bb-3041-4cf8-8b7b-3affe45a93ad",
        "id": "8c034622-b60b-4a13-b690-590c44774a4c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "cloud": {
        "account": {
            "name": "mock_tenant"
        }
    },
    "data_stream": {
        "dataset": "abnormal_security.audit",
        "namespace": "48779",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8c034622-b60b-4a13-b690-590c44774a4c",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "view_message_content",
        "agent_id_status": "verified",
        "dataset": "abnormal_security.audit",
        "ingested": "2024-07-26T12:39:58Z",
        "kind": "event",
        "original": "{\"action\":\"view_message_content\",\"actionDetails\":{\"messageId\":\"-8674108407491446899\",\"providedReason\":\"Reason\",\"requestUrl\":\"/v2.1/messages/email_content/\"},\"category\":\"threat_log\",\"sourceIp\":\"2a02:cf40::\",\"status\":\"FAILURE\",\"tenantName\":\"mock_tenant\",\"timestamp\":\"2024-07-18 18:41:37.467000+00:00\",\"user\":{\"email\":\"johan@example.com\"}}",
        "outcome": "failure",
        "reason": "Reason",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Abnormal Security",
        "vendor": "Abnormal"
    },
    "related": {
        "ip": [
            "2a02:cf40::"
        ],
        "user": [
            "johan@example.com"
        ]
    },
    "source": {
        "geo": {
            "continent_name": "Europe",
            "country_iso_code": "NO",
            "country_name": "Norway",
            "location": {
                "lat": 62,
                "lon": 10
            }
        },
        "ip": "2a02:cf40::",
        "user": {
            "email": "johan@example.com"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "abnormal_security-audit"
    ],
    "url": {
        "extension": "1/messages/email_content/",
        "original": "/v2.1/messages/email_content/",
        "path": "/v2.1/messages/email_content/"
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
    "@timestamp": "2024-07-26T12:40:36.695Z",
    "abnormal_security": {
        "case": {
            "affected_employee": "Dav Hallet",
            "analysis": "Profile Updated",
            "customer_visible_time": "2024-02-24T19:57:37.000Z",
            "description": "Multiple failed login attempts",
            "first_observed": "2024-06-19T14:55:05.000Z",
            "id": "1234",
            "remediation_status": "Under Review",
            "severity": "Unrecognized devices logging in",
            "severity_level": "Low",
            "status": "Assessment Needed",
            "threat_ids": [
                "184712ab-6d8b-47b3-89d3-a314efef79e2",
                "184712ab-6d8b-47b3-89d3-a314efef79ee",
                "184712ab-6d8b-47b3-89d3-a314efef79ef"
            ]
        }
    },
    "agent": {
        "ephemeral_id": "5baa7174-a91b-4190-b4eb-2f290ca03001",
        "id": "8c034622-b60b-4a13-b690-590c44774a4c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "abnormal_security.case",
        "namespace": "71872",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8c034622-b60b-4a13-b690-590c44774a4c",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "dataset": "abnormal_security.case",
        "id": "1234",
        "ingested": "2024-07-26T12:40:48Z",
        "kind": "event",
        "original": "{\"affectedEmployee\":\"Dav Hallet\",\"analysis\":\"Profile Updated\",\"caseId\":\"1234\",\"case_status\":\"Assessment Needed\",\"customerVisibleTime\":\"2024-02-24T19:57:37Z\",\"description\":\"Multiple failed login attempts\",\"firstObserved\":\"2024-06-19T14:55:05Z\",\"remediation_status\":\"Under Review\",\"severity\":\"Unrecognized devices logging in\",\"severity_level\":\"Low\",\"threatIds\":[\"184712ab-6d8b-47b3-89d3-a314efef79e2\",\"184712ab-6d8b-47b3-89d3-a314efef79ee\",\"184712ab-6d8b-47b3-89d3-a314efef79ef\"]}",
        "start": "2024-06-19T14:55:05.000Z",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "message": "Multiple failed login attempts",
    "observer": {
        "product": "Abnormal Security",
        "vendor": "Abnormal"
    },
    "related": {
        "user": [
            "Dav Hallet"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "abnormal_security-case"
    ],
    "user": {
        "target": {
            "name": "Dav Hallet"
        }
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
    "@timestamp": "2020-06-09T17:42:59.000Z",
    "abnormal_security": {
        "threat": {
            "abx_message_id": "4551618356913732000",
            "abx_portal_url": "https://portal.abnormalsecurity.com/home/threat-center/remediation-history/4551618356913732076",
            "attachment_count": 0,
            "attachment_names": [
                "attachment.pdf"
            ],
            "attack": {
                "strategy": "Name Impersonation",
                "type": "Extortion",
                "vector": "Text"
            },
            "attacked_party": "VIP",
            "auto_remediated": true,
            "cc_emails": [
                "cc@example.com"
            ],
            "from_address": "support@secure-reply.org",
            "from_name": "Support",
            "id": "184712ab-6d8b-47b3-89d3-a314efef79e2",
            "impersonated_party": "None / Others",
            "internet_message_id": "<5edfca1c.1c69fb81.4b055.8fd5@mx.google.com>",
            "is_read": true,
            "post_remediated": false,
            "received_time": "2020-06-09T17:42:59.000Z",
            "recipient_address": "example@example.com",
            "remediation_status": "Auto Remediated",
            "remediation_timestamp": "2020-06-09T17:42:59.000Z",
            "reply_to_emails": [
                "reply-to@example.com"
            ],
            "return_path": "support@secure-reply.org",
            "sender_domain": "secure-reply.org",
            "sender_ip_address": "100.101.102.103",
            "sent_time": "2020-06-09T17:42:59.000Z",
            "subject": "Phishing Email",
            "summary_insights": [
                "Bitcoin Topics",
                "Personal Information Theft",
                "Unusual Sender"
            ],
            "to_addresses": [
                "example@example.com",
                "another@example.com"
            ],
            "url_count": 0,
            "urls": [
                "https://www.google.com/"
            ]
        }
    },
    "agent": {
        "ephemeral_id": "4ca1450d-7023-4f15-adf9-d6aec73ee951",
        "id": "8c034622-b60b-4a13-b690-590c44774a4c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "abnormal_security.threat",
        "namespace": "84342",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8c034622-b60b-4a13-b690-590c44774a4c",
        "snapshot": false,
        "version": "8.13.0"
    },
    "email": {
        "attachments": [
            {
                "file": {
                    "name": "attachment.pdf"
                }
            }
        ],
        "cc": {
            "address": [
                "cc@example.com"
            ]
        },
        "delivery_timestamp": "2020-06-09T17:42:59.000Z",
        "from": {
            "address": [
                "support@secure-reply.org"
            ]
        },
        "message_id": "<5edfca1c.1c69fb81.4b055.8fd5@mx.google.com>",
        "origination_timestamp": "2020-06-09T17:42:59.000Z",
        "reply_to": {
            "address": [
                "reply-to@example.com"
            ]
        },
        "subject": "Phishing Email",
        "to": {
            "address": [
                "example@example.com",
                "another@example.com"
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
        "id": "4551618356913732000",
        "ingested": "2024-07-26T12:41:38Z",
        "kind": "alert",
        "original": "{\"abxMessageId\":4551618356913732000,\"abxPortalUrl\":\"https://portal.abnormalsecurity.com/home/threat-center/remediation-history/4551618356913732076\",\"attachmentCount\":0,\"attachmentNames\":[\"attachment.pdf\"],\"attackStrategy\":\"Name Impersonation\",\"attackType\":\"Extortion\",\"attackVector\":\"Text\",\"attackedParty\":\"VIP\",\"autoRemediated\":true,\"ccEmails\":[\"cc@example.com\"],\"fromAddress\":\"support@secure-reply.org\",\"fromName\":\"Support\",\"impersonatedParty\":\"None / Others\",\"internetMessageId\":\"\\u003c5edfca1c.1c69fb81.4b055.8fd5@mx.google.com\\u003e\",\"isRead\":true,\"postRemediated\":false,\"receivedTime\":\"2020-06-09T17:42:59Z\",\"recipientAddress\":\"example@example.com\",\"remediationStatus\":\"Auto Remediated\",\"remediationTimestamp\":\"2020-06-09T17:42:59Z\",\"replyToEmails\":[\"reply-to@example.com\"],\"returnPath\":\"support@secure-reply.org\",\"senderDomain\":\"secure-reply.org\",\"senderIpAddress\":\"100.101.102.103\",\"sentTime\":\"2020-06-09T17:42:59Z\",\"subject\":\"Phishing Email\",\"summaryInsights\":[\"Bitcoin Topics\",\"Personal Information Theft\",\"Unusual Sender\"],\"threatId\":\"184712ab-6d8b-47b3-89d3-a314efef79e2\",\"toAddresses\":\"example@example.com, another@example.com\",\"urlCount\":0,\"urls\":[\"https://www.google.com/\"]}",
        "reference": "https://portal.abnormalsecurity.com/home/threat-center/remediation-history/4551618356913732076",
        "type": [
            "indicator",
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Abnormal Security",
        "vendor": "Abnormal"
    },
    "related": {
        "hosts": [
            "secure-reply.org"
        ],
        "ip": [
            "100.101.102.103"
        ],
        "user": [
            "cc@example.com",
            "support@secure-reply.org",
            "Support",
            "example@example.com",
            "reply-to@example.com",
            "another@example.com"
        ]
    },
    "source": {
        "domain": "secure-reply.org",
        "ip": "100.101.102.103",
        "user": {
            "name": "Support"
        }
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
                "address": "support@secure-reply.org"
            },
            "ip": "100.101.102.103",
            "reference": "https://portal.abnormalsecurity.com/home/threat-center/remediation-history/4551618356913732076",
            "type": "email-addr"
        },
        "technique": {
            "name": [
                "Extortion"
            ]
        }
    },
    "url": {
        "original": [
            "https://www.google.com/"
        ]
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
| abnormal_security.threat.id | An id which maps to a threat campaign. A threat campaign might be received by multiple users. | keyword |
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

