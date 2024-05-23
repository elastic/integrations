# ThreatConnect

ThreatConnect is a widely used Threat Intelligence Platform (TIP) designed to assist organizations in aggregating, analyzing, and sharing information related to cybersecurity threats. The platform provides tools and features that enable security teams to collaborate on threat intelligence, manage incidents, and make informed decisions to enhance their overall cybersecurity posture. This ThreatConnect integration enables you to consume and analyze ThreatConnect data within Elastic Security, including indicator events, providing you with visibility and context for your cloud environments within Elastic Security.

## Data stream

The ThreatConnect Integration collects indicators as the primary data type. Associated groups and associated indicators are brought in via Elastic custom mapping fields.

An **Indicator** inside [ThreatConnect](https://docs.threatconnect.com/en/latest/rest_api/v3/indicators/indicators.html) represents an atomic piece of information that has some intelligence value.

Reference for [REST APIs](https://docs.threatconnect.com/en/latest/rest_api/rest_api.html#getting-started) of ThreatConnect.

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Versions

The minimum required versions for the Elastic Stack is **8.12.0**.

The minimum required ThreatConnect Platform version is 7.3.1 This integration module uses the ThreatConnect V3 API.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.11.0**.
This module has been tested against the **ThreatConnect API Version v3**.
The minimum required ThreatConnect Platform version needs to be **7.3.1**.

## Setup

### To collect data from ThreatConnect, the following parameters from your ThreatConnect instance are required:

1. Access Id
2. Secret Key
3. URL

To create an API user account, please refer to [this](https://knowledge.threatconnect.com/docs/creating-user-accounts) article.

### Enabling the integration in Elastic:
1. In Kibana, go to Management > Integrations.
2. In the "Search for integrations" search bar, type ThreatConnect.
3. Click on the "ThreatConnect" integration from the search results.
4. Click on the "Add ThreatConnect" button to add the integration.
5. Configure all required integration parameters, including Access Id, Secret Key, and URL, to enable data collection from the ThreatConnect REST API.
6. Save the integration.

## Indicators Expiration

The ingested indicators expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to facilitate only active indicators be available to the end users. Since we want to retain only valuable information and avoid duplicated data, the ThreatConnect Elastic integration forces the intel indicators to rotate into a custom index called: `logs-ti_threatconnect_latest.dest_indicator-*`.
**Please, refer to this index in order to set alerts and so on.**

#### Handling Orphaned Indicators

In order to prevent orphaned indicators that may never expire in the destination index users can configure IOC Expiration Duration parameter while setting up the integration. This parameter deletes all data inside the destination index logs-ti_threatconnect_latest.dest_indicator after this specified duration is reached.

### How it works

This is possible thanks to a transform rule installed along with the integration. The transform rule parses the data stream content that is pulled from ThreatConnect and only adds new indicators.

Both the data stream and the latest index have applied expiration through ILM and a retention policy in the transform respectively.

## Logs Reference

### Indicator

This is the `Indicator` dataset.

#### Example

An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2023-12-05T06:38:53.000Z",
    "agent": {
        "ephemeral_id": "43b1a042-a9b3-4d01-b836-a9349883688b",
        "id": "c3650180-e3d1-4dad-9094-89c988e721d7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "ti_threatconnect.indicator",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c3650180-e3d1-4dad-9094-89c988e721d7",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_threatconnect.indicator",
        "id": "test.user@elastic.co",
        "ingested": "2024-05-16T22:35:04Z",
        "kind": "enrichment",
        "original": "{\"active\":true,\"activeLocked\":false,\"address\":\"test.user@elastic.co\",\"associatedGroups\":{\"data\":[{\"createdBy\":{\"firstName\":\"test\",\"id\":69,\"lastName\":\"user\",\"owner\":\"Elastic\",\"pseudonym\":\"testW\",\"userName\":\"test.user@elastic.co\"},\"dateAdded\":\"2023-12-05T06:38:33Z\",\"downVoteCount\":\"0\",\"id\":609427,\"lastModified\":\"2023-12-05T06:43:21Z\",\"legacyLink\":\"https://app.threatconnect.com/auth/vulnerability/vulnerability.xhtml?vulnerability=609427\",\"name\":\"Test2 \",\"ownerId\":51,\"ownerName\":\"Elastic\",\"type\":\"Vulnerability\",\"upVoteCount\":\"0\",\"webLink\":\"https://app.threatconnect.com/#/details/groups/609427/overview\"},{\"createdBy\":{\"firstName\":\"test\",\"id\":69,\"lastName\":\"user\",\"owner\":\"Elastic\",\"pseudonym\":\"testW\",\"userName\":\"test.user@elastic.co\"},\"dateAdded\":\"2023-12-04T07:18:52Z\",\"documentDateAdded\":\"2023-12-04T07:18:53Z\",\"documentType\":\"PDF\",\"downVoteCount\":\"0\",\"fileName\":\"testthreatgroup.pdf\",\"fileSize\":24467,\"generatedReport\":true,\"id\":601237,\"lastModified\":\"2023-12-05T06:38:46Z\",\"legacyLink\":\"https://app.threatconnect.com/auth/report/report.xhtml?report=601237\",\"name\":\"TestThreatGroup\",\"ownerId\":51,\"ownerName\":\"Elastic\",\"status\":\"Success\",\"type\":\"Report\",\"upVoteCount\":\"0\",\"webLink\":\"https://app.threatconnect.com/#/details/groups/601237/overview\"}]},\"associatedIndicators\":{\"data\":[{\"active\":true,\"activeLocked\":false,\"address\":\"testing@poverts.com\",\"confidence\":61,\"dateAdded\":\"2023-08-25T12:57:24Z\",\"id\":891599,\"lastModified\":\"2023-12-05T06:50:06Z\",\"legacyLink\":\"https://app.threatconnect.com/auth/indicators/details/emailaddress.xhtml?emailaddress=testing%40poverts.com\\u0026owner=Elastic\",\"ownerId\":51,\"ownerName\":\"Elastic\",\"privateFlag\":false,\"rating\":3,\"summary\":\"testing@poverts.com\",\"type\":\"EmailAddress\",\"webLink\":\"https://app.threatconnect.com/#/details/indicators/891599/overview\"},{\"active\":true,\"activeLocked\":false,\"dateAdded\":\"2023-08-24T06:28:17Z\",\"id\":738667,\"lastModified\":\"2023-12-05T06:47:59Z\",\"legacyLink\":\"https://app.threatconnect.com/auth/indicators/details/url.xhtml?orgid=738667\\u0026owner=Elastic\",\"ownerId\":51,\"ownerName\":\"Elastic\",\"privateFlag\":false,\"summary\":\"http://www.testingmcafeesites.com/testcat_pc.html\",\"text\":\"http://www.testingmcafeesites.com/testcat_pc.html\",\"type\":\"URL\",\"webLink\":\"https://app.threatconnect.com/#/details/indicators/738667/overview\"}]},\"attributes\":{},\"dateAdded\":\"2023-08-24T06:19:58Z\",\"id\":736758,\"lastModified\":\"2023-12-05T06:38:53Z\",\"legacyLink\":\"https://app.threatconnect.com/auth/indicators/details/emailaddress.xhtml?emailaddress=test.user%40elastic.co\\u0026owner=Elastic\",\"ownerId\":51,\"ownerName\":\"Elastic\",\"privateFlag\":false,\"securityLabels\":{\"data\":[{\"color\":\"FFC000\",\"dateAdded\":\"2016-08-31T00:00:00Z\",\"description\":\"This security label is used for information that requires support to be effectively acted upon, yet carries risks to privacy, reputation, or operations if shared outside of the organizations involved. Information with this label can be shared with members of an organization and its clients.\",\"id\":3,\"name\":\"TLP:AMBER\",\"owner\":\"System\"}]},\"summary\":\"test.user@elastic.co\",\"tags\":{\"data\":[{\"description\":\"Adversaries may steal monetary resources from targets through extortion, social engineering, technical theft, or other methods aimed at their own financial gain at the expense of the availability of these resources for victims. Financial theft is the ultimate objective of several popular campaign types including extortion by ransomware,(Citation: FBI-ransomware) business email compromise (BEC) and fraud,(Citation: FBI-BEC) \\\"pig butchering,\\\"(Citation: wired-pig butchering) bank hacking,(Citation: DOJ-DPRK Heist) and exploiting cryptocurrency networks.(Citation: BBC-Ronin) \\n\\nAdversaries may [Compromise Accounts](https://attack.mitre.org/techniques/T1586) to conduct unauthorized transfers of funds.(Citation: Internet crime report 2022) In the case of business email compromise or email fraud, an adversary may utilize [Impersonation](https://attack.mitre.org/techniques/T1656) of a trusted entity. Once the social engineering is successful, victims can be deceived into sending money to financial accounts controlled by an adversary.(Citation: FBI-BEC) This creates the potential for multiple victims (i.e., compromised accounts as well as the ultimate monetary loss) in incidents involving financial theft.(Citation: VEC)\\n\\nExtortion by ransomware may occur, for example, when an adversary demands payment from a victim after [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) (Citation: NYT-Colonial) and [Exfiltration](https://attack.mitre.org/tactics/TA0010) of data, followed by threatening public exposure unless payment is made to the adversary.(Citation: Mandiant-leaks)\\n\\nDue to the potentially immense business impact of financial theft, an adversary may abuse the possibility of financial theft and seeking monetary gain to divert attention from their true goals such as [Data Destruction](https://attack.mitre.org/techniques/T1485) and business disruption.(Citation: AP-NotPetya)\",\"id\":463701,\"lastUsed\":\"2023-12-04T06:44:44Z\",\"name\":\"Financial Theft\",\"platforms\":{\"count\":6,\"data\":[\"Linux\",\"macOS\",\"Windows\",\"Office 365\",\"SaaS\",\"Google Workspace\"]},\"techniqueId\":\"T1657\"}]},\"threatAssessConfidence\":0,\"threatAssessRating\":0,\"threatAssessScore\":281,\"threatAssessScoreFalsePositive\":0,\"threatAssessScoreObserved\":0,\"type\":\"EmailAddress\",\"webLink\":\"https://app.threatconnect.com/#/details/indicators/736758/overview\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "os": {
        "family": [
            "Linux",
            "macOS",
            "Windows",
            "Office 365",
            "SaaS",
            "Google Workspace"
        ]
    },
    "related": {
        "user": [
            "test.user",
            "test",
            "user",
            "test.user@elastic.co"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "threatconnect-indicator"
    ],
    "threat": {
        "indicator": {
            "email": {
                "address": "test.user@elastic.co"
            },
            "marking": {
                "tlp": [
                    "AMBER"
                ]
            },
            "provider": "ThreatConnect",
            "reference": [
                "https://app.threatconnect.com/auth/indicators/details/emailaddress.xhtml?emailaddress=test.user%40elastic.co&owner=Elastic",
                "https://app.threatconnect.com/#/details/indicators/736758/overview"
            ],
            "type": [
                "email-addr"
            ]
        },
        "technique": {
            "id": [
                "T1657"
            ]
        }
    },
    "threat_connect": {
        "indicator": {
            "active": {
                "locked": false,
                "value": true
            },
            "address": "test.user@elastic.co",
            "associated_groups": {
                "data": [
                    {
                        "created_by": {
                            "first_name": "test",
                            "id": "69",
                            "last_name": "user",
                            "owner": "Elastic",
                            "pseudonym": "testW",
                            "user_name": "test.user@elastic.co"
                        },
                        "date_added": "2023-12-05T06:38:33.000Z",
                        "down_vote_count": "0",
                        "id": "609427",
                        "last_modified": "2023-12-05T06:43:21.000Z",
                        "legacy_link": "https://app.threatconnect.com/auth/vulnerability/vulnerability.xhtml?vulnerability=609427",
                        "name": "Test2 ",
                        "owner": {
                            "id": "51",
                            "name": "Elastic"
                        },
                        "type": "Vulnerability",
                        "up_vote_count": "0",
                        "web_link": "https://app.threatconnect.com/#/details/groups/609427/overview"
                    },
                    {
                        "created_by": {
                            "first_name": "test",
                            "id": "69",
                            "last_name": "user",
                            "owner": "Elastic",
                            "pseudonym": "testW",
                            "user_name": "test.user@elastic.co"
                        },
                        "date_added": "2023-12-04T07:18:52.000Z",
                        "document": {
                            "date_added": "2023-12-04T07:18:53.000Z",
                            "type": "PDF"
                        },
                        "down_vote_count": "0",
                        "file": {
                            "name": "testthreatgroup.pdf",
                            "size": "24467"
                        },
                        "generated_report": true,
                        "id": "601237",
                        "last_modified": "2023-12-05T06:38:46.000Z",
                        "legacy_link": "https://app.threatconnect.com/auth/report/report.xhtml?report=601237",
                        "name": "TestThreatGroup",
                        "owner": {
                            "id": "51",
                            "name": "Elastic"
                        },
                        "status": "Success",
                        "type": "Report",
                        "up_vote_count": "0",
                        "web_link": "https://app.threatconnect.com/#/details/groups/601237/overview"
                    }
                ]
            },
            "associated_indicators": {
                "data": [
                    {
                        "active": {
                            "locked": false,
                            "value": true
                        },
                        "address": "testing@poverts.com",
                        "confidence": 61,
                        "date_added": "2023-08-25T12:57:24.000Z",
                        "id": "891599",
                        "last_modified": "2023-12-05T06:50:06.000Z",
                        "legacy_link": "https://app.threatconnect.com/auth/indicators/details/emailaddress.xhtml?emailaddress=testing%40poverts.com&owner=Elastic",
                        "owner": {
                            "id": "51",
                            "name": "Elastic"
                        },
                        "private_flag": false,
                        "rating": 3,
                        "summary": "testing@poverts.com",
                        "type": "EmailAddress",
                        "web_link": "https://app.threatconnect.com/#/details/indicators/891599/overview"
                    },
                    {
                        "active": {
                            "locked": false,
                            "value": true
                        },
                        "date_added": "2023-08-24T06:28:17.000Z",
                        "id": "738667",
                        "last_modified": "2023-12-05T06:47:59.000Z",
                        "legacy_link": "https://app.threatconnect.com/auth/indicators/details/url.xhtml?orgid=738667&owner=Elastic",
                        "owner": {
                            "id": "51",
                            "name": "Elastic"
                        },
                        "private_flag": false,
                        "summary": "http://www.testingmcafeesites.com/testcat_pc.html",
                        "text": "http://www.testingmcafeesites.com/testcat_pc.html",
                        "type": "URL",
                        "web_link": "https://app.threatconnect.com/#/details/indicators/738667/overview"
                    }
                ]
            },
            "date_added": "2023-08-24T06:19:58.000Z",
            "deleted_at": "2024-03-04T06:38:53.000Z",
            "expiration_duration": "90d",
            "id": "736758",
            "last_modified": "2023-12-05T06:38:53.000Z",
            "legacy_link": "https://app.threatconnect.com/auth/indicators/details/emailaddress.xhtml?emailaddress=test.user%40elastic.co&owner=Elastic",
            "owner": {
                "id": "51",
                "name": "Elastic"
            },
            "private_flag": false,
            "security_labels": {
                "data": [
                    {
                        "date_added": "2016-08-31T00:00:00.000Z",
                        "name": "TLP:AMBER"
                    }
                ]
            },
            "summary": "test.user@elastic.co",
            "tags": {
                "data": [
                    {
                        "last_used": "2023-12-04T06:44:44.000Z",
                        "name": "Financial Theft",
                        "technique": {
                            "id": "T1657"
                        }
                    }
                ]
            },
            "threat_assess": {
                "confidence": 0,
                "rating": 0,
                "score": {
                    "false_positive": 0,
                    "observed": 0,
                    "value": 281
                }
            },
            "type": "EmailAddress",
            "web_link": "https://app.threatconnect.com/#/details/indicators/736758/overview"
        }
    },
    "user": {
        "domain": "elastic.co",
        "email": "test.user@elastic.co",
        "name": "test.user"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| log.offset | Log offset. | long |
| tags | User defined tags. | keyword |
| threat.feed.name | Display friendly feed name. | constant_keyword |
| threat_connect.indicator.active.locked | Indicates whether the active status is locked. | boolean |
| threat_connect.indicator.active.value | Indicates whether the indicator is active. | boolean |
| threat_connect.indicator.address | The email address associated with the Email Address Indicator. | keyword |
| threat_connect.indicator.as_number | The AS number associated with the ASN Indicator. | keyword |
| threat_connect.indicator.associated_artifacts | A list of Artifacts associated to the Indicator. | flattened |
| threat_connect.indicator.associated_cases | A list of Cases associated to the Indicator. | flattened |
| threat_connect.indicator.associated_groups.data.assignments.data.type | Valid values for the type of assignment are Assigned and Escalate. | keyword |
| threat_connect.indicator.associated_groups.data.assignments.data.user.id | Unique identifier of users assigned to the Task or to whom the Task will be escalated. | keyword |
| threat_connect.indicator.associated_groups.data.body | The Emails body. | keyword |
| threat_connect.indicator.associated_groups.data.created_by.first_name | First name of user. | keyword |
| threat_connect.indicator.associated_groups.data.created_by.id | Unique Identifier of the user who created the group. | keyword |
| threat_connect.indicator.associated_groups.data.created_by.last_name | Last name of user. | keyword |
| threat_connect.indicator.associated_groups.data.created_by.owner | Owner of attribute creator. | keyword |
| threat_connect.indicator.associated_groups.data.created_by.pseudonym | Pseudonym or alias of the user. | keyword |
| threat_connect.indicator.associated_groups.data.created_by.user_name | Username of user. | keyword |
| threat_connect.indicator.associated_groups.data.date_added | Date and time group was added. | date |
| threat_connect.indicator.associated_groups.data.document.date_added | Date and time when the document was added. | date |
| threat_connect.indicator.associated_groups.data.document.type | The type of document. | keyword |
| threat_connect.indicator.associated_groups.data.down_vote_count | Downvote Intel Rating. | keyword |
| threat_connect.indicator.associated_groups.data.due_date | The date and time when the Task is due. | date |
| threat_connect.indicator.associated_groups.data.email_date | The date associated with an email. | date |
| threat_connect.indicator.associated_groups.data.escalation_date | The date and time when the Task should be escalated. | date |
| threat_connect.indicator.associated_groups.data.event_date | The date and time when the Event took place. | date |
| threat_connect.indicator.associated_groups.data.external.date.added | The date and time when the Group was created externally. | date |
| threat_connect.indicator.associated_groups.data.external.date.expires | The date and time when the Group expires externally. | date |
| threat_connect.indicator.associated_groups.data.external.last_modified | The date and time when the Group was last modified externally. | date |
| threat_connect.indicator.associated_groups.data.file.name | The file name of the Document. | keyword |
| threat_connect.indicator.associated_groups.data.file.size | The File size of the document. | keyword |
| threat_connect.indicator.associated_groups.data.file.text | The file text of the Signature. | keyword |
| threat_connect.indicator.associated_groups.data.file.type | The file type of the SignaturePossible values are Bro,ClamAV,CybOX,Iris Search Hash,KQL,OpenIOC,Regex,SPL,Sigma,Snort,Suricata,TQL Query,YARA. | keyword |
| threat_connect.indicator.associated_groups.data.first_seen | The date and time when the Group was first seen. | date |
| threat_connect.indicator.associated_groups.data.from | The Emails subject. | keyword |
| threat_connect.indicator.associated_groups.data.generated_report | Indicates whether the report is generated. | boolean |
| threat_connect.indicator.associated_groups.data.header | The Emails header. | keyword |
| threat_connect.indicator.associated_groups.data.id | Unique Identifier of Group. | keyword |
| threat_connect.indicator.associated_groups.data.last_modified | Date and time when the document was last updated. | date |
| threat_connect.indicator.associated_groups.data.last_seen | The date and time when the Group was last seen. | date |
| threat_connect.indicator.associated_groups.data.legacy_link | Legacy link to the group's details in the ThreatConnect web application. | keyword |
| threat_connect.indicator.associated_groups.data.malware | Indicates whether the Document is malware. | boolean |
| threat_connect.indicator.associated_groups.data.name | The Groups name. | keyword |
| threat_connect.indicator.associated_groups.data.owner.id | The ID of the owner to which the Group belongs. | keyword |
| threat_connect.indicator.associated_groups.data.owner.name | The name of the owner to which the Group belongs. | keyword |
| threat_connect.indicator.associated_groups.data.password | The password associated with the Document. | keyword |
| threat_connect.indicator.associated_groups.data.publish_date | The date and time when the Report was published. | date |
| threat_connect.indicator.associated_groups.data.reminder_date | The date and time when a reminder about the Task will be sent. | date |
| threat_connect.indicator.associated_groups.data.score_breakdown | A breakdown or explanation of the score, providing additional information about how the score was determined. | keyword |
| threat_connect.indicator.associated_groups.data.score_includes_body | Indicates whether the score includes information from the email body. | boolean |
| threat_connect.indicator.associated_groups.data.status | The status of the Group type. | keyword |
| threat_connect.indicator.associated_groups.data.subject | The Emails From field. | keyword |
| threat_connect.indicator.associated_groups.data.to | The receiver email address. | keyword |
| threat_connect.indicator.associated_groups.data.type | The type of Group being created.Possiblevalues:Adversary,AttackPattern,Campaign,CourseofAction,Document,Email,Event,Incident,IntrusionSet,Malware,Report,Signature,Tactic,Task,Threat,Tool, Vulnerability. | keyword |
| threat_connect.indicator.associated_groups.data.up_vote | Use this field to update the Groups Intel Rating. | boolean |
| threat_connect.indicator.associated_groups.data.up_vote_count | Upvote Intel Rating. | keyword |
| threat_connect.indicator.associated_groups.data.web_link | Link to the group's details in the ThreatConnect web application. | keyword |
| threat_connect.indicator.associated_groups.data.xid | The Groups XID. | keyword |
| threat_connect.indicator.associated_indicators.data.active.locked | Indicates whether the active status is locked. | boolean |
| threat_connect.indicator.associated_indicators.data.active.value | Indicates whether the indicator is active. | boolean |
| threat_connect.indicator.associated_indicators.data.address | The email address associated with the Email Address Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.as_number | The AS number associated with the ASN Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.block | The block of network IP addresses associated with the CIDR Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.confidence | The Indicators Confidence Rating. | long |
| threat_connect.indicator.associated_indicators.data.date_added | Date and time when the indicator was added. | date |
| threat_connect.indicator.associated_indicators.data.description | Description of the indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.dns_active | Indicates whether the DNS feature is active for the Host Indicator. | boolean |
| threat_connect.indicator.associated_indicators.data.external.date.added | The date and time when the Indicator was created externally. | date |
| threat_connect.indicator.associated_indicators.data.external.date.expires | The date and time when the Indicator expires externally. | date |
| threat_connect.indicator.associated_indicators.data.external.last_modified | The date and time when the Indicator was last modified externally. | date |
| threat_connect.indicator.associated_indicators.data.first_seen | The date and time when the Indicator was first seen. | date |
| threat_connect.indicator.associated_indicators.data.hashtag | The hashtag term associated with the Hashtag Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.host_name | The host name associated with the Host Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.id | Unique identifier for the indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.ip | The IP address associated with the Address Indicator. | ip |
| threat_connect.indicator.associated_indicators.data.key_name | The name of the registry key associated with the Registry Key Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.last_modified | Date and time when the indicator was last modified. | date |
| threat_connect.indicator.associated_indicators.data.last_seen | The date and time when the Indicator was last seen. | date |
| threat_connect.indicator.associated_indicators.data.legacy_link | Legacy link to the indicator's details in the ThreatConnect web application. | keyword |
| threat_connect.indicator.associated_indicators.data.md5 | MD5 hash value associated with the indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.mutex | The synchronization primitive used to identify malware files that is associated with the Mutex. | keyword |
| threat_connect.indicator.associated_indicators.data.owner.id | Identifier for the owner of the indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.owner.name | Name of the organization that owns the indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.private_flag | Indicates whether the indicator is marked as private. | boolean |
| threat_connect.indicator.associated_indicators.data.rating | The Indicators Threat Rating. | double |
| threat_connect.indicator.associated_indicators.data.sha1 | The SHA1 hash associated with the File Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.sha256 | The SHA256 hash associated with the File Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.size | The size of the file associated with the File Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.subject | The subject line of the email associated with the Email Subject Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.summary | Summary or description of the indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.text | The URL associated with the URL Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.type | Type of the indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.user_agent_string | The characteristic identification string associated with the User Agent Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.value.name | The registry value associated with the Registry Key Indicator. | keyword |
| threat_connect.indicator.associated_indicators.data.value.type | Possible values:REG_NONE,REG_BINARY,REG_DWORD,REG_DWORD_LITTLE_ENDIAN,REG_DWORD_BIG_ENDIAN,REG_EXPAND_SZ,REG_LINK,REG_MULTI_SZ,REG_QWORD,REG_QWORD_LITTLE_ENDIAN,REG_SZ. | keyword |
| threat_connect.indicator.associated_indicators.data.web_link | Link to the indicator's details in the ThreatConnect web application. | keyword |
| threat_connect.indicator.associated_indicators.data.whois_active | Indicates whether the Whois feature is active for the Host Indicator. | boolean |
| threat_connect.indicator.attributes.data.created_by.first_name | First name of the user who created the victim attribute. | keyword |
| threat_connect.indicator.attributes.data.created_by.id | Unique Identifier of the user who created the attribute. | keyword |
| threat_connect.indicator.attributes.data.created_by.last_name | Lastname of the user who created the victim attribute. | keyword |
| threat_connect.indicator.attributes.data.created_by.owner | Owner of attribute creator. | keyword |
| threat_connect.indicator.attributes.data.created_by.pseudonym | Pseudonym or alias of the user. | keyword |
| threat_connect.indicator.attributes.data.created_by.user_name | Username of the user who created the victim attribute. | keyword |
| threat_connect.indicator.attributes.data.date_added | Date and time when the attribute was added. | date |
| threat_connect.indicator.attributes.data.default | Indicates whether the Attribute is the default Attribute of its type for the Indicator to which it is added (this field applies to certain Attribute and data types only). | boolean |
| threat_connect.indicator.attributes.data.id | Unique Identifier of attribute. | keyword |
| threat_connect.indicator.attributes.data.last_modified | Date and time when attribute was modified. | date |
| threat_connect.indicator.attributes.data.pinned | Indicates whether the Attribute is to be displayed as a Pinned Attribute on the Details screen for the Indicator to which the Attribute is added. | boolean |
| threat_connect.indicator.attributes.data.source | The Attributes source. | keyword |
| threat_connect.indicator.attributes.data.type | The Attributes type. | keyword |
| threat_connect.indicator.attributes.data.value | The Attributes value. | keyword |
| threat_connect.indicator.block | The block of network IP addresses associated with the CIDR Indicator. | keyword |
| threat_connect.indicator.confidence | The Indicators Confidence Rating. | long |
| threat_connect.indicator.custom_associations | Includes indicators with custom associations to the indicator. | flattened |
| threat_connect.indicator.date_added | Date and time when the indicator was added. | date |
| threat_connect.indicator.deleted_at | Date when the IOC was expired/deleted. | date |
| threat_connect.indicator.description | Description of the indicator. | keyword |
| threat_connect.indicator.dns_active | Indicates whether the DNS feature is active for the Host Indicator. | boolean |
| threat_connect.indicator.dns_resolution | Includes DNS resolution data related to the Host indicators. | flattened |
| threat_connect.indicator.enrichment | Includes Enrichment data related to the indicator. | flattened |
| threat_connect.indicator.expiration_duration | Duration when the IOC will expire. | keyword |
| threat_connect.indicator.external.date.added | The date and time when the Indicator was created externally. | date |
| threat_connect.indicator.external.date.expires | The date and time when the Indicator expires externally. | date |
| threat_connect.indicator.external_last.modified | The date and time when the Indicator was last modified externally. | date |
| threat_connect.indicator.false_positive_reported_by_user | Indicates whether false positive is reported by user. | boolean |
| threat_connect.indicator.false_positives | Count of false positives. | long |
| threat_connect.indicator.file_actions | A list of File Actions associated with the File Indicator. | flattened |
| threat_connect.indicator.file_occurrences | A list of File Occurrences associated with the File Indicator. | flattened |
| threat_connect.indicator.first_seen | The date and time when the Indicator was first seen. | date |
| threat_connect.indicator.generic_custom_indicator_values | Includes the fields over-writing the custom field names: value1, value2, and value3. | flattened |
| threat_connect.indicator.geo_location | Includes GEO location information related to the Host and IP indicators. | flattened |
| threat_connect.indicator.hashtag | The hashtag term associated with the Hashtag Indicator. | keyword |
| threat_connect.indicator.host_name | The host name associated with the Host Indicator. | keyword |
| threat_connect.indicator.id | Unique identifier for the indicator. | keyword |
| threat_connect.indicator.investigation_links | Includes investigation links related to the indicator type. | flattened |
| threat_connect.indicator.ip | The IP address associated with the Address Indicator. | ip |
| threat_connect.indicator.key_name | The name of the registry key associated with the Registry Key Indicator. | keyword |
| threat_connect.indicator.last_false_positive | Date and time of last false positive. | date |
| threat_connect.indicator.last_modified | Date and time when the indicator was last modified. | date |
| threat_connect.indicator.last_seen | The date and time when the Indicator was last seen. | date |
| threat_connect.indicator.legacy_link | Legacy link to the indicator's details in the ThreatConnect web application. | keyword |
| threat_connect.indicator.md5 | MD5 hash value associated with the indicator. | keyword |
| threat_connect.indicator.mutex | The synchronization primitive used to identify malware files that is associated with the Mutex. | keyword |
| threat_connect.indicator.observations | Includes the Observations fields. | flattened |
| threat_connect.indicator.owner.id | Identifier for the owner of the indicator. | keyword |
| threat_connect.indicator.owner.name | Name of the organization that owns the indicator. | keyword |
| threat_connect.indicator.private_flag | Indicates whether the indicator is marked as private. | boolean |
| threat_connect.indicator.rating | The Indicators Threat Rating. | double |
| threat_connect.indicator.security_labels.data.date_added | The date and time when the security label was added. | date |
| threat_connect.indicator.security_labels.data.name | Actual name or label of the security classification. | keyword |
| threat_connect.indicator.security_labels.data.owner | The entity or system that owns or manages the security label. | keyword |
| threat_connect.indicator.security_labels.data.source | The source of the security label. | keyword |
| threat_connect.indicator.sha1 | The SHA1 hash associated with the File Indicator. | keyword |
| threat_connect.indicator.sha256 | The SHA256 hash associated with the File Indicator. | keyword |
| threat_connect.indicator.size | The size of the file associated with the File Indicator. | keyword |
| threat_connect.indicator.source | The Indicators source. | keyword |
| threat_connect.indicator.subject | The subject line of the email associated with the Email Subject Indicator. | keyword |
| threat_connect.indicator.summary | Summary or description of the indicator. | keyword |
| threat_connect.indicator.tags.data.last_used | Date and time when tag was last used. | date |
| threat_connect.indicator.tags.data.name | Name of tag. | keyword |
| threat_connect.indicator.tags.data.owner | The Organization, Community, or Source to which the Tag belongs. | keyword |
| threat_connect.indicator.tags.data.platforms.count | Count of platforms. | long |
| threat_connect.indicator.tags.data.platforms.data | Platform on which tag is added. | keyword |
| threat_connect.indicator.tags.data.technique.id | Unique Identifier of tag technique. | keyword |
| threat_connect.indicator.text | The URL associated with the URL Indicator. | keyword |
| threat_connect.indicator.threat_assess.confidence | The confidence level associated with the threat assessment. | double |
| threat_connect.indicator.threat_assess.rating | A numerical rating indicating the threat assessment level. | double |
| threat_connect.indicator.threat_assess.score.false_positive | The count of false positives associated with the threat assessment score. | long |
| threat_connect.indicator.threat_assess.score.observed | The observed value associated with the threat assessment score. | long |
| threat_connect.indicator.threat_assess.score.value | The overall score assigned to the threat, indicating its severity or risk. | long |
| threat_connect.indicator.tracked_users | Includes Observations and False Positive stats of tracked users. | flattened |
| threat_connect.indicator.type | Type of the indicator (e.g., File, IP address). | keyword |
| threat_connect.indicator.user_agent_string | The characteristic identification string associated with the User Agent Indicator. | keyword |
| threat_connect.indicator.value.name | The registry value associated with the Registry Key Indicator. | keyword |
| threat_connect.indicator.value.type | Possible values:REG_NONE,REG_BINARY,REG_DWORD,REG_DWORD_LITTLE_ENDIAN,REG_DWORD_BIG_ENDIAN,REG_EXPAND_SZ,REG_LINK,REG_MULTI_SZ,REG_QWORD,REG_QWORD_LITTLE_ENDIAN,REG_SZ. | keyword |
| threat_connect.indicator.web_link | Link to the indicator's details in the ThreatConnect web application. | keyword |
| threat_connect.indicator.who_is | Includes WhoIs information related to the Host indicators. | flattened |
| threat_connect.indicator.whois_active | Indicates whether the Whois feature is active for the Host Indicator. | boolean |

