# CrowdStrike Falcon Intelligence

CrowdStrike Falcon Intelligence is a threat intelligence product that provides advanced cybersecurity insights to organizations. Leveraging machine learning and behavioural analytics, Falcon Intelligence delivers real-time threat data, enabling proactive threat detection and response. With a focus on actionable intelligence, it empowers businesses to stay ahead of cyber adversaries and enhance their overall security posture. This [CrowdStrike Falcon Intelligence](https://www.crowdstrike.com/en-us/) integration enables you to consume and analyze CrowdStrike Falcon Intelligence data within Elastic Security, including Intel Indicator and IOCs, providing you with visibility and context for your cloud environments within Elastic Security.

## Data streams

The CrowdStrike Falcon Intelligence integration collects two types of data: IOC and Intel Indicator.

Both the endpoints are related to the threat intelligence. Intel Indicators provide information about a hash, particularly related to malware and threat types, while IOC provides information about the detection of an IPv4 address, including severity, platforms, and global application status.

Reference for CrowdStrike Falcon Intelligence APIs - https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-oauth2-based-apis. -> Go to the Accessing CrowdStrike API specification and find the API reference link for your cloud environment region.

NOTE: Your Base URL depends on your cloud environment region.
For example, the US-2 cloud environment will have the base URL as https://falcon.us-2.crowdstrike.com.

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

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.11.0**.
This module has been tested against the **CrowdStrike Falcon Intelligence API Version v1**.

## Setup

### To collect data from CrowdStrike Falcon Intelligence, the following parameters from your CrowdStrike Falcon Intelligence instance are required:

1. Client ID
2. Client Secret
3. Token url
4. API Endpoint url
5. Required scopes for each data stream :

    | Data Stream   | Scope         |
    | ------------- | ------------- |
    | Intel         | read:intel    |
    | IOC           | read:iocs     |

Follow the [documentation](https://www.crowdstrike.com/blog/tech-center/consume-ioc-and-threat-feeds/) for enabling the scopes from the CrowdStrike console.

User should either have `admin` role or `Detection Exception Manager` role to access IOCs endpoint. Follow the [documentation](https://falcon.crowdstrike.com/documentation/page/f20650df/default-roles-reference) for managing user roles and permissions.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type CrowdStrike Falcon Intelligence
3. Click on the "CrowdStrike Falcon Intelligence" integration from the search results.
4. Click on the "Add CrowdStrike Falcon Intelligence" button to add the integration.
5. Add all the required integration configuration parameters, such as Client ID, Client Secret, URL, and Token URL. For all data streams, these parameters must be provided in order to retrieve logs.
6. Save the integration.

## IoCs Expiration

The ingested IOCs expire after a certain duration. A separate [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for Intel and IOC datasets to facilitate only active Indicators and IOCs, respectively, being available to the end users. Since we want to retain only valuable information and avoid duplicated data, the CrowdStrike Falcon Intelligence Elastic integration forces the intel indicators to rotate into a custom index called: `logs-ti_crowdstrike_latest.dest_intel` and forces the IOC logs to rotate into a custom index called: `logs-ti_crowdstrike_latest.dest_ioc`.
**Please, refer to this index in order to set alerts and so on.**

#### Handling Orphaned IOCs

IOC expiration is set default to false in CrowdStrike console but user can set the expiration duration in using the admin console. Some CrowdStrike IOCs may never expire and will continue to stay in the latest destination index. To avoid any false positives from such orphaned IOCs, users are allowed to configure `IOC Expiration Duration` parameter for both the dataset Intel and IOC, respectively, while setting up the integration. This parameter deletes all data inside the destination index `logs-ti_crowdstrike_latest.intel` and `logs-ti_crowdstrike_latest.ioc` after this specified duration is reached. Users must pull entire feed instead of incremental feed when this expiration happens so that the IOCs get reset.

### How it works

This is possible thanks to a transform rule installed along with the integration. The transform rule parses the data stream content that is pulled from CrowdStrike Falcon Intelligence and only adds new intel indicators.

Both the data stream and the latest index have applied expiration through ILM and a retention policy in the transform respectively.

## Logs Reference

### Intel

This is the `Intel` dataset.

#### Example

An example event for `intel` looks as following:

```json
{
    "@timestamp": "2023-11-21T06:16:01.000Z",
    "agent": {
        "ephemeral_id": "ee250a38-ef6d-486c-a245-6d0dd0785a11",
        "id": "803f2aef-a6c1-47c8-b64d-e484bb967db4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "ti_crowdstrike.intel",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "803f2aef-a6c1-47c8-b64d-e484bb967db4",
        "snapshot": false,
        "version": "8.12.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_crowdstrike.intel",
        "id": "hash_sha256_c98e1a7f563824cd448b47613743dcd1c853742b78f42b000192b83d",
        "ingested": "2024-03-28T10:49:11Z",
        "kind": "enrichment",
        "original": "{\"_marker\":\"17005473618d17ae6353d123235e4158c5c81f25f0\",\"actors\":[\"SALTYSPIDER\"],\"deleted\":false,\"domain_types\":[\"abc.com\"],\"id\":\"hash_sha256_c98e1a7f563824cd448b47613743dcd1c853742b78f42b000192b83d\",\"indicator\":\"c98e192bf71a7f97563824cd448b47613743dcd1c853742b78f42b000192b83d\",\"ip_address_types\":[\"81.2.69.192\"],\"kill_chains\":[\"Installation\",\"C2\"],\"labels\":[{\"created_on\":1700547356,\"last_valid_on\":1700547360,\"name\":\"MaliciousConfidence/High\"},{\"created_on\":1700547359,\"last_valid_on\":1700547359,\"name\":\"Malware/Mofksys\"},{\"created_on\":1700547359,\"last_valid_on\":1700547359,\"name\":\"ThreatType/Commodity\"},{\"created_on\":1700547359,\"last_valid_on\":1700547359,\"name\":\"ThreatType/CredentialHarvesting\"},{\"created_on\":1700547359,\"last_valid_on\":1700547359,\"name\":\"ThreatType/InformationStealer\"}],\"last_updated\":1700547361,\"malicious_confidence\":\"high\",\"malware_families\":[\"Mofksys\"],\"published_date\":1700547356,\"relations\":[{\"created_date\":1700547339,\"id\":\"domain.com.yy\",\"indicator\":\"domain.ds\",\"last_valid_date\":1700547339,\"type\":\"domain\"},{\"created_date\":1700547339,\"id\":\"domain.xx.yy\",\"indicator\":\"domain.xx.fd\",\"last_valid_date\":1700547339,\"type\":\"domain\"}],\"reports\":[\"reports\"],\"targets\":[\"abc\"],\"threat_types\":[\"Commodity\",\"CredentialHarvesting\",\"InformationStealer\"],\"type\":\"hash_sha256\",\"vulnerabilities\":[\"vuln\"]}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hash": [
            "c98e192bf71a7f97563824cd448b47613743dcd1c853742b78f42b000192b83d"
        ],
        "ip": [
            "81.2.69.192"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "ti_crowdstrike-intel"
    ],
    "threat": {
        "indicator": {
            "confidence": "High",
            "file": {
                "hash": {
                    "sha256": "c98e192bf71a7f97563824cd448b47613743dcd1c853742b78f42b000192b83d"
                }
            },
            "name": "c98e192bf71a7f97563824cd448b47613743dcd1c853742b78f42b000192b83d",
            "provider": "crowdstrike",
            "type": "file"
        }
    },
    "ti_crowdstrike": {
        "intel": {
            "_marker": "17005473618d17ae6353d123235e4158c5c81f25f0",
            "actors": [
                "SALTYSPIDER"
            ],
            "deleted": false,
            "deleted_at": "2023-11-21T11:16:01.000Z",
            "domain_types": [
                "abc.com"
            ],
            "expiration_duration": "5h",
            "id": "hash_sha256_c98e1a7f563824cd448b47613743dcd1c853742b78f42b000192b83d",
            "ip_address_types": [
                "81.2.69.192"
            ],
            "kill_chains": [
                "Installation",
                "C2"
            ],
            "labels": [
                {
                    "created_on": "2023-11-21T06:15:56.000Z",
                    "last_valid_on": "2023-11-21T06:16:00.000Z",
                    "name": "MaliciousConfidence/High"
                },
                {
                    "created_on": "2023-11-21T06:15:59.000Z",
                    "last_valid_on": "2023-11-21T06:15:59.000Z",
                    "name": "Malware/Mofksys"
                },
                {
                    "created_on": "2023-11-21T06:15:59.000Z",
                    "last_valid_on": "2023-11-21T06:15:59.000Z",
                    "name": "ThreatType/Commodity"
                },
                {
                    "created_on": "2023-11-21T06:15:59.000Z",
                    "last_valid_on": "2023-11-21T06:15:59.000Z",
                    "name": "ThreatType/CredentialHarvesting"
                },
                {
                    "created_on": "2023-11-21T06:15:59.000Z",
                    "last_valid_on": "2023-11-21T06:15:59.000Z",
                    "name": "ThreatType/InformationStealer"
                }
            ],
            "last_updated": "2023-11-21T06:16:01.000Z",
            "malicious_confidence": "high",
            "malware_families": [
                "Mofksys"
            ],
            "published_date": "2023-11-21T06:15:56.000Z",
            "relations": [
                {
                    "created_date": "2023-11-21T06:15:39.000Z",
                    "id": "domain.com.yy",
                    "indicator": "domain.ds",
                    "last_valid_date": "2023-11-21T06:15:39.000Z",
                    "type": "domain"
                },
                {
                    "created_date": "2023-11-21T06:15:39.000Z",
                    "id": "domain.xx.yy",
                    "indicator": "domain.xx.fd",
                    "last_valid_date": "2023-11-21T06:15:39.000Z",
                    "type": "domain"
                }
            ],
            "reports": [
                "reports"
            ],
            "targets": [
                "abc"
            ],
            "threat_types": [
                "Commodity",
                "CredentialHarvesting",
                "InformationStealer"
            ],
            "type": "hash_sha256",
            "value": "c98e192bf71a7f97563824cd448b47613743dcd1c853742b78f42b000192b83d",
            "vulnerabilities": [
                "vuln"
            ]
        }
    },
    "vulnerability": {
        "category": [
            "vuln"
        ]
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
| ti_crowdstrike.intel._marker | A special marker associated with the Intel Indicator. | keyword |
| ti_crowdstrike.intel.actors | Information related to actors associated with the Intel Indicator. | keyword |
| ti_crowdstrike.intel.deleted | Indicates whether the Intel Indicator has been deleted. | boolean |
| ti_crowdstrike.intel.deleted_at | Date when IOC was deleted/expired. | date |
| ti_crowdstrike.intel.domain_types | Information related to domain types associated with the Intel Indicator. | keyword |
| ti_crowdstrike.intel.expiration_duration |  | keyword |
| ti_crowdstrike.intel.id | A unique identifier for the Intel Indicator. | keyword |
| ti_crowdstrike.intel.ip_address_types | Information related to IP address types associated with the Intel Indicator. | keyword |
| ti_crowdstrike.intel.kill_chains | Information related to kill chains associated with the Intel Indicator. | keyword |
| ti_crowdstrike.intel.labels.created_on | Timestamp indicating when the labels were created. | date |
| ti_crowdstrike.intel.labels.last_valid_on | Timestamp indicating when the labels were last valid. | date |
| ti_crowdstrike.intel.labels.name | The name of labels associated with the Intel Indicator. | keyword |
| ti_crowdstrike.intel.last_updated | Timestamp indicating when the Intel Indicator was last updated. | date |
| ti_crowdstrike.intel.malicious_confidence | Indicates the level of confidence that the Intel Indicator is malicious. | keyword |
| ti_crowdstrike.intel.malware_families | Information related to malware families associated with the Intel Indicator. | keyword |
| ti_crowdstrike.intel.published_date | Timestamp indicating when the Intel Indicator was published. | date |
| ti_crowdstrike.intel.relations.created_date | Create date of relation. | date |
| ti_crowdstrike.intel.relations.id | Id of the relation. | keyword |
| ti_crowdstrike.intel.relations.indicator | Indicator associated with the relation. | keyword |
| ti_crowdstrike.intel.relations.last_valid_date | Last valid date of relation. | date |
| ti_crowdstrike.intel.relations.type | Type of relation. | keyword |
| ti_crowdstrike.intel.reports | Information related to reports associated with the Intel Indicator. | keyword |
| ti_crowdstrike.intel.targets | Information related to targets associated with the Intel Indicator. | keyword |
| ti_crowdstrike.intel.threat_types | Information related to threat types associated with the Intel Indicator. | keyword |
| ti_crowdstrike.intel.type | The type of indicator, indicating it is a SHA256 hash. | keyword |
| ti_crowdstrike.intel.value | The specific value of the indicator. | keyword |
| ti_crowdstrike.intel.vulnerabilities | Information related to vulnerabilities associated with the Intel Indicator. | keyword |


### IOC

This is the `IOC` dataset.

#### Example

An example event for `ioc` looks as following:

```json
{
    "@timestamp": "2023-11-01T10:22:23.106Z",
    "agent": {
        "ephemeral_id": "ca4c5a70-0aa1-4cb3-867c-3c099798eef4",
        "id": "803f2aef-a6c1-47c8-b64d-e484bb967db4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "ti_crowdstrike.ioc",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "803f2aef-a6c1-47c8-b64d-e484bb967db4",
        "snapshot": false,
        "version": "8.12.0"
    },
    "event": {
        "action": "detect-again",
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_crowdstrike.ioc",
        "id": "34874a88935860cf6yyfc856d6abb6f35a29d8c077195ed6291aa8373696b44",
        "ingested": "2024-03-28T10:50:10Z",
        "kind": "enrichment",
        "original": "{\"action\":\"detect again\",\"applied_globally\":true,\"created_by\":\"abc.it@example.com\",\"created_on\":\"2023-11-01T10:22:23.10607613Z\",\"deleted\":false,\"description\":\"IS-38887\",\"expired\":false,\"from_parent\":false,\"id\":\"34874a88935860cf6yyfc856d6abb6f35a29d8c077195ed6291aa8373696b44\",\"metadata\":{\"filename\":\"High_Serverity_Heuristic_Sandbox_Threat.docx\"},\"modified_by\":\"example.it@ex.com\",\"modified_on\":\"2023-11-01T10:22:23.10607613Z\",\"platforms\":[\"windows\",\"mac\",\"linux\"],\"severity\":\"critical\",\"tags\":[\"IS-38887\"],\"type\":\"ipv4\",\"value\":\"81.2.69.192\"}",
        "type": [
            "indicator"
        ]
    },
    "file": {
        "name": "High_Serverity_Heuristic_Sandbox_Threat.docx"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "ip": [
            "81.2.69.192"
        ],
        "user": [
            "example.it@ex.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "ti_crowdstrike-ioc"
    ],
    "threat": {
        "indicator": {
            "description": "IS-38887",
            "first_seen": "2023-11-01T10:22:23.106Z",
            "ip": "81.2.69.192",
            "modified_at": "2023-11-01T10:22:23.106Z",
            "name": "81.2.69.192",
            "provider": "crowdstrike",
            "type": "ipv4-addr"
        }
    },
    "ti_crowdstrike": {
        "ioc": {
            "action": "detect again",
            "applied_globally": true,
            "created_by": "abc.it@example.com",
            "created_on": "2023-11-01T10:22:23.106Z",
            "deleted": false,
            "deleted_at": "2023-11-01T15:22:23.106Z",
            "description": "IS-38887",
            "expiration_duration": "5h",
            "expired": false,
            "from_parent": false,
            "id": "34874a88935860cf6yyfc856d6abb6f35a29d8c077195ed6291aa8373696b44",
            "metadata": {
                "filename": "High_Serverity_Heuristic_Sandbox_Threat.docx"
            },
            "modified_by": "example.it@ex.com",
            "modified_on": "2023-11-01T10:22:23.106Z",
            "platforms": [
                "windows",
                "mac",
                "linux"
            ],
            "severity": "critical",
            "tags": [
                "IS-38887"
            ],
            "type": "ipv4",
            "value": "81.2.69.192"
        }
    },
    "user": {
        "domain": "example.com",
        "name": "abc.it"
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
| ti_crowdstrike.ioc.action | Describes the action taken when the IOC is detected. | keyword |
| ti_crowdstrike.ioc.applied_globally | Indicates whether the IOC is applied globally. | boolean |
| ti_crowdstrike.ioc.created_by | Indicates the entity or user who created the IOC. | keyword |
| ti_crowdstrike.ioc.created_on | Timestamp indicating when the IOC was created. | date |
| ti_crowdstrike.ioc.deleted | Indicates whether the IOC has been deleted. | boolean |
| ti_crowdstrike.ioc.deleted_at | Date when IOC was deleted/expired. | date |
| ti_crowdstrike.ioc.description | A textual description associated with the IOC. | keyword |
| ti_crowdstrike.ioc.expiration_duration |  | keyword |
| ti_crowdstrike.ioc.expired | Indicates whether the IOC has expired. | boolean |
| ti_crowdstrike.ioc.from_parent | Indicates whether the IOC originated from a parent entity. | boolean |
| ti_crowdstrike.ioc.id | A unique identifier for the IOC. | keyword |
| ti_crowdstrike.ioc.metadata | Additional information or context about the IOC. | flattened |
| ti_crowdstrike.ioc.modified_by | Indicates the entity or user who last modified the IOC. | keyword |
| ti_crowdstrike.ioc.modified_on | Timestamp indicating when the IOC was last modified. | date |
| ti_crowdstrike.ioc.platforms | Specifies the platforms associated with the IOC. | keyword |
| ti_crowdstrike.ioc.severity | Indicates the severity level associated with the detection. | keyword |
| ti_crowdstrike.ioc.tags | Tags associated with the IOC. | keyword |
| ti_crowdstrike.ioc.type | The type of indicator. | keyword |
| ti_crowdstrike.ioc.value | The specific value of the indicator. | ip |
