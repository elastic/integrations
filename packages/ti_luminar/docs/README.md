# Luminar Intelligence integration

This integration connects with the [Luminar Threat Intelligence](https://www.cognyte.com/) TAXII version 2 server.
It includes the following datasets for retrieving logs:

| Dataset | Luminar Collection name |
|--------:|:-----------------------|
|     ioc | IOCs                   |
|  leakedrecords | Leaked Records  |
|      cyberfeeds | Cyber Feeds    |

## Expiration of Indicators of Compromise (IOCs)
The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to 
facilitate only active IOCs be available to the end users. Each transform creates a destination index named `logs-ti_luminar_latest.*` which only contains active and unexpired IOCs.
Destinations indices are aliased to `logs-ti_luminar_latest.<feed name>`.

| Source Datastream        | Destination Index Pattern          | Destination Alias           |
|:-------------------------|:-----------------------------------|-----------------------------|
| `logs-ti_luminar.iocs-*`     | logs-ti_luminar_latest.iocs-*     | logs-ti_luminar_latest.iocs     |
| `logs-ti_luminar.leakedrecords-*`  | logs-ti_luminar_latest.leakedrecords-*  | logs-ti_luminar_latest.leakedrecords  |
| `logs-ti_luminar.cyberfeeds-*`      |  logs-ti_luminar_latest.cyberfeeds-*      | logs-ti_luminar_latest.cyberfeeds      |

### ILM Policy
ILM policy is added to the source indices, so it doesn't lead to unbounded growth.
Data in these source indices will be deleted after a certain number of days from ingested days:

|                  Index | Deleted after |
|-----------------------:|:--------------|
|     `logs-ti_luminar.iocs-default_policy` | 5d          |
|  `logs-ti_luminar.leakedrecords-default_policy` | 5d            |
|      `logs-ti_luminar.cyberfeeds-default_policy` | 5d            |

## Requirements

Elastic Agent must be installed.
For more information,
refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure,
and manage your agents in a central location.
We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach,
you install Elastic Agent and manually configure the agent locally on the system where it’s installed.
You are responsible for managing and upgrading the agents.
This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone.
Docker images for all versions of Elastic Agent are available from the Elastic Docker registry,
and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information,
refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Luminar Threat Intelligence.
3. Click on the "Luminar Threat Intelligence" integration from the search results.
4. Click on the "Add Luminar Threat Intelligence" button to add the integration.
5. Configure all required integration parameters, including accountId, clientId, clientSecret that you have received from Luminar during onboarding process. For more information, please visit [Luminar Threat Intelligence](https://www.cognyte.com/) page.
6. Enable data streams you are interested in and have access to.
7. Save the integration.

## Logs

### IOCs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| luminar.aliases | The aliases of the stix object. | keyword |
| luminar.confidence | The confidence property identifies the confidence that the creator has in the correctness of their data. The confidence value MUST be a number in the range of 0-100. | integer |
| luminar.country | The country name or code of the stix object. | keyword |
| luminar.created | The time at which the stix object was originally created. | date |
| luminar.created_by_ref | The created_by_ref property specifies the id property of the object that describes the entity that created this object. | keyword |
| luminar.description | The description of the stix object. | keyword |
| luminar.extensions | Specifies any extensions of the object, as a dictionary. | flattened |
| luminar.external_references | The external_references property specifies a list of external references which refers to non-STIX information. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems. | flattened |
| luminar.id | The ID of the stix object. | keyword |
| luminar.identity_class | The class of identity stix object. | keyword |
| luminar.indicator_types | The types of the indicator. | keyword |
| luminar.ioc_expiration_date | The expiration date of the indicator. It can be defined from the source event, by the revoked or valid_until fields, or from the integration configuration by ioc_expiration_duration. | date |
| luminar.ioc_expiration_duration | The configured expiration duration for the indicator. | keyword |
| luminar.ioc_expiration_reason | Reason why the indicator is expired. Defined by the integration in the ingest pipeline. | keyword |
| luminar.is_family | The is_family property indicates whether the malware object is a family of malware. | boolean |
| luminar.malware_types | The types of the malware. | keyword |
| luminar.modified | The time at which the stix Object was last modified. | date |
| luminar.name | The name of the stix object. | keyword |
| luminar.object_refs | The references of the stix object. | keyword |
| luminar.pattern | The pattern of the indicator stix object. | keyword |
| luminar.relationship_type | The relationship type of the stix object. | keyword |
| luminar.source_ref | The source reference of the relationship stix object. | keyword |
| luminar.target_ref | The target reference of the relationship stix object. | keyword |
| luminar.threat_actor_types | The types of the threat-actor stix object. | keyword |
| luminar.type | The type of the stix object. | keyword |
| luminar.valid_from | The time from which the indicator is considered a valid indicator. | date |
| luminar.valid_until | The time until which the indicator is considered a valid indicator. | date |
| luminar.version | The version of the software object. | keyword |
| organization.class | The class of the organization in identity stix object. | keyword |
| related.directory | The related directory of the stix object. | keyword |
| related.source_ref | The source reference of the stix object. | keyword |
| related.target_ref | The target reference of the stix object. | keyword |
| related.type | The relationship type of the stix object. | keyword |
| related.url | The related URL of the stix object. | keyword |
| threat.actor.aliases | The aliases of the threat actor stix object. | keyword |
| threat.actor.description | The description of the threat actor stix object. | keyword |
| threat.actor.name | The name of the threat actor stix object. | keyword |
| threat.actor.types | The types of the threat actor stix object. | keyword |
| threat.campaign.name | The name of the campaign stix object. | keyword |
| threat.indicator.directory.path | The directory path of the indicator stix object. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.mutex | The mutex of the indicator stix object. | keyword |
| threat.indicator.score | The score of the indicator stix object. | integer |
| threat.indicator.types | The types of the indicator stix object. | keyword |
| threat.software.capabilities | The capabilities of the malware stix object. | keyword |
| threat.software.malware_types | The malware types of the malware stix object. | keyword |
| threat.software.version | The version of the malware stix object. | keyword |


An example event for `iocs` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "bcacd033-7146-45b0-9e5c-9b269f0786a1",
        "ephemeral_id": "976c4824-0ae1-41c1-abbd-625f828b3af3",
        "type": "filebeat",
        "version": "8.18.2"
    },
    "luminar": {
        "ioc_expiration_reason": "Expiration set from valid_until field",
        "created": "2025-07-08T00:00:00.000Z",
        "confidence": 82,
        "ioc_expiration_duration": "90d",
        "pattern": "[url:value = 'https://[2a02:4780:53:2919:52a4:dfdc:caee:8116]']",
        "valid_from": "2025-07-08T00:00:00.000Z",
        "type": "indicator",
        "labels": [
            "malware",
            "phishing"
        ],
        "extensions": {
            "score": 96,
            "luminar_tenant_id": "00bed954-4b1a-4d52-97f7-2a2c51b824ff",
            "resolving_domains": [
                "armcommodities.com"
            ],
            "extension_type": "property-extension"
        },
        "valid_until": "2025-07-15T00:00:00.000Z",
        "ioc_expiration_date": "2025-07-15T00:00:00.000Z",
        "indicator_types": [
            "malicious-activity"
        ],
        "modified": "2025-07-08T13:00:55.389Z",
        "id": "indicator--31885a32-9800-5b89-bde1-86e2a36731db",
        "created_by_ref": "identity--5bf1ac35-8d08-509e-b31a-044cb09b4199"
    },
    "elastic_agent": {
        "id": "bcacd033-7146-45b0-9e5c-9b269f0786a1",
        "version": "8.18.2",
        "snapshot": false
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "luminar_iocs",
        "luminar_stix_indicator"
    ],
    "input": {
        "type": "cel"
    },
    "@timestamp": "2025-07-08T00:00:00.000Z",
    "ecs": {
        "version": "8.17.0"
    },
    "related": {
        "hosts": [
            "armcommodities.com"
        ],
        "url": [
            "https://[2a02:4780:53:2919:52a4:dfdc:caee:8116]"
        ]
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "ti_luminar.iocs"
    },
    "threat": {
        "indicator": {
            "score": 96,
            "types": [
                "malicious-activity"
            ],
            "first_seen": "2025-07-08T00:00:00.000Z",
            "last_seen": "2025-07-08T13:00:55.389Z",
            "provider": "luminar",
            "confidence": "High",
            "modified_at": "2025-07-08T13:00:55.389Z",
            "type": "url",
            "url": {
                "original": [
                    "https://[2a02:4780:53:2919:52a4:dfdc:caee:8116]"
                ]
            }
        },
        "feed": {
            "reference": "www.cyberluminar.com",
            "name": "IOCs"
        }
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-07-10T07:20:31Z",
        "original": "{\"confidence\":82,\"created\":\"2025-07-08T00:00:00.000Z\",\"created_by_ref\":\"identity--5bf1ac35-8d08-509e-b31a-044cb09b4199\",\"extensions\":{\"extension-definition--ddd2bf71-3c91-5f4d-8251-10cd685737c3\":{\"extension_type\":\"property-extension\",\"luminar_tenant_id\":\"00bed954-4b1a-4d52-97f7-2a2c51b824ff\",\"resolving_domains\":[\"armcommodities.com\"],\"score\":96}},\"id\":\"indicator--31885a32-9800-5b89-bde1-86e2a36731db\",\"indicator_types\":[\"malicious-activity\"],\"labels\":[\"malware\",\"phishing\"],\"modified\":\"2025-07-08T13:00:55.389Z\",\"pattern\":\"[url:value = 'https://[2a02:4780:53:2919:52a4:dfdc:caee:8116]']\",\"pattern_type\":\"stix\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2025-07-08T00:00:00.000Z\",\"valid_until\":\"2025-07-15T00:00:00.000Z\"}",
        "kind": "enrichment",
        "category": [
            "threat"
        ],
        "type": [
            "indicator"
        ],
        "dataset": "ti_luminar.iocs"
    }
}
```

### Leaked Records

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| file.reference | The reference of the file object. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| luminar.account_login | The account_login of the user account. | keyword |
| luminar.capabilities | The capabilities of malware object. | keyword |
| luminar.created | The time at which the stix object was originally created. | date |
| luminar.created_by_ref | The created_by_ref property specifies the id property of the object that describes the entity that created this object. | keyword |
| luminar.credential | The credential of user object. | keyword |
| luminar.description | The description of the stix object. | keyword |
| luminar.display_name | The display_name of user object. | keyword |
| luminar.extensions | Specifies any extensions of the object, as a dictionary. | flattened |
| luminar.id | The ID of the stix object. | keyword |
| luminar.is_family | The is_family property indicates whether the malware object is a family of malware. | boolean |
| luminar.malware_types | The types of the malware. | keyword |
| luminar.modified | The time at which the stix Object was last modified. | date |
| luminar.name | The name of the stix object. | keyword |
| luminar.parent_directory_ref | The parent_directory_ref of file. | keyword |
| luminar.path | The path of directory or file object. | keyword |
| luminar.relationship_type | The relationship type of the stix object. | keyword |
| luminar.sample_refs | The sample_refs of malware object. | keyword |
| luminar.source_ref | The source reference of the relationship stix object. | keyword |
| luminar.target_ref | The target reference of the relationship stix object. | keyword |
| luminar.type | The type of the stix object. | keyword |
| luminar.value | The value of stix object. | keyword |
| related.references | The references of the stix object. | keyword |
| related.source_ref | The source reference of the stix object. | keyword |
| related.target_ref | The target reference of the stix object. | keyword |
| related.type | The relationship type of the stix object. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.software.capabilities | The capabilities of the malware stix object. | keyword |
| threat.software.malware_types | The malware types of the malware stix object. | keyword |
| user.credential | The credential of the user object. | keyword |


An example event for `leakedrecords` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "6095e1b1-35f8-4c17-a6db-7898c2c0bf0e",
        "ephemeral_id": "f0ea587e-9aed-48f8-965a-fe2003563778",
        "type": "filebeat",
        "version": "8.18.2"
    },
    "luminar": {
        "extensions": {
            "luminar_threat_score": 71,
            "collection_date": "2025-07-08T13:00:04.523Z",
            "computer_name": "DESKTOP-EP0RTVA (hmars)",
            "luminar_tenant_id": "00bed954-4b1a-4d52-97f7-2a2c51b824ff",
            "extension_type": "property-extension"
        },
        "created": "2025-07-08T11:01:44.457Z",
        "name": "Lumma - DESKTOP-EP0RTVA (hmars) - 73.160.225.166 - 08/07/2025",
        "modified": "2025-07-08T14:40:12.887Z",
        "id": "incident--d8666238-3fae-558f-bda8-02dac24e0380",
        "created_by_ref": "identity--5bf1ac35-8d08-509e-b31a-044cb09b4199",
        "type": "incident"
    },
    "elastic_agent": {
        "id": "6095e1b1-35f8-4c17-a6db-7898c2c0bf0e",
        "version": "8.18.2",
        "snapshot": false
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "luminar_leakedrecords",
        "luminar_stix_incident"
    ],
    "input": {
        "type": "cel"
    },
    "@timestamp": "2025-07-08T11:01:44.457Z",
    "ecs": {
        "version": "8.17.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "ti_luminar.leakedrecords"
    },
    "host": {
        "name": "DESKTOP-EP0RTVA (hmars)"
    },
    "threat": {
        "feed": {
            "reference": "www.cyberluminar.com",
            "name": "Leaked Records"
        }
    },
    "event": {
        "agent_id_status": "verified",
        "reason": "Lumma - DESKTOP-EP0RTVA (hmars) - 73.160.225.166 - 08/07/2025",
        "ingested": "2025-07-09T23:49:11Z",
        "original": "{\"created\":\"2025-07-08T11:01:44.457Z\",\"created_by_ref\":\"identity--5bf1ac35-8d08-509e-b31a-044cb09b4199\",\"extensions\":{\"extension-definition--ddd2bf71-3c91-5f4d-8251-10cd685737c3\":{\"collection_date\":\"2025-07-08T13:00:04.523Z\",\"computer_name\":\"DESKTOP-EP0RTVA (hmars)\",\"extension_type\":\"property-extension\",\"luminar_tenant_id\":\"00bed954-4b1a-4d52-97f7-2a2c51b824ff\",\"luminar_threat_score\":71}},\"id\":\"incident--d8666238-3fae-558f-bda8-02dac24e0380\",\"modified\":\"2025-07-08T14:40:12.887Z\",\"name\":\"Lumma - DESKTOP-EP0RTVA (hmars) - 73.160.225.166 - 08/07/2025\",\"spec_version\":\"2.1\",\"type\":\"incident\"}",
        "kind": "alert",
        "action": "user-password-leak",
        "end": "2025-07-08T14:40:12.887Z",
        "id": "incident--d8666238-3fae-558f-bda8-02dac24e0380",
        "category": [
            "threat"
        ],
        "type": [
            "info"
        ],
        "dataset": "ti_luminar.leakedrecords"
    }
}
```

### Cyber Feeds

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| luminar.aliases | The aliases of the stix object. | keyword |
| luminar.country | The country name or code of the stix object. | keyword |
| luminar.created | The time at which the stix object was originally created. | date |
| luminar.description | The description of the stix object. | keyword |
| luminar.extensions | Specifies any extensions of the object, as a dictionary. | flattened |
| luminar.external_references | The external_references property specifies a list of external references which refers to non-STIX information. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems. | flattened |
| luminar.id | The ID of the stix object. | keyword |
| luminar.identity_class | The class of identity stix object. | keyword |
| luminar.indicator_types | The types of the indicator. | keyword |
| luminar.ioc_expiration_date | The expiration date of the indicator. It can be defined from the source event, by the revoked or valid_until fields, or from the integration configuration by ioc_expiration_duration. | date |
| luminar.ioc_expiration_duration | The configured expiration duration for the indicator. | keyword |
| luminar.ioc_expiration_reason | Reason why the indicator is expired. Defined by the integration in the ingest pipeline. | keyword |
| luminar.modified | The time at which the stix Object was last modified. | date |
| luminar.name | The name of the stix object. | keyword |
| luminar.object_refs | The references of the stix object. | keyword |
| luminar.pattern | The pattern of the indicator stix object. | keyword |
| luminar.published | The published date of the report stix object. | date |
| luminar.relationship_type | The relationship type of the stix object. | keyword |
| luminar.report_types | The types of the report stix object. | keyword |
| luminar.source_ref | The source reference of the relationship stix object. | keyword |
| luminar.target_ref | The target reference of the relationship stix object. | keyword |
| luminar.threat_actor_types | The types of the threat-actor stix object. | keyword |
| luminar.type | The type of the stix object. | keyword |
| luminar.valid_from | The time from which the indicator is considered a valid indicator. | date |
| organization.class | The class of the organization in identity stix object. | keyword |
| related.directory | The related directory of the stix object. | keyword |
| related.references | The references of the stix object. | keyword |
| related.source_ref | The source reference of the stix object. | keyword |
| related.target_ref | The target reference of the stix object. | keyword |
| related.type | The relationship type of the stix object. | keyword |
| related.url | The related URL of the stix object. | keyword |
| threat.actor.aliases | The aliases of the threat actor stix object. | keyword |
| threat.actor.description | The description of the threat actor stix object. | keyword |
| threat.actor.name | The name of the threat actor stix object. | keyword |
| threat.actor.types | The types of the threat actor stix object. | keyword |
| threat.campaign.name | The name of the campaign stix object. | keyword |
| threat.indicator.directory.path | The directory path of the indicator stix object. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.mutex | The mutex of the indicator stix object. | keyword |
| threat.indicator.score | The score of the indicator stix object. | integer |
| threat.indicator.types | The types of the indicator stix object. | keyword |
| threat.software.capabilities | The capabilities of the malware stix object. | keyword |
| threat.software.malware_types | The malware types of the malware stix object. | keyword |


An example event for `cyberfeeds` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "6095e1b1-35f8-4c17-a6db-7898c2c0bf0e",
        "ephemeral_id": "f0ea587e-9aed-48f8-965a-fe2003563778",
        "type": "filebeat",
        "version": "8.18.2"
    },
    "luminar": {
        "extensions": {
            "luminar_tenant_id": "00bed954-4b1a-4d52-97f7-2a2c51b824ff",
            "extension_type": "property-extension"
        },
        "created": "2025-07-08T06:03:17.000Z",
        "name": "Atomic macOS Infostealer Adds Backdoor for Persistent Attacks",
        "modified": "2025-07-08T19:00:13.515Z",
        "description": "A new version of the Atomic macOS info-stealer (AMOS) has been discovered with an embedded backdoor that allows attackers persistent, remote access to compromised systems by executing arbitrary commands, surviving reboots, and maintaining long-term control. The malware targets macOS files, cryptocurrency extensions, and user passwords and uses LaunchDaemons and hidden scripts ('.helper' and '.agent') to ensure persistence, leveraging stolen user credentials to install components with superuser privileges. Active campaigns have impacted over 120 countries, with the United States, France, Italy, the United Kingdom, and Canada among the most affected, and a large-scale September 2024 operation linked to the cybercrime group 'Marko Polo' targeting Apple computers. Recent distribution has shifted from cracked software sites to more targeted phishing at cryptocurrency owners and freelancers. The backdoor enables remote command execution, keystroke logging, additional payload delivery, and supports evasion techniques such as sandbox and VM checks with obfuscated strings. ",
        "report_types": [
            "campaign",
            "malware",
            "threat-actor"
        ],
        "id": "report--ff5e5db3-6eb0-5975-b44d-d6a621287f77",
        "published": "2025-07-08T06:03:17.000Z",
        "type": "report",
        "object_refs": [
            "campaign--6e954cd1-43a7-566f-81b9-a85db81cf29c",
            "location--5678b9ec-4db5-5a98-a903-e5897acc6b8b",
            "location--247e7d3c-2a0f-5542-8970-90ae6604788f",
            "location--83d6dd19-7ed7-5c27-977f-20709369b2bc",
            "location--05b29aab-c640-5254-9023-2cd2e770f5fd",
            "location--d7e23c9c-5114-57ed-a274-2a507e960c52",
            "malware--ad5919f6-bdb5-5acd-b963-5967d1b3b012",
            "threat-actor--641c7988-4013-563c-9a88-ab5abb28564f",
            "software--3f32a881-1e30-5a35-b159-9211d1e6aa43",
            "relationship--1f965da1-4562-5820-84f6-9945623aaa37",
            "relationship--5813dcad-c754-5971-a3bd-deb680972a4f",
            "relationship--89eb85d2-91e5-567e-8c88-4136a02f09a5",
            "relationship--d455d8fd-49cc-5eb3-85ec-9efc67922d71",
            "relationship--7e41c4e3-7a73-5d9b-a2b0-1c6975d13cc1",
            "relationship--fd0ce53b-c62d-59e5-9cea-3bf5fd599e83"
        ]
    },
    "elastic_agent": {
        "id": "6095e1b1-35f8-4c17-a6db-7898c2c0bf0e",
        "version": "8.18.2",
        "snapshot": false
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "luminar_cyberfeeds",
        "luminar_stix_report"
    ],
    "input": {
        "type": "cel"
    },
    "@timestamp": "2025-07-08T06:03:17.000Z",
    "ecs": {
        "version": "8.17.0"
    },
    "related": {
        "references": [
            "campaign--6e954cd1-43a7-566f-81b9-a85db81cf29c",
            "location--5678b9ec-4db5-5a98-a903-e5897acc6b8b",
            "location--247e7d3c-2a0f-5542-8970-90ae6604788f",
            "location--83d6dd19-7ed7-5c27-977f-20709369b2bc",
            "location--05b29aab-c640-5254-9023-2cd2e770f5fd",
            "location--d7e23c9c-5114-57ed-a274-2a507e960c52",
            "malware--ad5919f6-bdb5-5acd-b963-5967d1b3b012",
            "threat-actor--641c7988-4013-563c-9a88-ab5abb28564f",
            "software--3f32a881-1e30-5a35-b159-9211d1e6aa43",
            "relationship--1f965da1-4562-5820-84f6-9945623aaa37",
            "relationship--5813dcad-c754-5971-a3bd-deb680972a4f",
            "relationship--89eb85d2-91e5-567e-8c88-4136a02f09a5",
            "relationship--d455d8fd-49cc-5eb3-85ec-9efc67922d71",
            "relationship--7e41c4e3-7a73-5d9b-a2b0-1c6975d13cc1",
            "relationship--fd0ce53b-c62d-59e5-9cea-3bf5fd599e83"
        ]
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "ti_luminar.cyberfeeds"
    },
    "threat": {
        "feed": {
            "reference": "www.cyberluminar.com",
            "name": "Cyber Feeds"
        }
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-07-09T23:48:46Z",
        "original": "{\"created\":\"2025-07-08T06:03:17.000Z\",\"description\":\"A new version of the Atomic macOS info-stealer (AMOS) has been discovered with an embedded backdoor that allows attackers persistent, remote access to compromised systems by executing arbitrary commands, surviving reboots, and maintaining long-term control. The malware targets macOS files, cryptocurrency extensions, and user passwords and uses LaunchDaemons and hidden scripts ('.helper' and '.agent') to ensure persistence, leveraging stolen user credentials to install components with superuser privileges. Active campaigns have impacted over 120 countries, with the United States, France, Italy, the United Kingdom, and Canada among the most affected, and a large-scale September 2024 operation linked to the cybercrime group 'Marko Polo' targeting Apple computers. Recent distribution has shifted from cracked software sites to more targeted phishing at cryptocurrency owners and freelancers. The backdoor enables remote command execution, keystroke logging, additional payload delivery, and supports evasion techniques such as sandbox and VM checks with obfuscated strings. \",\"extensions\":{\"extension-definition--ddd2bf71-3c91-5f4d-8251-10cd685737c3\":{\"extension_type\":\"property-extension\",\"luminar_tenant_id\":\"00bed954-4b1a-4d52-97f7-2a2c51b824ff\"}},\"id\":\"report--ff5e5db3-6eb0-5975-b44d-d6a621287f77\",\"modified\":\"2025-07-08T19:00:13.515Z\",\"name\":\"Atomic macOS Infostealer Adds Backdoor for Persistent Attacks\",\"object_refs\":[\"campaign--6e954cd1-43a7-566f-81b9-a85db81cf29c\",\"location--5678b9ec-4db5-5a98-a903-e5897acc6b8b\",\"location--247e7d3c-2a0f-5542-8970-90ae6604788f\",\"location--83d6dd19-7ed7-5c27-977f-20709369b2bc\",\"location--05b29aab-c640-5254-9023-2cd2e770f5fd\",\"location--d7e23c9c-5114-57ed-a274-2a507e960c52\",\"malware--ad5919f6-bdb5-5acd-b963-5967d1b3b012\",\"threat-actor--641c7988-4013-563c-9a88-ab5abb28564f\",\"software--3f32a881-1e30-5a35-b159-9211d1e6aa43\",\"relationship--1f965da1-4562-5820-84f6-9945623aaa37\",\"relationship--5813dcad-c754-5971-a3bd-deb680972a4f\",\"relationship--89eb85d2-91e5-567e-8c88-4136a02f09a5\",\"relationship--d455d8fd-49cc-5eb3-85ec-9efc67922d71\",\"relationship--7e41c4e3-7a73-5d9b-a2b0-1c6975d13cc1\",\"relationship--fd0ce53b-c62d-59e5-9cea-3bf5fd599e83\"],\"published\":\"2025-07-08T06:03:17.000Z\",\"report_types\":[\"campaign\",\"malware\",\"threat-actor\"],\"spec_version\":\"2.1\",\"type\":\"report\"}",
        "kind": [
            "event",
            "enrichment"
        ],
        "name": "Atomic macOS Infostealer Adds Backdoor for Persistent Attacks",
        "description": "A new version of the Atomic macOS info-stealer (AMOS) has been discovered with an embedded backdoor that allows attackers persistent, remote access to compromised systems by executing arbitrary commands, surviving reboots, and maintaining long-term control. The malware targets macOS files, cryptocurrency extensions, and user passwords and uses LaunchDaemons and hidden scripts ('.helper' and '.agent') to ensure persistence, leveraging stolen user credentials to install components with superuser privileges. Active campaigns have impacted over 120 countries, with the United States, France, Italy, the United Kingdom, and Canada among the most affected, and a large-scale September 2024 operation linked to the cybercrime group 'Marko Polo' targeting Apple computers. Recent distribution has shifted from cracked software sites to more targeted phishing at cryptocurrency owners and freelancers. The backdoor enables remote command execution, keystroke logging, additional payload delivery, and supports evasion techniques such as sandbox and VM checks with obfuscated strings. ",
        "category": [
            "threat"
        ],
        "type": [
            "info"
        ],
        "dataset": "ti_luminar.cyberfeeds"
    }
}
```