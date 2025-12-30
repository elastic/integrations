# Flashpoint Integration for Elastic

## Overview

[Flashpoint](https://flashpoint.io/) is a comprehensive threat intelligence platform that delivers actionable insights from dark web, deep web, and technical sources. It combines human-curated intelligence with automated collection to help organizations identify emerging threats, monitor adversary activity, and assess cyber risk with enriched context.

The Flashpoint integration for Elastic collects security indicators from the **Flashpoint Ignite API** and visualizes them in Kibana.

### Compatibility

The Flashpoint integration is compatible with Ignite API version **1.2**.

### How it works

This integration periodically queries the Flashpoint Ignite API to retrieve logs.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Indicator`: Collects `indicator` logs from the Flashpoint Ignite API (endpoint: `/technical-intelligence/v2/indicators`),

### Supported use cases

Integrating Flashpoint Indicators with Elastic SIEM provides centralized visibility into threat intelligence indicators and their associated sightings. Kibana dashboards highlight key metrics such as `Total Indicators` and `Total Indicator Sightings`, enabling quick assessment of indicator volume and activity.

Visualizations present indicators categorized by `Type` and `Score Tier` through pie charts. Tables surface `Top MITRE Tactics`, `Top Sighting Sources`, and `Top Platform URLs`, supporting deeper investigation and context. A control panel allows interactive filtering to efficiently analyze indicators across multiple dimensions.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Flashpoint

To collect data through the Flashpoint Ignite API, you need to provide an **API Token**. Authentication is handled using the **API Token**, which serves as the required credential.

#### Retrieve an API Token:

1. Log in to the **Flashpoint** Instance.
2. Click on your profile icon in the top-right corner and select **Manage API Tokens**.
3. Click **Generate Token**.
4. Enter a name for the API token and click **Generate Token**.
5. Copy and securely store the generated API token for use in the integration configuration.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.


### configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Flashpoint**.
3. Select the **Flashpoint** integration from the search results.
4. Select **Add Flashpoint** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs from Flashpoint API**, you'll need to:

        - Configure **API Token**.
        - Adjust the integration configuration parameters if required, including the **Initial Interval**, **Interval**, **Page Size** etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Flashpoint**, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **ti_flashpoint**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Indicator

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| ti_flashpoint.indicator.apt_description | A description of the related threat actor. | keyword |
| ti_flashpoint.indicator.created_at | The date and time the indicator was created within Flashpoint's dataset. | date |
| ti_flashpoint.indicator.entity_type | The entity type of the object. | keyword |
| ti_flashpoint.indicator.external_references.source_name | The name of the reference's source. | keyword |
| ti_flashpoint.indicator.external_references.url | The URL of the reference. | keyword |
| ti_flashpoint.indicator.hashes.md5 |  | keyword |
| ti_flashpoint.indicator.hashes.sha1 |  | keyword |
| ti_flashpoint.indicator.hashes.sha256 |  | keyword |
| ti_flashpoint.indicator.href | The URL to the indicator's full context data. | keyword |
| ti_flashpoint.indicator.id | The unique identifier for this indicator within Flashpoint's dataset. | keyword |
| ti_flashpoint.indicator.last_seen_at | The date and time the indicator was last seen by related sources. | date |
| ti_flashpoint.indicator.latest_sighting.apt_description | A description of the APT associated with the sighting. | keyword |
| ti_flashpoint.indicator.latest_sighting.description |  | keyword |
| ti_flashpoint.indicator.latest_sighting.href | The href of the sighting. | keyword |
| ti_flashpoint.indicator.latest_sighting.id | Unique identifier of the sighting. | keyword |
| ti_flashpoint.indicator.latest_sighting.malware_description | A description of the malware associated with the sighting. | keyword |
| ti_flashpoint.indicator.latest_sighting.mitre_attack_ids.id |  | keyword |
| ti_flashpoint.indicator.latest_sighting.mitre_attack_ids.name |  | keyword |
| ti_flashpoint.indicator.latest_sighting.mitre_attack_ids.tactics | A list of tactics associated with the MITRE ATT&CK technique. | keyword |
| ti_flashpoint.indicator.latest_sighting.related_iocs.href | The URL to the indicator's full context data. | keyword |
| ti_flashpoint.indicator.latest_sighting.related_iocs.id | The unique identifier for this indicator within Flashpoint's dataset. | keyword |
| ti_flashpoint.indicator.latest_sighting.related_iocs.score.last_scored_at | The date and time the indicator was last scored. | date |
| ti_flashpoint.indicator.latest_sighting.related_iocs.score.raw_score | The raw score of the indicator. | long |
| ti_flashpoint.indicator.latest_sighting.related_iocs.score.value | The score tier of the indicator. | keyword |
| ti_flashpoint.indicator.latest_sighting.related_iocs.type | Defines what type of indicator this is. | keyword |
| ti_flashpoint.indicator.latest_sighting.related_iocs.value | The value of the indicator. | keyword |
| ti_flashpoint.indicator.latest_sighting.sighted_at | The date and time the indicator was seen by the source. | date |
| ti_flashpoint.indicator.latest_sighting.source | The source of the sighting. | keyword |
| ti_flashpoint.indicator.latest_sighting.tags | A list of tags associated with the Sighting. | keyword |
| ti_flashpoint.indicator.malware_description |  | keyword |
| ti_flashpoint.indicator.mitre_attack_ids.id |  | keyword |
| ti_flashpoint.indicator.mitre_attack_ids.name |  | keyword |
| ti_flashpoint.indicator.mitre_attack_ids.tactics | A list of tactics associated with the MITRE ATT&CK technique. | keyword |
| ti_flashpoint.indicator.modified_at | The date and time the indicator was last modified within Flashpoint's dataset. | date |
| ti_flashpoint.indicator.platform_urls.ignite | Links to the indicator in various Flashpoint platforms. | keyword |
| ti_flashpoint.indicator.relationships.iocs.href | The URL to the indicator's full context data. | keyword |
| ti_flashpoint.indicator.relationships.iocs.id | The unique identifier for this indicator within Flashpoint's dataset. | keyword |
| ti_flashpoint.indicator.relationships.iocs.type | Defines what type of indicator this is. | keyword |
| ti_flashpoint.indicator.relationships.iocs.value | The value of the indicator. | keyword |
| ti_flashpoint.indicator.score.last_scored_at | The date and time the indicator was last scored. | date |
| ti_flashpoint.indicator.score.raw_score | The raw score of the indicator. | keyword |
| ti_flashpoint.indicator.score.value | The score tier of the indicator. | keyword |
| ti_flashpoint.indicator.sightings.apt_description | A description of the APT associated with the sighting. | keyword |
| ti_flashpoint.indicator.sightings.description |  | keyword |
| ti_flashpoint.indicator.sightings.href | The href of the sighting. | keyword |
| ti_flashpoint.indicator.sightings.id | Unique identifier of the sighting. | keyword |
| ti_flashpoint.indicator.sightings.malware_description | A description of the malware associated with the sighting. | keyword |
| ti_flashpoint.indicator.sightings.mitre_attack_ids.id |  | keyword |
| ti_flashpoint.indicator.sightings.mitre_attack_ids.name |  | keyword |
| ti_flashpoint.indicator.sightings.mitre_attack_ids.tactics | A list of tactics associated with the MITRE ATT&CK technique. | keyword |
| ti_flashpoint.indicator.sightings.related_iocs.href | The URL to the indicator's full context data. | keyword |
| ti_flashpoint.indicator.sightings.related_iocs.id | The unique identifier for this indicator within Flashpoint's dataset. | keyword |
| ti_flashpoint.indicator.sightings.related_iocs.score.last_scored_at | The date and time the indicator was last scored. | keyword |
| ti_flashpoint.indicator.sightings.related_iocs.score.raw_score | The raw score of the indicator. | long |
| ti_flashpoint.indicator.sightings.related_iocs.score.value | The score tier of the indicator. | keyword |
| ti_flashpoint.indicator.sightings.related_iocs.type | Defines what type of indicator this is. | keyword |
| ti_flashpoint.indicator.sightings.related_iocs.value | The value of the indicator. | keyword |
| ti_flashpoint.indicator.sightings.sighted_at | The date and time the indicator was seen by the source. | date |
| ti_flashpoint.indicator.sightings.source | The source of the sighting. | keyword |
| ti_flashpoint.indicator.sightings.tags | A list of tags associated with the Sighting. | keyword |
| ti_flashpoint.indicator.sort_date | The date and time defaulted for sorting indicators. This is the same value as last_seen_at. | date |
| ti_flashpoint.indicator.total_sightings | The total number of sightings for the indicator. | long |
| ti_flashpoint.indicator.type | Defines what type of indicator. | keyword |
| ti_flashpoint.indicator.value | The value of the indicator. | keyword |


### Example event

#### Indicator

An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2025-12-23T10:58:20.798Z",
    "agent": {
        "ephemeral_id": "b5fb84e6-f093-4c7b-93d8-83a7a7f972e4",
        "id": "7141cbb4-52bf-429c-89b6-2de166e645e4",
        "name": "elastic-agent-11590",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_flashpoint.indicator",
        "namespace": "75315",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "7141cbb4-52bf-429c-89b6-2de166e645e4",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-11-03T08:35:08.714Z",
        "dataset": "ti_flashpoint.indicator",
        "id": "EtniFes7WyWvawEXcL2fmQ",
        "ingested": "2025-12-23T12:55:39Z",
        "kind": "enrichment",
        "original": "{\"created_at\":\"2025-11-03T08:35:08.714000Z\",\"entity_type\":\"indicator\",\"href\":\"https://api.flashpoint.io/technical-intelligence/v2/indicators/EtniFes7WyWvawEXcL2fmQ\",\"id\":\"EtniFes7WyWvawEXcL2fmQ\",\"last_seen_at\":\"2025-12-23T10:47:29.731000Z\",\"latest_sighting\":{\"description\":\"Observation: xworm [2025-12-23T10:47:29.731Z]\",\"href\":\"https://api.flashpoint.io/technical-intelligence/v2/sightings/-mQDA1JEVYiXKTSenQuSbg\",\"id\":\"-mQDA1JEVYiXKTSenQuSbg\",\"sighted_at\":\"2025-12-23T10:47:29.731000Z\",\"source\":\"flashpoint_extraction\",\"tags\":[\"aes_key:be7b7befe99d381fbe34ef443b3179be7b7befe99d381fbe34ef443b31790e00\",\"extracted_config:true\",\"group:feturednew\",\"malware:xworm\",\"mutex:hr5unzmp8fhkimje\",\"source:flashpoint_extraction\",\"type:trojan\"]},\"modified_at\":\"2025-12-23T10:58:20.798000Z\",\"platform_urls\":{\"ignite\":\"https://app.flashpoint.io/cti/malware/iocs/EtniFes7WyWvawEXcL2fmQ\"},\"score\":{\"last_scored_at\":\"2025-11-03T08:46:17.620389Z\",\"value\":\"informational\"},\"sightings\":[{\"description\":\"Observation: xworm [2025-12-23T10:47:29.731Z]\",\"href\":\"https://api.flashpoint.io/technical-intelligence/v2/sightings/-mQDA1JEVYiXKTSenQuSbg\",\"id\":\"-mQDA1JEVYiXKTSenQuSbg\",\"sighted_at\":\"2025-12-23T10:47:29.731000Z\",\"source\":\"flashpoint_extraction\",\"tags\":[\"aes_key:be7b7befe99d381fbe34ef443b3179be7b7befe99d381fbe34ef443b31790e00\",\"extracted_config:true\",\"group:feturednew\",\"malware:xworm\",\"mutex:hr5unzmp8fhkimje\",\"source:flashpoint_extraction\",\"type:trojan\"]}],\"sort_date\":\"2025-12-23T10:47:29.731000Z\",\"total_sightings\":11,\"type\":\"domain\",\"value\":\"featured.xyz\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "ti_flashpoint-indicator"
    ],
    "threat": {
        "indicator": {
            "id": [
                "EtniFes7WyWvawEXcL2fmQ"
            ],
            "last_seen": "2025-12-23T10:47:29.731Z",
            "modified_at": "2025-12-23T10:58:20.798Z",
            "reference": [
                "https://app.flashpoint.io/cti/malware/iocs/EtniFes7WyWvawEXcL2fmQ",
                "https://api.flashpoint.io/technical-intelligence/v2/indicators/EtniFes7WyWvawEXcL2fmQ"
            ],
            "type": "domain-name"
        }
    },
    "ti_flashpoint": {
        "indicator": {
            "created_at": "2025-11-03T08:35:08.714Z",
            "entity_type": "indicator",
            "href": "https://api.flashpoint.io/technical-intelligence/v2/indicators/EtniFes7WyWvawEXcL2fmQ",
            "id": "EtniFes7WyWvawEXcL2fmQ",
            "last_seen_at": "2025-12-23T10:47:29.731Z",
            "latest_sighting": {
                "description": "Observation: xworm [2025-12-23T10:47:29.731Z]",
                "href": "https://api.flashpoint.io/technical-intelligence/v2/sightings/-mQDA1JEVYiXKTSenQuSbg",
                "id": "-mQDA1JEVYiXKTSenQuSbg",
                "sighted_at": "2025-12-23T10:47:29.731000Z",
                "source": "flashpoint_extraction",
                "tags": [
                    "aes_key:be7b7befe99d381fbe34ef443b3179be7b7befe99d381fbe34ef443b31790e00",
                    "extracted_config:true",
                    "group:feturednew",
                    "malware:xworm",
                    "mutex:hr5unzmp8fhkimje",
                    "source:flashpoint_extraction",
                    "type:trojan"
                ]
            },
            "modified_at": "2025-12-23T10:58:20.798Z",
            "platform_urls": {
                "ignite": "https://app.flashpoint.io/cti/malware/iocs/EtniFes7WyWvawEXcL2fmQ"
            },
            "score": {
                "last_scored_at": "2025-11-03T08:46:17.620Z",
                "value": "informational"
            },
            "sightings": [
                {
                    "description": "Observation: xworm [2025-12-23T10:47:29.731Z]",
                    "href": "https://api.flashpoint.io/technical-intelligence/v2/sightings/-mQDA1JEVYiXKTSenQuSbg",
                    "id": "-mQDA1JEVYiXKTSenQuSbg",
                    "sighted_at": "2025-12-23T10:47:29.731Z",
                    "source": "flashpoint_extraction",
                    "tags": [
                        "aes_key:be7b7befe99d381fbe34ef443b3179be7b7befe99d381fbe34ef443b31790e00",
                        "extracted_config:true",
                        "group:feturednew",
                        "malware:xworm",
                        "mutex:hr5unzmp8fhkimje",
                        "source:flashpoint_extraction",
                        "type:trojan"
                    ]
                }
            ],
            "sort_date": "2025-12-23T10:47:29.731Z",
            "total_sightings": 11,
            "type": "domain",
            "value": "featured.xyz"
        }
    }
}
```


### Inputs used

These input is used in the integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)


### API usage

This integration dataset uses the following API:

* List Indicators (endpoint: `/technical-intelligence/v2/indicators`)
