# Flashpoint Integration for Elastic

## Overview

[Flashpoint](https://flashpoint.io/) is a comprehensive threat intelligence platform that delivers actionable insights from dark web, deep web, and technical sources. It combines human-curated intelligence with automated collection to help organizations identify emerging threats, monitor adversary activity, and assess cyber risk with enriched context.

The Flashpoint integration for Elastic collects alerts and indicators from the **Flashpoint Ignite API** and visualizes them in Kibana.

### Compatibility

The Flashpoint integration is compatible with Ignite API version **1.2**.

### How it works

This integration periodically queries the Flashpoint Ignite API to retrieve logs.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Alert`: Collects `alert` logs from the Flashpoint Ignite API (endpoint: `/alert-management/v1/notifications`),
- `Indicator`: Collects `indicator` logs from the Flashpoint Ignite API (endpoint: `/technical-intelligence/v2/indicators`),

### Supported Use Cases

Integrating Flashpoint with Elastic SIEM provides centralized visibility into both threat intelligence **Alerts** and **Indicators**, enabling efficient monitoring and investigation within Kibana dashboards.

For **Alerts**, dashboard presents key metrics such as `Total Alerts` and `Alert Trends Over Time`, helping analysts quickly detect activity spikes and monitor evolving threat patterns.

For **Indicators**, dashboard highlights `Total Indicators` and `Indicators by Type`, providing insight into indicator volume and classification for effective threat analysis.

Interactive filtering controls allow analysts to drill down across alerts and indicators, supporting streamlined investigation workflows within a unified threat intelligence view.

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

#### Alert

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
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| ti_flashpoint.alert.created_at |  | date |
| ti_flashpoint.alert.data_type |  | keyword |
| ti_flashpoint.alert.generated_at |  | date |
| ti_flashpoint.alert.highlight_text |  | keyword |
| ti_flashpoint.alert.highlights.body.text/plain |  | keyword |
| ti_flashpoint.alert.highlights.container.name |  | keyword |
| ti_flashpoint.alert.highlights.description |  | keyword |
| ti_flashpoint.alert.highlights.site.title |  | keyword |
| ti_flashpoint.alert.highlights.site_actor.names.aliases |  | keyword |
| ti_flashpoint.alert.highlights.site_actor.names.handle |  | keyword |
| ti_flashpoint.alert.highlights.title |  | keyword |
| ti_flashpoint.alert.id |  | keyword |
| ti_flashpoint.alert.is_read |  | boolean |
| ti_flashpoint.alert.parent_data_type |  | keyword |
| ti_flashpoint.alert.reason.details.params.exclude |  | flattened |
| ti_flashpoint.alert.reason.details.params.include.date.end |  | keyword |
| ti_flashpoint.alert.reason.details.params.include.date.label |  | keyword |
| ti_flashpoint.alert.reason.details.params.include.date.start |  | keyword |
| ti_flashpoint.alert.reason.details.sources |  | keyword |
| ti_flashpoint.alert.reason.entity |  | flattened |
| ti_flashpoint.alert.reason.id |  | keyword |
| ti_flashpoint.alert.reason.name |  | keyword |
| ti_flashpoint.alert.reason.origin |  | keyword |
| ti_flashpoint.alert.reason.text |  | keyword |
| ti_flashpoint.alert.resource.author |  | keyword |
| ti_flashpoint.alert.resource.authors |  | keyword |
| ti_flashpoint.alert.resource.basetypes |  | keyword |
| ti_flashpoint.alert.resource.container.container.name |  | keyword |
| ti_flashpoint.alert.resource.container.container.native_id |  | keyword |
| ti_flashpoint.alert.resource.container.container.title |  | keyword |
| ti_flashpoint.alert.resource.container.name |  | keyword |
| ti_flashpoint.alert.resource.container.native_id |  | keyword |
| ti_flashpoint.alert.resource.container.server |  | keyword |
| ti_flashpoint.alert.resource.container.title |  | keyword |
| ti_flashpoint.alert.resource.country |  | keyword |
| ti_flashpoint.alert.resource.created_at |  | date |
| ti_flashpoint.alert.resource.description |  | keyword |
| ti_flashpoint.alert.resource.id |  | keyword |
| ti_flashpoint.alert.resource.link |  | keyword |
| ti_flashpoint.alert.resource.media_v2.image_enrichment.enrichments.v1.image_analysis.safe_search.adult |  | long |
| ti_flashpoint.alert.resource.media_v2.image_enrichment.enrichments.v1.image_analysis.safe_search.medical |  | long |
| ti_flashpoint.alert.resource.media_v2.image_enrichment.enrichments.v1.image_analysis.safe_search.racy |  | long |
| ti_flashpoint.alert.resource.media_v2.image_enrichment.enrichments.v1.image_analysis.safe_search.spoof |  | long |
| ti_flashpoint.alert.resource.media_v2.image_enrichment.enrichments.v1.image_analysis.safe_search.violence |  | long |
| ti_flashpoint.alert.resource.media_v2.media_type |  | keyword |
| ti_flashpoint.alert.resource.media_v2.mime_type |  | keyword |
| ti_flashpoint.alert.resource.media_v2.phash |  | keyword |
| ti_flashpoint.alert.resource.media_v2.phash256 |  | keyword |
| ti_flashpoint.alert.resource.media_v2.sha1 |  | keyword |
| ti_flashpoint.alert.resource.media_v2.storage_uri |  | keyword |
| ti_flashpoint.alert.resource.parent_basetypes |  | keyword |
| ti_flashpoint.alert.resource.report.summary |  | keyword |
| ti_flashpoint.alert.resource.report.title |  | keyword |
| ti_flashpoint.alert.resource.section |  | keyword |
| ti_flashpoint.alert.resource.site.title |  | keyword |
| ti_flashpoint.alert.resource.site_actor.names.handle |  | keyword |
| ti_flashpoint.alert.resource.site_actor.native_id |  | keyword |
| ti_flashpoint.alert.resource.sort_date |  | date |
| ti_flashpoint.alert.resource.title |  | keyword |
| ti_flashpoint.alert.source |  | keyword |
| ti_flashpoint.alert.status |  | keyword |
| ti_flashpoint.alert.tags |  | flattened |


### Example event

#### Alert

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2025-12-12T11:41:37.775Z",
    "agent": {
        "ephemeral_id": "6e8be1d8-c393-4df7-b03b-a2cf290ae5d8",
        "id": "bdce496c-d968-45ef-a38b-5dc5377aef73",
        "name": "elastic-agent-97762",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "container": {
        "id": "966491148640211034",
        "name": "newbies-2"
    },
    "data_stream": {
        "dataset": "ti_flashpoint.alert",
        "namespace": "26612",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "bdce496c-d968-45ef-a38b-5dc5377aef73",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2025-12-12T11:41:37.775Z",
        "dataset": "ti_flashpoint.alert",
        "id": "1fc0fc04-5a85-41ff-970d-acda1c0dd390",
        "ingested": "2026-02-19T05:51:00Z",
        "kind": "alert",
        "original": "{\"created_at\":\"2025-12-12T11:41:37.775301Z\",\"data_type\":\"news\",\"generated_at\":\"2025-12-12T11:41:35.896396Z\",\"highlight_text\":\"16\\nImage \\u003cmark\\u003eCredit\\u003c/mark\\u003e :\",\"highlights\":{\"body.text/plain\":[\"16\\nImage \\u003cmark\\u003eCredit\\u003c/mark\\u003e.\"]},\"id\":\"1fc0fc04-5a85-41ff-970d-acda1c0dd390\",\"is_read\":false,\"parent_data_type\":null,\"reason\":{\"details\":{\"params\":{\"exclude\":{},\"include\":{\"date\":{\"end\":\"now\",\"label\":\"Last 30 Days\",\"start\":\"now-30d\"}}},\"sources\":[\"communities\",\"media\",\"marketplaces\",\"news\"]},\"entity\":null,\"id\":\"0f325ca9-a28f-421b-8d0c-db3329366e5f\",\"name\":\"credit\",\"origin\":\"searches\",\"text\":\"credit\"},\"resource\":{\"author\":\"Alias Doe\",\"authors\":[\"Alias Doe\"],\"basetypes\":[\"article\",\"news\",\"newscatcher\"],\"container\":{\"name\":\"newbies-2\",\"native_id\":\"966491148640211034\"},\"country\":\"IN\",\"created_at\":{\"date-time\":\"2025-12-12T09:06:06+00:00\",\"raw\":\"2025-12-12 09:06:06\",\"timestamp\":1765530366},\"description\":\"Rajinikanth, who has ruled both South and Bollywood cinema, turns 75 today. Born on December 12, 1950, the superstar continues to deliver box-office blockbusters and is now gearing up for several exciting upcoming films.\",\"id\":\"c4FF4mbNV7m2vBWPIaV0uw\",\"link\":\"https://example.com\",\"media_v2\":[{\"mime_type\":\"image/jpeg\",\"phash\":\"9a996984a473e3c7\",\"phash256\":\"9abe917a69c984a6a4d47368e34cc526ed85658cc913cdb3986b9b4cd31c3673\",\"sha1\":\"ddc7b1f8b32056803bdce609c1262e59836bec87\",\"storage_uri\":\"gs://kraken-datalake-media/artifacts/71/71a2a7e557b989f25b89a7cbd9ec3a65183a4717bc2a05ede89971064f177b58\"}],\"site\":{\"title\":\"example.com\"},\"sort_date\":\"2025-12-12T09:06:06Z\",\"title\":\"Jailer 2 to Coolie 2: Rajinikanth at 75 Ready to Thrill Fans with Upcoming Hits\"},\"source\":\"news\",\"status\":null,\"tags\":{}}",
        "reason": "credit",
        "url": "https://example.com"
    },
    "file": {
        "hash": {
            "sha1": [
                "ddc7b1f8b32056803bdce609c1262e59836bec87"
            ]
        },
        "mime_type": [
            "image/jpeg"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hash": [
            "9a996984a473e3c7",
            "9abe917a69c984a6a4d47368e34cc526ed85658cc913cdb3986b9b4cd31c3673",
            "ddc7b1f8b32056803bdce609c1262e59836bec87"
        ],
        "user": [
            "Alias Doe"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "ti_flashpoint-alert"
    ],
    "ti_flashpoint": {
        "alert": {
            "created_at": "2025-12-12T11:41:37.775Z",
            "data_type": "news",
            "generated_at": "2025-12-12T11:41:35.896Z",
            "highlight_text": "16\nImage <mark>Credit</mark> :",
            "highlights": {
                "body.text/plain": [
                    "16\nImage <mark>Credit</mark>."
                ]
            },
            "id": "1fc0fc04-5a85-41ff-970d-acda1c0dd390",
            "is_read": false,
            "reason": {
                "details": {
                    "params": {
                        "include": {
                            "date": {
                                "end": "now",
                                "label": "Last 30 Days",
                                "start": "now-30d"
                            }
                        }
                    },
                    "sources": [
                        "communities",
                        "media",
                        "marketplaces",
                        "news"
                    ]
                },
                "id": "0f325ca9-a28f-421b-8d0c-db3329366e5f",
                "name": "credit",
                "origin": "searches",
                "text": "credit"
            },
            "resource": {
                "author": "Alias Doe",
                "authors": [
                    "Alias Doe"
                ],
                "basetypes": [
                    "article",
                    "news",
                    "newscatcher"
                ],
                "container": {
                    "name": "newbies-2",
                    "native_id": "966491148640211034"
                },
                "country": "IN",
                "created_at": "2025-12-12T09:06:06.000Z",
                "description": "Rajinikanth, who has ruled both South and Bollywood cinema, turns 75 today. Born on December 12, 1950, the superstar continues to deliver box-office blockbusters and is now gearing up for several exciting upcoming films.",
                "id": "c4FF4mbNV7m2vBWPIaV0uw",
                "link": "https://example.com",
                "media_v2": [
                    {
                        "mime_type": "image/jpeg",
                        "phash": "9a996984a473e3c7",
                        "phash256": "9abe917a69c984a6a4d47368e34cc526ed85658cc913cdb3986b9b4cd31c3673",
                        "sha1": "ddc7b1f8b32056803bdce609c1262e59836bec87",
                        "storage_uri": "gs://kraken-datalake-media/artifacts/71/71a2a7e557b989f25b89a7cbd9ec3a65183a4717bc2a05ede89971064f177b58"
                    }
                ],
                "site": {
                    "title": "example.com"
                },
                "sort_date": "2025-12-12T09:06:06.000Z",
                "title": "Jailer 2 to Coolie 2: Rajinikanth at 75 Ready to Thrill Fans with Upcoming Hits"
            },
            "source": "news"
        }
    },
    "user": {
        "name": "Alias Doe"
    }
}
```

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
        "ephemeral_id": "6be00241-2481-4599-a6a9-ebe1fcdd4b3e",
        "id": "3443134e-6b7f-40a2-b029-c07f7f142c7f",
        "name": "elastic-agent-75965",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_flashpoint.indicator",
        "namespace": "95274",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "3443134e-6b7f-40a2-b029-c07f7f142c7f",
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
        "ingested": "2026-02-19T06:10:11Z",
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

* List Alerts (endpoint: `/alert-management/v1/notifications`)|
* List Indicators (endpoint: `/technical-intelligence/v2/indicators`)
