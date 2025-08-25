# Cyera Integration for Elastic

## Overview

[Cyera](https://www.cyera.com/) is a cloud data security platform (DSPM – Data Security Posture Management). It focuses on discovering, classifying, monitoring, and protecting sensitive data across cloud environments (AWS, Azure, GCP, SaaS, M365, Snowflake, etc.).

The Cyera integration for Elastic allows you to collect logs and visualise the data in Kibana.

### Compatibility

The Cyera integration supports the following versions of Cyera APIs.

| Data streams   | Version |
|----------------|---------|
| Classification | v1      |
| Issue          | v3      |
| Datastore      | v2      |
| Event          | v1      |

### How it works

This integration periodically queries the Cyera API to retrieve classifications.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Classification`: Collects classifications that have been identified by the Cyera system.

### Supported use cases
Integrating Cyera Classification data stream with Elastic SIEM provides visibility into sensitive data classification across cloud and SaaS environments. By correlating Cyera’s classification intelligence with Elastic analytics, security teams can strengthen data security posture and simplify compliance. Dashboards in Kibana present breakdowns by sensitivity, category, and trends over time, enabling faster investigations and improved accountability.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Cyera

While collecting data through the Cyera APIs, authentication is handled using a `Client ID` and `Client Secret`, which serve as the required credentials. Any requests made without credentials will be rejected by the Cyera APIs.

#### Obtain `Credentials`:

- Generate a Cyera API client, retrieve the Client ID and Client Secret.
- Confirm your Cyera API URL, a default is loaded in the configuration.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Cyera**.
3. Select the **Cyera** integration from the search results.
4. Select **Add Cyera** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect Cyera logs via API**, you'll need to:

        - Configure **URL**, **Client ID**, and **Client Secret**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the Initial Interval, Interval, Batch Size etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In Kibana, navigate to **Dashboards**.
2. In the search bar, type **cyera**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In Kibana, navigate to **Management** > **Stack Management**.
2. Under **Data**, select **Transforms**.
3. In the search bar, type **cyera**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

### Classification

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cyera.classification.classification_name | Name of the classification. | keyword |
| cyera.classification.collections | Collections associated with the classification. | keyword |
| cyera.classification.context.business_context.key |  | keyword |
| cyera.classification.context.business_context.value |  | keyword |
| cyera.classification.context.data_subject_age | Age range of the data subject. | keyword |
| cyera.classification.context.geo_locations | Geographical locations associated with the classification. | keyword |
| cyera.classification.context.identifiability |  | keyword |
| cyera.classification.context.identified |  | boolean |
| cyera.classification.context.role | Role context for the classification. | keyword |
| cyera.classification.context.synthetic | Indicates if the classification is synthetic. | boolean |
| cyera.classification.context.tokenization | Tokenization context for the classification. | keyword |
| cyera.classification.custom_collections | Custom collections associated with the classification. | keyword |
| cyera.classification.data.category |  | keyword |
| cyera.classification.data.class_name |  | keyword |
| cyera.classification.default_sensitivity.display_name |  | keyword |
| cyera.classification.default_sensitivity.value |  | keyword |
| cyera.classification.frameworks |  | keyword |
| cyera.classification.group |  | keyword |
| cyera.classification.learned |  | boolean |
| cyera.classification.level |  | keyword |
| cyera.classification.name |  | keyword |
| cyera.classification.sensitivity.display_name |  | keyword |
| cyera.classification.sensitivity.value | Sensitivity level of the classified data. | keyword |
| cyera.classification.uid | Unique identifier for the classification. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |


#### Example event

An example event for `classification` looks as following:

```json
{
    "@timestamp": "2025-08-25T10:38:07.608Z",
    "agent": {
        "ephemeral_id": "24a2c926-b4be-42fc-9f63-21a734ef4617",
        "id": "aac8f457-45f9-44fd-ad55-d8743253b902",
        "name": "elastic-agent-15896",
        "type": "filebeat",
        "version": "9.1.2"
    },
    "cyera": {
        "classification": {
            "classification_name": "ABA Routing Number",
            "context": {
                "data_subject_age": "None",
                "identifiability": "PossiblyIdentifiable",
                "identified": false,
                "synthetic": false,
                "tokenization": "Plain"
            },
            "data": {
                "category": "Financial",
                "class_name": "ABA Routing Number"
            },
            "default_sensitivity": {
                "display_name": "Internal",
                "value": "Internal"
            },
            "group": "Financial",
            "learned": false,
            "level": "Element",
            "name": "ABA Routing Number",
            "sensitivity": {
                "display_name": "Internal",
                "value": "Internal"
            },
            "uid": "01980ae3-3870-7f54-86b8-81aac1416d93"
        }
    },
    "data_stream": {
        "dataset": "cyera.classification",
        "namespace": "37095",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "aac8f457-45f9-44fd-ad55-d8743253b902",
        "snapshot": false,
        "version": "9.1.2"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "cyera.classification",
        "id": "01980ae3-3870-7f54-86b8-81aac1416d93",
        "ingested": "2025-08-25T10:38:10Z",
        "kind": "event",
        "module": "cyera",
        "original": "{\"classificationGroup\":\"Financial\",\"classificationLevel\":\"Element\",\"classificationName\":\"ABA Routing Number\",\"collections\":[],\"context\":{\"businessContext\":[],\"dataSubjectAge\":\"None\",\"geoLocations\":[],\"identifiability\":\"PossiblyIdentifiable\",\"identified\":false,\"role\":null,\"synthetic\":false,\"tokenization\":\"Plain\"},\"customCollections\":[],\"dataCategory\":\"Financial\",\"dataClassName\":\"ABA Routing Number\",\"defaultSensitivity\":\"Internal\",\"defaultSensitivityDisplayName\":\"Internal\",\"frameworks\":[],\"learned\":false,\"name\":\"ABA Routing Number\",\"sensitivity\":\"Internal\",\"sensitivityDisplayName\":\"Internal\",\"uid\":\"01980ae3-3870-7f54-86b8-81aac1416d93\"}"
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_transform_source": "true"
    },
    "observer": {
        "product": "Cyera",
        "vendor": "Cyera"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cyera-classification"
    ]
}
```

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)
