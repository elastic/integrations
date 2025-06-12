# Custom Threat Intelligence integration

The Custom Threat Intelligence package is an integration designed to ingest threat intelligence IOCs in the [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) format and convert them into the Elastic Common Schema (ECS) for seamless ingestion into Elasticsearch. It has been delivered to ingest threat intelligence data for those APIs that do not currently have an existing integration.

The integration comes with a default pipeline that automatically maps standard STIX 2.1 data into ECS fields. However, it also offers the flexibility to handle custom STIX data by allowing users to add custom pipelines accordingly.

## Key features

#### Supported data sources

RESTful API:
- Connects to public or private RESTful APIs that provide threat intelligence in STIX 2.1 format.
- Supports standard HTTP methods for data retrieval, including GET and POST.

TAXII 2.1 Protocol:
- Acts as a [TAXII](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html) client to connect to TAXII 2.x servers, enabling the collection of threat intelligence feeds in STIX format.
- It only supports collection models for TAXII data retrieval.

Log files:
- Ingests threat intelligence indicators provided in logfile, for air-gapped environments.

#### STIX 2.1 Compliance

Indicators are categorized based on their type and stored for further processing. Currently, the supported IOCs types are:
- Autonomous System
- Domain Name
- Email
- File
- IPv4
- IPv6
- URL
- Windows Registry
- x509 Certificates

The default pipeline is able to ingest other types of indicators, although they are not 100% mapped into ECS.

### Configuration guidelines

Due to the lack of standards from some TI providers, it is possible that some extra configuration is required for certain use cases. 

When connecting to STIX APIs, by default, the integration provides a native way of acting as a TAXII client. Therefore, for collecting data from TAXII 2.x servers no extra configuration is needed apart from providing the server URL, and authentication credentials when needed.

However, for APIs that don't follow a specific communication protocol. The correct ingestion of STIX data would require:
- Add a CEL program where API specifications are met. Pay special attention to HTTP headers, query parameters, pagination, and the processing of the payload.
- Add a initial state to be provided to the program. Generally, it would include the API URL, authentication parameters and intervals. More information can be found in the [documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html#input-state-cel).

By default the integration only supports STIX 2.1 indicators. This means that to process IOCs in other formats, the `Restrict STIX 2.1 format` option must be disabled, and a custom pipeline added to map the indicators correctly.

### Collecting Threat Intelligence from ISAC Feeds

The Custom Threat Intelligence integration allows you to connect to and pull threat indicators from any server supporting the TAXII protocol. This makes this integration the perfect fit for retrieving structured threat intelligence from Information Sharing and Analysis Centers (ISACs), such as MS-ISAC, FS-ISAC, H-ISAC, and others. These ISACs provide STIX-formatted threat data through TAXII servers.

To configure the integration to pull threat intelligence from an ISAC feed, follow these steps:

1. Ensure ISAC Membership: Confirm that you are a member of the desired ISAC (e.g., MS-ISAC, FS-ISAC) and have access to its TAXII server credentials. Some ISACs require registration and approval before providing TAXII feed access.

2. Obtain the following information from your ISAC:
    - Server URL: The endpoint for the ISAC’s TAXII server (e.g. https://example-isac.org/taxii/).
    - Collection Name: The specific collection containing the threat intelligence you want to retrieve.
    - Authentication Credentials: Username, password, API Key, or client certificate, as required by the ISAC.

3. Set up the integration:
    - The server URL and collection name should be used to build the URL as follows: `https://{base_url}/{api-root}/collections/{name}/objects/`
    - Provide the username/password, API Key or upload a client certificate, depending on the ISAC’s requirements.
    - Set how often the integration should pull updates (e.g. every hour). You can also set the time range to search for indicators when the agent runs for the first time with the Initial Interval.

Once the integration is running and pulling data, it automatically maps threat indicator fields from STIX to ECS. Verify that the imported indicators (e.g. IPs, domains, hashes) align with your detection rules.

### Expiration of Indicators of Compromise (IOCs)

The Custom Threat Intelligence integration supports IOC expiration. The ingested IOCs expire after certain duration. Based on the [STIX 2.1 reference](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html), the following options are available to determine the expiration of indicators:
- The `valid_until` field that indicates the time at which this Indicator should no longer be considered a valid indicator
- The `revoked` field that means that the indicator is no longer considered valid by the object creator.
- When missing `valid_until` and `revoked`, the indicator expires according to the default expiration set by `IOC Expiration Duration` configuration parameter. For more details, see [Handling Orphaned IOCs](#handling-orphaned-iocs).

The field `stix.ioc_expiration_reason` indicates which among the 3 methods stated above is the reason for indicator expiration.

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_custom_latest.dest_indicator-*` which only contains active and unexpired IOCs. The latest destination index also has an alias named `logs-ti_custom_latest.indicator`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs.

#### Handling orphaned IOCs

Some IOCs may never expire and will continue to stay in the latest destination indices `logs-ti_custom_latest.dest_indicator-*`. To avoid any false positives from such orphaned IOCs, users are allowed to configure `IOC Expiration Duration` parameter while setting up the integration. This parameter deletes any indicator ingested into destination indices `logs-ti_custom_latest.dest_indicator-*` after this specified duration is reached, defaults to `90d` from source's `@timestamp` field. Note that `IOC Expiration Duration` parameter only exists to add a fail-safe default expiration in case IOCs never expire.

#### ILM Policy

To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_custom.indicator-*` are allowed to contain duplicates from each polling interval. ILM policy is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date.

## Logs reference

### indicator

The `indicator` dataset stores STIX 2.1 indicators processed into ECS.

#### Example

An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2020-03-24T14:31:50.000Z",
    "agent": {
        "ephemeral_id": "e82cb16e-47ab-41c6-a2ab-aa35eff2b7bc",
        "id": "d99709cd-2211-496e-8b4e-7f3065444cff",
        "name": "elastic-agent-48140",
        "type": "filebeat",
        "version": "8.14.0"
    },
    "data_stream": {
        "dataset": "ti_custom.indicator",
        "namespace": "67549",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "d99709cd-2211-496e-8b4e-7f3065444cff",
        "snapshot": false,
        "version": "8.14.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_custom.indicator",
        "ingested": "2025-06-02T07:13:32Z",
        "kind": "enrichment",
        "original": "{\"confidence\":20,\"created\":\"2020-03-24T14:31:50.000Z\",\"created_by_ref\":\"identity--4f347cc9-4658-59ee-9707-134f434f9d1c\",\"description\":\"RiskIQ expansion\",\"id\":\"indicator--33041420-b509-504c-b30d-9a8ec505d7ee\",\"labels\":[\"certainty-50\",\"perpetual\",\"osint\"],\"lang\":\"en\",\"modified\":\"2023-10-18T07:51:59.171Z\",\"name\":\"abbbe10e3c6e5ed480a0743c540dbaba62ecaaf6\",\"object_marking_refs\":[\"marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9\"],\"pattern\":\"[file:hashes.'SHA-1' = 'abbbe10e3c6e5ed480a0743c540dbaba62ecaaf6']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"revoked\":true,\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2020-03-24T14:31:50.000Z\",\"valid_until\":\"2021-03-24T14:31:50.000Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hash": [
            "abbbe10e3c6e5ed480a0743c540dbaba62ecaaf6"
        ]
    },
    "stix": {
        "confidence": 20,
        "created": "2020-03-24T14:31:50.000Z",
        "created_by_ref": "identity--4f347cc9-4658-59ee-9707-134f434f9d1c",
        "id": "indicator--33041420-b509-504c-b30d-9a8ec505d7ee",
        "ioc_expiration_date": "2021-03-24T14:31:50.000Z",
        "ioc_expiration_duration": "5d",
        "ioc_expiration_reason": "Expiration set from valid_until field",
        "lang": "en",
        "modified": "2023-10-18T07:51:59.171Z",
        "object_marking_refs": [
            "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
        ],
        "pattern": "[file:hashes.'SHA-1' = 'abbbe10e3c6e5ed480a0743c540dbaba62ecaaf6']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "revoked": true,
        "spec_version": "2.1",
        "type": "indicator",
        "valid_from": "2020-03-24T14:31:50.000Z",
        "valid_until": "2021-03-24T14:31:50.000Z"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "ti_custom-indicator",
        "certainty-50",
        "perpetual",
        "osint"
    ],
    "threat": {
        "feed": {
            "name": "STIX Provider",
            "reference": "https://stix-example.com"
        },
        "indicator": {
            "confidence": "Low",
            "description": "RiskIQ expansion",
            "file": {
                "hash": {
                    "sha1": [
                        "abbbe10e3c6e5ed480a0743c540dbaba62ecaaf6"
                    ]
                }
            },
            "first_seen": "2020-03-24T14:31:50.000Z",
            "last_seen": "2023-10-18T07:51:59.171Z",
            "modified_at": "2023-10-18T07:51:59.171Z",
            "name": "abbbe10e3c6e5ed480a0743c540dbaba62ecaaf6",
            "type": "file"
        }
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
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Input type | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| stix.confidence | The confidence property identifies the confidence that the creator has in the correctness of their data. The confidence value MUST be a number in the range of 0-100. | integer |
| stix.created | The time at which the STIX Indicator Object was originally created | date |
| stix.created_by_ref | The created_by_ref property specifies the id property of the identity object that describes the entity that created this object. | keyword |
| stix.extensions | Specifies any extensions of the object, as a dictionary. | flattened |
| stix.external_references | The external_references property specifies a list of external references which refers to non-STIX information. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems. | flattened |
| stix.id | The ID of the indicator. | keyword |
| stix.indicator_types |  | keyword |
| stix.ioc_expiration_date | The expiration date of the indicator. It can be defined from the source event, by the revoked or valid_until fields, or from the integration configuration by ioc_expiration_duration. | date |
| stix.ioc_expiration_duration | The configured expiration duration for the indicator. | keyword |
| stix.ioc_expiration_reason | Reason why the indicator is expired. Defined by the integration in the ingest pipeline. | keyword |
| stix.kill_chain_phases | Describes the various phases of the kill chain that the attacker undertakes. | flattened |
| stix.lang | Feed language. | keyword |
| stix.modified | Date of the last modification. | date |
| stix.object_marking_refs | The object_marking_refs property specifies a list of id properties of marking-definition objects that apply to this object. | keyword |
| stix.pattern | The detection pattern for the indicator. | keyword |
| stix.pattern_type | The pattern language used in this indicator, which is always "stix". | keyword |
| stix.pattern_version | The version of the pattern language that is used in this indicator. | keyword |
| stix.revoked | The revoked property is only used by STIX Objects that support versioning and indicates whether the object has been revoked. Revoked objects are no longer considered valid by the object creator. Revoking an object is permanent; future versions of the object with this id must not be created. | boolean |
| stix.spec_version | The version of the STIX specification used to represent this object. The value of this property must be 2.1. | keyword |
| stix.type | Type of the STIX Object. | keyword |
| stix.valid_from | The time from which the indicator is considered a valid indicator. | date |
| stix.valid_until | The time at which the indicator should no longer be considered a valid indicator. | date |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |

