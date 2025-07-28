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
    - Server URL: The endpoint for the ISAC’s TAXII server (e.g. <EXAMPLE_ISAC_ORG>/taxii/).
    - Collection Name: The specific collection containing the threat intelligence you want to retrieve.
    - Authentication Credentials: Username, password, API Key, or client certificate, as required by the ISAC.

3. Set up the integration:
    - The server URL and collection name should be used to build the URL as follows: `<BASE_URL>/{api-root}/collections/{name}/objects/`
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

{{event "indicator"}}

{{fields "indicator"}}
