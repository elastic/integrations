# Custom Threat Intelligence integration

The Custom Threat Intelligence package is an integration designed to ingest threat intelligence IOCs in the [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) format and convert them into the Elastic Common Schema (ECS) for seamless ingestion into Elasticsearch. It has been delivered to ingest threat intelligence data for those APIs that do not currently have an existing integration.

The integration comes with a default pipeline that automatically maps standard STIX 2.1 data into ECS fields. However, it also offers the flexibility to handle custom STIX data by allowing users to add custom pipelines accordingly.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

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
    - Server URL: The endpoint for the ISAC’s TAXII server (for example, `https://example.org/taxii/`).
    - Collection Name: The specific collection containing the threat intelligence you want to retrieve.
    - Authentication Credentials: Username, password, API Key, or client certificate, as required by the ISAC.

3. Set up the integration:
    - The server URL and collection name should be used to build the URL as follows: `https://{base_url}/{api-root}/collections/{name}/objects/`
    - Provide the username/password, API Key or upload a client certificate, depending on the ISAC’s requirements.
    - Set how often the integration should pull updates (e.g. every hour). You can also set the time range to search for indicators when the agent runs for the first time with the Initial Interval.

Once the integration is running and pulling data, it automatically maps threat indicator fields from STIX to ECS. Verify that the imported indicators (e.g. IPs, domains, hashes) align with your detection rules.

### Collecting from TAXII servers that use an API key/secret pair

Some TAXII 2.1 servers issue an API key and secret instead of a username and password, and expect them to be sent as HTTP Basic credentials rather than as a bearer token. The steps below use [IsMalicious](https://ismalicious.com/api-docs) as an example, but apply to any server with the same model.

1. Obtain the API key and secret from your provider account, and confirm the account has feed access.
2. Call the server's TAXII discovery endpoint (for example `https://api.ismalicious.com/taxii`) to find the API root, then list its collections (`https://api.ismalicious.com/taxii/api-root/collections`). Authenticate with HTTP Basic using the key as username and the secret as password. Note the ID of each collection you can read.
3. Add the **Custom Threat Intelligence** integration in Fleet, enable the RESTful API stream, and configure:

   | Setting | Value |
   | --- | --- |
   | URL API endpoint | `https://<server>/<api-root>/collections/<COLLECTION_ID>/objects/` |
   | Enable TAXII 2.1 | Enabled |
   | Basic Auth Username | Your API key |
   | Basic Auth Password | Your API secret |
   | API Key / API Key Type | Leave unset |

   Leave **Accept header value** and **Content-Type header value** at their defaults. Configure one stream per collection. For example, the `malicious-ips` collection on IsMalicious uses `https://api.ismalicious.com/taxii/api-root/collections/malicious-ips/objects/`.
4. Set **Initial Interval** and **Interval** according to collection size. Pagination follows the server's `next` token automatically. Use **Limit** to bound the page size, and raise **Maximum Pages Per Interval** if a large initial import hits the [CEL execution limit](#exceeding-maximum-number-of-cel-executions).
5. Verify indicators arrive with the expected values, types and timestamps, and use the `logs-ti_custom_latest.indicator` alias for indicator match rules. See [Expiration of Indicators of Compromise](#expiration-of-indicators-of-compromise-iocs) for how `valid_until`, `revoked` and the `IOC Expiration Duration` fail-safe are applied.

### Expiration of Indicators of Compromise (IOCs)

The Custom Threat Intelligence integration supports IOC expiration. The ingested IOCs expire after certain duration. Based on the [STIX 2.1 reference](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html), the following options are available to determine the expiration of indicators:
- The `valid_until` field that indicates the time at which this Indicator should no longer be considered a valid indicator
- The `revoked` field that means that the indicator is no longer considered valid by the object creator.
- When missing `valid_until` and `revoked`, the indicator expires according to the default expiration set by `IOC Expiration Duration` configuration parameter. For more details, see [Handling Orphaned IOCs](#handling-orphaned-iocs).

The field `stix.ioc_expiration_reason` indicates which among the 3 methods stated above is the reason for indicator expiration.

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_custom_latest.dest_indicator-*` which only contains active and unexpired IOCs. The latest destination index also has an alias named `logs-ti_custom_latest.indicator`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs.

#### Handling orphaned IOCs

Some IOCs may never expire and will continue to stay in the latest destination indices `logs-ti_custom_latest.dest_indicator-*`. To avoid any false positives from such orphaned IOCs, users are allowed to configure `IOC Expiration Duration` parameter while setting up the integration. This parameter deletes any indicator ingested into destination indices `logs-ti_custom_latest.dest_indicator-*` after this specified duration is reached, defaults to `90d` from source's `@timestamp` field. Note that `IOC Expiration Duration` parameter only exists to add a fail-safe default expiration in case IOCs never expire.

#### Data retention

Threat indicators are re-collected across polling intervals, and the latest transform keeps the active, deduplicated view in its destination index. The source data streams therefore hold repeated copies of the same indicators.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-ti_custom.indicator-*` | `logs-ti_custom.indicator-default_policy`: roll over after 1d, delete 2d after rollover | delete 5d after rollover |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies. The data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead. It also works per backing index: Elasticsearch [rolls the write index over automatically](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/data-stream-lifecycle-settings#cluster-lifecycle-default-rollover) on age, size, or document count, and [deletes a backing index once the retention has passed since it rolled over](https://www.elastic.co/docs/manage-data/lifecycle/data-stream#data-streams-lifecycle-how-it-works). A document therefore stays for the retention plus up to one rollover interval. The rollover age is derived from the retention and is an implementation detail that Elasticsearch may change. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management → Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-ti_custom.indicator-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.

## Troubleshooting

### "exceeding maximum number of CEL executions"

The CEL input limits how many pages it fetches during a single polling interval. The default is `1000`. High-volume TAXII feeds with large collections may exceed this limit, causing the integration to enter a DEGRADED state with this message.

To resolve this, increase `Maximum Pages Per Interval` in the integration's advanced settings. The value must be a positive integer and should be large enough to allow the agent to paginate through the full result set within one interval. Alternatively, reduce the polling interval so each run has fewer pages to fetch.

## Logs reference

### indicator

The `indicator` dataset stores STIX 2.1 indicators processed into ECS.

#### Example

{{event "indicator"}}

{{fields "indicator"}}
