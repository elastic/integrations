# OpenCTI

The OpenCTI integration allows you to ingest data from the [OpenCTI](https://filigran.io/solutions/products/opencti-threat-intelligence/) threat intelligence platform.

Use this integration to get indicator data from OpenCTI. You can monitor and explore the ingested data on the OpenCTI dashboard or in Kibana's Discover tab. Indicator match rules in {{ url "security" "Elastic Security" }} can then use the ingested indicator data to generate alerts about detected threats.

## Data streams

The OpenCTI integration collects one type of data stream: indicator.

**Indicator** are lists of records created over time.
Each event in the Indicator data stream collected by the OpenCTI integration is an indicator that can be used to detect suspicious or malicious cyber activity. The data is fetched from [OpenCTI's GraphQL API](https://docs.opencti.io/latest/deployment/integrations/#graphql-api).

## Requirements

This integration requires Filebeat version 8.16.0, or later.

It has been updated for OpenCTI version 6.1.0 and requires that version or later.

## Setup

For additional information about threat intelligence integrations, including the steps required to add an integration, please refer to the {{ url "security-ti-integrations" "Enable threat intelligence integrations" }} page of the Elastic Security documentation.

When adding the OpenCTI integration, you will need to provide a base URL for the target OpenCTI instance. It should be just the base URL (e.g. `https://demo.opencti.io`) and not include an additional path for the API or UI.

The simplest authentication method to use is an API key (bearer token). You can find a value for the API key on your profile page in the OpenCTI user interface. Advanced integration settings can be used to configure various OAuth2-based authentication arrangements, and to enter SSL settings for mTLS authentication and for other purposes. For information on setting up the OpenCTI side of an authentication strategy, please refer to [OpenCTI's authentication documentation](https://docs.opencti.io/latest/deployment/authentication/).

### Filtering

The OpenCTI integration supports advanced filtering capabilities to help you control which indicators are ingested. This allows you to focus on specific types of indicators, confidence levels, authors, or time ranges that are most relevant to your security operations.

#### Available Filters

The following filters can be configured when setting up the integration (Note: The integration automatically filters for entity type 'Indicator' only):

- **Pattern Types**: Filter indicators by pattern type (e.g., 'stix'). The values are customizable in OpenCTI, and any custom pattern types defined in your OpenCTI instance are supported (if an observable is associated).

- **Indicator Types**: Filter indicators by type. Values are customizable in OpenCTI. Common defaults include: 'malicious-activity', 'attribution', 'benign', 'anomalous-activity', 'compromised', 'unknown'. Custom types defined in your OpenCTI instance are also supported.

- **Revoked Status**: Filter by revoked status. Set to 'true' to get only revoked indicators, 'false' for only active (non-revoked) indicators, or leave empty to get all indicators regardless of revoked status.

- **Valid From (Start Date)**: Filter indicators with valid_from date after this date. Use ISO 8601 format (e.g., '2024-01-01T00:00:00Z') or relative date expressions (e.g., 'now-30d', 'now-7d').

- **Valid Until (End Date)**: Filter indicators with valid_until date before this date. Use ISO 8601 format (e.g., '2024-12-31T23:59:59Z') or relative date expressions (e.g., 'now+30d', 'now+7d').

- **Label IDs**: Filter by label IDs. Enter the UUIDs of the labels to filter indicators that have these labels applied. **Important: You must use label IDs (UUIDs), not label names.** You can find label IDs in the OpenCTI interface by navigating to Settings > Taxonomies > Labels, or via the API.

- **Minimum Confidence Level**: Filter indicators with confidence level greater than or equal to a specified value (0-100).

- **Author IDs**: Filter by author IDs (createdBy relationship). Enter the UUIDs of the authors to filter indicators created by them. **Important: You must use author IDs (UUIDs), not author names.** You can find author IDs in the OpenCTI interface by clicking on an entity and checking its details, or via the API.

- **Creator IDs**: Filter by technical creator IDs. Enter the UUIDs of the internal users who created the indicators in OpenCTI.

- **Created After**: Filter indicators created after a specific date. Use ISO 8601 format (e.g., '2024-01-01T00:00:00Z') or relative date expressions (e.g., 'now-30d', 'now-7d', 'now-24h').

- **Modified After**: Filter indicators modified after a specific date. Use ISO 8601 format (e.g., '2024-01-01T00:00:00Z') or relative date expressions (e.g., 'now-30d', 'now-7d', 'now-24h').

- **Marking Definition IDs**: Filter by marking definitions (e.g., TLP levels). Enter the UUIDs of the marking definitions. **Important: You must use marking definition IDs (UUIDs), not names.** Common TLP marking IDs:
  - TLP:CLEAR (TLP:WHITE): `marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da`
  - TLP:GREEN: `marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb`
  - TLP:AMBER: `marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421`
  - TLP:RED: `marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1`

#### Filter Examples

Here are some practical examples of filter configurations:

1. **High-confidence indicators only**: Set `Minimum Confidence Level` to 75 to ingest only indicators with high confidence.

2. **Active threat indicators**: Set `Indicator Types` to ['malicious-activity', 'compromised'] and `Revoked Status` to 'false' to focus on active, non-revoked threats.

3. **Currently valid indicators**: Set `Valid From (Start Date)` to 'now-365d' and `Valid Until (End Date)` to 'now+30d' to get indicators that are currently within their validity period.

4. **Recent indicators**: Set `Created After` to 'now-7d' to collect only indicators created in the last 7 days.

5. **Specific pattern types**: Set `Pattern Types` to ['stix'] to collect only STIX pattern indicators, or include your custom pattern types defined in OpenCTI.

6. **Specific campaign tracking**: Use `Label IDs` filter with specific campaign label UUIDs (e.g., ['550e8400-e29b-41d4-a716-446655440000']) to track indicators related to particular threat campaigns.

7. **Indicators from specific sources**: Use `Author IDs` with the UUIDs of specific threat intelligence sources (e.g., ['123e4567-e89b-12d3-a456-426655440000']) to filter indicators from trusted sources.

8. **Recently modified high-value indicators**: Combine `Modified After` set to 'now-24h', `Minimum Confidence Level` to 80, and `Revoked Status` to 'false' to get recently updated, high-confidence active indicators.

9. **TLP-restricted indicators**: Use `Marking Definition IDs` with TLP:CLEAR and TLP:GREEN UUIDs to only ingest indicators that are safe to share broadly: ['marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da', 'marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb'].

All filters work together using AND logic at the top level. Within each multi-value filter (like pattern types or label IDs), OR logic is applied between values.

#### High Availability and Deduplication

The OpenCTI integration supports running on multiple Elastic Agents for high availability. When multiple agents fetch the same indicators:

- **Automatic Deduplication**: The integration uses a fingerprint-based document ID to prevent duplicates. Each indicator gets a consistent ID based on its `standard_id` and `modified` timestamp.
- **No Manual Configuration Needed**: Deduplication works automatically - just deploy the integration to multiple agents.
- **Update Handling**: When an indicator is updated in OpenCTI, the new version replaces the old one in Elasticsearch.

#### Best Practices for HA Setup

1. **Stagger Execution Times**: To avoid all agents hitting OpenCTI simultaneously, consider offsetting their schedules slightly (e.g., Agent 1 at :00, Agent 2 at :02).
2. **Use the Same Configuration**: Ensure all agents use identical filter settings to fetch the same dataset.
3. **Monitor Performance**: Check OpenCTI server load when multiple agents are polling.

### Finding IDs in OpenCTI

Since several filters require UUIDs rather than names, here are ways to find these IDs:

1. **Label IDs**:
   - In OpenCTI UI: Navigate to Settings → Taxonomies → Labels. Click on a label to see its ID in the URL or details.
   - Via API: Query the `labels` endpoint to list all labels with their IDs.

2. **Author IDs**:
   - In OpenCTI UI: Click on any entity that has an author, then click on the author name to see its details including the ID.
   - Via API: Query the `identities` endpoint to list all identities (organizations, individuals) with their IDs.

3. **Creator IDs**:
   - In OpenCTI UI: Navigate to Settings → Security → Users to see user IDs.
   - Via API: Query the `users` endpoint (requires appropriate permissions).

For more information about OpenCTI's filtering system, refer to the [OpenCTI filters documentation](https://docs.opencti.io/latest/reference/filters/).

## Logs

### Indicator

The `indicator` data stream includes indicators of the following types (`threat.indicator.type`): `artifact`, `autonomous-system`, `bank-account`, `cryptocurrency-wallet`, `cryptographic-key`, `directory`, `domain-name`, `email-addr`, `email-message`, `email-mime-part-type`, `hostname`, `ipv4-addr`, `ipv6-addr`, `mac-addr`, `media-content`, `mutex`, `network-traffic`, `payment-card`, `phone-number`, `process`, `software`, `file`, `text`, `url`, `user-account`, `user-agent`, `windows-registry-key`, `windows-registry-value-type`, `x509-certificate`, `unknown`.

OpenCTI's data model closely follows the [STIX standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html). It supports complex indicators defined using STIX patterns or other languages, and each indicator can be related to one or more observables. In the [ECS threat fields](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html) the focus is on atomic indicators. This integration fetches as much data as possible about indicators and their related observables, and populates relevant ECS fields wherever possible. It uses related observables rather than the indicator pattern as the data source for type-specific indicator fields.

#### Expiration of inactive indicators

The `opencti.indicator.invalid_or_revoked_from` field is set to the earliest time at which an indicator reaches its `valid_until` time or is marked as revoked. From that time the indicator should no longer be considered active.

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to provide a view of active indicators for end users. This transform creates destination indices that are accessible via the alias `logs-ti_opencti_latest.indicator`. When querying for active indicators or setting up indicator match rules, use that alias to avoid false positives from expired indicators.

The dashboards show only active indicators, except the Ingestion dashboard, which shows data from both the source data stream and the indices of the latest indicators.

Indicators that are never expired or revoked will not be removed from the indices of the latest indicators. If accumulation of indicators is a problem there, it can be managed upstream in OpenCTI, or by manually deleting indicators from those indices.

To prevent unbounded growth of the source data stream `logs-ti_opencti.indicator-*`, it has an index lifecycle management (ILM) policy that deletes records 5 days after ingestion.

#### Example

Here is an example `indicator` event:

{{event "indicator"}}

#### Exported fields

Fields for indicators of any type are mapped to ECS fields when possible (primarily `threat.indicator.*`) and otherwise stored with a vendor prefix (`opencti.indicator.*`).

Fields for related observables of the various types are always stored under `opencti.observable.<type>.*` and when possible their values will be copied into corresponding ECS fields.

The `related.*` fields will also be populated with any relevant data.

Timestamps are mapped as follows:

| Source      | Destination                   | Description |
|-------------|-------------------------------|-------------|
| -           | @timestamp                    | Time the event was received by the pipeline |
| -           | event.ingested                | Time the event arrived in the central data store |
| created     | event.created                 | Time of the indicator's creation |
| modified    | threat.indicator.modified_at  | Time of the indicator's last modification |
| valid_from  | opencti.indicator.valid_from  | Time from which this indicator is considered a valid indicator of the behaviors it is related to or represents |
| valid_until | opencti.indicator.valid_until | Time at which this indicator should no longer be considered a valid indicator of the behaviors it is related to or represents |
| -           | opencti.indicator.invalid_or_revoked_from | The earliest time at which an indicator reaches its `valid_until` time or is marked as revoked |

The table below lists all `opencti.*` fields.

The documentation for ECS fields can be found at:
- [ECS Event Fields](https://www.elastic.co/guide/en/ecs/current/ecs-event.html)
- [ECS Threat Fields](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html)
- [ECS Related Fields](https://www.elastic.co/guide/en/ecs/current/ecs-related.html)

{{fields "indicator"}}
