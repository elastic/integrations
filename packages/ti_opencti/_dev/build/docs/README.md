# OpenCTI

The OpenCTI integration allows you to ingest data from the [OpenCTI](https://filigran.io/solutions/products/opencti-threat-intelligence/) threat intelligence platform.

Use this integration to get indicator data from OpenCTI. You can monitor and explore the ingested data on the OpenCTI dashboard or in Kibana's Discover tab. Indicator match rules in {{ url "security" "Elastic Security" }} can then use the ingested indicator data to generate alerts about detected threats.

## Data streams

The OpenCTI integration collects one type of data stream: logs.

**Logs** are lists of records created over time.
Each event in the log data stream collected by the OpenCTI integration is an indicator that can be used to detect suspicious or malicious cyber activity. The data is fetched from [OpenCTI's GraphQL API](https://docs.opencti.io/latest/deployment/integrations/#graphql-api).

## Requirements

This integration requires Filebeat version 8.9.0, or later.

It has been updated for OpenCTI version 5.12.24 and requires that version or later.

## Setup

For additional information about threat intelligence integrations, including the steps required to add an integration, please refer to the {{ url "security-ti-integrations" "Enable threat intelligence integrations" }} page of the Elastic Security documentation.

When adding the OpenCTI integration, you will need to provide a base URL for the target OpenCTI instance. It should be just the base URL (e.g. `https://demo.opencti.io`) and not include an additional path for the API or UI.

The simplest authentication method to use is an API key (bearer token). You can find a value for the API key on your profile page in the OpenCTI user interface. Advanced integration settings can be used to configure various OAuth2-based authentication arrangements, and to enter SSL settings for mTLS authentication and for other purposes. For information on setting up the OpenCTI side of an authentication strategy, please refer to [OpenCTI's authentication documentation](https://docs.opencti.io/latest/deployment/authentication/).

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
