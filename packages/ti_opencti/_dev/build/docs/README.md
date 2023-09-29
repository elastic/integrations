# OpenCTI

The OpenCTI integration allows you to ingest data from the [OpenCTI](https://filigran.io/solutions/products/opencti-threat-intelligence/) threat intelligence platform.

Use this integration to get indicator data from OpenCTI. You can monitor and explore the ingested data on the OpenCTI dashboard or in Kibana's Discover tab. Indicator match rules in {{ url "security" "Elastic Security" }} can then use the ingested indicator data to generate alerts about detected threats.

## Data streams

The OpenCTI integration collects one type of data stream: logs.

**Logs** are lists of records created over time.
Each event in the log data stream collected by the OpencTI integration is an indicator that can be used to detect suspicious or malicious cyber activitity. The data is fetched from [OpenCTI's GraphQL API](https://docs.opencti.io/latest/deployment/integrations/#graphql-api).

## Requirements

This integration requires Filebeat version 8.9.0, or later.

It was developed using OpenCTI version 5.10.1.

## Setup

For additinal information about threat intelligence integrations, including the steps required to add an integration, please refer to the {{ url "security-ti-integrations" "Enable threat intelligence integrations" }} page of the Elastic Security documentation.

When adding the OpenCTI integration, you will need to provide a base URL for the target OpenCTI instance. It should be just the base URL (e.g. `https://demo.opencti.io`) and not include an additional path for the API (e.g. ~~`https://demo.opencti.io/graphql`~~) or user interface (e.g. ~~`https://demo.opencti.io/dashboard`~~).

The simplest authentication method to use is an API key (bearer token). You can find a value for the API key on your profile page in the OpenCTI user interface. Advanced integration settings can be used to configure various OAuth2-based authentication arrangements, and to enter SSL settings for mTLS authentication and for other purposes. For information on setting up the OpenCTI side of an authentication strategy, please refer to [OpenCTI's authentication documentation](https://docs.opencti.io/latest/deployment/authentication/).

## Logs

### Indicator

The `indicator` data stream includes indicators of the following types (`threat.indicator.type`): `artifact`, `autonomous-system`, `bank-account`, `cryptocurrency-wallet`, `cryptographic-key`, `directory`, `domain-name`, `email-addr`, `email-message`, `email-mime-part-type`, `hostname`, `ipv4-addr`, `ipv6-addr`, `mac-addr`, `media-content`, `mutex`, `network-traffic`, `payment-card`, `phone-number`, `process`, `software`, `file`, `text`, `url`, `user-account`, `user-agent`, `windows-registry-key`, `windows-registry-value-type`, `x509-certificate`, `unknown`.

#### Example

Here is an example `indicator` event:

{{event "indicator"}}

#### Exported fields

Fields for indicators of any type are mapped to ECS fields when possible (primarily `threat.indicator.*`) and otherwise stored with a vendor prefix (`opencti.indicator.*`).

Fields for related observables of the various types are always stored under `opencti.observable.<type>.*` and when possible their values will be copied into corresponding ECS fields.

The `related.*` fields will also be populated with any relevant data.

The table below lists all `opencti.*` fields.

The documentation for ECS fields can be found at:
- [ECS Event Fields](https://www.elastic.co/guide/en/ecs/current/ecs-event.html)
- [ECS Threat Fields](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html)
- [ECS Related Fields](https://www.elastic.co/guide/en/ecs/current/ecs-related.html)

{{fields "indicator"}}
