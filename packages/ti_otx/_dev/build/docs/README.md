# Alienvault OTX Integration

This integration is for [Alienvault OTX](https://otx.alienvault.com/api). It retrieves indicators for all pulses subscribed to a specific user account on OTX

## Configuration

To use this package, it is required to have an account on [Alienvault OTX](https://otx.alienvault.com/). Once an account has been created, and at least 1 pulse has been subscribed to, the API key can be retrieved from your [user profile dashboard](https://otx.alienvault.com/api). In the top right corner there should be an OTX KEY.

## Logs

### Threat

Retrieves all the related indicators over time, related to your pulse subscriptions on OTX.

{{fields "threat"}}

{{event "threat"}}

### Pulses Subscribed (Recommended)

Retrieves all indicators from subscribed pulses on OTX from API `/api/v1/pulses/subscribed` using Filebeat's [CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html). 
The following subscriptions are included by this API:
 - All pulses by users you are subscribed to
 - All pulses you are directly subscribed to
 - All pulses you have created yourself
 - All pulses from groups you are a member of

#### Indicators of Comprosie (IoC) Expiration
`Pulses Subscribed` datastream also supports IoC expiration by using [latest transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-overview.html#latest-transform-overview). Below are the steps on how it is handled:
1. All the indicators are retrieved into source indices named `logs-ti_otx.pulses_subscribed-*` using CEL input and processed via ingest pipelines. These indicators have a property named `expiration` which is either a `null` value or a timestamp such as `"2023-09-07T00:00:00"`. When the value is `null` or if the timestamp value is less than current timestamp `now()`, the indicator is not expired, and hence is still active.
2. A latest transform is continuosly run on source indices. The purpose of this transform is to:
    - Move only the `active` indicators from source indices into destination indices named `logs-ti_otx_latest.pulses_subscribed-<NUMBER>` where `NUMBER` indicates index version. 
    - Delete expired indicators based on the `expiration` timestamp value.
3. All the active indicators can be retrieved using destination index alias `logs-ti_otx_latest.pulses_subscribed` which points to the latest destination index version.

-  **Note**: Do not use the source indices `logs-ti_otx.pulses_subscribed-*`, because when the indicators expire, the source indices will contain duplicates. Always use the destination index alias: `logs-ti_otx_latest.pulses_subscribed` to query all active indicators.

{{fields "pulses_subscribed"}}

{{event "pulses_subscribed"}}