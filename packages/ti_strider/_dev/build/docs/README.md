# Strider Shield

This integration connects with [the REST API provided by Strider Intel](https://www.striderintel.com/shield/) to ingest threat indicators.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

This integration is designed to run on a [Fleet Agent](https://www.elastic.co/docs/reference/fleet)

## Expiration of Indicators of Compromise (IOCs)

Indicators are expired after a certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for a source index to allow only active indicators to be available to the end users. The transform creates a destination index named `logs-ti_strider_latest.indicator*` which only contains active and unexpired indicators. Destination indices are aliased to `logs-ti_strider_latest.indicator`.

### ILM Policy

To facilitate IOC expiration, source datastream-backed indices `logs-ti_strider.indicator-*` are allowed to contain duplicates. ILM policy `logs-ti_strider.indicator-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `7 days` from ingestion date

## Data Streams

### Indicator

The Shield integration collects logs from the API based on a polling interval, 

{{event "indicator"}}
