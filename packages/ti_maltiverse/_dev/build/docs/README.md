# Maltiverse Integration

[Maltiverse](https://maltiverse.com) is a threat intelligence platform. It works as a broker for Threat intelligence sources that are aggregated from more than a hundred different Public, Private and Community sources. Once the data is ingested, the IoC Scoring Algorithm applies a qualitative classification to the IoC that changes. Finally this data can be queried in a Threat Intelligence feed that can be delivered to your Firewalls, SOAR, SIEM, EDR or any other technology.

This integration fetches Maltiverse Threat Intelligence feeds and add them into Elastic Threat Intelligence. It supports `hostname`, `hash`, `ipv4` and `url` indicators.

In order to download feed you need to [register](https://maltiverse.com/auth/register) and generate an API key on you profile page.

## IoCs Expiration
Since we want to retain only valuable information and avoid duplicated data, the Maltiverse Elastic integration forces the indicators to rotate into a custom index called: `logs-ti_maltiverse_latest.indicator`.
**Please, refer to this index in order to set alerts and so on.**

### How it works
This is possible thanks to a transform rule installed along with the integration. The transform rule parses the data_stream content that is pulled from Maltiverse and only adds new indicators.

Both, the data_stream and the _latest index have applied expiration through ILM and a retention policy in the transform respectively._

## Logs

### Indicator

{{fields "indicator"}}

{{event "indicator"}}