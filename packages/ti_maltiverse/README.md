# Maltiverse Integration

[Maltiverse](https://maltiverse.com) is a threat intelligence platform. It works as a broker for Threat intelligence sources that are aggregated from more than a hundred different Public, Private and Community sources. Once the data is ingested, the IoC Scoring Algorithm applies a qualitative classification to the IoC that changes. Finally this data can be queried in a Threat Intelligence feed that can be delivered to your Firewalls, SOAR, SIEM, EDR or any other technology.

This integration fetches Maltiverse Threat Intelligence feeds and add them into Elastic Intelligence. It supports `hostname`, `hash`, `ipv4` and `url` indicators.

In order to download feed you need to [register](https://maltiverse.com/auth/register) and generate an API key on you profile page.
