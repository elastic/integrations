# HoneyLabs Integration

The HoneyLabs integration ingests threat intelligence indicators from [HoneyLabs](https://honeylabs.net) into Elasticsearch. HoneyLabs runs internet-facing honeypot sensors and publishes the addresses and URLs it has evidence of malicious intent for. Indicators ingested with this integration can be explored in [Intelligence > Indicators](https://www.elastic.co/guide/en/security/current/indicators-of-compromise.html) in Kibana and matched against your own events with indicator match rules.

## Overview

### Compatibility

This integration reads the HoneyLabs public feeds at `https://honeylabs.net/feed/` and the HoneyLabs TAXII 2.1 server at `https://honeylabs.net/taxii2/api/`. The feed format is documented at [https://honeylabs.net/feed/about](https://honeylabs.net/feed/about).

### How it works

Elastic Agent polls HoneyLabs with the CEL input. Without an API key it reads the anonymous JSON feeds, which need no account. Each feed holds every indicator of its window (7 days for exploiters, 14 days for malware infrastructure), so each poll collects the whole feed. With an API key it reads the TAXII 2.1 collections instead and asks only for indicators added since the previous poll.

An ingest pipeline maps each indicator to the ECS `threat.indicator.*` fields. A [transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) per data stream keeps the latest copy of each indicator in a destination index and removes it once it expires.

## What data does this integration collect?

The integration collects two data streams:

- `exploiter`: source IP addresses observed running an exploit or loader command against HoneyLabs sensors, including addresses that logged in to a sensor and ran commands in a shell. Known research scanners are excluded. Each indicator carries the first and last sighting, the number of events, the autonomous system, the country, whether the address is a Tor exit, and the MITRE ATT&CK techniques its shell sessions showed.
- `malware_infrastructure`: loader and command-and-control URLs taken from captured exploit payloads and from the downloads named inside shell sessions. Each indicator carries the URL, its host, the first and last sighting and the number of sightings.

Both data streams set `threat.indicator.reference` to the HoneyLabs lookup page of the address, which lists the evidence behind the indicator.

When an API key is set, indicators also carry a confidence from 0 to 100 (`honeylabs.*.confidence`, mapped to `threat.indicator.confidence`), a description, STIX labels, the malware family where one is known and, for URLs, whether the URL is a Mozi peer download served by an infected device.

### Supported use cases

- Match inbound connections in firewall, proxy, web server and authentication logs against addresses that are exploiting systems on the internet now.
- Match outbound requests in proxy and DNS logs against URLs that serve malware to compromised hosts.
- Look up the evidence for an indicator on its HoneyLabs lookup page during an investigation.

## What do I need to use this integration?

- Elastic Stack: Elasticsearch for storing data and Kibana for viewing it. You can use Elastic Cloud or self-manage the Elastic Stack.
- Elastic Agent with outbound HTTPS access to `honeylabs.net`.
- Optionally, a HoneyLabs API key. Keys are free and are created at [https://honeylabs.net/dashboard](https://honeylabs.net/dashboard). A paid HoneyLabs plan extends the TAXII collections from 7 or 14 days to 30 days.

## How do I deploy this integration?

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

### Onboard and configure

1. In Kibana, go to **Management > Integrations** and search for **HoneyLabs**.
2. Click **Add HoneyLabs**.
3. Leave **API Key** empty to read the anonymous feeds, or enter a HoneyLabs API key to read the TAXII 2.1 collections.
4. Adjust the polling interval and the IOC expiration duration of each data stream if needed.
5. Save the integration and add it to an agent policy.

The settings are:

- **API Key**: optional HoneyLabs API key. When set, the TAXII 2.1 collections are read instead of the anonymous feeds.
- **Interval**: time between polls, `1h` by default. HoneyLabs rebuilds the feeds every few minutes, so an interval below `15m` adds requests without adding data.
- **IOC Expiration Duration**: how long after its last sighting an indicator stays in the latest index. The defaults (`7d` for exploiters, `14d` for malware infrastructure) match the windows of the feeds.

Advanced settings hold the HoneyLabs URL, the feed path and TAXII collection ID of each data stream, the TAXII page size, the TAXII overlap (how far before the newest indicator of the previous poll the next poll starts, `1h` by default, so a sighting recorded late is still collected), proxy and SSL options, and the request tracer.

### Validation

1. Check that the Elastic Agent reports a healthy status in Fleet.
2. Within one polling interval, documents appear in `logs-ti_honeylabs.exploiter-*` and `logs-ti_honeylabs.malware_infrastructure-*` in Discover.
3. Within a few minutes after that, the transforms fill `logs-ti_honeylabs_latest.exploiter` and `logs-ti_honeylabs_latest.malware_infrastructure`.

## Troubleshooting

- A `401` error on the TAXII path means the API key is missing, invalid or revoked. Remove the key to fall back to the anonymous feeds, or create a new key.
- A `403` error means the configured TAXII collection needs a paid HoneyLabs plan. The default collections do not.
- Documents with `event.kind: pipeline_error` carry the cause in `error.message`. Enable **Preserve original event** to keep the raw indicator in `event.original`.

## Reference

### IOC expiration

An indicator expires `ioc_expiration_duration` after its last sighting. The pipeline writes that time to `honeylabs.exploiter.deleted_at` or `honeylabs.malware_infrastructure.deleted_at`, and the transform removes the indicator from the destination index once it has passed. An indicator that HoneyLabs sees again gets a new last sighting on the next poll and stays.

- Source indices (`logs-ti_honeylabs.exploiter-*`, `logs-ti_honeylabs.malware_infrastructure-*`) hold every collected copy. See [Data retention](#data-retention) for how long.
- Destination indices (`logs-ti_honeylabs_latest.dest_exploiter-*`, `logs-ti_honeylabs_latest.dest_malware_infrastructure-*`) hold one current copy of each indicator. They are aliased as `logs-ti_honeylabs_latest.exploiter` and `logs-ti_honeylabs_latest.malware_infrastructure`. Point indicator match rules at these aliases.

### Data retention

Indicators are collected again on every poll, and the latest transform keeps the deduplicated view in its destination index. The source data streams therefore hold repeated copies of the same indicators. The package bounds their growth with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-ti_honeylabs.exploiter-*` | `logs-ti_honeylabs.exploiter-default_policy`: roll over after 1d, delete 7d after rollover | delete 7d after rollover |
| `logs-ti_honeylabs.malware_infrastructure-*` | `logs-ti_honeylabs.malware_infrastructure-default_policy`: roll over after 1d, delete 7d after rollover | delete 7d after rollover |

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management > Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-ti_honeylabs.exploiter-default/_lifecycle` with the body `{"data_retention": "30d"}`. Replace `default` with your namespace.

The transform destination indices are not affected by either.

To view only HoneyLabs indicators in the Intelligence page, filter with:

```
threat.feed.name: "HoneyLabs Exploiters" or threat.feed.name: "HoneyLabs Malware Infrastructure"
```

### Terms of use

The HoneyLabs feeds are free to use for security research, asset inventory and defensive monitoring, including inside a commercial organisation's own defences. Redistribution as part of a product or a paid service needs a licence from HoneyLabs. See [https://honeylabs.net/feed/about](https://honeylabs.net/feed/about).

### Exploiter

{{fields "exploiter"}}

{{event "exploiter"}}

### Malware infrastructure

{{fields "malware_infrastructure"}}

{{event "malware_infrastructure"}}
