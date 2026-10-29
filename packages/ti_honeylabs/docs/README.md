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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| honeylabs.exploiter.akin | HTTP request (Akin) fingerprints of the address that are shared by a scanning tool population. | keyword |
| honeylabs.exploiter.confidence | Confidence from 0 to 100 that HoneyLabs assigns from the number of observed events. Present when the indicator was read from TAXII. | long |
| honeylabs.exploiter.deleted_at | Time at which the indicator expires from the latest index. | date |
| honeylabs.exploiter.id | STIX identifier of the indicator. Present when the indicator was read from TAXII. | keyword |
| honeylabs.exploiter.interactive_sessions | Number of the address's events that were interactive sessions, in which it logged in to a sensor and ran commands or named a download. | long |
| honeylabs.exploiter.ioc_expiration_duration | The configured expiration duration. | keyword |
| honeylabs.exploiter.ja4 | TLS client (JA4) fingerprints of the address that are shared by a scanning tool population. | keyword |
| honeylabs.exploiter.labels | STIX labels of the indicator. Present when the indicator was read from TAXII. | keyword |
| honeylabs.exploiter.malware_family | Malware family of the payloads the address tried to load, where one is known. | keyword |
| honeylabs.exploiter.tor_exit | Whether the address was a Tor exit node when the feed was built. | boolean |
| honeylabs.exploiter.valid_until | End of the STIX validity period of the indicator. Present when the indicator was read from TAXII. | date |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.feed.name | Display friendly feed name. | constant_keyword |


An example event for `exploiter` looks as following:

```json
{
    "@timestamp": "2026-10-29T20:46:30.899Z",
    "agent": {
        "ephemeral_id": "80791c8e-4be4-4161-86c1-7b683a30f50a",
        "id": "7b86c944-c526-46b3-a53e-7ae2ebe90d56",
        "name": "elastic-agent-37910",
        "type": "filebeat",
        "version": "9.5.5"
    },
    "data_stream": {
        "dataset": "ti_honeylabs.exploiter",
        "namespace": "29961",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "7b86c944-c526-46b3-a53e-7ae2ebe90d56",
        "snapshot": false,
        "version": "9.5.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_honeylabs.exploiter",
        "ingested": "2026-10-29T20:46:34Z",
        "kind": "enrichment",
        "module": "ti_honeylabs",
        "original": "{\"confidence\":90,\"created\":\"2026-10-22T20:38:45.000Z\",\"description\":\"Ran exploit or loader commands against HoneyLabs honeypot sensors from AS206264 (DE): 327 events between 2026-10-22T20:38:45.000Z and 2026-10-29T19:59:29.000Z. 327 of them were interactive sessions in which it logged in and ran commands or named a download. Its interactive sessions showed MITRE ATT\\u0026CK T1190 Exploit Public-Facing Application, T1105 Ingress Tool Transfer.\",\"external_references\":[{\"source_name\":\"HoneyLabs\",\"url\":\"https://honeylabs.net/lookup/89.160.20.112\"},{\"external_id\":\"T1190\",\"source_name\":\"mitre-attack\",\"url\":\"https://attack.mitre.org/techniques/T1190/\"},{\"external_id\":\"T1105\",\"source_name\":\"mitre-attack\",\"url\":\"https://attack.mitre.org/techniques/T1105/\"}],\"id\":\"indicator--8f77131c-ddce-5b4b-8e49-49763da60072\",\"indicator_types\":[\"malicious-activity\"],\"kill_chain_phases\":[{\"kill_chain_name\":\"lockheed-martin-cyber-kill-chain\",\"phase_name\":\"exploitation\"},{\"kill_chain_name\":\"mitre-attack\",\"phase_name\":\"initial-access\"},{\"kill_chain_name\":\"mitre-attack\",\"phase_name\":\"command-and-control\"}],\"labels\":[\"honeylabs\",\"exploitation\",\"interactive-session\",\"asn:AS206264\",\"country:DE\",\"mitre-attack:T1190\",\"mitre-attack:T1105\"],\"modified\":\"2026-10-29T19:59:29.000Z\",\"name\":\"Exploitation source: 89.160.20.112\",\"pattern\":\"[ipv4-addr:value = '89.160.20.112']\",\"pattern_type\":\"stix\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2026-10-22T20:38:45.000Z\",\"valid_until\":\"2026-11-05T19:59:29.000Z\"}",
        "type": [
            "indicator"
        ]
    },
    "honeylabs": {
        "exploiter": {
            "confidence": 90,
            "deleted_at": "2026-11-05T19:59:29.000Z",
            "id": "indicator--8f77131c-ddce-5b4b-8e49-49763da60072",
            "ioc_expiration_duration": "7d",
            "labels": [
                "honeylabs",
                "exploitation",
                "interactive-session",
                "asn:AS206264",
                "country:DE",
                "mitre-attack:T1190",
                "mitre-attack:T1105"
            ],
            "tor_exit": false,
            "valid_until": "2026-11-05T19:59:29.000Z"
        }
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "honeylabs-exploiter"
    ],
    "threat": {
        "feed": {
            "name": "HoneyLabs Exploiters"
        },
        "framework": "MITRE ATT&CK",
        "indicator": {
            "as": {
                "number": 206264
            },
            "confidence": "High",
            "description": "Ran exploit or loader commands against HoneyLabs honeypot sensors from AS206264 (DE): 327 events between 2026-10-22T20:38:45.000Z and 2026-10-29T19:59:29.000Z. 327 of them were interactive sessions in which it logged in and ran commands or named a download. Its interactive sessions showed MITRE ATT&CK T1190 Exploit Public-Facing Application, T1105 Ingress Tool Transfer.",
            "first_seen": "2026-10-22T20:38:45.000Z",
            "geo": {
                "country_iso_code": "DE"
            },
            "ip": "89.160.20.112",
            "last_seen": "2026-10-29T19:59:29.000Z",
            "marking": {
                "tlp": "CLEAR"
            },
            "modified_at": "2026-10-29T19:59:29.000Z",
            "name": "89.160.20.112",
            "provider": "HoneyLabs",
            "reference": "https://honeylabs.net/lookup/89.160.20.112",
            "type": "ipv4-addr"
        },
        "technique": {
            "id": [
                "T1190",
                "T1105"
            ],
            "reference": [
                "https://attack.mitre.org/techniques/T1190/",
                "https://attack.mitre.org/techniques/T1105/"
            ]
        }
    }
}
```

### Malware infrastructure

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| honeylabs.malware_infrastructure.confidence | Confidence from 0 to 100 that HoneyLabs assigns from the number of sightings. URLs served by Mozi peers are capped at 50. Present when the indicator was read from TAXII. | long |
| honeylabs.malware_infrastructure.deleted_at | Time at which the indicator expires from the latest index. | date |
| honeylabs.malware_infrastructure.id | STIX identifier of the indicator. Present when the indicator was read from TAXII. | keyword |
| honeylabs.malware_infrastructure.interactive_sessions | Number of interactive shell sessions that named the URL as a download. | long |
| honeylabs.malware_infrastructure.ioc_expiration_duration | The configured expiration duration. | keyword |
| honeylabs.malware_infrastructure.labels | STIX labels of the indicator. Present when the indicator was read from TAXII. | keyword |
| honeylabs.malware_infrastructure.malware_family | Malware family of the payload served at the URL, where one is known. | keyword |
| honeylabs.malware_infrastructure.mozi_peer | Whether the URL is a Mozi peer download served by an infected device rather than by attacker-run infrastructure. Present when the indicator was read from TAXII. | boolean |
| honeylabs.malware_infrastructure.valid_until | End of the STIX validity period of the indicator. Present when the indicator was read from TAXII. | date |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.feed.name | Display friendly feed name. | constant_keyword |


An example event for `malware_infrastructure` looks as following:

```json
{
    "@timestamp": "2026-10-29T20:47:50.527Z",
    "agent": {
        "ephemeral_id": "16f29d25-cb66-4dec-8898-c8eaee3890a1",
        "id": "1fe29e3a-47a8-4804-b064-2ec4bc26fcd7",
        "name": "elastic-agent-50800",
        "type": "filebeat",
        "version": "9.5.5"
    },
    "data_stream": {
        "dataset": "ti_honeylabs.malware_infrastructure",
        "namespace": "95529",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "1fe29e3a-47a8-4804-b064-2ec4bc26fcd7",
        "snapshot": false,
        "version": "9.5.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_honeylabs.malware_infrastructure",
        "ingested": "2026-10-29T20:47:54Z",
        "kind": "enrichment",
        "module": "ti_honeylabs",
        "original": "{\"confidence\":50,\"created\":\"2026-10-29T17:08:35.000Z\",\"description\":\"Mozi botnet download served by an infected device on a random port. Mozi's operators shut it down in 2023; its remaining infected peers keep passing the payload on. Useful for spotting an infected device on your own network, not as attacker-run infrastructure. 1 sighting, last 2026-10-29T17:08:35.000Z.\",\"external_references\":[{\"source_name\":\"HoneyLabs\",\"url\":\"https://honeylabs.net/lookup/175.16.199.1\"}],\"id\":\"indicator--e146e905-27ec-5c73-869d-18da5d851214\",\"indicator_types\":[\"malicious-activity\"],\"kill_chain_phases\":[{\"kill_chain_name\":\"lockheed-martin-cyber-kill-chain\",\"phase_name\":\"installation\"}],\"labels\":[\"honeylabs\",\"malware-infrastructure\",\"loader-url\",\"interactive-session\",\"mozi-peer\",\"malware:mozi\"],\"modified\":\"2026-10-29T17:08:35.000Z\",\"name\":\"Mozi peer download: http://175.16.199.1:60373/Mozi.m\",\"pattern\":\"[url:value = 'http://175.16.199.1:60373/Mozi.m']\",\"pattern_type\":\"stix\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2026-10-29T17:08:35.000Z\",\"valid_until\":\"2026-11-12T17:08:35.000Z\"}",
        "type": [
            "indicator"
        ]
    },
    "honeylabs": {
        "malware_infrastructure": {
            "confidence": 50,
            "deleted_at": "2026-11-12T17:08:35.000Z",
            "id": "indicator--e146e905-27ec-5c73-869d-18da5d851214",
            "ioc_expiration_duration": "14d",
            "labels": [
                "honeylabs",
                "malware-infrastructure",
                "loader-url",
                "interactive-session",
                "mozi-peer",
                "malware:mozi"
            ],
            "malware_family": "mozi",
            "mozi_peer": true,
            "valid_until": "2026-11-12T17:08:35.000Z"
        }
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "honeylabs-malware-infrastructure"
    ],
    "threat": {
        "feed": {
            "name": "HoneyLabs Malware Infrastructure"
        },
        "indicator": {
            "confidence": "Medium",
            "description": "Mozi botnet download served by an infected device on a random port. Mozi's operators shut it down in 2023; its remaining infected peers keep passing the payload on. Useful for spotting an infected device on your own network, not as attacker-run infrastructure. 1 sighting, last 2026-10-29T17:08:35.000Z.",
            "first_seen": "2026-10-29T17:08:35.000Z",
            "ip": "175.16.199.1",
            "last_seen": "2026-10-29T17:08:35.000Z",
            "marking": {
                "tlp": "CLEAR"
            },
            "modified_at": "2026-10-29T17:08:35.000Z",
            "name": "http://175.16.199.1:60373/Mozi.m",
            "provider": "HoneyLabs",
            "reference": "https://honeylabs.net/lookup/175.16.199.1",
            "type": "url",
            "url": {
                "domain": "175.16.199.1",
                "extension": "m",
                "full": "http://175.16.199.1:60373/Mozi.m",
                "original": "http://175.16.199.1:60373/Mozi.m",
                "path": "/Mozi.m",
                "port": 60373,
                "scheme": "http"
            }
        }
    }
}
```
