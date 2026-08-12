# Shodan Integration for Elastic

## Overview

The Shodan integration collects internet-exposure threat intelligence from [Shodan](https://www.shodan.io/) and its free Certificate Transparency Logs (CTL) service. It has two independent parts:

* **Host Search**: polls Shodan for a query you define and maps each matching host — open ports, software, known vulnerabilities, geolocation — into ECS `threat.indicator` fields. Requires a Shodan account and API key.
* **Certificate Transparency**: polls Shodan's free CTL service for a domain you configure and maps each observed certificate — subject/issuer, validity window, alternative names — into ECS `threat.indicator.x509` fields. No account needed.

### How it works

**Host Search** polls on an interval and pages through results up to **Max Pages Per Collection Interval** (default `10` pages, 100 results each; leave empty for no cap). Shodan bills API credits per page, so this cap protects against a broad query burning through your credit balance in a single interval — see [Performance and scaling](#performance-and-scaling) below. Re-polling the same host (same IP+port) updates its existing record instead of creating a duplicate.

**Certificate Transparency** polls once per interval and returns every certificate for the domain in a single request — no pagination, no credit cost. Re-observing the same certificate (same hash) doesn't create a duplicate.

## What data does this integration collect?

* **Host threat indicators**: internet-exposed hosts matching your Shodan query — IP, port, software/version, CVEs, geolocation, ASN/ISP.
* **Certificate transparency records**: certificates observed for your configured domain — subject/issuer, validity window, alternative (SAN) names.

### Supported use cases

**Host Search**: inventory your (or a third party's) internet-facing attack surface, enrich security events by correlating IPs against Shodan-reported exposure, or alert on newly-exposed vulnerabilities.

**Certificate Transparency**: discover subdomains you didn't know existed, or alert when a certificate for your domain is issued by an unrecognized CA — a common sign of mis-issuance or domain compromise.

## What do I need to use this integration?

* An Elastic Agent installation, either self-managed or through Elastic Cloud.
* Host Search only: a [Shodan account](https://account.shodan.io/register) with an API key. Some search filters (e.g. `has_vuln`) require a paid membership — see [Shodan's pricing](https://www.shodan.io/pricing).
* Certificate Transparency needs no account or API key.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed — see the [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). Elastic Agent polls the Shodan API directly, so no additional infrastructure is required on your network.

### Set up steps in Shodan

For Host Search:

1. Sign in (or register) at [account.shodan.io](https://account.shodan.io/).
2. Copy your API key from your [account page](https://account.shodan.io/).
3. Decide on a Shodan [search query](https://www.shodan.io/search/filters) for the hosts you want to monitor (e.g. `has_vuln:true`, `org:"My Company" country:US`, `port:3389`).

Certificate Transparency needs no setup in Shodan — just pick the domain you want to monitor.

#### Vendor resources

- [Shodan API documentation](https://developer.shodan.io/api)
- [Shodan search query filters](https://www.shodan.io/search/filters)
- [Shodan account/API key page](https://account.shodan.io/)
- [Shodan CTL service](https://ctl.shodan.io/)

### Set up steps in Kibana

1. In Kibana, go to **Management > Integrations**.
2. Search for **Shodan** and click **Add Shodan**.
3. Configure whichever of the two policy templates you need:
    - **Shodan Host Search**:
        - **Shodan API Key**
        - **Search Query** (defaults to `has_vuln:true`)
        - **Collection Interval** (defaults to `24h`)
        - **Max Pages Per Collection Interval** (defaults to `10`; leave empty for no cap)
        - **Preserve Original Event** — optionally keep the raw Shodan JSON for debugging
    - **Shodan Certificate Transparency**:
        - **Domain** (e.g. `example.com`)
        - **Collection Interval** (defaults to `24h`)
        - **Preserve Original Event** — optionally keep the raw CTL JSON for debugging
4. Save the integration.

### Validation

**Host Search**: after one collection interval, check **Discover** with the `logs-shodan.host-*` data view — you should see one document per matching host. No documents? Confirm the API key is valid and the query returns results at [shodan.io/search](https://www.shodan.io/search).

**Certificate Transparency**: check `logs-shodan.domain-*` in Discover — one document per certificate. No documents? Confirm the domain has publicly-issued certificates via [crt.sh](https://crt.sh/).

## Troubleshooting

**Host Search:**
- No data: verify the API key is valid and hasn't hit its credit limit.
- Fewer results than expected: some filters (`has_vuln`, `vuln`) need a paid tier; also check whether **Max Pages Per Collection Interval** is capping results (expected, not an error).
- High credit usage: narrow your query (e.g. scope to a `hostname`, `org`, or `net` range) and keep **Max Pages Per Collection Interval** set, not empty.

**Certificate Transparency:**
- No data: confirm the domain is spelled correctly and has publicly-issued certificates.

## Performance and scaling

Shodan bills credits per page for Host Search (100 results/page) and enforces per-plan rate limits. Keep the collection interval conservative (default `24h`) and **Max Pages Per Collection Interval** deliberate — a broad query can match millions of hosts, and without a cap one interval could exhaust your credit balance.

Certificate Transparency has no pagination or credit cost — it scales independently of Host Search.

For more on scaling architectures, see [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures).

## Reference

### Inputs used

These inputs can be used with this integration:
<details>
<summary>cel</summary>

## Setup

For more details about the CEL input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html).

Before configuring the CEL input, make sure you have:
- Network connectivity to the target API endpoint
- Valid authentication credentials (API keys, tokens, or certificates as required)
- Appropriate permissions to read from the target data source

### Collecting logs from CEL

To configure the CEL input, you must specify the `request.url` value pointing to the API endpoint. The interval parameter controls how frequently requests are made and is the primary way to balance data freshness with API rate limits and costs. Authentication is often configured through the `request.headers` section using the appropriate method for the service.

NOTE: To access the API service, make sure you have the necessary API credentials and that the Filebeat instance can reach the endpoint URL. Some services may require IP whitelisting or VPN access.

To collect logs via API endpoint, configure the following parameters:

- API Endpoint URL
- API credentials (tokens, keys, or username/password)
- Request interval (how often to fetch data)
</details>


### API usage

* [Shodan Host Search API](https://developer.shodan.io/api#host-search) (`/shodan/host/search`)
* [Shodan CTL service](https://ctl.shodan.io/) (`/api/v1/domain/{domain}`)

### Vendor documentation links

- [Shodan API documentation](https://developer.shodan.io/api)
- [Shodan search query filters](https://www.shodan.io/search/filters)
- [Shodan account/API key page](https://account.shodan.io/)
- [Shodan CTL service](https://ctl.shodan.io/)

### Data streams

#### host

The `host` data stream provides internet-exposed host records from Shodan host search results.

##### host fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| threat.indicator.as.isp | ISP name for the indicator's autonomous system, as reported by Shodan. | keyword |
| threat.indicator.software.name | Name of the software/product detected on the indicator. | keyword |
| threat.indicator.software.version | Version of the software/product detected on the indicator. | keyword |
| threat.indicator.tags | Tags associated with the indicator, as provided by Shodan. | keyword |
| threat.indicator.vulnerability.id | CVE or other vulnerability IDs reported by Shodan for the indicator. | keyword |


##### host sample event

An example event for `host` looks as following:

```json
{
    "@timestamp": "2026-08-12T06:36:09.889Z",
    "agent": {
        "ephemeral_id": "6cc60311-3c12-41c9-8743-5b53f789932b",
        "id": "0c9322ae-6841-442b-a17c-c4b3a3350e19",
        "name": "elastic-agent-19179",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "shodan.host",
        "namespace": "75466",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "0c9322ae-6841-442b-a17c-c4b3a3350e19",
        "snapshot": false,
        "version": "9.4.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "shodan.host",
        "ingested": "2026-08-12T06:36:12Z",
        "kind": "enrichment",
        "module": "shodan",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_transform_source": "true"
    },
    "observer": {
        "product": "Threat Intelligence",
        "vendor": "Shodan"
    },
    "related": {
        "ip": [
            "198.51.100.20"
        ]
    },
    "tags": [
        "preserve_original_event"
    ],
    "threat": {
        "feed": {
            "description": "Threat feed from Shodan internet scan results",
            "name": "Shodan Host Search",
            "reference": "https://www.shodan.io/"
        },
        "indicator": {
            "as": {
                "organization": {
                    "name": "No Cap Page One"
                }
            },
            "description": "Shodan scan result for 198.51.100.20 (No Cap Page One)",
            "first_seen": "2023-12-03T00:00:00.000Z",
            "ip": "198.51.100.20",
            "last_seen": "2026-08-12T06:36:09.889Z",
            "marking": {
                "tlp": "WHITE"
            },
            "port": 22,
            "provider": "shodan",
            "type": "ipv4-addr"
        }
    }
}
```

#### domain

The `domain` data stream provides certificate transparency records for a configured domain, collected via Shodan's free CTL service.

##### domain fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |


##### domain sample event

An example event for `domain` looks as following:

```json
{
    "@timestamp": "2026-08-12T03:51:10.263Z",
    "agent": {
        "ephemeral_id": "c06ef2f1-e264-4476-8236-fd867a2eb86a",
        "id": "8329b9ab-330d-41cf-ae1b-c95cdd284545",
        "name": "elastic-agent-58100",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "shodan.domain",
        "namespace": "78609",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "8329b9ab-330d-41cf-ae1b-c95cdd284545",
        "snapshot": false,
        "version": "9.4.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "shodan.domain",
        "ingested": "2026-08-12T03:51:13Z",
        "kind": "enrichment",
        "module": "shodan",
        "type": [
            "indicator"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "elastic-agent-58100",
        "ip": [
            "172.19.0.2",
            "172.18.0.4"
        ],
        "mac": [
            "A2-46-C6-65-39-6F",
            "C6-7D-1F-2F-D7-4F"
        ],
        "name": "elastic-agent-58100",
        "os": {
            "family": "",
            "kernel": "5.15.0-139-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Certificate Transparency",
        "vendor": "Shodan"
    },
    "related": {
        "hosts": [
            "example.com",
            "www.example.com",
            "api.example.com"
        ]
    },
    "tags": [
        "preserve_original_event"
    ],
    "threat": {
        "feed": {
            "description": "Certificate transparency log records observed for a domain via Shodan CTL",
            "name": "Shodan Certificate Transparency",
            "reference": "https://ctl.shodan.io/"
        },
        "indicator": {
            "description": "Certificate transparency record for www.example.com, issued by E7",
            "last_seen": "2026-08-12T03:51:10.263Z",
            "provider": "shodan",
            "reference": "https://crt.sh/?sha256=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "type": "x509-certificate",
            "x509": {
                "alternative_names": [
                    "example.com",
                    "www.example.com",
                    "api.example.com"
                ],
                "issuer": {
                    "common_name": [
                        "E7"
                    ]
                },
                "not_after": "2024-11-13T22:13:20.000Z",
                "not_before": "2023-11-14T22:13:20.000Z",
                "subject": {
                    "common_name": [
                        "www.example.com"
                    ]
                }
            }
        }
    }
}
```

### Latest host indicator state

The raw `host` data stream is append-only, so re-detecting the same `ip:port` doesn't update the existing document. For a current, deduplicated view, this integration installs a transform that rolls the raw stream up into a "latest state" index keyed by IP and port, dropping indicators not re-confirmed within 7 days. Query it at `logs-shodan_latest.host`.

`domain` has no equivalent transform — certificates are already deduplicated by hash, so there's no "latest state" to roll up to.

### Transforms used

#### host
* Description: Latest state of each Shodan host indicator, unique by IP and port. Keeps only the most recently seen document per indicator, and drops indicators not re-confirmed within the retention window, so this index reflects current exposure rather than accumulating unbounded history.
* Source Index: logs-shodan.host\*
* Destination Index: logs-shodan_latest.host-1

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.full.text | Multi-field of `host.os.full`. | match_only_text |
| input.type | Type of Filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| threat.feed.description | Description of the threat feed in a UI friendly format. | keyword |
| threat.feed.name | The name of the threat feed in UI friendly format. | keyword |
| threat.feed.reference | Reference information for the threat feed in a UI friendly format. | keyword |
| threat.indicator.as.isp | ISP name for the indicator's autonomous system, as reported by Shodan. | keyword |
| threat.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.indicator.as.organization.name | Organization name. | keyword |
| threat.indicator.as.organization.name.text | Multi-field of `threat.indicator.as.organization.name`. | match_only_text |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.geo.city_name | City name. | keyword |
| threat.indicator.geo.country_iso_code | Country ISO code. | keyword |
| threat.indicator.geo.country_name | Country name. | keyword |
| threat.indicator.geo.location | Longitude and latitude. | geo_point |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.marking.tlp | Traffic Light Protocol sharing markings. | keyword |
| threat.indicator.port | Identifies a threat indicator as a port number (irrespective of direction). | long |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.software.name | Name of the software/product detected on the indicator. | keyword |
| threat.indicator.software.version | Version of the software/product detected on the indicator. | keyword |
| threat.indicator.tags | Tags associated with the indicator, as provided by Shodan. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.vulnerability.id | CVE or other vulnerability IDs reported by Shodan for the indicator. | keyword |

