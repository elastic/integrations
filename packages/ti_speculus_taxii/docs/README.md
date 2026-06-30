# Speculus Threat Intelligence

## Overview

The Speculus Threat Intelligence integration connects to the Speculus TAXII 2.1 server and collects threat intelligence indicators in [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) format. The indicators are mapped to the Elastic Common Schema (ECS) and indexed into Elasticsearch for use in detection rules, indicator-match enrichment, and threat hunting.

Speculus is a curated IP threat intelligence feed. Each indicator carries a risk score, observed activity, named attribution where known, and rich network context (geo, ISP/ASN, cloud provider, residential proxy, scanner, and Tor classifications).

### Compatibility

This integration is compatible with the Speculus TAXII 2.1 server and has been tested against Elastic Stack 8.18.0 and later.

### How it works

The Elastic Agent uses the CEL input to poll the single Speculus TAXII collection. On each interval tick the agent sends `added_after` for incremental sync (and the TAXII `next` cursor for pagination), then forwards each STIX object to the ingest pipeline. The pipeline parses the STIX `pattern` and maps fields to ECS `threat.indicator.*`. Non-ECS STIX fields, including the Speculus `x_speculus_*` extension properties, are namespaced under `ti_speculus_taxii.stix.*`.

## What data does this integration collect?

This integration collects a single data stream:

- **indicator**: STIX 2.1 indicator objects from the Speculus TAXII server. Each indicator is emitted with `event.kind: enrichment` and mapped to ECS `threat.indicator.*` fields. The feed consists of IPv4 indicators (with IPv6 planned).

### Supported use cases

- Enriching alerts in Elastic Security with STIX-based threat indicators.
- Driving indicator-match detection rules.
- Building dashboards and reports over current threat landscape activity.

## What do I need to use this integration?

- A self-managed or Cloud Elastic deployment with Elastic Stack 8.18.0 or later.
- An Elastic Agent enrolled in Fleet (Fleet-managed deployment is recommended; agentless deployment is also supported).
- A Speculus account with TAXII access and an API key.

## How do I deploy this integration?

This integration is deployed using the Elastic Agent. See the general [Observability getting started guide](https://www.elastic.co/guide/en/observability/current/observability-get-started.html) for an end-to-end overview of installing the Agent and adding integrations.

### Onboard and configure

1. In Kibana, navigate to **Management > Integrations** and search for "Speculus Threat Intelligence".
2. Click **Add Speculus Threat Intelligence**.
3. Configure the following settings:
   - **Speculus TAXII Base URL**: Default `https://feed.speculus.co`. Change only if Speculus provides a different host.
   - **Collection ID**: Default is the `speculus-ioc-feed` collection. Change only if Speculus provides a different collection.
   - **API Key**: Your Speculus API key, sent as a Bearer token. Stored as a policy secret and masked in the UI.
   - **Interval**: Time between polling cycles (default `15m`, matching the Speculus feed refresh cadence).
   - **Initial Interval**: How far back to look on first start (default `720h`, i.e. 30 days).
   - **IOC Expiration Duration**: How long indicators remain valid after their last seen timestamp (default `90d`).
   - **Limit**: Max STIX objects per TAXII request (default `1000`). The agent paginates using the TAXII `next` cursor.
   - **Proxy URL** (optional): If you need to connect through a proxy.
   - **SSL Configuration** (optional): Custom SSL settings if needed.
4. Both Fleet-managed and agentless deployment modes are supported.
5. Click **Save and continue** to deploy the integration.

### Validation

After deployment, verify that data is flowing:

1. In Kibana, open **Discover** and select the `logs-ti_speculus_taxii.indicator-*` data view. Documents should start appearing within one `Interval`.
2. Confirm `threat.indicator.ip` and `threat.indicator.confidence` are populated on the documents.

## Troubleshooting

### No data appearing

1. Verify the API key is correct and active.
2. Check that the base URL and collection ID are reachable.
3. Inspect Elastic Agent logs for connection errors. `401`/`403` indicates an invalid or expired API key; `timeout` indicates network or proxy issues.

### Mapping failures

Check the failure store: `GET .fs-logs-ti_speculus_taxii.indicator-*/_count`. The expected value is `0`. If non-zero, query the failure store for `error.message` to identify the offending field or document.

### STIX parsing errors

1. Check the `event.original` field for the raw STIX document.
2. Verify the STIX `spec_version` is `2.1` (other versions are dropped).
3. Inspect `error.message` for the specific parser error.

## Performance and scaling

The CEL input paginates the collection using the TAXII `next` cursor with the configured `Limit` (default `1000` objects per request). On steady-state runs only indicators modified since the last sweep are returned, keeping each tick lightweight.

## Reference

### Logs reference

#### Indicator

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| _conf.ioc_expiration_duration |  | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| threat.feed.name | The name of the threat feed in UI friendly format. | constant_keyword |
| threat.feed.reference | Reference information for the threat feed in a UI friendly format. | keyword |
| threat.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.indicator.as.organization.name | Organization name. | keyword |
| threat.indicator.as.organization.name.text | Multi-field of `threat.indicator.as.organization.name`. | match_only_text |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.geo.city_name | City name. | keyword |
| threat.indicator.geo.country_iso_code | Country ISO code. | keyword |
| threat.indicator.geo.country_name | Country name. | keyword |
| threat.indicator.geo.location | Longitude and latitude. | geo_point |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.marking.tlp | Traffic Light Protocol sharing markings. | keyword |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| ti_speculus_taxii.stix.confidence | The confidence that the creator has in the correctness of their data, in the range 0-100. For Speculus this is the underlying risk score. | integer |
| ti_speculus_taxii.stix.created | The time at which the STIX Indicator Object was originally created. | date |
| ti_speculus_taxii.stix.created_by_ref | The id property of the identity object that describes the entity that created this object. | keyword |
| ti_speculus_taxii.stix.description | Human-readable description of the indicator. | keyword |
| ti_speculus_taxii.stix.id | The ID of the indicator. | keyword |
| ti_speculus_taxii.stix.indicator_types | The STIX indicator types that categorize this indicator, for example malicious-activity. | keyword |
| ti_speculus_taxii.stix.ioc_expiration_date | The expiration date of the indicator. It can be defined from the source event, by the revoked or valid_until fields, or from the integration configuration by ioc_expiration_duration. | date |
| ti_speculus_taxii.stix.ioc_expiration_duration | The configured expiration duration for the indicator. | keyword |
| ti_speculus_taxii.stix.ioc_expiration_reason | Reason why the indicator is expired. Defined by the integration in the ingest pipeline. | keyword |
| ti_speculus_taxii.stix.labels | STIX labels classifying the indicator (e.g. risk level, proxy type, activity category). | keyword |
| ti_speculus_taxii.stix.modified | Date of the last modification. | date |
| ti_speculus_taxii.stix.modified_at | ECS-style alias of `modified` emitted by the Speculus feed. | date |
| ti_speculus_taxii.stix.name | Short descriptive name for the indicator. | keyword |
| ti_speculus_taxii.stix.object_marking_refs | A list of id properties of marking-definition objects that apply to this object. | keyword |
| ti_speculus_taxii.stix.pattern | The detection pattern for the indicator. | keyword |
| ti_speculus_taxii.stix.pattern_type | The pattern language used in this indicator, which is always "stix". | keyword |
| ti_speculus_taxii.stix.revoked | Indicates whether the object has been revoked. | boolean |
| ti_speculus_taxii.stix.spec_version | The version of the STIX specification used to represent this object. The value of this property must be 2.1. | keyword |
| ti_speculus_taxii.stix.type | Type of the STIX Object. | keyword |
| ti_speculus_taxii.stix.valid_from | The time from which the indicator is considered a valid indicator. | date |
| ti_speculus_taxii.stix.valid_until | The time at which the indicator should no longer be considered a valid indicator. | date |
| ti_speculus_taxii.stix.x_speculus_activity | Observed malicious activity category (e.g. C2, Botnet, Phishing, Scanner). | keyword |
| ti_speculus_taxii.stix.x_speculus_attribution | Named threat actor, malware family, or tool attributed to the indicator. | keyword |
| ti_speculus_taxii.stix.x_speculus_cloud_provider.provider | Cloud provider name (AWS, Azure, GCP, Google). | keyword |
| ti_speculus_taxii.stix.x_speculus_cloud_provider.region | Cloud region. | keyword |
| ti_speculus_taxii.stix.x_speculus_cloud_provider.service | Cloud service. | keyword |
| ti_speculus_taxii.stix.x_speculus_first_seen | First time Speculus observed the indicator. | date |
| ti_speculus_taxii.stix.x_speculus_identity.asn | Autonomous system number associated with the IP. | long |
| ti_speculus_taxii.stix.x_speculus_identity.connection_type | Connection type (e.g. wireless, wired). | keyword |
| ti_speculus_taxii.stix.x_speculus_identity.ip | The IP address. | ip |
| ti_speculus_taxii.stix.x_speculus_identity.isp | Internet service provider name. | keyword |
| ti_speculus_taxii.stix.x_speculus_identity.org | Organization name associated with the IP. | keyword |
| ti_speculus_taxii.stix.x_speculus_is_blacklisted | Whether the indicator appears on third-party reputation blacklists. | boolean |
| ti_speculus_taxii.stix.x_speculus_is_datacenter | Whether the indicator is a datacenter address. | boolean |
| ti_speculus_taxii.stix.x_speculus_is_scanner | Whether the indicator is a known commercial scanner. | boolean |
| ti_speculus_taxii.stix.x_speculus_is_tor_node | Whether the indicator is a Tor exit node. | boolean |
| ti_speculus_taxii.stix.x_speculus_last_seen | Most recent time Speculus observed the indicator. | date |
| ti_speculus_taxii.stix.x_speculus_location.city | City name. | keyword |
| ti_speculus_taxii.stix.x_speculus_location.country | Country name. | keyword |
| ti_speculus_taxii.stix.x_speculus_location.country_code | ISO country code. | keyword |
| ti_speculus_taxii.stix.x_speculus_location.lat | Latitude. | double |
| ti_speculus_taxii.stix.x_speculus_location.lon | Longitude. | double |
| ti_speculus_taxii.stix.x_speculus_residential_proxy.days_seen | Number of distinct days the proxy was observed. | integer |
| ti_speculus_taxii.stix.x_speculus_residential_proxy.first_seen | First time the proxy was observed. | date |
| ti_speculus_taxii.stix.x_speculus_residential_proxy.last_seen | Most recent time the proxy was observed. | date |
| ti_speculus_taxii.stix.x_speculus_residential_proxy.provider | Residential proxy provider name. | keyword |
| ti_speculus_taxii.stix.x_speculus_residential_proxy.type | Residential proxy type. | keyword |
| ti_speculus_taxii.stix.x_speculus_risk | Speculus risk classification (low, medium, high, very high). | keyword |
| ti_speculus_taxii.stix.x_speculus_scanner_name | Name of the commercial scanner, when identified (e.g. Censys, Shodan). | keyword |
| ti_speculus_taxii.stix.x_speculus_score | Speculus risk score for the indicator (0-100). | integer |
| ti_speculus_taxii.stix.x_speculus_vpn_proxy | Whether the indicator is a VPN or public proxy. | boolean |


An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2026-06-26T01:41:05.160Z",
    "agent": {
        "ephemeral_id": "43af6da1-b18c-4817-8688-f525c200d434",
        "id": "8257fe94-2ac6-48cf-bd18-2ded67e2c463",
        "name": "elastic-agent-58386",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_speculus_taxii.indicator",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "8257fe94-2ac6-48cf-bd18-2ded67e2c463",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_speculus_taxii.indicator",
        "id": "indicator--00000062-24ff-5d95-af62-99932efee6c4",
        "ingested": "2026-06-26T01:45:00Z",
        "kind": "enrichment",
        "original": "{\"type\":\"indicator\",\"spec_version\":\"2.1\",\"id\":\"indicator--00000062-24ff-5d95-af62-99932efee6c4\",\"created_by_ref\":\"identity--1444bd44-5335-5f48-b93b-99429c4c9ff2\",\"created\":\"2026-06-26T01:41:05.160Z\",\"modified\":\"2026-06-26T01:41:05.160Z\",\"name\":\"Speculus: residential proxy - 203.0.113.50\",\"description\":\"This IP is a Botting Tools residential proxy node in Hanau, Germany.\",\"indicator_types\":[\"anomalous-activity\"],\"pattern\":\"[ipv4-addr:value = '203.0.113.50']\",\"pattern_type\":\"stix\",\"valid_from\":\"2026-06-26T01:41:05.160Z\",\"object_marking_refs\":[\"marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9\"],\"x_speculus_risk\":\"low\",\"x_speculus_is_datacenter\":true,\"x_speculus_vpn_proxy\":true,\"x_speculus_identity\":{\"ip\":\"203.0.113.50\",\"isp\":\"F.N.S. HOLDINGS LIMITED\",\"org\":\"VPN Consumer Frankfurt, Germany\",\"asn\":206092},\"x_speculus_location\":{\"city\":\"Hanau\",\"country\":\"Germany\",\"country_code\":\"DE\",\"lat\":50.1342,\"lon\":8.91418}}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "ip": [
            "203.0.113.50"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "ti_speculus_taxii-indicator",
        "speculus:risk:low",
        "speculus:proxy:residential",
        "speculus:datacenter",
        "speculus:vpn-or-proxy"
    ],
    "threat": {
        "feed": {
            "name": "Speculus TAXII",
            "reference": "https://speculus.co"
        },
        "indicator": {
            "as": {
                "number": 206092,
                "organization": {
                    "name": "VPN Consumer Frankfurt, Germany"
                }
            },
            "confidence": "Low",
            "description": "This IP is a Botting Tools residential proxy node in Hanau, Germany.",
            "first_seen": "2026-06-26T01:41:05.160Z",
            "geo": {
                "city_name": "Hanau",
                "country_iso_code": "DE",
                "country_name": "Germany",
                "location": {
                    "lat": 50.1342,
                    "lon": 8.91418
                }
            },
            "ip": [
                "203.0.113.50"
            ],
            "last_seen": "2026-06-26T01:41:05.160Z",
            "marking": {
                "tlp": "WHITE"
            },
            "modified_at": "2026-06-26T01:41:05.160Z",
            "name": "Speculus: residential proxy - 203.0.113.50",
            "provider": "Speculus",
            "type": "ipv4-addr"
        }
    },
    "ti_speculus_taxii": {
        "stix": {
            "created": "2026-06-26T01:41:05.160Z",
            "created_by_ref": "identity--1444bd44-5335-5f48-b93b-99429c4c9ff2",
            "id": "indicator--00000062-24ff-5d95-af62-99932efee6c4",
            "indicator_types": [
                "anomalous-activity"
            ],
            "ioc_expiration_date": "2026-09-24T01:41:05.160Z",
            "ioc_expiration_duration": "90d",
            "ioc_expiration_reason": "Expiration set by Elastic from the integration's parameter `IOC Expiration Duration`",
            "modified": "2026-06-26T01:41:05.160Z",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
            "pattern": "[ipv4-addr:value = '203.0.113.50']",
            "pattern_type": "stix",
            "spec_version": "2.1",
            "valid_from": "2026-06-26T01:41:05.160Z"
        }
    }
}
```

### Inputs used in this integration

- [CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html): Polls the Speculus TAXII 2.1 server with `added_after` filtering and TAXII `next` cursor pagination.

### APIs used to collect data

- `GET /{api_root}/collections/{collection_id}/objects/?added_after={ts}&limit={n}` — Returns a STIX 2.1 envelope of indicator objects.
- `GET /{api_root}/collections/{collection_id}/objects/?next={cursor}&limit={n}` — Returns the next page of the collection.

### STIX to ECS field mapping

| STIX Field | ECS Field |
|------------|-----------|
| `id` | `event.id` |
| `type` | `threat.indicator.type` |
| `modified` | `threat.indicator.last_seen`, `threat.indicator.modified_at` |
| `valid_from` | `threat.indicator.first_seen` |
| `valid_until` | `ti_speculus_taxii.stix.ioc_expiration_date` |
| `confidence` | `threat.indicator.confidence` |
| `description` | `threat.indicator.description` |
| `name` | `threat.indicator.name` |
| `labels` | `tags` |
| `x_speculus_location.lat/lon` | `threat.indicator.geo.location` |
| `x_speculus_location.country_code` | `threat.indicator.geo.country_iso_code` |
| `x_speculus_identity.asn` | `threat.indicator.as.number` |
| `x_speculus_identity.org/isp` | `threat.indicator.as.organization.name` |

### Confidence mapping

STIX `confidence` (0-100, the Speculus risk score) is mapped to ECS `threat.indicator.confidence`:

| STIX Confidence | ECS Confidence |
|-----------------|----------------|
| 0 | None |
| 1-25 | Low |
| 26-49 | Medium |
| 50-100 | High |
| absent | Low |

### IOC expiration

By default, indicators expire 90 days after their last seen timestamp. The behavior is controlled by **IOC Expiration Duration**:

- If `valid_until` is present in the STIX object, it is used as the expiration date.
- Otherwise the expiration is calculated as `modified + ioc_expiration_duration`.
- The reason is recorded in `ti_speculus_taxii.stix.ioc_expiration_reason`.

### External references

- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [Elastic Threat Intelligence Integration Guide](https://www.elastic.co/guide/en/security/current/threat-intelligence.html)
