# GreyNoise

## Overview

[GreyNoise](https://www.greynoise.io/) is a cybersecurity platform that helps security teams filter out "internet noise" — background internet scanning activity that's not necessarily targeted or malicious. It collects, analyzes, and labels massive amounts of data from internet-wide scans, typically originating from bots, security researchers, or compromised systems.

## Prerequisites for GreyNoise

Customers must have access to the **Enterprise API** to fetch data from GreyNoise. You can verify your API key access [here](https://viz.greynoise.io/account/api-key).

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### To Collect Logs Through REST API

1. After logging in to GreyNoise, navigate to your [account page](https://viz.greynoise.io/account/api-key).
2. Click "View API Key" to display and copy your unique API key.

### Enabling the Integration in Elastic

1. In Kibana, go to **Management > Integrations**.
2. In the "Search for integrations" search bar, type **GreyNoise**.
3. Click the **GreyNoise** integration from the search results.
4. Click the **Add GreyNoise** button to add the integration.
5. While adding the integration, provide the following details to collect logs via REST API:
   - API Key
   - Interval
   - (Optional) Query for custom query filtering
6. Click **Save and Continue** to save the integration.

**Note:** The "last_seen" field should not be included in the query as it is predefined with a fixed value of "1d".

## Transforming Data for Up-to-Date Insights

To keep the collected data up to date, **Transforms** are used.

You can view transforms by navigating to **Management > Stack Management > Transforms**.

Here, you can see continuously running transforms and view the latest transformed GreyNoise data in the **Discover** section.

The `labels.is_transform_source` field indicates log origin:
- **False** for transformed index
- **True** for source index

Currently, one transform is running for the IP datastream:

| Transform Name | Description |
|----------------|-------------|
| IP Transform (ID: `logs-ti_greynoise.ip`) | Keeps IP entity type data up to date |

For example:
- The query `event.module: ti_greynoise and labels.is_transform_source: true` shows logs from the **source index**
- The query `event.module: ti_greynoise and labels.is_transform_source: false` shows logs from the **transformed index**

A **retention policy** removes data older than the default retention period. For more details, refer to the [Retention Policy Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/put-transform.html#:~:text=to%20false.-,retention_policy,-(Optional%2C%20object)%20Defines).

In this integration, the IP data stream has a default **retention period of 7 days**.

## Troubleshooting

1. If you experience latency issues during data collection, consider increasing the `HTTP Client Timeout` configuration parameter.
2. If server-side errors occur, consider reducing the `Page Size` configuration parameter.
   **Note:** Avoid setting the `Page Size` too low, as this may increase the number of API requests, potentially causing processing issues.
3. If events are not appearing in the transformed index, check if transforms are running without errors. For issues, refer to [Troubleshooting transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-troubleshooting.html).

## Logs Reference

### IP

This is the `IP` dataset. It uses the [GNQL Endpoint](https://docs.greynoise.io/reference/gnqlquery-1) to fetch data from GreyNoise with "last_seen:1d". It uses version v3 of the API to collect indicators. Currently, the [Triage](https://docs.greynoise.io/docs/intelligence-module-triage) and [Business Services](https://docs.greynoise.io/docs/intelligence-module-business-services) Intelligence Modules are being collected through this data stream.

#### Example

An example event for `ip` looks as following:

```json
{
    "@timestamp": "2025-05-30T12:55:33.381Z",
    "agent": {
        "ephemeral_id": "f00c4032-2cd5-4ba7-ac74-1eeaecf7b82b",
        "id": "e02d601f-5175-4894-b432-6aec71fb67cf",
        "name": "elastic-agent-83925",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "data_stream": {
        "dataset": "ti_greynoise.ip",
        "namespace": "37673",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "e02d601f-5175-4894-b432-6aec71fb67cf",
        "snapshot": false,
        "version": "8.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_greynoise.ip",
        "ingested": "2025-05-30T12:55:36Z",
        "kind": "enrichment",
        "original": "{\"business_service_intelligence\":{\"category\":\"public_dns\",\"description\":\"Google's global domain name system (DNS) resolution service.\",\"explanation\":\"Public DNS services are used as alternatives to ISP's name servers. You may see devices on your network communicating with Google Public DNS over port 53/TCP or 53/UDP to resolve DNS lookups.\",\"found\":true,\"last_updated\":\"2021-11-24T11:42:37Z\",\"name\":\"Google Public DNS\",\"reference\":\"https://developers.google.com/speed/public-dns/docs/isp#alternative\",\"trust_level\":\"1\"},\"internet_scanner_intelligence\":{\"actor\":\"unknown\",\"bot\":false,\"classification\":\"malicious\",\"cves\":[],\"first_seen\":\"\",\"found\":true,\"last_seen\":\"2025-04-22\",\"metadata\":{\"asn\":\"AS269415\",\"carrier\":\"\",\"category\":\"isp\",\"datacenter\":\"\",\"destination_asns\":[],\"destination_cities\":[],\"destination_countries\":[\"Iran\",\"Kazakhstan\"],\"destination_country_codes\":[\"IR\",\"KZ\"],\"domain\":\"clicknetfibra.net.br\",\"latitude\":0,\"longitude\":0,\"mobile\":false,\"organization\":\"CLICKNET FIBRA LTDA\",\"os\":\"\",\"rdns\":\"speedtest.clicknetfibra.net.br\",\"rdns_parent\":\"clicknetfibra.net.br\",\"rdns_validated\":false,\"region\":\"Mato Grosso do Sul\",\"sensor_count\":0,\"sensor_hits\":0,\"single_destination\":false,\"source_city\":\"Dourados\",\"source_country\":\"Brazil\",\"source_country_code\":\"BR\"},\"source\":{\"bytes\":0},\"spoofable\":true,\"ssh\":{\"key\":[]},\"tags\":[],\"tls\":{\"cipher\":[],\"ja4\":[]},\"tor\":false,\"vpn\":false,\"vpn_service\":\"\"},\"ip\":\"1.128.0.0\",\"last_seen_timestamp\":\"2025-04-22 00:26:29\"}",
        "type": [
            "indicator"
        ]
    },
    "greynoise": {
        "ip": {
            "business_service_intelligence": {
                "category": "public_dns",
                "description": "Google's global domain name system (DNS) resolution service.",
                "explanation": "Public DNS services are used as alternatives to ISP's name servers. You may see devices on your network communicating with Google Public DNS over port 53/TCP or 53/UDP to resolve DNS lookups.",
                "found": true,
                "last_updated": "2021-11-24T11:42:37.000Z",
                "name": "Google Public DNS",
                "reference": "https://developers.google.com/speed/public-dns/docs/isp#alternative",
                "trust_level": "1"
            },
            "indicator": {
                "ip": "1.128.0.0"
            },
            "internet_scanner_intelligence": {
                "actor": "unknown",
                "bot": false,
                "classification": "malicious",
                "found": true,
                "last_seen": "2025-04-22T00:00:00.000Z",
                "metadata": {
                    "asn": "AS269415",
                    "category": "isp",
                    "mobile": false,
                    "organization": "CLICKNET FIBRA LTDA",
                    "rdns": "speedtest.clicknetfibra.net.br",
                    "region": "Mato Grosso do Sul",
                    "source_city": "Dourados",
                    "source_country": "Brazil",
                    "source_country_code": "BR"
                },
                "spoofable": true,
                "tor": false,
                "vpn": false
            }
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Threat Intelligence",
        "vendor": "GreyNoise"
    },
    "organization": {
        "name": "unknown"
    },
    "related": {
        "ip": [
            "1.128.0.0"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "greynoise-ip"
    ],
    "threat": {
        "feed": {
            "description": "Threat feed from the GreyNoise cybersecurity platform",
            "name": "GreyNoise IP",
            "reference": "https://docs.greynoise.io/docs/using-greynoise-as-an-indicator-feed"
        },
        "indicator": {
            "as": {
                "number": 269415,
                "organization": {
                    "name": "CLICKNET FIBRA LTDA"
                }
            },
            "description": "1.128.0.0 IP has been observed mass scanning the internet by GreyNoise with a classification of malicious",
            "geo": {
                "city_name": "Dourados",
                "country_iso_code": "BR",
                "country_name": "Brazil",
                "region_name": "Mato Grosso do Sul"
            },
            "ip": "1.128.0.0",
            "name": "1.128.0.0",
            "provider": "GreyNoise",
            "reference": "https://www.greynoise.io/ip/1.128.0.0",
            "type": "ipv4-addr",
            "url": {
                "full": "https://developers.google.com/speed/public-dns/docs/isp#alternative"
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| greynoise.ip.business_service_intelligence.category | Business Services category the provider belongs to, identifying the type of service provided. | keyword |
| greynoise.ip.business_service_intelligence.description | A description of the provider and what they do. | keyword |
| greynoise.ip.business_service_intelligence.explanation | An explanation of the category type and what may be expected from this provider and category. | keyword |
| greynoise.ip.business_service_intelligence.found | Indicates if an IP is part of the Business Services dataset or not. | boolean |
| greynoise.ip.business_service_intelligence.last_updated | Date and time when this record was last updated from its source. | date |
| greynoise.ip.business_service_intelligence.name | The name of the provider and/or service. | keyword |
| greynoise.ip.business_service_intelligence.reference | Reference URL for information about this provider and/or service. | keyword |
| greynoise.ip.business_service_intelligence.trust_level | Defines the trust level assigned to this IP/provider. | keyword |
| greynoise.ip.indicator.ip | IP address observed on the GreyNoise sensor network. | ip |
| greynoise.ip.internet_scanner_intelligence.actor | Confirmed owner or operator of the IP address. | keyword |
| greynoise.ip.internet_scanner_intelligence.bot | Indicates whether the IP is associated with known bot activity. | boolean |
| greynoise.ip.internet_scanner_intelligence.classification | Classification of the IP address. Possible values: benign, unknown, malicious, suspicious. | keyword |
| greynoise.ip.internet_scanner_intelligence.found | Indicates if the IP was observed scanning the GreyNoise sensor network. Also referred to as 'noise'. | boolean |
| greynoise.ip.internet_scanner_intelligence.last_seen | Date when the IP was most recently observed on the GreyNoise sensor network (YYYY-MM-DD format). | date |
| greynoise.ip.internet_scanner_intelligence.last_seen_timestamp | Time when the IP was most recently observed on the GreyNoise sensor network. | date |
| greynoise.ip.internet_scanner_intelligence.metadata.asn | ASN (Autonomous System Number) associated with the IP address. | keyword |
| greynoise.ip.internet_scanner_intelligence.metadata.category | Category of the IP address such as hosting or ISP. | keyword |
| greynoise.ip.internet_scanner_intelligence.metadata.mobile | Defines if the IP is part of a known cellular network. | boolean |
| greynoise.ip.internet_scanner_intelligence.metadata.organization | Organization associated with the IP address. | keyword |
| greynoise.ip.internet_scanner_intelligence.metadata.rdns | rDNS (reverse DNS lookup) value for the IP address. | keyword |
| greynoise.ip.internet_scanner_intelligence.metadata.region | Region (state or province) where the IP address is registered or operates. | keyword |
| greynoise.ip.internet_scanner_intelligence.metadata.source_city | City where the IP address is registered or operates. | keyword |
| greynoise.ip.internet_scanner_intelligence.metadata.source_country | Country where the IP address is registered or operates. | keyword |
| greynoise.ip.internet_scanner_intelligence.metadata.source_country_code | Country code of the IP address based on ISO 3166-1 alpha-2. | keyword |
| greynoise.ip.internet_scanner_intelligence.spoofable | Indicates whether the IP completed a three-way handshake with the GreyNoise sensor network. If false, the traffic may be spoofed. | boolean |
| greynoise.ip.internet_scanner_intelligence.tag.names | Tags describing the observed scanning behavior of the IP address. | keyword |
| greynoise.ip.internet_scanner_intelligence.tor | Indicates whether the IP is a known Tor exit node. | boolean |
| greynoise.ip.internet_scanner_intelligence.vpn | Indicates if the IP is associated with a known VPN service. | boolean |
| greynoise.ip.internet_scanner_intelligence.vpn_service | Name of the VPN service associated with the IP (if applicable). | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |

