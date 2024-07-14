# Collective Intelligence Framework v3 Integration

This integration connects with the [REST API from the running CIFv3 instance](https://github.com/csirtgadgets/bearded-avenger-deploymentkit/wiki/REST-API) to retrieve indicators.

## Expiration of Indicators of Compromise (IOCs)
Indicators are expired after a certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for a source index to allow only active indicators to be available to the end users. The transform creates a destination index named `logs-ti_cif3_latest.dest_feed*` which only contains active and unexpired indicators. Destination indices are aliased to `logs-ti_cif3_latest.feed`. The indicator match rules and dashboards are updated to show only active indicators.

| Indicator Type    | Indicator Expiration Duration                  |
|:------------------|:------------------------------------------------|
| `ipv4-addr`       | `45d`                                           |
| `ipv6-addr`       | `45d`                                           |
| `domain-name`     | `90d`                                           |
| `url`             | `365d`                                          |
| `file`            | `365d`                                          |
| All Other Types   | Derived from `IOC Expiration Duration` setting  |

### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_cif3.feed-*` are allowed to contain duplicates. ILM policy `logs-ti_cif3.feed-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

## Data Streams

### Feed

The CIFv3 integration collects threat indicators based on user-defined configuration including a polling interval, how far back in time it should look, and other filters like indicator type and tags.

CIFv3 `confidence` field values (0..10) are converted to ECS confidence (None, Low, Medium, High) in the following way:

| CIFv3 Confidence | ECS Conversion |
| ---------------- | -------------- |
| Beyond Range     | None           |
| 0 - \<3          | Low            |
| 3 - \<7          | Medium         |
| 7 - 10           | High           |

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cif3.application | The application used by the indicator, such as telnet or ssh. | keyword |
| cif3.asn | AS Number of IP. | integer |
| cif3.asn_desc | AS Number org name. | keyword |
| cif3.cc | Country code of GeoIP. | keyword |
| cif3.city | GeoIP city information. | keyword |
| cif3.confidence | The confidence on a scale of 0-10 that the tags appropriately contextualize the indicator. | float |
| cif3.count | The number of times the same indicator has been reported with the same metadata by the same provider. | integer |
| cif3.deleted_at | The indicator expiration timestamp. | date |
| cif3.description | A description of the indicator. | keyword |
| cif3.expiration_duration | The configured expiration duration. | keyword |
| cif3.indicator | The value of the indicator, for example if the type is fqdn, this would be the value. | keyword |
| cif3.indicator_iprange | IPv4 or IPv6 IP Range. | ip_range |
| cif3.indicator_ipv4 | IPv4 address. | ip |
| cif3.indicator_ipv4_mask | subnet mask of IPv4 CIDR. | integer |
| cif3.indicator_ipv6 | singleton IPv6 address. | keyword |
| cif3.indicator_ipv6_mask | subnet mask of IPv6 CIDR. | integer |
| cif3.indicator_ssdeep_chunk | SSDEEP hash chunk. | text |
| cif3.indicator_ssdeep_chunksize | SSDEEP hash chunk size. | integer |
| cif3.indicator_ssdeep_double_chunk | SSDEEP hash double chunk. | text |
| cif3.itype | The indicator type, can for example be "ipv4, fqdn, email, url, sha256". | keyword |
| cif3.latitude | Latitude of GeoIP. | keyword |
| cif3.location | Lat/Long of GeoIP. | geo_point |
| cif3.longitude | Longitude of GeoIP. | keyword |
| cif3.portlist | The port or range of ports used by the indicator. | text |
| cif3.protocol | The protocol used by the indicator. | text |
| cif3.provider | The source of the indicator information. | keyword |
| cif3.rdata | Extra text or descriptive content related to the indicator such as OS, reverse lookup, etc. | keyword |
| cif3.reference | A reference URL with further info related to the indicator. | keyword |
| cif3.region | GeoIP region information. | keyword |
| cif3.tags | Comma-separated list of words describing the indicator such as "malware,exploit". | keyword |
| cif3.timezone | Timezone of GeoIP. | text |
| cif3.uuid | The ID of the indicator. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Name of the module this data is coming from. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.tls.client.ja3 | An md5 hash that identifies clients based on their TLS handshake. | keyword |


An example event for `feed` looks as following:

```json
{
    "@timestamp": "2024-04-10T04:46:58.281Z",
    "agent": {
        "ephemeral_id": "94c530db-5c8f-407c-939b-cd1d21d547fc",
        "id": "28f0e936-c71c-4f75-8919-506fed4d20e7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "cif3": {
        "deleted_at": "2022-09-03T20:25:53.000Z",
        "expiration_duration": "45d",
        "indicator": "20.206.75.106",
        "itype": "ipv4",
        "portlist": "443",
        "uuid": "ac240898-1443-4d7e-a98a-1daed220c162"
    },
    "data_stream": {
        "dataset": "ti_cif3.feed",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "28f0e936-c71c-4f75-8919-506fed4d20e7",
        "snapshot": false,
        "version": "8.12.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-04-10T04:46:58.281Z",
        "dataset": "ti_cif3.feed",
        "ingested": "2024-04-10T04:47:10Z",
        "kind": "enrichment",
        "original": "{\"application\":\"https\",\"asn\":8075,\"asn_desc\":\"microsoft-corp-msn-as-block\",\"cc\":\"br\",\"city\":\"campinas\",\"confidence\":10,\"count\":1,\"firsttime\":\"2022-07-20T20:25:53.000000Z\",\"group\":[\"everyone\"],\"indicator\":\"20.206.75.106\",\"indicator_ipv4\":\"20.206.75.106\",\"itype\":\"ipv4\",\"lasttime\":\"2022-07-20T20:25:53.000000Z\",\"latitude\":-22.9035,\"location\":[-47.0565,-22.9035],\"longitude\":-47.0565,\"portlist\":\"443\",\"protocol\":\"tcp\",\"provider\":\"sslbl.abuse.ch\",\"reference\":\"https://sslbl.abuse.ch/blacklist/sslipblacklist.csv\",\"region\":\"sao paulo\",\"reporttime\":\"2022-07-21T20:33:26.585967Z\",\"tags\":[\"botnet\"],\"timezone\":\"america/sao_paulo\",\"tlp\":\"white\",\"uuid\":\"ac240898-1443-4d7e-a98a-1daed220c162\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "network": {
        "protocol": "https",
        "transport": "tcp"
    },
    "related": {
        "ip": [
            "20.206.75.106"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cif3-indicator",
        "botnet"
    ],
    "threat": {
        "indicator": {
            "as": {
                "number": 8075,
                "organization": {
                    "name": "microsoft-corp-msn-as-block"
                }
            },
            "confidence": "High",
            "first_seen": "2022-07-20T20:25:53.000Z",
            "geo": {
                "country_iso_code": "br",
                "location": {
                    "lat": -22.9035,
                    "lon": -47.0565
                },
                "region_name": "sao paulo",
                "timezone": "america/sao_paulo"
            },
            "ip": "20.206.75.106",
            "last_seen": "2022-07-20T20:25:53.000Z",
            "marking": {
                "tlp": "WHITE"
            },
            "modified_at": "2022-07-21T20:33:26.585967Z",
            "name": "20.206.75.106",
            "provider": "sslbl.abuse.ch",
            "reference": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
            "sightings": 1,
            "type": "ipv4-addr"
        }
    }
}
```
