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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| maltiverse.address | registered address | keyword |
| maltiverse.address.address | Multi-field of `maltiverse.address`. | match_only_text |
| maltiverse.as_name | AS registered name | keyword |
| maltiverse.as_name.as_name | Multi-field of `maltiverse.as_name`. | match_only_text |
| maltiverse.asn_cidr | CIDR associated | keyword |
| maltiverse.asn_country_code | Country code asociated with ASN | keyword |
| maltiverse.asn_date | date when asn registered | date |
| maltiverse.asn_registry | ASN registry | keyword |
| maltiverse.blacklist.count | number of reports for the indicator | long |
| maltiverse.blacklist.description | what we saw | keyword |
| maltiverse.blacklist.description.description | Multi-field of `maltiverse.blacklist.description`. | match_only_text |
| maltiverse.blacklist.external_references |  | flattened |
| maltiverse.blacklist.first_seen | first sighting | date |
| maltiverse.blacklist.labels |  | keyword |
| maltiverse.blacklist.last_seen | last sighting | date |
| maltiverse.blacklist.source | reporter of the activity | keyword |
| maltiverse.cidr | CIDR associated | keyword |
| maltiverse.city | City | keyword |
| maltiverse.classification | Classification of the threat | keyword |
| maltiverse.country_code | Country code of the threat | keyword |
| maltiverse.creation_time | creation date | date |
| maltiverse.domain_consonants |  | long |
| maltiverse.domain_length |  | long |
| maltiverse.email | email address | keyword |
| maltiverse.entropy |  | double |
| maltiverse.feed | Origin of the IoC | keyword |
| maltiverse.hostname |  | keyword |
| maltiverse.ip_addr | IP address | ip |
| maltiverse.is_alive |  | boolean |
| maltiverse.is_cdn | boolean description tag | boolean |
| maltiverse.is_cnc | boolean description tag | boolean |
| maltiverse.is_distributing_malware | boolean description tag | boolean |
| maltiverse.is_hosting | boolean description tag | boolean |
| maltiverse.is_iot_threat | boolean description tag | boolean |
| maltiverse.is_known_attacker | boolean description tag | boolean |
| maltiverse.is_known_scanner | boolean description tag | boolean |
| maltiverse.is_mining_pool | boolean description tag | boolean |
| maltiverse.is_open_proxy | boolean description tag | boolean |
| maltiverse.is_phishing |  | boolean |
| maltiverse.is_sinkhole | boolean description tag | boolean |
| maltiverse.is_storing_phishing |  | boolean |
| maltiverse.is_tor_node | boolean description tag | boolean |
| maltiverse.is_vpn_node | boolean description tag | boolean |
| maltiverse.last_online_time |  | keyword |
| maltiverse.location | Longitude and latitude. | geo_point |
| maltiverse.modification_time | Last modification date | date |
| maltiverse.number_of_blacklisted_domains_resolving | Blacklisted domains resolving associated | long |
| maltiverse.number_of_domains_resolving | Domains resolving associated | long |
| maltiverse.number_of_offline_malicious_urls_allocated | URLs allocated | long |
| maltiverse.number_of_online_malicious_urls_allocated | URLs allocated | long |
| maltiverse.number_of_whitelisted_domains_resolving | Whitelisted domains resolving associated | long |
| maltiverse.postal_code |  | keyword |
| maltiverse.registrant_name | Registrant name | keyword |
| maltiverse.registrant_name.registrant_name | Multi-field of `maltiverse.registrant_name`. | match_only_text |
| maltiverse.resolved_ip |  | flattened |
| maltiverse.tag | Tags of the threat | keyword |
| maltiverse.type | Type of the threat | keyword |
| maltiverse.urlchecksum |  | keyword |


An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2022-11-05T05:37:57.000Z",
    "agent": {
        "ephemeral_id": "b5733e23-446c-4102-952c-66874de0414e",
        "id": "0b6be6e3-4e8a-4084-942d-124b48dc67d5",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.1"
    },
    "data_stream": {
        "dataset": "ti_maltiverse.indicator",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0b6be6e3-4e8a-4084-942d-124b48dc67d5",
        "snapshot": false,
        "version": "8.8.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2023-09-21T20:46:55.738Z",
        "dataset": "ti_maltiverse.indicator",
        "id": "NsHdp9tZZtzo6Kzlv6Z1TmPP47U=",
        "ingested": "2023-09-21T20:46:58Z",
        "kind": "enrichment",
        "original": "{\"blacklist\":{\"count\":1,\"description\":\"QakBot\",\"first_seen\":\"2022-11-03 06:23:53\",\"labels\":[\"malicious-activity\"],\"last_seen\":\"2022-11-05 05:37:57\",\"source\":\"ThreatFox Abuse.ch\"},\"classification\":\"malicious\",\"creation_time\":\"2022-11-03 06:23:53\",\"domain\":\"autooutletllc.com\",\"hostname\":\"autooutletllc.com\",\"is_alive\":false,\"is_cnc\":true,\"is_distributing_malware\":false,\"is_iot_threat\":false,\"is_phishing\":false,\"last_online_time\":\"2022-11-05 05:37:57\",\"modification_time\":\"2022-11-05 05:37:57\",\"tag\":[\"bb05\",\"iso\",\"qakbot\",\"qbot\",\"quakbot\",\"tr\",\"w19\",\"zip\",\"oakboat\",\"pinkslipbot\"],\"tld\":\"com\",\"type\":\"url\",\"url\":\"https://autooutletllc.com/spares.php\",\"urlchecksum\":\"4aa7a29969dc1dffa5cad5af6cb343b9a9b40ea9646fed619d4c8d6472629128\"}",
        "severity": 9,
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "maltiverse": {
        "blacklist": {
            "labels": [
                "malicious-activity"
            ]
        },
        "classification": "malicious",
        "creation_time": "2022-11-03T06:23:53.000Z",
        "feed": "test",
        "hostname": "autooutletllc.com",
        "is_alive": false,
        "is_cnc": true,
        "is_distributing_malware": false,
        "is_iot_threat": false,
        "is_phishing": false,
        "last_online_time": "2022-11-05T05:37:57.000Z",
        "modification_time": "2022-11-05T05:37:57.000Z",
        "type": "url",
        "urlchecksum": "4aa7a29969dc1dffa5cad5af6cb343b9a9b40ea9646fed619d4c8d6472629128"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "ti_maltiverse-indicator",
        "bb05",
        "iso",
        "qakbot",
        "qbot",
        "quakbot",
        "tr",
        "w19",
        "zip",
        "oakboat",
        "pinkslipbot"
    ],
    "threat": {
        "feed": {
            "reference": "https://maltiverse.com/feed/test"
        },
        "indicator": {
            "confidence": "High",
            "description": "QakBot",
            "first_seen": "2022-11-03T06:23:53.000Z",
            "last_seen": "2022-11-05T05:37:57.000Z",
            "marking": {
                "tlp": "WHITE"
            },
            "provider": "ThreatFox Abuse.ch",
            "reference": "https://maltiverse.com/url/4aa7a29969dc1dffa5cad5af6cb343b9a9b40ea9646fed619d4c8d6472629128",
            "sightings": 1,
            "type": "url",
            "url": {
                "full": "https://autooutletllc.com/spares.php",
                "registered_domain": "autooutletllc.com",
                "top_level_domain": "com"
            }
        }
    }
}

```