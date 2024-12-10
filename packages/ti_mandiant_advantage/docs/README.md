# Mandiant Advantage

## Overview

The [Mandiant Advantage](https://www.mandiant.com/advantage) integration allows users to retrieve IOCs (Indicators of Compromise) from the Threat Intelligence Advantage Module. 

These indicators can be used for correlation in Elastic Security to help discover potential threats. Mandiant Threat Intelligence gives security practitioners unparalleled visibility and expertise into threats that matter to their business right now.

Our threat intelligence is compiled by over 500 threat intelligence analysts across 30 countries, researching actors via undercover adversarial pursuits, incident forensics, malicious infrastructure reconstructions and actor identification processes that comprise the deep knowledge embedded in the Mandiant Intel Grid.

## Data streams

The Mandiant Advantage integration collects one type of data stream: `threat_intelligence`

### **Threat Intelligence**

IOCs are retrieved via the Mandiant Threat Intelligence API.


## Compatibility

- This integration has been tested against the Threat Intelligence API v4.


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

For instructions on how to get Threat Intelligence API v4 credentials, see the [Mandiant Documentation Portal.](https://docs.mandiant.com/home/mati-threat-intelligence-api-v4#tag/Getting-Started)

### Filtering IOCs

The integration allows you to filter the amount of IOCs that are ingested, by using the following configuration parameters:

* **Initial interval**
  * The time in the past to start the collection of Indicator data from, based on an indicators last_update date. 
  * Supported units for this parameter are h/m/s. The default value is 720h (i.e 30 days)
  * You may reduce this interval if you do not want as much historical data to be ingested when the integration first runs.
* **Minimum IC-Score**
  * Indicators that have an IC-Score greater than or equal to the given value will be collected. 
  * Indicators with any IC-Score will be collected if a value is set to 0.
  * You might set this to a different value such as 80, to ensure that only high confidence indicators are ingested.  

## Logs reference

### Threat Intelligence

Retrieves IOCs using the Mandiant Threat Intelligence API over time.

An example event for `threat_intelligence` looks as following:

```json
{
    "@timestamp": "2023-01-26T08:19:05.976Z",
    "agent": {
        "ephemeral_id": "6c2fce20-5eb3-4d82-8d3f-317839b5f840",
        "id": "4b0cd8f9-b1e6-47f3-bdb8-024cdea5fb03",
        "name": "elastic-agent-68415",
        "type": "filebeat",
        "version": "8.14.3"
    },
    "data_stream": {
        "dataset": "ti_mandiant_advantage.threat_intelligence",
        "namespace": "36354",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "4b0cd8f9-b1e6-47f3-bdb8-024cdea5fb03",
        "snapshot": false,
        "version": "8.14.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-09-02T08:29:29.223Z",
        "dataset": "ti_mandiant_advantage.threat_intelligence",
        "ingested": "2024-09-02T08:29:30Z",
        "kind": "enrichment",
        "module": "ti_mandiant_advantage_threat_intelligence",
        "original": "{\"campaigns\":[{\"id\":\"campaign--bff76355-4d90-5f1f-b402-565a8fb2ac61\",\"name\":\"GLOBAL.21.005\",\"title\":\"Exploitation of CVE-2021-44228 (aka \\\"Log4Shell\\\") in Various Products\"}],\"first_seen\":\"2021-06-19T23:34:03.000Z\",\"id\":\"ipv4--55ba8198-79a1-5f13-b537-632c8bad942f\",\"is_publishable\":true,\"last_seen\":\"2022-12-26T23:34:03.000Z\",\"last_updated\":\"2023-01-26T08:19:05.976Z\",\"misp\":{\"akamai\":false,\"alexa\":false,\"alexa_1M\":false,\"amazon-aws\":false,\"apple\":false,\"automated-malware-analysis\":false,\"bank-website\":false,\"cisco_1M\":false,\"cisco_top1000\":false,\"cisco_top10k\":false,\"cisco_top20k\":false,\"cisco_top5k\":false,\"cloudflare\":false,\"common-contact-emails\":false,\"common-ioc-false-positive\":false,\"covid\":false,\"covid-19-cyber-threat-coalition-whitelist\":false,\"covid-19-krassi-whitelist\":false,\"crl-hostname\":false,\"crl-ip\":false,\"dax30\":false,\"disposable-email\":false,\"dynamic-dns\":false,\"eicar.com\":false,\"empty-hashes\":false,\"fastly\":false,\"google\":false,\"google-chrome-crux-1million\":false,\"google-gcp\":false,\"google-gmail-sending-ips\":false,\"googlebot\":false,\"ipv6-linklocal\":false,\"majestic_million\":false,\"majestic_million_1M\":false,\"microsoft\":false,\"microsoft-attack-simulator\":false,\"microsoft-azure\":false,\"microsoft-azure-appid\":false,\"microsoft-azure-china\":false,\"microsoft-azure-germany\":false,\"microsoft-azure-us-gov\":false,\"microsoft-office365\":false,\"microsoft-office365-cn\":false,\"microsoft-office365-ip\":false,\"microsoft-win10-connection-endpoints\":false,\"moz-top500\":false,\"mozilla-CA\":false,\"mozilla-IntermediateCA\":false,\"multicast\":false,\"nioc-filehash\":false,\"ovh-cluster\":false,\"parking-domain\":false,\"parking-domain-ns\":false,\"phone_numbers\":false,\"public-dns-hostname\":false,\"public-dns-v4\":false,\"public-dns-v6\":false,\"public-ipfs-gateways\":false,\"rfc1918\":false,\"rfc3849\":false,\"rfc5735\":false,\"rfc6598\":false,\"rfc6761\":false,\"second-level-tlds\":false,\"security-provider-blogpost\":false,\"sinkholes\":false,\"smtp-receiving-ips\":false,\"smtp-sending-ips\":false,\"stackpath\":false,\"tenable-cloud-ipv4\":false,\"tenable-cloud-ipv6\":false,\"ti-falsepositives\":false,\"tlds\":false,\"tranco\":false,\"tranco10k\":false,\"university_domains\":false,\"url-shortener\":false,\"vpn-ipv4\":false,\"vpn-ipv6\":false,\"whats-my-ip\":false,\"wikimedia\":false},\"mscore\":58,\"reports\":[{\"audience\":[\"cyber espionage\",\"fusion\"],\"id\":\"report--2781217d-3b75-5e22-b3f7-8db3e09d2b70\",\"published_date\":\"2022-05-11T19:53:16.583Z\",\"report_id\":\"22-00011950\",\"title\":\"APT29 Targets European Diplomatic Entities with ROOTSAW Dropper and New BEATDROP Variants Using Dropbox and Slack for C\\u0026C\",\"type\":\"Event Coverage/Implication\"}],\"sources\":[{\"category\":[],\"first_seen\":\"2022-02-23T10:10:01.828+0000\",\"last_seen\":\"2022-02-23T10:10:01.828+0000\",\"osint\":true,\"source_name\":\"blocklist_de\"},{\"category\":[\"exploit/vuln-scanning\",\"exploit\"],\"first_seen\":\"2021-06-19T23:34:03.810+0000\",\"last_seen\":\"2022-12-26T23:34:03.998+0000\",\"osint\":true,\"source_name\":\"blocklist_net_ua\"},{\"category\":[],\"first_seen\":\"2022-06-03T23:39:01.621+0000\",\"last_seen\":\"2022-06-03T23:39:01.621+0000\",\"osint\":false,\"source_name\":\"Mandiant\"},{\"category\":[],\"first_seen\":\"2022-06-20T20:20:01.549+0000\",\"last_seen\":\"2022-06-20T20:20:01.549+0000\",\"osint\":true,\"source_name\":\"the_haleys_ssh_dict_attack\"}],\"type\":\"ipv4\",\"value\":\"1.128.3.4\"}",
        "risk_score": 58,
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "mandiant": {
        "threat_intelligence": {
            "ioc": {
                "campaigns": [
                    {
                        "id": "campaign--bff76355-4d90-5f1f-b402-565a8fb2ac61",
                        "name": "GLOBAL.21.005",
                        "title": "Exploitation of CVE-2021-44228 (aka \"Log4Shell\") in Various Products"
                    }
                ],
                "categories": [
                    "exploit/vuln-scanning",
                    "exploit"
                ],
                "first_seen": "2021-06-19T23:34:03.000Z",
                "id": "ipv4--55ba8198-79a1-5f13-b537-632c8bad942f",
                "is_publishable": true,
                "last_seen": "2022-12-26T23:34:03.000Z",
                "last_update_date": "2023-01-26T08:19:05.976Z",
                "misp_warning_list_misses": [
                    "covid",
                    "smtp-receiving-ips",
                    "eicar.com",
                    "majestic_million",
                    "alexa",
                    "sinkholes",
                    "cisco_top1000",
                    "crl-hostname",
                    "microsoft",
                    "microsoft-office365",
                    "googlebot",
                    "microsoft-azure-germany",
                    "microsoft-attack-simulator",
                    "microsoft-azure",
                    "rfc5735",
                    "parking-domain",
                    "tranco10k",
                    "dax30",
                    "public-dns-v4",
                    "dynamic-dns",
                    "public-dns-v6",
                    "covid-19-cyber-threat-coalition-whitelist",
                    "common-ioc-false-positive",
                    "cisco_1M",
                    "google-gmail-sending-ips",
                    "microsoft-azure-china",
                    "stackpath",
                    "google",
                    "cloudflare",
                    "moz-top500",
                    "tlds",
                    "tranco",
                    "university_domains",
                    "smtp-sending-ips",
                    "cisco_top20k",
                    "empty-hashes",
                    "nioc-filehash",
                    "amazon-aws",
                    "url-shortener",
                    "microsoft-office365-ip",
                    "microsoft-azure-us-gov",
                    "microsoft-win10-connection-endpoints",
                    "majestic_million_1M",
                    "mozilla-CA",
                    "microsoft-office365-cn",
                    "whats-my-ip",
                    "vpn-ipv6",
                    "public-ipfs-gateways",
                    "rfc3849",
                    "rfc6761",
                    "security-provider-blogpost",
                    "tenable-cloud-ipv4",
                    "cisco_top5k",
                    "tenable-cloud-ipv6",
                    "apple",
                    "public-dns-hostname",
                    "mozilla-IntermediateCA",
                    "microsoft-azure-appid",
                    "rfc1918",
                    "ti-falsepositives",
                    "akamai",
                    "bank-website",
                    "alexa_1M",
                    "automated-malware-analysis",
                    "rfc6598",
                    "google-gcp",
                    "multicast",
                    "ovh-cluster",
                    "phone_numbers",
                    "fastly",
                    "google-chrome-crux-1million",
                    "cisco_top10k",
                    "second-level-tlds",
                    "wikimedia",
                    "disposable-email",
                    "common-contact-emails",
                    "parking-domain-ns",
                    "vpn-ipv4",
                    "ipv6-linklocal",
                    "covid-19-krassi-whitelist",
                    "crl-ip"
                ],
                "mscore": 58,
                "reports": [
                    {
                        "audience": [
                            "cyber espionage",
                            "fusion"
                        ],
                        "id": "report--2781217d-3b75-5e22-b3f7-8db3e09d2b70",
                        "published_date": "2022-05-11T19:53:16.583Z",
                        "report_id": "22-00011950",
                        "title": "APT29 Targets European Diplomatic Entities with ROOTSAW Dropper and New BEATDROP Variants Using Dropbox and Slack for C&C",
                        "type": "Event Coverage/Implication"
                    }
                ],
                "sources": [
                    {
                        "first_seen": "2022-02-23T10:10:01.828+0000",
                        "last_seen": "2022-02-23T10:10:01.828+0000",
                        "osint": true,
                        "source_name": "blocklist_de"
                    },
                    {
                        "category": [
                            "exploit/vuln-scanning",
                            "exploit"
                        ],
                        "first_seen": "2021-06-19T23:34:03.810+0000",
                        "last_seen": "2022-12-26T23:34:03.998+0000",
                        "osint": true,
                        "source_name": "blocklist_net_ua"
                    },
                    {
                        "first_seen": "2022-06-03T23:39:01.621+0000",
                        "last_seen": "2022-06-03T23:39:01.621+0000",
                        "osint": false,
                        "source_name": "Mandiant"
                    },
                    {
                        "first_seen": "2022-06-20T20:20:01.549+0000",
                        "last_seen": "2022-06-20T20:20:01.549+0000",
                        "osint": true,
                        "source_name": "the_haleys_ssh_dict_attack"
                    }
                ],
                "type": "ipv4",
                "value": "1.128.3.4"
            }
        }
    },
    "related": {
        "ip": [
            "1.128.3.4"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "mandiant-threat-intelligence-indicator"
    ],
    "threat": {
        "feed": {
            "name": "Mandiant Threat Intelligence"
        },
        "indicator": {
            "as": {
                "number": 1221,
                "organization": {
                    "name": "Telstra Pty Ltd"
                }
            },
            "confidence": "Medium",
            "first_seen": "2021-06-19T23:34:03.000Z",
            "ip": "1.128.3.4",
            "last_seen": "2022-12-26T23:34:03.000Z",
            "marking": {
                "tlp": "RED",
                "tlp_version": "2.0"
            },
            "modified_at": "2023-01-26T08:19:05.976Z",
            "provider": [
                "blocklist_de",
                "blocklist_net_ua",
                "Mandiant",
                "the_haleys_ssh_dict_attack"
            ],
            "type": "ipv4-addr"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| mandiant.threat_intelligence.ioc.associated_hashes | List of associated hashes and their types. | object |
| mandiant.threat_intelligence.ioc.attributed_associations | List of attributed associations that this indicator has to other Malware families or Actors. | object |
| mandiant.threat_intelligence.ioc.campaigns | List of related campaigns. | object |
| mandiant.threat_intelligence.ioc.categories | Categories associated with this indicator. | keyword |
| mandiant.threat_intelligence.ioc.first_seen | IOC first seen date. | date |
| mandiant.threat_intelligence.ioc.id | IOC internal ID. | keyword |
| mandiant.threat_intelligence.ioc.is_exclusive | Whether the indicator is exclusive to Mandiant or not. | boolean |
| mandiant.threat_intelligence.ioc.is_publishable | Whether the indicator is publishable or not. | boolean |
| mandiant.threat_intelligence.ioc.last_seen | IOC last seen date. | date |
| mandiant.threat_intelligence.ioc.last_update_date | IOC last update date. | date |
| mandiant.threat_intelligence.ioc.misp_warning_list_hits | Which MISP warning lists the indicator was found in. | keyword |
| mandiant.threat_intelligence.ioc.misp_warning_list_misses | Which MISP warning lists the indicator was not found in. | keyword |
| mandiant.threat_intelligence.ioc.mscore | M-Score (IC-Score) between 0 - 100. | integer |
| mandiant.threat_intelligence.ioc.reports | List of related reports. | object |
| mandiant.threat_intelligence.ioc.sources.\* |  | keyword |
| mandiant.threat_intelligence.ioc.sources.osint |  | boolean |
| mandiant.threat_intelligence.ioc.type | IOC type. | keyword |
| mandiant.threat_intelligence.ioc.value | IOC value. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |

