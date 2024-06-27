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
    "@timestamp": "2023-05-05T15:45:59.710Z",
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "kind": "enrichment",
        "module": "ti_mandiant_advantage_threat_intelligence",
        "risk_score": 50,
        "type": [
            "indicator"
        ]
    },
    "mandiant": {
        "threat_intelligence": {
            "ioc": {
                "categories": [
                    "exploit/vuln-scanning",
                    "exploit",
                    "spam/sender",
                    "spam"
                ],
                "first_seen": "2022-06-18T23:22:01.000Z",
                "id": "ipv4--af6febd0-3351-5b32-a66c-bbac306c7360",
                "last_seen": "2023-03-23T23:22:01.000Z",
                "last_update_date": "2023-05-05T15:45:59.710Z",
                "mscore": 50,
                "sources": [
                    {
                        "first_seen": "2022-09-22T23:40:00.911+0000",
                        "last_seen": "2022-09-23T00:33:09.000+0000",
                        "osint": true,
                        "source_name": "voipbl"
                    },
                    {
                        "category": [
                            "exploit/vuln-scanning",
                            "exploit"
                        ],
                        "first_seen": "2022-09-14T09:20:00.904+0000",
                        "last_seen": "2023-02-24T18:20:00.857+0000",
                        "osint": true,
                        "source_name": "greensnow"
                    },
                    {
                        "category": [
                            "spam/sender",
                            "spam"
                        ],
                        "first_seen": "2022-06-18T23:22:01.386+0000",
                        "last_seen": "2023-03-23T23:22:01.308+0000",
                        "osint": true,
                        "source_name": "sblam_blacklist"
                    },
                    {
                        "first_seen": "2022-09-14T23:34:04.312+0000",
                        "last_seen": "2022-09-23T00:33:09.000+0000",
                        "osint": true,
                        "source_name": "blocklist_net_ua"
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
            "first_seen": "2022-06-18T23:22:01.000Z",
            "ip": "1.128.3.4",
            "last_seen": "2023-03-23T23:22:01.000Z",
            "marking": {
                "tlp": "GREEN",
                "tlp_version": "2.0"
            },
            "modified_at": "2023-05-05T15:45:59.710Z",
            "provider": [
                "voipbl",
                "greensnow",
                "sblam_blacklist",
                "blocklist_net_ua"
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
| mandiant.threat_intelligence.ioc.categories | Categories associated with this indicator. | keyword |
| mandiant.threat_intelligence.ioc.first_seen | IOC first seen date. | date |
| mandiant.threat_intelligence.ioc.id | IOC internal ID. | keyword |
| mandiant.threat_intelligence.ioc.is_exclusive | Whether the indicator is exclusive to Mandiant or not. | boolean |
| mandiant.threat_intelligence.ioc.last_seen | IOC last seen date. | date |
| mandiant.threat_intelligence.ioc.last_update_date | IOC last update date. | date |
| mandiant.threat_intelligence.ioc.mscore | M-Score (IC-Score) between 0 - 100. | integer |
| mandiant.threat_intelligence.ioc.sources | List of the indicator sources. | object |
| mandiant.threat_intelligence.ioc.type | IOC type. | keyword |
| mandiant.threat_intelligence.ioc.value | IOC value. | keyword |

