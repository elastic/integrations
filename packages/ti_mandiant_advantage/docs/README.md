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
        "version": "8.7.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "kind": "enrichment",
        "module": "ti_mandiant_advantage_threat_intelligence",
        "risk_score": 50.0,
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
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
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
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name | The name of the threat feed in UI friendly format. | keyword |
| threat.group.id | The id of the group for a set of related intrusion activity that are tracked by a common name in the security community. While not required, you can use a MITRE ATT&CK® group id. | keyword |
| threat.group.name | The name of the group for a set of related intrusion activity that are tracked by a common name in the security community. While not required, you can use a MITRE ATT&CK® group name. | keyword |
| threat.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.indicator.as.organization.name | Organization name. | keyword |
| threat.indicator.as.organization.name.text | Multi-field of `threat.indicator.as.organization.name`. | match_only_text |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.hash.sha384 | SHA384 hash. | keyword |
| threat.indicator.file.hash.sha512 | SHA512 hash. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.geo.city_name | City name. | keyword |
| threat.indicator.geo.continent_name | Name of the continent. | keyword |
| threat.indicator.geo.country_iso_code | Country ISO code. | keyword |
| threat.indicator.geo.country_name | Country name. | keyword |
| threat.indicator.geo.location | Longitude and latitude. | geo_point |
| threat.indicator.geo.region_iso_code | Region ISO code. | keyword |
| threat.indicator.geo.region_name | Region name. | keyword |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.marking.tlp | Traffic Light Protocol sharing markings. | keyword |
| threat.indicator.marking.tlp_version | Traffic Light Protocol version. | keyword |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| threat.indicator.url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| threat.indicator.url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| threat.indicator.url.full.text | Multi-field of `threat.indicator.url.full`. | match_only_text |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |
| threat.indicator.url.password | Password of the request. | keyword |
| threat.indicator.url.path | Path of the request, such as "/search". | wildcard |
| threat.indicator.url.port | Port of the request, such as 443. | long |
| threat.indicator.url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| threat.indicator.url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| threat.indicator.url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| threat.indicator.url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| threat.indicator.url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| threat.indicator.url.username | Username of the request. | keyword |
| threat.software.name | The name of the software used by this threat to conduct behavior commonly modeled using MITRE ATT&CK®. While not required, you can use a MITRE ATT&CK® software name. | keyword |
| threat.software.type | The type of software used by this threat to conduct behavior commonly modeled using MITRE ATT&CK®. While not required, you can use a MITRE ATT&CK® software type. | keyword |

