# Sophos Integration

The Sophos integration collects and parses logs from Sophos Products.

Currently, it accepts logs in syslog format or from a file for the following devices:

- `utm` dataset: supports [Unified Threat Management](https://www.sophos.com/en-us/support/documentation/sophos-utm) (formerly known as Astaro Security Gateway) logs.
- `xg` dataset: supports [Sophos XG SFOS logs](https://docs.sophos.com/nsg/sophos-firewall/17.5/Help/en-us/webhelp/onlinehelp/nsg/sfos/concepts/Logs.html).

To configure a remote syslog destination, please reference the [SophosXG/SFOS Documentation](https://community.sophos.com/kb/en-us/123184).

The syslog format chosen should be `Default`.

## Compatibility

This module has been tested against SFOS version 17.5.x and 18.0.x.
Versions above this are expected to work but have not been tested.

## Logs

### UTM log

The `utm` dataset collects Unified Threat Management logs. Currently, it collects the following log categories: DNS, DHCP, HTTP and Packet Filter.

An example event for `utm` looks as following:

```json
{
    "@timestamp": "2023-03-08T15:00:00.000Z",
    "agent": {
        "ephemeral_id": "cc0463c4-c141-46e2-81a4-c9ffe70bf450",
        "id": "533bdb32-d7d6-482e-a4ee-22a7c8ba474c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.1"
    },
    "data_stream": {
        "dataset": "sophos.utm",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.129"
    },
    "device": {
        "id": "0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "533bdb32-d7d6-482e-a4ee-22a7c8ba474c",
        "snapshot": false,
        "version": "8.8.1"
    },
    "event": {
        "action": "pass",
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "sophos.utm",
        "id": "0001",
        "ingested": "2023-07-20T08:37:19Z",
        "kind": "event",
        "provider": "http",
        "severity": 6,
        "timezone": "+00:00",
        "type": [
            "info"
        ]
    },
    "group": {
        "name": "testgroup"
    },
    "host": {
        "hostname": "sophos-test-vm1"
    },
    "http": {
        "request": {
            "bytes": 311,
            "id": "0x7fad9e44ac00",
            "method": "HEAD",
            "referrer": "https://referer.test.com/"
        },
        "response": {
            "status_code": 200
        }
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "172.31.0.4:45730"
        }
    },
    "network": {
        "application": "googplay",
        "protocol": "http"
    },
    "observer": {
        "product": "UTM",
        "type": "firewall",
        "vendor": "Sophos"
    },
    "process": {
        "name": "httpproxy",
        "pid": 6267
    },
    "related": {
        "hosts": [
            "sophos-test-vm1"
        ],
        "ip": [
            "67.43.156.2",
            "89.160.20.129"
        ],
        "user": [
            "testuser"
        ]
    },
    "sophos": {
        "utm": {
            "ad_domain": "example.com",
            "app_id": "816",
            "aptptime": 0,
            "auth": "0",
            "authtime": 0,
            "avscantime": 0,
            "cached": "0",
            "category": [
                "178"
            ],
            "categoryname": [
                "Internet Services"
            ],
            "cattime": 200,
            "content_type": "application/octet-stream",
            "country": "United States",
            "dnstime": 5,
            "filteraction": "REF_HTTP_ACTION",
            "fullreqtime": 32181,
            "name": "http access",
            "profile": "HTTP_Sophos_Profile_1",
            "reputation": "trusted",
            "severity": "info",
            "sub": "http",
            "sys": "SecureWeb"
        }
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.2"
    },
    "tags": [
        "sophos-utm",
        "forwarded"
    ],
    "url": {
        "domain": "myurl.test.com",
        "original": "https://myurl.test.com/extension",
        "path": "/extension",
        "scheme": "https"
    },
    "user": {
        "name": "testuser"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Other",
        "original": "Microsoft BITS/7.8"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| client.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| client.as.organization.name | Organization name. | keyword |
| client.as.organization.name.text | Multi-field of `client.as.organization.name`. | match_only_text |
| client.geo.city_name | City name. | keyword |
| client.geo.continent_name | Name of the continent. | keyword |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| client.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| client.geo.region_iso_code | Region ISO code. | keyword |
| client.geo.region_name | Region name. | keyword |
| client.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.mac | MAC address of the client. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| client.port | Port of the client. | long |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| destination.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.mac | MAC address of the destination. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| destination.port | Port of the destination. | long |
| device.id | The unique identifier of a device. The identifier must not change across application sessions but stay fixed for an instance of a (mobile) device.  On iOS, this value must be equal to the vendor identifier (https://developer.apple.com/documentation/uikit/uidevice/1620059-identifierforvendor). On Android, this value must be equal to the Firebase Installation ID or a globally unique UUID which is persisted across sessions in your application. For GDPR and data protection law reasons this identifier should not carry information that would allow to identify a user. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |
| http.request.id | A unique identifier for each HTTP request to correlate logs between clients and servers in transactions. The id may be contained in a non-standard HTTP header, such as `X-Request-ID` or `X-Correlation-ID`. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.status_code | HTTP response status code. | long |
| input.type | Input type. | keyword |
| log.file.path | Full path to the log file this event came from. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.facility.name | The Syslog text-based facility of the log event, if available. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| log.syslog.severity.name | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different severity value (e.g. firewall, IDS), your source's text severity should go to `log.level`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `log.level`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.application | When a specific application or service is identified from network connection details (source/dest IPs, ports, certificates, or wire format), this field captures the application's or service's name. For example, the original event identifies the network connection being from a specific web service in a `https` network connection, like `facebook` or `twitter`. The field value must be normalized to lowercase for querying. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| server.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| server.as.organization.name | Organization name. | keyword |
| server.as.organization.name.text | Multi-field of `server.as.organization.name`. | match_only_text |
| server.geo.city_name | City name. | keyword |
| server.geo.continent_name | Name of the continent. | keyword |
| server.geo.country_iso_code | Country ISO code. | keyword |
| server.geo.country_name | Country name. | keyword |
| server.geo.location | Longitude and latitude. | geo_point |
| server.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| server.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| server.geo.region_iso_code | Region ISO code. | keyword |
| server.geo.region_name | Region name. | keyword |
| server.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| sophos.utm.action | Event action. | keyword |
| sophos.utm.ad_domain |  | keyword |
| sophos.utm.app_id | Application ID. | keyword |
| sophos.utm.aptptime |  | long |
| sophos.utm.auth | Auth ID. | keyword |
| sophos.utm.authtime | Authorization time. | long |
| sophos.utm.avscantime | AntiVirus scan time. | long |
| sophos.utm.cached | Cached bytes. | keyword |
| sophos.utm.category | Array of category IDs. | keyword |
| sophos.utm.categoryname | Array of category names. | keyword |
| sophos.utm.cattime |  | long |
| sophos.utm.client.hostname | Client hostname in DHCP events. | keyword |
| sophos.utm.code | Code ID. | keyword |
| sophos.utm.content_type | HTTP header content-type. | keyword |
| sophos.utm.country | HTTP request country source. | keyword |
| sophos.utm.dnstime | DNS time. | long |
| sophos.utm.exceptions |  | keyword |
| sophos.utm.extension | URL extension. | keyword |
| sophos.utm.filteraction | Filter action. | keyword |
| sophos.utm.fullreqtime | Full HTTP request time. | long |
| sophos.utm.function | The failed function in case of error. | keyword |
| sophos.utm.id | Packet Filter rule ID. | keyword |
| sophos.utm.length | Packet length in bytes. | long |
| sophos.utm.line | The failed line in case of error. | keyword |
| sophos.utm.mark | The Netfilter conntrack mark. | keyword |
| sophos.utm.name | Event description. | keyword |
| sophos.utm.overridecategory |  | keyword |
| sophos.utm.overridereputation |  | keyword |
| sophos.utm.prec |  | keyword |
| sophos.utm.profile | HTTP profile. | keyword |
| sophos.utm.reason |  | keyword |
| sophos.utm.reputation |  | keyword |
| sophos.utm.router.ip | DHCP router IP. | ip |
| sophos.utm.sandbox |  | keyword |
| sophos.utm.severity | Event severity. | keyword |
| sophos.utm.socket | Socket where DHCP server is listening. | keyword |
| sophos.utm.sub |  | keyword |
| sophos.utm.subnet | Subnet where DHCP server is listening. | keyword |
| sophos.utm.sys | System name. | keyword |
| sophos.utm.tcpflags | TCP flags set in any packet of session. | keyword |
| sophos.utm.tos | Type of Service. | keyword |
| sophos.utm.ttl | Time to Live. | long |
| sophos.utm.type | Type ID. | keyword |
| sophos.utm.url | HTTP request URL. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| url.username | Username of the request. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### XG log

This is the Sophos `xg` dataset. Reference information about the log formats
can be found in the [Sophos syslog guide](
https://docs.sophos.com/nsg/sophos-firewall/18.5/PDF/SF%20syslog%20guide%2018.5.pdf).

An example event for `xg` looks as following:

```json
{
    "@timestamp": "2016-12-02T18:50:20.000Z",
    "agent": {
        "ephemeral_id": "12701a32-24a5-401a-a7f4-b8202e00f440",
        "id": "533bdb32-d7d6-482e-a4ee-22a7c8ba474c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.1"
    },
    "data_stream": {
        "dataset": "sophos.xg",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "533bdb32-d7d6-482e-a4ee-22a7c8ba474c",
        "snapshot": false,
        "version": "8.8.1"
    },
    "event": {
        "action": "alert",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "code": "16010",
        "dataset": "sophos.xg",
        "ingested": "2023-07-20T08:39:24Z",
        "kind": "event",
        "outcome": "success",
        "severity": 1,
        "timezone": "GMT"
    },
    "host": {
        "name": "XG230"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "level": "alert",
        "source": {
            "address": "172.31.0.4:59318"
        }
    },
    "observer": {
        "product": "XG",
        "serial_number": "1234567890123456",
        "type": "firewall",
        "vendor": "Sophos"
    },
    "related": {
        "hosts": [
            "XG230"
        ],
        "ip": [
            "10.108.108.49"
        ]
    },
    "sophos": {
        "xg": {
            "action": "Deny",
            "context_match": "Not",
            "context_prefix": "blah blah hello ",
            "context_suffix": " hello blah ",
            "device": "SFW",
            "device_name": "SF01V",
            "dictionary_name": "complicated_Custom",
            "direction": "in",
            "file_name": "cgi_echo.pl",
            "log_component": "Web Content Policy",
            "log_id": "058420116010",
            "log_subtype": "Alert",
            "log_type": "Content Filtering",
            "site_category": "Information Technology",
            "timezone": "GMT",
            "transaction_id": "e4a127f7-a850-477c-920e-a471b38727c1",
            "user": "gi123456",
            "website": "ta-web-static-testing.qa. astaro.de"
        }
    },
    "source": {
        "ip": "10.108.108.49"
    },
    "tags": [
        "sophos-xg",
        "forwarded"
    ]
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.mac | MAC address of the destination. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| destination.user.email | User email address. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.hash | Hash (perhaps logstash fingerprint) of raw field to be able to demonstrate log integrity. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.hash.sha512 | SHA512 hash. | keyword |
| file.mime_type | MIME type should identify the format of the file or stream of bytes using https://www.iana.org/assignments/media-types/media-types.xhtml[IANA official types], where possible. When more than one type is applicable, the most specific type should be used. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| log.source.address |  | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.egress.zone | Network zone of outbound traffic as reported by the observer to categorize the destination area of egress traffic, e.g. Internal, External, DMZ, HR, Legal, etc. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.zone | Network zone of incoming traffic as reported by the observer to categorize the source area of ingress traffic. e.g. internal, External, DMZ, HR, Legal, etc. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.serial_number | Observer serial number. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.ruleset | Name of the ruleset, policy, group, or parent category in which the rule used to generate this event is a member. | keyword |
| sophos.xg.action | Event Action | keyword |
| sophos.xg.activityname | Web policy activity that matched and caused the policy result. | keyword |
| sophos.xg.ap | Access Point Serial ID or LocalWifi0 or LocalWifi1. | keyword |
| sophos.xg.app_category | Name of the category under which application falls | keyword |
| sophos.xg.app_filter_policy_id | Application filter policy ID applied on the traffic | keyword |
| sophos.xg.app_is_cloud | Application is Cloud | keyword |
| sophos.xg.app_name | Application name | keyword |
| sophos.xg.app_resolved_by | Application is resolved by signature or synchronized application | keyword |
| sophos.xg.app_risk | Risk level assigned to the application | keyword |
| sophos.xg.app_technology | Technology of the application | keyword |
| sophos.xg.appfilter_policy_id | Application Filter policy applied on the traffic | integer |
| sophos.xg.application | Application name | keyword |
| sophos.xg.application_category | Application is resolved by signature or synchronized application | keyword |
| sophos.xg.application_filter_policy | Application Filter policy applied on the traffic | integer |
| sophos.xg.application_name | Application name | keyword |
| sophos.xg.application_risk | Risk level assigned to the application | keyword |
| sophos.xg.application_technology | Technology of the application | keyword |
| sophos.xg.appresolvedby | Technology of the application | keyword |
| sophos.xg.auth_client | Auth Client | keyword |
| sophos.xg.auth_mechanism | Auth mechanism | keyword |
| sophos.xg.av_policy_name | Malware scanning policy name which is applied on the traffic | keyword |
| sophos.xg.backup_mode | Backup mode | keyword |
| sophos.xg.branch_name | Branch Name | keyword |
| sophos.xg.category | IPS signature category. | keyword |
| sophos.xg.category_type | Type of category under which website falls | keyword |
| sophos.xg.classification | Signature classification | keyword |
| sophos.xg.client_host_name | Client host name | keyword |
| sophos.xg.client_physical_address | Client physical address | keyword |
| sophos.xg.clients_conn_ssid | Number of client connected to the SSID. | long |
| sophos.xg.collisions | collisions | long |
| sophos.xg.con_event | Event Start/Stop | keyword |
| sophos.xg.con_id | Unique identifier of connection | integer |
| sophos.xg.configuration | Configuration | float |
| sophos.xg.conn_id | Unique identifier of connection | integer |
| sophos.xg.connectionname | Connectionname | keyword |
| sophos.xg.connectiontype | Connectiontype | keyword |
| sophos.xg.connevent | Event on which this log is generated | keyword |
| sophos.xg.connid | Connection ID | keyword |
| sophos.xg.content_type | Type of the content | keyword |
| sophos.xg.contenttype | Type of the content | keyword |
| sophos.xg.context_match | Context Match | keyword |
| sophos.xg.context_prefix | Content Prefix | keyword |
| sophos.xg.context_suffix | Context Suffix | keyword |
| sophos.xg.cookie | cookie | keyword |
| sophos.xg.date | Date (yyyy-mm-dd) when the event occurred | date |
| sophos.xg.destinationip | Original destination IP address of traffic | ip |
| sophos.xg.device | device | keyword |
| sophos.xg.device_id | Serial number of the device | keyword |
| sophos.xg.device_model | Model number of the device | keyword |
| sophos.xg.device_name | Model number of the device | keyword |
| sophos.xg.dictionary_name | Dictionary Name | keyword |
| sophos.xg.dir_disp | TPacket direction. Possible values:“org”, “reply”, “” | keyword |
| sophos.xg.direction | Direction | keyword |
| sophos.xg.domainname | Domain from which virus was downloaded | keyword |
| sophos.xg.download_file_name | Download file name | keyword |
| sophos.xg.download_file_type | Download file type | keyword |
| sophos.xg.dst_country_code | Code of the country to which the destination IP belongs | keyword |
| sophos.xg.dst_domainname | Receiver domain name | keyword |
| sophos.xg.dst_ip | Original destination IP address of traffic | ip |
| sophos.xg.dst_port | Original destination port of TCP and UDP traffic | integer |
| sophos.xg.dst_zone_type | Type of destination zone | keyword |
| sophos.xg.dstdomain | Destination Domain | keyword |
| sophos.xg.duration | Durability of traffic (seconds) | long |
| sophos.xg.email_subject | Email Subject | keyword |
| sophos.xg.ep_uuid | Endpoint UUID | keyword |
| sophos.xg.ether_type | ethernet frame type | keyword |
| sophos.xg.eventid | ATP Evenet ID | keyword |
| sophos.xg.eventtime | Event time | date |
| sophos.xg.eventtype | ATP event type | keyword |
| sophos.xg.exceptions | List of the checks excluded by web exceptions. | keyword |
| sophos.xg.execution_path | ATP execution path | keyword |
| sophos.xg.extra | extra | keyword |
| sophos.xg.file_name | Filename | keyword |
| sophos.xg.file_path | File path | keyword |
| sophos.xg.file_size | File Size | integer |
| sophos.xg.filename | File name associated with the event | keyword |
| sophos.xg.filepath | Path of the file containing virus | keyword |
| sophos.xg.filesize | Size of the file that contained virus | integer |
| sophos.xg.free | free | integer |
| sophos.xg.from_email_address | Sender email address | keyword |
| sophos.xg.ftp_direction | Direction of FTP transfer: Upload or Download | keyword |
| sophos.xg.ftp_url | FTP URL from which virus was downloaded | keyword |
| sophos.xg.ftpcommand | FTP command used when virus was found | keyword |
| sophos.xg.fw_rule_id | Firewall Rule ID which is applied on the traffic | integer |
| sophos.xg.fw_rule_type | Firewall rule type which is applied on the traffic | keyword |
| sophos.xg.hb_health | Heartbeat status | keyword |
| sophos.xg.hb_status | Heartbeat status | keyword |
| sophos.xg.host | Host | keyword |
| sophos.xg.http_category | HTTP Category | keyword |
| sophos.xg.http_category_type | HTTP Category Type | keyword |
| sophos.xg.httpresponsecode | code of HTTP response | long |
| sophos.xg.iap | Internet Access policy ID applied on the traffic | keyword |
| sophos.xg.icmp_code | ICMP code of ICMP traffic | keyword |
| sophos.xg.icmp_type | ICMP type of ICMP traffic | keyword |
| sophos.xg.idle_cpu | idle ## | float |
| sophos.xg.idp_policy_id | IPS policy ID which is applied on the traffic | integer |
| sophos.xg.idp_policy_name | IPS policy name i.e. IPS policy name which is applied on the traffic | keyword |
| sophos.xg.in_interface | Interface for incoming traffic, e.g., Port A | keyword |
| sophos.xg.interface | interface | keyword |
| sophos.xg.ipaddress | Ipaddress | keyword |
| sophos.xg.ips_policy_id | IPS policy ID applied on the traffic | integer |
| sophos.xg.lease_time | Lease Time | keyword |
| sophos.xg.localgateway | Localgateway | keyword |
| sophos.xg.localnetwork | Localnetwork | keyword |
| sophos.xg.log_component | Component responsible for logging e.g. Firewall rule | keyword |
| sophos.xg.log_id | Unique 12 characters code (0101011) | keyword |
| sophos.xg.log_subtype | Sub type of event | keyword |
| sophos.xg.log_type | Type of event e.g. firewall event | keyword |
| sophos.xg.log_version | Log Version | keyword |
| sophos.xg.login_user | ATP login user | keyword |
| sophos.xg.mailid | mailid | keyword |
| sophos.xg.mailsize | mailsize | integer |
| sophos.xg.message | Message | keyword |
| sophos.xg.mode | Mode | keyword |
| sophos.xg.nat_rule_id | NAT Rule ID | keyword |
| sophos.xg.newversion | Newversion | keyword |
| sophos.xg.oldversion | Oldversion | keyword |
| sophos.xg.out_interface | Interface for outgoing traffic, e.g., Port B | keyword |
| sophos.xg.override_authorizer | Override authorizer | keyword |
| sophos.xg.override_name | Override name | keyword |
| sophos.xg.override_token | Override token | keyword |
| sophos.xg.phpsessid | PHP session ID | keyword |
| sophos.xg.platform | Platform of the traffic. | keyword |
| sophos.xg.policy_type | Policy type applied to the traffic | keyword |
| sophos.xg.priority | Severity level of traffic | keyword |
| sophos.xg.protocol | Protocol number of traffic | keyword |
| sophos.xg.qualifier | Qualifier | keyword |
| sophos.xg.quarantine | Path and filename of the file quarantined | keyword |
| sophos.xg.quarantine_reason | Quarantine reason | keyword |
| sophos.xg.querystring | querystring | keyword |
| sophos.xg.raw_data | Raw data | keyword |
| sophos.xg.received_pkts | Total number of packets received | long |
| sophos.xg.receiveddrops | received drops | long |
| sophos.xg.receivederrors | received errors | keyword |
| sophos.xg.receivedkbits | received kbits | long |
| sophos.xg.recv_bytes | Total number of bytes received | long |
| sophos.xg.red_id | RED ID | keyword |
| sophos.xg.referer | Referer | keyword |
| sophos.xg.remote_ip | Remote IP | ip |
| sophos.xg.remotenetwork | remotenetwork | keyword |
| sophos.xg.reported_host | Reported Host | keyword |
| sophos.xg.reported_ip | Reported IP | keyword |
| sophos.xg.reports | Reports | float |
| sophos.xg.rule_priority | Priority of IPS policy | keyword |
| sophos.xg.sent_bytes | Total number of bytes sent | long |
| sophos.xg.sent_pkts | Total number of packets sent | long |
| sophos.xg.server | Server | keyword |
| sophos.xg.sessionid | Sessionid | keyword |
| sophos.xg.sha1sum | SHA1 checksum of the item being analyzed | keyword |
| sophos.xg.signature | Signature | float |
| sophos.xg.signature_id | Signature ID | keyword |
| sophos.xg.signature_msg | Signature messsage | keyword |
| sophos.xg.site_category | Site Category | keyword |
| sophos.xg.source | Source | keyword |
| sophos.xg.sourceip | Original source IP address of traffic | ip |
| sophos.xg.spamaction | Spam Action | keyword |
| sophos.xg.sqli | related SQLI caught by the WAF | keyword |
| sophos.xg.src_country_code | Code of the country to which the source IP belongs | keyword |
| sophos.xg.src_domainname | Sender domain name | keyword |
| sophos.xg.src_ip | Original source IP address of traffic | ip |
| sophos.xg.src_mac | Original source MAC address of traffic | keyword |
| sophos.xg.src_port | Original source port of TCP and UDP traffic | integer |
| sophos.xg.src_zone_type | Type of source zone | keyword |
| sophos.xg.ssid | Configured SSID name. | keyword |
| sophos.xg.start_time | Start time | date |
| sophos.xg.starttime | Starttime | date |
| sophos.xg.status | Ultimate status of traffic – Allowed or Denied | keyword |
| sophos.xg.status_code | Status code | keyword |
| sophos.xg.subject | Email subject | keyword |
| sophos.xg.syslog_server_name | Syslog server name. | keyword |
| sophos.xg.system_cpu | system | float |
| sophos.xg.target | Platform of the traffic. | keyword |
| sophos.xg.temp | Temp | float |
| sophos.xg.threatname | ATP threatname | keyword |
| sophos.xg.timestamp | timestamp | date |
| sophos.xg.timezone | Original reported timezone for the event timestamp. | keyword |
| sophos.xg.to_email_address | Receipeint email address | keyword |
| sophos.xg.total_memory | Total Memory | integer |
| sophos.xg.trans_dst_ip | Translated destination IP address for outgoing traffic | ip |
| sophos.xg.trans_dst_port | Translated destination port for outgoing traffic | integer |
| sophos.xg.trans_src_ip | Translated source IP address for outgoing traffic | ip |
| sophos.xg.trans_src_port | Translated source port for outgoing traffic | integer |
| sophos.xg.transaction_id | Transaction ID | keyword |
| sophos.xg.transactionid | Transaction ID of the AV scan. | keyword |
| sophos.xg.transmitteddrops | transmitted drops | long |
| sophos.xg.transmittederrors | transmitted errors | keyword |
| sophos.xg.transmittedkbits | transmitted kbits | long |
| sophos.xg.unit | unit | keyword |
| sophos.xg.updatedip | updatedip | ip |
| sophos.xg.upload_file_name | Upload file name | keyword |
| sophos.xg.upload_file_type | Upload file type | keyword |
| sophos.xg.url | URL from which virus was downloaded | keyword |
| sophos.xg.used | used | integer |
| sophos.xg.used_quota | Used Quota | keyword |
| sophos.xg.user | User | keyword |
| sophos.xg.user_cpu | system | float |
| sophos.xg.user_gp | Group name to which the user belongs. | keyword |
| sophos.xg.user_group | Group name to which the user belongs | keyword |
| sophos.xg.user_name | user_name | keyword |
| sophos.xg.users | Number of users from System Health / Live User events. | long |
| sophos.xg.vconn_id | Connection ID of the master connection | integer |
| sophos.xg.virus | virus name | keyword |
| sophos.xg.web_policy_id | Web policy ID | keyword |
| sophos.xg.website | Website | keyword |
| sophos.xg.xss | related XSS caught by the WAF | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| source.user.email | User email address. | keyword |
| source.user.group.name | Name of the group. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| url.username | Username of the request. | keyword |
| user.email | User email address. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.kernel | Operating system kernel version as a raw string. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

