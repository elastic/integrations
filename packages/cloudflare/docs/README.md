# Cloudflare Integration

The Cloudflare integration collects events from the Cloudflare API, specifically reading from the Cloudflare Logpull API.

## Logs

### Logpull

The Cloudflare Logpull records network events related to your organization in order to provide an audit trail that can be used to understand platform activity and to diagnose problems. This module is implemented using the httpjson input.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.address | Some event client addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| client.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| client.as.organization.name | Organization name. | keyword |
| client.bytes | Bytes sent from the client to the server. | long |
| client.domain | Client domain. | keyword |
| client.geo.city_name | City name. | keyword |
| client.geo.continent_name | Name of the continent. | keyword |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.geo.region_iso_code | Region ISO code. | keyword |
| client.geo.region_name | Region name. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| cloudflare.cache.bytes | Number of bytes returned by the cache | long |
| cloudflare.cache.status | Status of cache | keyword |
| cloudflare.cache.status_code | HTTP status code returned by the cache to the edge. All requests (including non-cacheable ones) go through the cache. | long |
| cloudflare.cache.tiered_fill | Tiered Cache was used to serve this request | boolean |
| cloudflare.client.ip_class | Class of client, ex. badHost | searchEngine | allowlist | greylist.... | keyword |
| cloudflare.client.ssl.protocol | Client SSL (TLS) protocol | keyword |
| cloudflare.device_type | Client device type | keyword |
| cloudflare.edge.colo.code | IATA airport code of data center that received the request | keyword |
| cloudflare.edge.colo.id | Cloudflare edge colo id | long |
| cloudflare.edge.pathing.op | Indicates what type of response was issued for this request (unknown = no specific action) | keyword |
| cloudflare.edge.pathing.src | Details how the request was classified based on security checks (unknown = no specific classification) | keyword |
| cloudflare.edge.pathing.status | Indicates what data was used to determine the handling of this request (unknown = no data) | keyword |
| cloudflare.edge.rate_limit.action | The action taken by the blocking rule; empty if no action taken | keyword |
| cloudflare.edge.rate_limit.id | The internal rule ID of the rate-limiting rule that triggered a block (ban) or log action. 0 if no action taken. | long |
| cloudflare.edge.request.host | Host header on the request from the edge to the origin | keyword |
| cloudflare.edge.response.bytes | Number of bytes returned by the edge to the client | long |
| cloudflare.edge.response.compression_ratio | Edge response compression ratio | long |
| cloudflare.edge.response.content_type | Edge response Content-Type header value | keyword |
| cloudflare.edge.response.status_code | HTTP status code returned by Cloudflare to the client | long |
| cloudflare.firewall.actions | Array of actions the Cloudflare firewall products performed on this request. The individual firewall products associated with this action be found in FirewallMatchesSources and their respective RuleIds can be found in FirewallMatchesRuleIDs. The length of the array is the same as FirewallMatchesRuleIDs and FirewallMatchesSources. | array |
| cloudflare.firewall.rule_ids | Array of RuleIDs of the firewall product that has matched the request. The firewall product associated with the RuleID can be found in FirewallMatchesSources. The length of the array is the same as FirewallMatchesActions and FirewallMatchesSources. | array |
| cloudflare.firewall.sources | The firewall products that matched the request. The same product can appear multiple times, which indicates different rules or actions that were activated. The RuleIDs can be found in FirewallMatchesRuleIDs, the actions can be found in FirewallMatchesActions. The length of the array is the same as FirewallMatchesRuleIDs and FirewallMatchesActions. | array |
| cloudflare.origin.response.bytes | Number of bytes returned by the origin server | long |
| cloudflare.origin.response.expires | Value of the origin 'expires' header | date |
| cloudflare.origin.response.last_modified | Value of the origin 'last-modified' header | date |
| cloudflare.origin.response.status_code | Status returned by the origin server | long |
| cloudflare.origin.response.time | Number of nanoseconds it took the origin to return the response to edge | long |
| cloudflare.origin.ssl.protocol | SSL (TLS) protocol used to connect to the origin | keyword |
| cloudflare.parent.ray_id | Ray ID of the parent request if this request was made using a Worker script | keyword |
| cloudflare.ray_id | Ray ID of the parent request if this request was made using a Worker script | keyword |
| cloudflare.security_level | The security level configured at the time of this request. This is used to determine the sensitivity of the IP Reputation system. | keyword |
| cloudflare.waf.action | Action taken by the WAF, if triggered | keyword |
| cloudflare.waf.flags | Additional configuration flags: simulate (0x1) | null | keyword |
| cloudflare.waf.matched_var | The full name of the most-recently matched variable | keyword |
| cloudflare.waf.profile | low | med | high | keyword |
| cloudflare.waf.rule.id | ID of the applied WAF rule | keyword |
| cloudflare.waf.rule.message | Rule message associated with the triggered rule | keyword |
| cloudflare.worker.cpu_time | Amount of time in microseconds spent executing a worker, if any | long |
| cloudflare.worker.status | Status returned from worker daemon | keyword |
| cloudflare.worker.subrequest | Whether or not this request was a worker subrequest | boolean |
| cloudflare.worker.subrequest_count | Number of subrequests issued by a worker when handling this request | long |
| cloudflare.zone.id | Internal zone ID | long |
| cloudflare.zone.name | The human-readable name of the zone (e.g. 'cloudflare.com'). | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.body.bytes | Size in bytes of the request body. | long |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.protocol | L7 Network protocol name. ex. http, lumberjack, transport protocol. The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| observer.geo.city_name | City name. | keyword |
| observer.geo.continent_name | Name of the continent. | keyword |
| observer.geo.country_iso_code | Country ISO code. | keyword |
| observer.geo.country_name | Country name. | keyword |
| observer.geo.location | Longitude and latitude. | geo_point |
| observer.geo.region_iso_code | Region ISO code. | keyword |
| observer.geo.region_name | Region name. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | Source domain. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| source.user.full_name | User's full name, if available. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | keyword |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | keyword |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.username | Username of the request. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


An example event for `logpull` looks as following:

```json
{
    "@timestamp": "2019-08-02T15:29:08.000Z",
    "agent": {
        "ephemeral_id": "3c4ff675-b9b0-4088-91be-ceb05758b84d",
        "hostname": "docker-fleet-agent",
        "id": "215f4abb-ee20-49c3-9075-e8d3838466ba",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.15.0"
    },
    "client": {
        "address": "35.232.161.245",
        "as": {
            "number": 15169,
            "organization": {
                "name": "Google LLC"
            }
        },
        "bytes": 2577,
        "geo": {
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 38.6583,
                "lon": -77.2481
            },
            "region_iso_code": "US-VA",
            "region_name": "Virginia"
        },
        "ip": "35.232.161.245",
        "port": 55028
    },
    "cloudflare": {
        "cache": {
            "status": "unknown",
            "tiered_fill": false
        },
        "client": {
            "ip_class": "noRecord",
            "ssl": {
                "protocol": "TLSv1.2"
            }
        },
        "device_type": "desktop",
        "edge": {
            "colo": {
                "id": 14
            },
            "pathing": {
                "op": "chl",
                "src": "filterBasedFirewall",
                "status": "captchaNew"
            },
            "rate_limit": {
                "id": 0
            },
            "response": {
                "bytes": 2848,
                "compression_ratio": 2.64,
                "content_type": "text/html",
                "status_code": 403
            }
        },
        "firewall": {
            "actions": [
                "simulate",
                "challenge"
            ],
            "rule_ids": [
                "094b71fea25d4860a61fa0c6fbbd8d8b",
                "e454fd4a0ce546b3a9a462536613692c"
            ],
            "sources": [
                "firewallRules",
                "firewallRules"
            ]
        },
        "origin": {
            "response": {
                "bytes": 0,
                "status_code": 0,
                "time": 0
            },
            "ssl": {
                "protocol": "unknown"
            }
        },
        "parent": {
            "ray_id": "00"
        },
        "ray_id": "500115ec386354d8",
        "security_level": "med",
        "waf": {
            "action": "unknown",
            "flags": "0",
            "profile": "unknown"
        },
        "worker": {
            "cpu_time": 0,
            "status": "unknown",
            "subrequest": false,
            "subrequest_count": 0
        },
        "zone": {
            "id": 155978002
        }
    },
    "data_stream": {
        "dataset": "cloudflare.logpull",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 2848
    },
    "ecs": {
        "version": "1.10.0"
    },
    "elastic_agent": {
        "id": "215f4abb-ee20-49c3-9075-e8d3838466ba",
        "snapshot": true,
        "version": "7.15.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "network",
        "created": "2021-08-09T12:14:00.331Z",
        "dataset": "cloudflare.logpull",
        "duration": 0,
        "end": "2019-08-02T15:29:08.000Z",
        "ingested": "2021-08-09T12:14:04Z",
        "kind": "event",
        "original": "{\"CacheCacheStatus\":\"unknown\",\"CacheResponseBytes\":0,\"CacheResponseStatus\":0,\"CacheTieredFill\":false,\"ClientASN\":15169,\"ClientCountry\":\"us\",\"ClientDeviceType\":\"desktop\",\"ClientIP\":\"35.232.161.245\",\"ClientIPClass\":\"noRecord\",\"ClientRequestBytes\":2577,\"ClientRequestHost\":\"cf-analytics.com\",\"ClientRequestMethod\":\"POST\",\"ClientRequestPath\":\"/wp-cron.php\",\"ClientRequestProtocol\":\"HTTP/1.1\",\"ClientRequestReferer\":\"https://cf-analytics.com/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000\",\"ClientRequestURI\":\"/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000\",\"ClientRequestUserAgent\":\"WordPress/5.2.2;https://cf-analytics.com\",\"ClientSSLCipher\":\"ECDHE-ECDSA-AES128-GCM-SHA256\",\"ClientSSLProtocol\":\"TLSv1.2\",\"ClientSrcPort\":55028,\"EdgeColoID\":14,\"EdgeEndTimestamp\":\"2019-08-02T15:29:08Z\",\"EdgePathingOp\":\"chl\",\"EdgePathingSrc\":\"filterBasedFirewall\",\"EdgePathingStatus\":\"captchaNew\",\"EdgeRateLimitAction\":\"\",\"EdgeRateLimitID\":0,\"EdgeRequestHost\":\"\",\"EdgeResponseBytes\":2848,\"EdgeResponseCompressionRatio\":2.64,\"EdgeResponseContentType\":\"text/html\",\"EdgeResponseStatus\":403,\"EdgeServerIP\":\"\",\"EdgeStartTimestamp\":\"2019-08-02T15:29:08Z\",\"FirewallMatchesActions\":[\"simulate\",\"challenge\"],\"FirewallMatchesRuleIDs\":[\"094b71fea25d4860a61fa0c6fbbd8d8b\",\"e454fd4a0ce546b3a9a462536613692c\"],\"FirewallMatchesSources\":[\"firewallRules\",\"firewallRules\"],\"OriginIP\":\"\",\"OriginResponseBytes\":0,\"OriginResponseHTTPExpires\":\"\",\"OriginResponseHTTPLastModified\":\"\",\"OriginResponseStatus\":0,\"OriginResponseTime\":0,\"OriginSSLProtocol\":\"unknown\",\"ParentRayID\":\"00\",\"RayID\":\"500115ec386354d8\",\"SecurityLevel\":\"med\",\"WAFAction\":\"unknown\",\"WAFFlags\":\"0\",\"WAFMatchedVar\":\"\",\"WAFProfile\":\"unknown\",\"WAFRuleID\":\"\",\"WAFRuleMessage\":\"\",\"WorkerCPUTime\":0,\"WorkerStatus\":\"unknown\",\"WorkerSubrequest\":false,\"WorkerSubrequestCount\":0,\"ZoneID\":155978002}",
        "start": "2019-08-02T15:29:08.000Z"
    },
    "http": {
        "request": {
            "bytes": 2577,
            "method": "POST",
            "referrer": "https://cf-analytics.com/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000"
        },
        "response": {
            "bytes": 2848,
            "status_code": 403
        },
        "version": "1.1"
    },
    "input": {
        "type": "httpjson"
    },
    "network": {
        "bytes": 5425,
        "protocol": "http",
        "transport": "tcp"
    },
    "observer": {
        "type": "proxy",
        "vendor": "cloudflare"
    },
    "server": {
        "bytes": 2848
    },
    "source": {
        "address": "35.232.161.245",
        "as": {
            "number": 15169,
            "organization": {
                "name": "Google LLC"
            }
        },
        "bytes": 2577,
        "geo": {
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 38.6583,
                "lon": -77.2481
            },
            "region_iso_code": "US-VA",
            "region_name": "Virginia"
        },
        "ip": "35.232.161.245",
        "port": 55028
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "tls": {
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256",
        "version": "1.2",
        "version_protocol": "tls"
    },
    "url": {
        "domain": "cf-analytics.com",
        "extension": "php",
        "full": "https://cf-analytics.com/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000",
        "original": "/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000",
        "path": "/wp-cron.php",
        "query": "doing_wp_cron=1564759748.3962020874023437500000",
        "scheme": "https"
    },
    "user_agent": {
        "device": {
            "name": "Spider"
        },
        "name": "WordPress",
        "original": "WordPress/5.2.2;https://cf-analytics.com",
        "version": "5.2.2"
    }
}
```