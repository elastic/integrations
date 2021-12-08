# Akamai Integration

The Akamai integration collects events from the Akamai API, specifically reading from the [Akamai SIEM API](https://techdocs.akamai.com/siem-integration/reference/api).

## Logs

### SIEM

The Security Information and Event Management API allows you to capture security events generated on the ​Akamai​ platform in your SIEM application.

Use this API to get security event data generated on the ​Akamai​ platform and correlate it with data from other sources in your SIEM solution. Capture security event data incrementally, or replay missed security events from the past 12 hours. You can store, query, and analyze the data delivered through this API on your end, then go back and adjust your Akamai security settings. If you’re coding your own SIEM connector, it needs to adhere to these specifications in order to pull in security events from Akamai Security Events Collector (ASEC) and process them properly.

See https://techdocs.akamai.com/siem-integration/reference/api-get-started to setup your Akamai account and obtain your credentials

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| akamai.siem.bot.response_segment | Numeric response segment indicator. Segments are used to group and categorize bot scores. | long |
| akamai.siem.bot.score | Score assigned to the request by Botman Manager. | long |
| akamai.siem.client_data.app_bundle_id | Unique identifier of the app bundle. An app bundle contains both the software itself and the accompanying configuration information. | keyword |
| akamai.siem.client_data.app_version | Version number of the app. | keyword |
| akamai.siem.client_data.sdk_version | SDK version | keyword |
| akamai.siem.client_data.telemetry_type | Specifies the telemetry type in use. | long |
| akamai.siem.client_reputation | Client IP scores for Client Reputation. | keyword |
| akamai.siem.config_id | ID of the Security Configuration applied to the request. | keyword |
| akamai.siem.policy_id | ID of the Firewall policy applied to the request. | keyword |
| akamai.siem.request.headers | HTTP Request headers | flattened |
| akamai.siem.response.headers | HTTP response headers | flattened |
| akamai.siem.rules | Rules triggered by this request | nested |
| akamai.siem.slow_post_action | Action taken if a Slow POST attack is detected: W for Warn or A for deny (abort). | keyword |
| akamai.siem.slow_post_rate | Recorded rate of a detected Slow POST attack. | long |
| akamai.siem.user_risk.allow | Indicates whether the user is on the allow list. A 0 indicates that the user was not on the list; a 1 indicates that the user was on the list. | long |
| akamai.siem.user_risk.general | Indicators of general behavior observed for relevant attributes. For example, duc_1h represents the number of users recorded on a specific device in the past hour. | flattened |
| akamai.siem.user_risk.risk | Indicators that increased the calculated risk score. For example, the value udfp represents the risk of the device fingerprint based on the user's behavioral profile. | flattened |
| akamai.siem.user_risk.score | Calculated risk scores. Scores range from 0 (no risk) to 100 (the highest possible risk). | long |
| akamai.siem.user_risk.status | Status code indicating any errors that might have occurred when calculating the risk score. | long |
| akamai.siem.user_risk.trust | Indicators that were trusted. For example, the value ugp indicates that the user’s country or area is trusted. | flattened |
| akamai.siem.user_risk.uuid | Unique identifier of the user whose risk data is being provided. | keyword |
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
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
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
| http.request.id | A unique identifier for each HTTP request to correlate logs between clients and servers in transactions. The id may be contained in a non-standard HTTP header, such as `X-Request-ID` or `X-Correlation-ID`. | keyword |
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| network.protocol | L7 Network protocol name. ex. http, lumberjack, transport protocol. The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
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
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.username | Username of the request. | keyword |


An example event for `siem` looks as following:

```json
{
    "@timestamp": "2016-08-11T13:45:33.026Z",
    "agent": {
        "ephemeral_id": "4c2c62fa-7687-4176-8caf-2cfbd88d02ac",
        "hostname": "docker-fleet-agent",
        "id": "8bf63e47-c038-4463-8608-aaaa12031474",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.0"
    },
    "akamai": {
        "siem": {
            "bot": {
                "response_segment": 3,
                "score": 100
            },
            "client_data": {
                "app_bundle_id": "com.mydomain.myapp",
                "app_version": "1.23",
                "sdk_version": "4.7.1",
                "telemetry_type": 2
            },
            "config_id": "6724",
            "policy_id": "scoe_5426",
            "request": {
                "headers": {
                    "Accept": "text/html,application/xhtml xml",
                    "User-Agent": "BOT/0.1 (BOT for JCE)"
                }
            },
            "response": {
                "headers": {
                    "Content-Type": "text/html",
                    "Mime-Version": "1.0",
                    "Server": "AkamaiGHost"
                }
            },
            "rules": [
                {
                    "ruleActions": "ALERT",
                    "ruleData": "alert(",
                    "ruleMessages": "Cross-site Scripting (XSS) Attack",
                    "ruleSelectors": "ARGS:a",
                    "ruleTags": "WEB_ATTACK/XSS",
                    "rules": "950004"
                },
                {
                    "ruleActions": "DENY",
                    "ruleData": "curl",
                    "ruleMessages": "Request Indicates an automated program explored the site",
                    "ruleSelectors": "REQUEST_HEADERS:User-Agent",
                    "ruleTags": "AUTOMATION/MISC",
                    "rules": "990011"
                }
            ],
            "user_risk": {
                "allow": 0,
                "general": {
                    "duc_1d": "30",
                    "duc_1h": "10"
                },
                "risk": {
                    "udfp": "1325gdg4g4343g/M",
                    "unp": "74256/H"
                },
                "score": 75,
                "status": 0,
                "trust": {
                    "ugp": "US"
                },
                "uuid": "964d54b7-0821-413a-a4d6-8131770ec8d5"
            }
        }
    },
    "client": {
        "address": "52.91.36.10",
        "as": {
            "number": 14618,
            "organization": {
                "name": "Amazon.com, Inc."
            }
        },
        "geo": {
            "city_name": "Ashburn",
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 39.0481,
                "lon": -77.4728
            },
            "region_iso_code": "US-VA",
            "region_name": "Virginia"
        },
        "ip": "52.91.36.10"
    },
    "data_stream": {
        "dataset": "akamai.siem",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "8bf63e47-c038-4463-8608-aaaa12031474",
        "snapshot": true,
        "version": "7.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "network",
        "created": "2021-12-08T14:30:39.871Z",
        "dataset": "akamai.siem",
        "id": "2ab418ac8515f33",
        "ingested": "2021-12-08T14:30:40Z",
        "kind": "event",
        "original": "{\"attackData\":{\"clientIP\":\"52.91.36.10\",\"configId\":\"6724\",\"policyId\":\"scoe_5426\",\"ruleActions\":\"QUxFUlQ;REVOWQ==\",\"ruleData\":\"YWxlcnQo;Y3VybA==\",\"ruleMessages\":\"Q3Jvc3Mtc2l0ZSBTY3 JpcHRpbmcgKFhTUykgQXR0YWNr; UmVxdWVzdCBJbmRpY2F0ZXMgYW4 gYXV0b21hdGVkIHByb2 dyYW0gZXhwbG9yZWQgdGhlIHNpdGU=\",\"ruleSelectors\":\"QVJHUzph;UkVRVUVTVF9IRU FERVJTOlVzZXItQWdlbnQ=\",\"ruleTags\":\"V0VCX0FUVEFDSy9YU1M=;QV VUT01BVElPTi9NSVND\",\"ruleVersions\":\";\",\"rules\":\"OTUwMDA0;OTkwMDEx\"},\"botData\":{\"botScore\":\"100\",\"responseSegment\":\"3\"},\"clientData\":{\"appBundleId\":\"com.mydomain.myapp\",\"appVersion\":\"1.23\",\"sdkVersion\":\"4.7.1\",\"telemetryType\":\"2\"},\"format\":\"json\",\"geo\":{\"asn\":\"12271\",\"city\":\"NEWYORK\",\"continent\":\"NA\",\"country\":\"US\",\"regionCode\":\"NY\"},\"httpMessage\":{\"bytes\":\"34523\",\"host\":\"www.example.com\",\"method\":\"POST\",\"path\":\"/examples/1/\",\"port\":\"80\",\"protocol\":\"http/2\",\"query\":\"a%3D..%2F..%2F..%2Fetc%2Fpasswd\",\"requestHeaders\":\"User-Agent%3a%20BOT%2f0.1%20(BOT%20for%20JCE)%0d%0aAccept%3a%20text%2fhtml,application%2fxhtml+xml\",\"requestId\":\"2ab418ac8515f33\",\"responseHeaders\":\"Server%3a%20AkamaiGHost%0d%0aMime-Version%3a%201.0%0d%0aContent-Type%3a%20text%2fhtml\",\"start\":\"1470923133.026\",\"status\":\"301\",\"tls\":\"TLSv1.2\"},\"type\":\"akamai_siem\",\"userRiskData\":{\"allow\":\"0\",\"general\":\"duc_1h:10|duc_1d:30\",\"risk\":\"udfp:1325gdg4g4343g/M|unp:74256/H\",\"score\":\"75\",\"status\":\"0\",\"trust\":\"ugp:US\",\"uuid\":\"964d54b7-0821-413a-a4d6-8131770ec8d5\"},\"version\":\"1.0\"}",
        "start": "2016-08-11T13:45:33.026Z"
    },
    "host": {
        "name": "docker-fleet-agent"
    },
    "http": {
        "request": {
            "id": "2ab418ac8515f33",
            "method": "POST"
        },
        "response": {
            "bytes": 34523,
            "status_code": 301
        },
        "version": "2"
    },
    "input": {
        "type": "httpjson"
    },
    "network": {
        "protocol": "http",
        "transport": "tcp"
    },
    "observer": {
        "type": "proxy",
        "vendor": "akamai"
    },
    "related": {
        "ip": [
            "52.91.36.10"
        ]
    },
    "source": {
        "address": "52.91.36.10",
        "as": {
            "number": 14618,
            "organization": {
                "name": "Amazon.com, Inc."
            }
        },
        "geo": {
            "city_name": "Ashburn",
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 39.0481,
                "lon": -77.4728
            },
            "region_iso_code": "US-VA",
            "region_name": "Virginia"
        },
        "ip": "52.91.36.10"
    },
    "tags": [
        "akamai-siem",
        "forwarded",
        "preserve_original_event"
    ],
    "tls": {
        "version": "1.2",
        "version_protocol": "tls"
    },
    "url": {
        "domain": "www.example.com",
        "full": "www.example.com/examples/1/?a%3D..%2F..%2F..%2Fetc%2Fpasswd",
        "path": "/examples/1/",
        "port": 80,
        "query": "a=../../../etc/passwd"
    }
}
```