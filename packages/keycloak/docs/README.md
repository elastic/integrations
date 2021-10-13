# Keycloak Integration

The Keycloak integration collects events from the Keycloak log files.

## Logs

### log

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
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
| input.type | Type of Filebeat input. | keyword |
| keycloak.status | Status of cache | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.thread.name | Thread name. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
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
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |


An example event for `log` looks as following:

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
    "keycloak": {
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
        "dataset": "keycloak.logpull",
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
        "dataset": "keycloak.logpull",
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
        "vendor": "keycloak"
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