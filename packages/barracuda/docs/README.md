# Barracuda integration

This integration is for Barracuda device's logs. It includes the following
datasets for receiving logs over syslog or read from a file:

- `waf` dataset: supports Barracuda Web Application Firewall logs.

Use the Barracuda WAF data stream to ingest log data. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference `data_stream.dataset:barracuda.waf` when troubleshooting an issue.

## Upgrade

The upgrade from `Technical preview` to a `General Available` version will have datastream `spamfirewall` not supported in this integration anymore.

## WAF

Barracuda Web Application Firewall protects applications, APIs, and mobile app backends against a variety of attacks including the OWASP Top 10, zero-day threats, data leakage, and application-layer denial of service (DoS) attacks. By combining signature-based policies and positive security with robust anomaly-detection capabilities, Barracuda Web Application Firewall can defeat today’s most sophisticated attacks targeting your web applications.

## Requirements

This integration is built and tested against the Barracuda Web Application Firewall version **12.1**. Earlier versions may work, but have not been tested.

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

### Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## WAF Events

The `barracuda.waf` dataset provides events from the configured syslog server. All Barracuda WAF syslog specific fields are available in the `barracuda.waf` field group.

An example event for `waf` looks as following:

```json
{
    "@timestamp": "2023-03-01T13:54:44.502Z",
    "agent": {
        "ephemeral_id": "e94cc83b-92d3-493e-877a-8a0a1e7d995c",
        "id": "268b120d-46f4-4d33-b98c-9452ffcd92b9",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.6.2"
    },
    "barracuda": {
        "log": {
            "action_taken": "LOG",
            "attack_description": "NO_PARAM_PROFILE_MATCH",
            "attack_details": "Parameter\\=\"0x\\\\[\\\\]\" value\\=\"androxgh0st\"",
            "followup_action": "NONE",
            "log_type": "WF",
            "protocol": "TLSv1.2",
            "severity_level": "ALER",
            "unit_name": "barracuda"
        }
    },
    "client": {
        "ip": "193.56.29.26",
        "port": 61507
    },
    "data_stream": {
        "dataset": "barracuda.waf",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "10.9.0.4",
        "port": 443
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "268b120d-46f4-4d33-b98c-9452ffcd92b9",
        "snapshot": false,
        "version": "8.6.2"
    },
    "event": {
        "action": "LOG",
        "agent_id_status": "verified",
        "category": [
            "network",
            "intrusion_detection"
        ],
        "created": "2023-03-01T13:54:44.502Z",
        "dataset": "barracuda.waf",
        "ingested": "2023-03-28T13:27:44Z",
        "kind": "event",
        "original": "\u003c129\u003e2023-03-01 14:54:44.502 +0100  barracuda WF ALER NO_PARAM_PROFILE_MATCH 193.56.29.26 61507 10.9.0.4 443 Hackazon:adaptive_url_42099b4af021e53fd8fd URL_PROFILE LOG NONE [Parameter\\=\"0x\\\\[\\\\]\" value\\=\"androxgh0st\"] POST / TLSv1.2 \"-\" \"Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; HM NOTE 1W Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.0.5.850 U3/0.8.0 Mobile Safari/534.30\" 20.88.228.79 61507 \"-\" \"-\" 1869d743696-dfcf8d96",
        "timezone": "+00:00"
    },
    "http": {
        "request": {
            "method": "POST"
        }
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.18.0.4:57384"
        }
    },
    "network": {
        "forwarded_ip": "20.88.228.79"
    },
    "observer": {
        "product": "Web",
        "type": "WAF",
        "vendor": "Barracuda"
    },
    "rule": {
        "category": "URL_PROFILE",
        "name": "Hackazon:adaptive_url_42099b4af021e53fd8fd"
    },
    "server": {
        "ip": "10.9.0.4",
        "port": 443
    },
    "source": {
        "ip": "193.56.29.26",
        "port": 61507
    },
    "tags": [
        "preserve_original_event",
        "barracuda",
        "forwarded"
    ],
    "url": {
        "path": "/"
    },
    "user": {
        "id": "1869d743696-dfcf8d96"
    },
    "user_agent": {
        "device": {
            "name": "XiaoMi HM NOTE 1W"
        },
        "name": "UC Browser",
        "original": "Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; HM NOTE 1W Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.0.5.850 U3/0.8.0 Mobile Safari/534.30",
        "os": {
            "full": "Android 4.4.2",
            "name": "Android",
            "version": "4.4.2"
        },
        "version": "11.0.5"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| barracuda.log.action_taken | The appropriate action applied on the traffic. DENY - denotes that the traffic is denied. LOG - denotes monitoring of the traffic with the assigned rule. WARNING - warns about the traffic. | keyword |
| barracuda.log.attack_description | The name of the attack triggered by the request. | keyword |
| barracuda.log.attack_details | The details of the attack triggered by the request. | keyword |
| barracuda.log.authenticated_user | The username of the currently authenticated client requesting the web page. This is available only when the request is for a service that is using the AAA (Access Control) module. | keyword |
| barracuda.log.cache_hit | Specifies whether the response is served out of the Barracuda Web Application Firewall cache or from the backend server. Values:0 - if the request is fetched from the server and given to the user.1 - if the request is fetched from the cache and given to the user. | long |
| barracuda.log.custom_header.accept_encoding | The header Accept-Encoding in the Access Logs | keyword |
| barracuda.log.custom_header.connection | The header connection in the Access Logs | keyword |
| barracuda.log.custom_header.host | The header host in the Access Logs | keyword |
| barracuda.log.followup_action | The follow-up action as specified by the action policy. It can be either None or Locked in case the lockout is chosen. | keyword |
| barracuda.log.log_type | Specifies the type of log - Web Firewall Log, Access Log, Audit Log, Network Firewall Log or System Log - WF, TR, AUDIT, NF, SYS. | keyword |
| barracuda.log.policy | The ACL policy (Allow or Deny) applied to this ACL rule. | keyword |
| barracuda.log.profile_matched | Specifies whether the request matched a defined URL or Parameter Profile. Values:DEFAULT, PROFILED. | keyword |
| barracuda.log.protected | Specifies whether the request went through the Barracuda Web Application Firewall rules and policy checks. Values:PASSIVE, PROTECTED, UNPROTECTED. | keyword |
| barracuda.log.protocol | The protocol used for the request. | keyword |
| barracuda.log.request_cookie | Specifies whether the request is valid. Values:INVALID, VALID. | keyword |
| barracuda.log.response_timetaken | The total time taken to serve the request from the time the request landed on the Barracuda Web Application Firewall until the last byte given out to the client. | long |
| barracuda.log.response_type | Specifies whether the response came from the backend sever or from the Barracuda Web Application Firewall. Values:INTERNAL, SERVER. | keyword |
| barracuda.log.ruleName | The path of the URL ACL that matched with the request. Here "webapp1" is the web application and "deny_ban_dir" is the name of the URL ACL | keyword |
| barracuda.log.rule_type | This indicates the type of rule that was hit by the request that caused the attack. The following is the list of expected values for Rule Type Global - indicates that the request matched one of the global rules configured under Security Policies. Global URL ACL - indicates that the request matched one of the global URL ACL rules configured under Security Policies. URL ACL - indicates that the request matched one of the Allow/Deny rules configured specifically for the given website. URL Policy - indicates that the request matched one of the Advanced Security rules configured specifically for the given website. URL Profile - indicates that the request matched one of the rules configured on the URL Profile. Parameter Profile - indicates that the request matched one of the rules configured on the Parameter Profile. Header Profile - indicates that the request matched one of the rules configured on the Header Profile. | keyword |
| barracuda.log.server_time | The total time taken by the backend server to serve the request forwarded to it by the Barracuda Web Application Firewall. | long |
| barracuda.log.sessionid | The value of the session tokens found in the request if session tracking is enabled. | keyword |
| barracuda.log.severity_level | Defines the seriousness of the attack. EMERGENCY - System is unusable (highest priority). ALERT - Response must be taken immediately. CRITICAL - Critical conditions. ERROR - Error conditions. WARNING - Warning conditions. NOTICE - Normal but significant condition. INFORMATION - Informational message (on ACL configuration changes). DEBUG - Debug-level message (lowest priority). | keyword |
| barracuda.log.unit_name | Specifies the name of the unit. | keyword |
| barracuda.log.user_id | The identifier of the user. | keyword |
| barracuda.log.wf_matched | Specifies whether the request is valid. Values:INVALID, VALID. | keyword |
| client.address | Some event client addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| client.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| client.as.organization.name | Organization name. | keyword |
| client.as.organization.name.text | Multi-field of `client.as.organization.name`. | match_only_text |
| client.domain | The domain name of the client system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| client.geo.city_name | City name. | keyword |
| client.geo.continent_name | Name of the continent. | keyword |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.geo.region_iso_code | Region ISO code. | keyword |
| client.geo.region_name | Region name. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.user.id | Unique identifier of the user. | keyword |
| client.user.name | Short name or login of the user. | keyword |
| client.user.name.text | Multi-field of `client.user.name`. | match_only_text |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |
| http.request.id | A unique identifier for each HTTP request to correlate logs between clients and servers in transactions. The id may be contained in a non-standard HTTP header, such as `X-Request-ID` or `X-Correlation-ID`. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.inner | Network.inner fields are added in addition to network.vlan fields to describe the innermost VLAN when q-in-q VLAN tagging is present. Allowed fields include vlan.id and vlan.name. Inner vlan fields are typically used when sending traffic with multiple 802.1q encapsulations to a network sensor (e.g. Zeek, Wireshark.) | object |
| network.inner.vlan.id | VLAN ID as reported by the observer. | keyword |
| network.inner.vlan.name | Optional VLAN name as reported by the observer. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.egress.zone | Network zone of outbound traffic as reported by the observer to categorize the destination area of egress traffic, e.g. Internal, External, DMZ, HR, Legal, etc. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.zone | Network zone of incoming traffic as reported by the observer to categorize the source area of ingress traffic. e.g. internal, External, DMZ, HR, Legal, etc. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.description | The description of the rule generating the event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.geo.city_name | City name. | keyword |
| server.geo.continent_name | Name of the continent. | keyword |
| server.geo.country_iso_code | Country ISO code. | keyword |
| server.geo.country_name | Country name. | keyword |
| server.geo.location | Longitude and latitude. | geo_point |
| server.geo.region_iso_code | Region ISO code. | keyword |
| server.geo.region_name | Region name. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.user.name | Short name or login of the user. | keyword |
| server.user.name.text | Multi-field of `server.user.name`. | match_only_text |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
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
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.port | Port of the source. | long |
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.group.name | Name of the group. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
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
| user.id | Unique identifier of the user. | keyword |
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

