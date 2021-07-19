# Cloudflare Integration

The Cloudflare integration collects events from the Cloudflare API, specifically reading from the Cloudflare Logpull API.

## Logs

### Logpull

The Cloudflare Logpull records network events related to your organization in order to provide an audit trail that can be used to understand platform activity and to diagnose problems. This module is implemented using the httpjson input.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.address | Some event client addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket. You should always store the raw address in the .address field. | keyword |
| client.as.number | Unique number allocated to the autonomous system. | long |
| client.as.organization.name | Organization name. | keyword |
| client.bytes | Bytes sent from the client to the server. | long |
| client.domain | Client domain. | keyword |
| client.geo.city_name | City name. | keyword |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.geo.region_name | Region name. | keyword |
| client.ip | IP address of the client. | ip |
| client.port | Port of the client. | long |
| cloudflare.cache.bytes | Number of bytes returned by the cache | long |
| cloudflare.cache.status | Status of cache | keyword |
| cloudflare.cache.status_code | HTTP status code returned by the cache to the edge. All requests (including non-cacheable ones) go through the cache. | long |
| cloudflare.cache.tiered_fill | Tiered Cache was used to serve this request | boolean |
| cloudflare.client.ip_class | Class of client, ex. badHost | searchEngine | allowlist | greylist.... | keyword |
| cloudflare.device_type | Client device type | keyword |
| cloudflare.edge.colo.code | IATA airport code of data center that received the request | keyword |
| cloudflare.edge.colo.id | Cloudflare edge colo id | long |
| cloudflare.edge.pathing.op | Indicates what type of response was issued for this request (unknown = no specific action) | keyword |
| cloudflare.edge.pathing.src | Details how the request was classified based on security checks (unknown = no specific classification) | keyword |
| cloudflare.edge.pathing.status | Indicates what data was used to determine the handling of this request (unknown = no data) | keyword |
| cloudflare.edge.rate_limit.action | The action taken by the blocking rule; empty if no action taken | keyword |
| cloudflare.edge.rate_limit.id | The internal rule ID of the rate-limiting rule that triggered a block (ban) or log action. 0 if no action taken. | long |
| cloudflare.edge.request.host | Host header on the request from the edge to the origin | keyword |
| cloudflare.edge.response.compression_ratio | Edge response compression ratio | long |
| cloudflare.edge.response.content_type | Edge response Content-Type header value | keyword |
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
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket. You should always store the raw address in the .address field. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.bytes | Bytes sent from the destination to the server. | long |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination. | ip |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category. The second categorization field in the hierarchy. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | The kind of the event. The highest categorization field in the hierarchy. | keyword |
| event.original | Raw text message of entire event. | keyword |
| event.outcome | The outcome of the event. The lowest level categorization field in the hierarchy. | keyword |
| event.type | Event type. The third categorization field in the hierarchy. | keyword |
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
| http.request.method | HTTP request method. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | Log message optimized for viewing in a log viewer. | text |
| network.bytes | Total bytes transferred in both directions. | long |
| network.protocol | L7 Network protocol name. | keyword |
| network.transport | Protocol Name corresponding to the field `iana_number`. | keyword |
| observer.type | The type of the observer the data is coming from. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| server.address | Server network address. | keyword |
| server.bytes | Bytes sent from the server to the client. | long |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket. You should always store the raw address in the .address field. | keyword |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | Source domain. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
| source.port | Port of the source. | long |
| source.user.full_name | User’s full name, if available. | keyword |
| source.user.id | Unique identifiers of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url. | keyword |
| url.extension | Extension of the requested file, such as ".jpg". | keyword |
| url.original | Unmodified original url as seen in the event source. | keyword |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | keyword |
| url.port | Port of the request, such as 443. | long |
| url.query | Query of the request, such as "?search=asdf". | keyword |
| url.scheme | Scheme of the request, such as "https". | keyword |
| url.username | Username of the request. | keyword |
| user.domain | Name of the directory the user is a member of. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. | keyword |
| user.target.email | User email address. | keyword |
| user.target.full_name | User's full name, if available. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

