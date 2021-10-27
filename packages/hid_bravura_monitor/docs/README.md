# Hitachi ID Bravura Monitor Integration

The *Hitachi ID Bravura Monitor* integration fetches and parses logs from a Bravura Security Fabric instance.

When you run the integration, it performs a few tasks under the hood:

* Sets the default paths to the log files (but don't worry, you can override the
defaults)

* Makes sure each multiline log event gets sent as a single event

* Uses ingest node to parse and process the log lines, shaping the data into a structure suitable
for visualizing in Kibana

* Deploys dashboards for visualizing the log data

## Compatibility

The *Hitachi ID Bravura Monitor* integration was tested with logs from `IDM Suite 12.3.0` running on Windows Server 2016.

The integration was also tested with IDM Suite 11.x, 12.x series.

This integration is not available for Linux or Mac.

The integration is by default configured to read logs files stored in the `default` instance log directory.
However it can be configured for any file path. See the following example.

```yaml
- module: hid_bravura_monitor
  log:
    enabled: true
    var.paths: ["C:/Program Files/Hitachi ID/IDM Suite/Logs/default*/idmsuite*.log"]
    var.instancename: default
    var.timezone: UTC
    var.environment: PRODUCTION
    var.instancetype: Privilege-Identity-Password
```

*`var.instancename`*::

The name of the IDM Suite instance. The default is `default`. For example:

```yaml
- module: hid_bravura_monitor
  log:
    enabled: true
    var.instancename: inst1
    ...
```

*`var.node`*::

The address of the instance node. The default is filled with `host.name`. For example:

```yaml
- module: hid_bravura_monitor
  log:
    enabled: true
    var.node: 127.0.0.1
    ...
```

*`var.timezone`*::

The timezone for the given instance server. The default is `UTC`. For example:

```yaml
- module: hid_bravura_monitor
  log:
    enabled: true
    var.timezone: Canada/Mountain
    ...
```

*`var.environment`*::

The environment of the IDM Suite instance; choices are DEVELOPMENT, TESTING, PRODUCTION. The default is `PRODUCTION`. For example:

```yaml
- module: hid_bravura_monitor
  log:
    enabled: true
    var.environment: DEVELOPMENT
    ...
```

*`var.instancetype`*::

The type of IDM Suite instance installed; choices are any combinations of Privilege, Identity or Password. The default is `Privilege-Identity-Password`. For example:

```yaml
- module: hid_bravura_monitor
  log:
    enabled: true
    var.instancetype: Identity-Password
    ...
```

*`var.paths`*::

An array of glob-based paths that specify where to look for the log files. All
patterns supported by https://golang.org/pkg/path/filepath/#Glob[Go Glob]
are also supported here. For example, you can use wildcards to fetch all files
from a predefined level of subdirectories: `/path/to/log/*/*.log`. This
fetches all `.log` files from the subfolders of `/path/to/log`. It does not
fetch log files from the `/path/to/log` folder itself. If this setting is left
empty, {beatname_uc} will choose log paths based on your operating system.

## Logs

### log

The `log` dataset collects the Hitachi ID IDM Suite application logs.

An example event for `log` looks as following:

```json
{
    "hid_bravura_monitor": {
        "node": "Node1",
        "environment": "DEVELOPMENT",
        "instancename": "default",
        "instancetype": "Privilege"
    },
    "agent": {
        "hostname": "hostname",
        "name": "hostname",
        "id": "e2bee520-b4cd-44bf-95ea-55c7d8f8ecce",
        "ephemeral_id": "62ca6ad8-3e0a-4508-b353-496d9cf3eab5",
        "type": "filebeat",
        "version": "7.15.0"
    },
    "process": {
        "pid": "28924",
        "thread": {
            "id": "23600"
        }
    },
    "log": {
        "file": {
            "path": "C:\\Logs\\Node1\\default.2021-10-22-182438\\idmsuite.log"
        },
        "offset": 6632166,
        "level": "Info",
        "logger": "pamlws.exe"
    },
    "fileset": {
        "name": "log"
    },
    "message": "Source address [0.0.0.0] updated for wstn [00000000-0000-0000-0000-000000000000]",
    "input": {
        "type": "filestream"
    },
    "@timestamp": "2021-10-22T18:48:08.093-04:00",
    "ecs": {
        "version": "1.12.0"
    },
    "service": {
        "type": "hid_bravura_monitor"
    },
    "host": {
        "hostname": "hostname",
        "os": {
            "build": "14393.3085",
            "kernel": "10.0.14393.3085 (rs1_release.190703-1816)",
            "name": "Windows Server 2016 Standard",
            "type": "windows",
            "family": "windows",
            "version": "10.0",
            "platform": "windows"
        },
        "ip": [
            "fe80::c173:0000:4ee2:e0b1",
            "0.0.0.0",
            "fe80::5efe:a00:8ccb",
            "2001:0:0000:8072:10b8:724:f5ff:7334",
            "fe80::10b8:724:0000:7334"
        ],
        "name": "hostname",
        "id": "f17250ff-f437-4977-9ca6-c41032aca99a",
        "mac": [
            "00:00:00:00:00:00",
            "00:00:00:00:00:00:00:e0",
            "00:00:00:00:00:00:00:e0"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "timezone": "America/New_York",
        "module": "hid_bravura_monitor",
        "dataset": "hid_bravura_monitor.log"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.address | Some event client addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| client.domain | Client domain. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.user.name | Short name or login of the user. | keyword |
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
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | Destination domain. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.port | Port of the destination. | long |
| destination.user.name | Short name or login of the user. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| hid_bravura_monitor.environment | Instance environment | text |
| hid_bravura_monitor.instancename | Instance name | text |
| hid_bravura_monitor.instancetype | Instance type | text |
| hid_bravura_monitor.node | Node | text |
| hid_bravura_monitor.perf.address | Server address | text |
| hid_bravura_monitor.perf.adminid | Administrator ID | text |
| hid_bravura_monitor.perf.caller | Application caller | text |
| hid_bravura_monitor.perf.dbcommand | Database command | text |
| hid_bravura_monitor.perf.destination | Destination URL | text |
| hid_bravura_monitor.perf.duration | Performance duration | long |
| hid_bravura_monitor.perf.event | Event | text |
| hid_bravura_monitor.perf.exe | Executable | text |
| hid_bravura_monitor.perf.file | Source file | text |
| hid_bravura_monitor.perf.function | Performance function | text |
| hid_bravura_monitor.perf.kernel | Kernel Time | long |
| hid_bravura_monitor.perf.kind | Performance type (ie. PerfExe, PerfAjax, PerfFileRep, etc.) | text |
| hid_bravura_monitor.perf.line | Line number | long |
| hid_bravura_monitor.perf.message | Performance message | text |
| hid_bravura_monitor.perf.operation | Operation | text |
| hid_bravura_monitor.perf.receivequeue | Receive queue | text |
| hid_bravura_monitor.perf.records | Database records | long |
| hid_bravura_monitor.perf.result | Result | long |
| hid_bravura_monitor.perf.sessionid | Session ID | text |
| hid_bravura_monitor.perf.sysid | System ID | text |
| hid_bravura_monitor.perf.table | Database table | text |
| hid_bravura_monitor.perf.targetid | Target ID | text |
| hid_bravura_monitor.perf.transid | Transaction ID | text |
| hid_bravura_monitor.perf.type | IDWFM type | text |
| hid_bravura_monitor.perf.user | User time | long |
| hid_bravura_monitor.request.id | Request ID | text |
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
| input.type | Input type. | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.inner | Network.inner fields are added in addition to network.vlan fields to describe the innermost VLAN when q-in-q VLAN tagging is present. Allowed fields include vlan.id and vlan.name. Inner vlan fields are typically used when sending traffic with multiple 802.1q encapsulations to a network sensor (e.g. Zeek, Wireshark.) | object |
| network.inner.vlan.id | VLAN ID as reported by the observer. | keyword |
| network.inner.vlan.name | Optional VLAN name as reported by the observer. | keyword |
| network.protocol | L7 Network protocol name. ex. http, lumberjack, transport protocol. The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
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
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.domain | Server domain. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
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
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.port | Port of the source. | long |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
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
