# Hitachi ID Bravura Monitor Integration

The *Hitachi ID Bravura Monitor* integration fetches and parses logs from a Bravura Security Fabric instance.

When you run the integration, it performs the following tasks automatically:

* Sets the default paths to the log files (you can override the
defaults)

* Makes sure each multiline log event gets sent as a single event

* Uses ingest pipelines to parse and process the log lines, shaping the data into a structure suitable
for visualizing in Kibana

* Deploys dashboards for visualizing the log data

## Compatibility

The *Hitachi ID Bravura Monitor* integration was tested with logs from `Bravura Security Fabric 12.3.0` running on Windows Server 2016.

The integration was also tested with Bravura Security Fabric/IDM Suite 11.x, 12.x series.

This integration is not available for Linux or Mac.

The integration is by default configured to read logs files stored in the `default` instance log directory.
However it can be configured for any file path. See the following example.

```yaml
- id: b5e895ed-0726-4fa3-870c-464379d1c27b
    name: hid_bravura_monitor-1
    revision: 1
    type: filestream
    use_output: default
    meta:
      package:
        name: hid_bravura_monitor
        version: 1.0.0
    data_stream:
      namespace: default
    streams:
      - id: >-
          filestream-hid_bravura_monitor.log-b5e895ed-0726-4fa3-870c-464379d1c27b
        data_stream:
          dataset: hid_bravura_monitor.log
          type: logs
        paths:
          - 'C:/Program Files/Hitachi ID/IDM Suite/Logs/default*/idmsuite*.log'
        prospector.scanner.exclude_files:
          - .gz$
        line_terminator: carriage_return_line_feed
        tags: null
        processors:
          - add_fields:
              target: ''
              fields:
                hid_bravura_monitor.instancename: default
                hid_bravura_monitor.node: 0.0.0.0
                hid_bravura_monitor.environment: PRODUCTION
                hid_bravura_monitor.instancetype: Privilege-Identity-Password
                event.timezone: UTC
        parsers:
          - multiline:
              type: pattern
              pattern: '^[[:cntrl:]]'
              negate: true
              match: after
```

*`hid_bravura_monitor.instancename`*

The name of the Bravura Security Fabric instance. The default is `default`. For example:

```yaml
processors:
  - add_fields:
      target: ''
      fields:
        hid_bravura_monitor.instancename: default
        ...
```

*`hid_bravura_monitor.node`*

The address of the instance node. If the default `0.0.0.0` is left, the value is filled with `host.name`. For example:

```yaml
processors:
  - add_fields:
      target: ''
      fields:
        hid_bravura_monitor.node: 127.0.0.1
        ...
```

*`event.timezone`*

The timezone for the given instance server. The default is `UTC`. For example:

```yaml
processors:
  - add_fields:
      target: ''
      fields:
        event.timezone: Canada/Mountain
        ...
```

*`hid_bravura_monitor.environment`*

The environment of the Bravura Security Fabric instance; choices are DEVELOPMENT, TESTING, PRODUCTION. The default is `PRODUCTION`. For example:

```yaml
processors:
  - add_fields:
      target: ''
      fields:
        hid_bravura_monitor.environment: DEVELOPMENT
        ...
```

*`hid_bravura_monitor.instancetype`*

The type of Bravura Security Fabric instance installed; choices are any combinations of Privilege, Identity or Password. The default is `Privilege-Identity-Password`. For example:

```yaml
processors:
  - add_fields:
      target: ''
      fields:
        hid_bravura_monitor.instancetype: Identity
        ...
```

*`paths`*

An array of glob-based paths that specify where to look for the log files. All
patterns supported by https://golang.org/pkg/path/filepath/#Glob[Go Glob]
are also supported here. For example, you can use wildcards to fetch all files
from a predefined level of subdirectories: `/path/to/log/*/*.log`. This
fetches all `.log` files from the subfolders of `/path/to/log`. It does not
fetch log files from the `/path/to/log` folder itself. If this setting is left
empty, the integration will choose log paths based on your operating system.

## Logs

### log

The `log` dataset collects the Hitachi ID Bravura Security Fabric application logs.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2021-01-16T00:35:25.258Z",
    "agent": {
        "ephemeral_id": "00124c53-af5e-4d5f-818c-ff189690109e",
        "hostname": "docker-fleet-agent",
        "id": "9bcd741c-af93-434c-ad55-1ec23d08ab89",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.0"
    },
    "data_stream": {
        "dataset": "hid_bravura_monitor.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "9bcd741c-af93-434c-ad55-1ec23d08ab89",
        "snapshot": true,
        "version": "7.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "hid_bravura_monitor.log",
        "ingested": "2021-10-29T18:19:35Z",
        "original": "\u00182021-01-16 00:35:25.258.7085 - [] pamlws.exe [44408,52004] Error: LWS [HID-TEST] foundcomputer record not found",
        "timezone": "UTC"
    },
    "hid_bravura_monitor": {
        "environment": "PRODUCTION",
        "instancename": "default",
        "instancetype": "Privilege-Identity-Password",
        "node": "docker-fleet-agent"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "3bfbf225479aac5f850ea38f5d9d8a02",
        "ip": [
            "192.168.192.7"
        ],
        "mac": [
            "02:42:c0:a8:c0:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.10.16.3-microsoft-standard-WSL2",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/hid_bravura_monitor.log"
        },
        "level": "Error",
        "logger": "pamlws.exe",
        "offset": 218
    },
    "message": "LWS [HID-TEST] foundcomputer record not found",
    "process": {
        "pid": 44408,
        "thread": {
            "id": 52004
        }
    },
    "tags": [
        "preserve_original_event"
    ],
    "user": {
        "id": ""
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
| hid_bravura_monitor.environment | Instance environment | keyword |
| hid_bravura_monitor.instancename | Instance name | keyword |
| hid_bravura_monitor.instancetype | Instance type | keyword |
| hid_bravura_monitor.node | Node | keyword |
| hid_bravura_monitor.perf.address | Server address | wildcard |
| hid_bravura_monitor.perf.adminid | Administrator ID | keyword |
| hid_bravura_monitor.perf.caller | Application caller | keyword |
| hid_bravura_monitor.perf.dbcommand | Database command | keyword |
| hid_bravura_monitor.perf.destination | Destination URL | wildcard |
| hid_bravura_monitor.perf.duration | Performance duration | long |
| hid_bravura_monitor.perf.event | Event | keyword |
| hid_bravura_monitor.perf.exe | Executable | keyword |
| hid_bravura_monitor.perf.file | Source file | keyword |
| hid_bravura_monitor.perf.function | Performance function | keyword |
| hid_bravura_monitor.perf.kernel | Kernel Time | long |
| hid_bravura_monitor.perf.kind | Performance type (ie. PerfExe, PerfAjax, PerfFileRep, etc.) | keyword |
| hid_bravura_monitor.perf.line | Line number | long |
| hid_bravura_monitor.perf.message | Performance message | wildcard |
| hid_bravura_monitor.perf.operation | Operation | keyword |
| hid_bravura_monitor.perf.receivequeue | Receive queue | keyword |
| hid_bravura_monitor.perf.records | Database records | long |
| hid_bravura_monitor.perf.result | Result | long |
| hid_bravura_monitor.perf.sessionid | Session ID | keyword |
| hid_bravura_monitor.perf.sysid | System ID | keyword |
| hid_bravura_monitor.perf.table | Database table | keyword |
| hid_bravura_monitor.perf.targetid | Target ID | keyword |
| hid_bravura_monitor.perf.transid | Transaction ID | keyword |
| hid_bravura_monitor.perf.type | IDWFM type | keyword |
| hid_bravura_monitor.perf.user | User time | long |
| hid_bravura_monitor.request.id | Request ID | keyword |
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
| log.flags | Flags for the log file. | keyword |
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


### winlog

The `winglog` dataset collects the Hitachi ID Bravura Security Fabric event logs.

An example event for `winlog` looks as following:

```json
{
    "@timestamp": "2021-10-29T14:05:50.739Z",
    "cloud": {
        "provider": "aws",
        "instance": {
            "id": "i-043997b05c5fa45ee"
        },
        "machine": {
            "type": "t3a.xlarge"
        },
        "region": "us-east-1",
        "availability_zone": "us-east-1a",
        "account": {
            "id": "753231555564"
        },
        "image": {
            "id": "ami-0e6ddc753bf04d004"
        }
    },
    "log": {
        "level": "information"
    },
    "message": "User successfully logged in.|Profile=JOHND|Language=|Skin=",
    "winlog": {
        "record_id": 1548167,
        "api": "wineventlog",
        "opcode": "Info",
        "provider_guid": "{5a744344-18a9-480d-8a3a-0560ac58b841}",
        "channel": "Hitachi-Hitachi ID Systems-Hitachi ID Suite/Operational",
        "activity_id": "{4ffdfadd-63f2-41b2-9a4f-13534a729c54}",
        "user": {
            "identifier": "S-1-5-21-1512184445-966971527-3399726218-1035",
            "name": "psadmin",
            "domain": "DOMAIN1",
            "type": "User"
        },
        "event_data": {
            "Module": "psf.exe",
            "Profile": "JOHND",
            "Instance": "pmim"
        },
        "event_id": 92,
        "computer_name": "hitachi1.corp",
        "provider_name": "Hitachi-Hitachi ID Systems-Hitachi ID Suite",
        "task": "",
        "process": {
            "pid": 6368,
            "thread": {
                "id": 9064
            }
        }
    },
    "event": {
        "kind": "event",
        "code": 92,
        "provider": "Hitachi-Hitachi ID Systems-Hitachi ID Suite",
        "created": "2021-10-29T14:05:52.111Z"
    },
    "host": {
        "name": "hitachi1.corp",
        "architecture": "x86_64",
        "os": {
            "family": "windows",
            "name": "Windows Server 2019 Datacenter",
            "kernel": "10.0.17763.1999 (WinBuild.160101.0800)",
            "build": "17763.1999",
            "platform": "windows",
            "version": "10.0"
        },
        "id": "a9d2b7f5-6d62-46b3-8fbe-35a7e83d1dc8",
        "ip": [
            "0.0.0.0"
        ],
        "mac": [
            "0a:a5:af:ad:d3:ab"
        ],
        "hostname": "node1"
    },
    "agent": {
        "version": "8.0.0",
        "hostname": "node1",
        "ephemeral_id": "d061bfcf-e51b-4586-9ace-3d5b15f86e37",
        "id": "aa12ad42-61bc-466c-8887-1a15d4646fc7",
        "name": "node1",
        "type": "filebeat"
    },
    "ecs": {
        "version": "1.12.0"
    }
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
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | initial raw message | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.pid | Process id. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| source.domain | Source domain. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| winlog.activity_id | A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity. | keyword |
| winlog.api | The event log API type used to read the record. The possible values are "wineventlog" for the Windows Event Log API or "eventlogging" for the Event Logging API. The Event Logging API was designed for Windows Server 2003 or Windows 2000 operating systems. In Windows Vista, the event logging infrastructure was redesigned. On Windows Vista or later operating systems, the Windows Event Log API is used. Winlogbeat automatically detects which API to use for reading event logs. | keyword |
| winlog.channel | The name of the channel from which this record was read. This value is one of the names from the `event_logs` collection in the configuration. | keyword |
| winlog.computerObject.domain |  | keyword |
| winlog.computerObject.id |  | keyword |
| winlog.computerObject.name |  | keyword |
| winlog.computer_name | The name of the computer that generated the record. When using Windows event forwarding, this name can differ from `agent.hostname`. | keyword |
| winlog.event_data | The event-specific data. This field is mutually exclusive with `user_data`. If you are capturing event data on versions prior to Windows Vista, the parameters in `event_data` are named `param1`, `param2`, and so on, because event log parameters are unnamed in earlier versions of Windows. | object |
| winlog.event_data.Account | An object on a target system that establishes a user’s identity on that target system. | keyword |
| winlog.event_data.Action |  | keyword |
| winlog.event_data.ActionId |  | keyword |
| winlog.event_data.Arguments |  | keyword |
| winlog.event_data.AuthChain | Authentication chains offer a flexible authentication infrastructure, allowing you to customize the end-user authentication experience. An authentication chain contains authentication methods offered by available authentication modules. | keyword |
| winlog.event_data.AuthUser | Authentication user. | keyword |
| winlog.event_data.BatchSig | Request batch ID. | keyword |
| winlog.event_data.Binding |  | keyword |
| winlog.event_data.CanceledBy | The user who canceled the request. | keyword |
| winlog.event_data.ChangedBy | The user who made the change. | keyword |
| winlog.event_data.Checkout |  | keyword |
| winlog.event_data.ClientIPs |  | ip |
| winlog.event_data.DelayThreshold |  | long |
| winlog.event_data.Description |  | keyword |
| winlog.event_data.EffectiveUser |  | keyword |
| winlog.event_data.ErrorCode |  | keyword |
| winlog.event_data.Event |  | keyword |
| winlog.event_data.EventID |  | keyword |
| winlog.event_data.FailedTargets |  | keyword |
| winlog.event_data.GroupSet |  | keyword |
| winlog.event_data.Hostname |  | keyword |
| winlog.event_data.Identity | Identify users. | keyword |
| winlog.event_data.Initiator |  | keyword |
| winlog.event_data.Instance |  | keyword |
| winlog.event_data.Issuer |  | keyword |
| winlog.event_data.Language | Language used. | keyword |
| winlog.event_data.LoginURL | User login URL. | keyword |
| winlog.event_data.LogonDomain |  | keyword |
| winlog.event_data.LogonSystem |  | keyword |
| winlog.event_data.LogonUser |  | keyword |
| winlog.event_data.MAQ | Account set access. | keyword |
| winlog.event_data.Message |  | keyword |
| winlog.event_data.MessageType |  | keyword |
| winlog.event_data.Method |  | keyword |
| winlog.event_data.Module |  | keyword |
| winlog.event_data.Node |  | keyword |
| winlog.event_data.OSLogin |  | keyword |
| winlog.event_data.OTPLogin | API login. | keyword |
| winlog.event_data.Operation |  | keyword |
| winlog.event_data.Orchestration | Subscriber orchestration. | keyword |
| winlog.event_data.Owner |  | keyword |
| winlog.event_data.Platform |  | keyword |
| winlog.event_data.Policy |  | keyword |
| winlog.event_data.Port |  | keyword |
| winlog.event_data.Procedure |  | keyword |
| winlog.event_data.Profile |  | keyword |
| winlog.event_data.QSetID | Question set ID. | keyword |
| winlog.event_data.QSetType | Question set type. | keyword |
| winlog.event_data.QueueDelay | Database replication queue delay. | long |
| winlog.event_data.QueueSize | Database replication queue size. | long |
| winlog.event_data.QueueType | Database replication queue type. | keyword |
| winlog.event_data.Reason |  | keyword |
| winlog.event_data.Recipient | Recipient of the request. | keyword |
| winlog.event_data.Replica | Replica database or server. | keyword |
| winlog.event_data.RequestID |  | keyword |
| winlog.event_data.Requester |  | keyword |
| winlog.event_data.Result |  | keyword |
| winlog.event_data.RevokedBy | Workflow request has been revoked by. | keyword |
| winlog.event_data.Runtime |  | long |
| winlog.event_data.SPFolder | Service provider folder. | keyword |
| winlog.event_data.SessionID |  | keyword |
| winlog.event_data.Skin | Skin for Bravura Security Fabric instance. | keyword |
| winlog.event_data.Source |  | keyword |
| winlog.event_data.StoredProc | Stored procedure. | keyword |
| winlog.event_data.System |  | keyword |
| winlog.event_data.Target |  | keyword |
| winlog.event_data.TargetName |  | keyword |
| winlog.event_data.TermintedBy | Request terminated by. | keyword |
| winlog.event_data.Type |  | keyword |
| winlog.event_data.URI | The HTTP(S) address of the SOAP API of the Bravura Security Fabric server. | keyword |
| winlog.event_data.WaterMark | Database replication watermark. | keyword |
| winlog.event_data.Workstation |  | keyword |
| winlog.event_id | The event identifier. The value is specific to the source of the event. | keyword |
| winlog.keywords | The keywords are used to classify an event. | keyword |
| winlog.level | The event severity.  Levels are Critical, Error, Warning and Information, Verbose | keyword |
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.outcome | Success or Failure of the event. | keyword |
| winlog.process.pid | The process_id of the Client Server Runtime Process. | long |
| winlog.process.thread.id |  | long |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.provider_name | The source of the event log record (the application or service that logged the record). | keyword |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0. | keyword |
| winlog.related_activity_id | A globally unique identifier that identifies the activity to which control was transferred to. The related events would then have this identifier as their `activity_id` identifier. | keyword |
| winlog.symbolic_id | Symbolic event id | keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. The category used by the Event Logging API (on pre Windows Vista operating systems) is written to this field. | keyword |
| winlog.time_created | Time event was created | keyword |
| winlog.trustAttribute |  | keyword |
| winlog.trustDirection |  | keyword |
| winlog.trustType |  | keyword |
| winlog.user.domain | The domain that the account associated with this event is a member of. | keyword |
| winlog.user.identifier | Identifier of the user associated with this event. | keyword |
| winlog.user.name | Name of the user associated with this event. | keyword |
| winlog.user.type | The type of account associated with this event. | keyword |
| winlog.user_data | The event specific data. This field is mutually exclusive with `event_data`. | object |
| winlog.version | The version number of the event's definition. | long |
