# Endace

Endace is a company known for its network recording, traffic capture, and analysis technology. Endace's solutions are often used for network security, performance monitoring, and troubleshooting.
This integration allows users to ingest Network flow data from either Endace Flow via syslog input or use Elastic Agent to generate and ship Network Flow data to an Elastic deployment. Both of these methods add the `event.reference` field to each event when ingested into Elasticsearch which is a URL used to pivot to Endace.   


## Additional Setup

### Dataview
Once the integration is deployed, in order for the pivot link to be clickable to format for the `event.reference` field needs to be set, this can be done via Kibana Dev Tools and making the following request:
```
POST kbn:/api/data_views/data_view/logs-*/fields
{
    "fields": {
        "event.reference": {
            "format":{
              "id": "url"
            }
        }
    }
}
```

### IP Reputation
When in Elastic Security users are able to quickly lookup information about IPs from external services, to add Endace as an IP Reputation lookup service run the following in Kibana Dev Tools. Ensure to replace `<Your Endace appliance url>` with your Endace appliance URL.

```
POST kbn:/api/kibana/settings
{"changes":{"securitySolution:ipReputationLinks": """[
  { "name": "Endace", "url_template": "https://<Your Endace appliance url>/vision2/v1/pivotintovision/?datasources=tag:all&title=Untitled&reltime=12h&sip={{ip}}&tools=conversations_by_ipaddress" },
  { "name": "virustotal.com", "url_template": "https://www.virustotal.com/gui/search/{{ip}}" },
  { "name": "talosIntelligence.com", "url_template": "https://talosintelligence.com/reputation_center/lookup?search={{ip}}" }
]"""}}
```


## Integration Variables
#### `endace_url`
The base URL for Endace UI. Example: https://myvprobe.com

#### `endace_datasources`
The datasource within Endace to pivot to. Example: tag:rotation-file

#### `endace_tools`
The tools to use within the Endace Pivot. Example: trafficOverTime_by_app,conversations_by_ipaddress


#### `endace_lookback`
The lookback time in Minutes of how long to look back over ontop of the event start and finish time.

## Endace Flow
#### `map_to_ecs`

Remap any non-ECS Packetbeat fields in root to their correct ECS fields.
This will rename fields that are moved so the fields will not be present
at the root of the document and so any rules that depend on the fields
will need to be updated.

The legacy behaviour of this option is to not remap to ECS. This behaviour
is still the default, but is deprecated and users are encouraged to set
this option to true.

ECS remapping may have an impact on workflows that depend on the identity
of non-ECS fields, and users should assess their use of these fields before
making the change. Users who need to retain data collected with the legacy
mappings may need to re-index their older documents. Instructions for doing
this are available [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html).
The pipeline used to perform ECS remapping for each data stream can be found
in `Stack Management`›`Ingest Pipelines` and and searching for
"logs-network_traffic compatibility".

The deprecation and retirement timeline for legacy behavior is available
[here](https://github.com/elastic/integrations/issues/8185).

#### `enabled`

The enabled setting is a boolean setting to enable or disable protocols
without having to comment out configuration sections. If set to false,
the protocol is disabled.

The default value is true.

#### `ports`

Exception: For ICMP the option `enabled` has to be used instead.

The ports where Network Packet Capture will look to capture traffic for specific
protocols. Network Packet Capture installs a
[BPF](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter) filter based
on the ports specified in this section. If a packet doesn’t match the
filter, very little CPU is required to discard the packet. Network Packet Capture
also uses the ports specified here to determine which parser to use for
each packet.

#### `monitor_processes`

If this option is enabled then network traffic events will be enriched
with information about the process associated with the events.

The default value is false.

#### `send_request`

If this option is enabled, the raw message of the request (`request`
field) is sent to Elasticsearch. The default is false. This option is
useful when you want to index the whole request. Note that for HTTP, the
body is not included by default, only the HTTP headers.

#### `send_response`

If this option is enabled, the raw message of the response (`response`
field) is sent to Elasticsearch. The default is false. This option is
useful when you want to index the whole response. Note that for HTTP,
the body is not included by default, only the HTTP headers.

#### `transaction_timeout`

The per protocol transaction timeout. Expired transactions will no
longer be correlated to incoming responses, but sent to Elasticsearch
immediately.

#### `tags`

A list of tags that will be sent with the transaction event. This
setting is optional.

#### `processors`

A list of processors to apply to the data generated by the protocol.

#### `keep_null`

If this option is set to true, fields with `null` values will be
published in the output document. By default, `keep_null` is set to
`false`.


## Network Flows

Overall flow information about the network connections on a
host.

You can configure Network Packet Capture to collect and report statistics
on network flows. A *flow* is a group of packets sent over the same time
period that share common properties, such as the same source and destination
address and protocol. You can use this feature to analyze network
traffic over specific protocols on your network.

For each flow, Network Packet Capture reports the number of packets and the
total number of bytes sent from the source to the destination. Each flow event
also contains information about the source and destination hosts, such
as their IP address. For bi-directional flows, Network Packet Capture reports
statistics for the reverse flow.

Network Packet Capture collects and reports statistics up to and including the
transport layer.

**Configuration options**

You can specify the following options for capturing flows.

#### `enabled`

Enables flows support if set to true. Set to false to disable network
flows support without having to delete or comment out the flows section.
The default value is true.

#### `timeout`

Timeout configures the lifetime of a flow. If no packets have been
received for a flow within the timeout time window, the flow is killed
and reported. The default value is 30s.

#### `period`

Configure the reporting interval. All flows are reported at the very
same point in time. Periodical reporting can be disabled by setting the
value to -1. If disabled, flows are still reported once being timed out.
The default value is 10s.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.geo.city_name | City name. | keyword |
| client.geo.continent_name | Name of the continent. | keyword |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.geo.region_iso_code | Region ISO code. | keyword |
| client.geo.region_name | Region name. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.process.args | The command-line of the process that initiated the transaction. | keyword |
| client.process.executable | Absolute path to the client process executable. | keyword |
| client.process.name | The name of the process that initiated the transaction. | keyword |
| client.process.start | The time the client process started. | date |
| client.process.working_directory | The working directory of the client process. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.mac | MAC address of the destination. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.reference | Reference URL linking to additional information about this event. This URL links to a static definition of this event. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| flow.id | Internal flow ID based on connection meta data and address. | keyword |
| flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
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
| method | The command/verb/method of the transaction. For HTTP, this is the method name (GET, POST, PUT, and so on), for SQL this is the verb (SELECT, UPDATE, DELETE, and so on). | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| network_traffic.flow.final | Indicates if event is last event in flow. If final is false, the event reports an intermediate flow state only. | boolean |
| network_traffic.flow.id | Internal flow ID based on connection meta data and address. | keyword |
| network_traffic.flow.vlan | VLAN identifier from the 802.1q frame. In case of a multi-tagged frame this field will be an array with the outer tag's VLAN identifier listed first. | long |
| network_traffic.status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.mac | MAC addresses of the observer. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| params | The request parameters. For HTTP, these are the POST or GET parameters. For Thrift-RPC, these are the parameters from the request. | text |
| path | The path the transaction refers to. For HTTP, this is the URL. For SQL databases, this is the table name. For key-value stores, this is the key. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.start | The time the process started. | date |
| process.working_directory | The working directory of the process. | keyword |
| process.working_directory.text | Multi-field of `process.working_directory`. | match_only_text |
| query | The query in a human readable format. For HTTP, it will typically be something like `GET /users/_search?name=test`. For MySQL, it is something like `SELECT id from users where name=test`. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| request | For text protocols, this is the request as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| resource | The logical resource that this transaction refers to. For HTTP, this is the URL path up to the last slash (/). For example, if the URL is `/users/1`, the resource is `/users`. For databases, the resource is typically the table name. The field is not filled for all transaction types. | keyword |
| response | For text protocols, this is the response as seen on the wire (application layer only). For binary protocols this is our representation of the request. | text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.geo.city_name | City name. | keyword |
| server.geo.continent_name | Name of the continent. | keyword |
| server.geo.country_iso_code | Country ISO code. | keyword |
| server.geo.country_name | Country name. | keyword |
| server.geo.location | Longitude and latitude. | geo_point |
| server.geo.region_iso_code | Region ISO code. | keyword |
| server.geo.region_name | Region name. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| server.process.args | The command-line of the process that served the transaction. | keyword |
| server.process.executable | Absolute path to the server process executable. | keyword |
| server.process.name | The name of the process that served the transaction. | keyword |
| server.process.start | The time the server process started. | date |
| server.process.working_directory | The working directory of the server process. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| status | The high level status of the transaction. The way to compute this value depends on the protocol, but the result has a meaning independent of the protocol. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| type | The type of the transaction (for example, HTTP, MySQL, Redis, or RUM) or "flow" in case of flows. | keyword |


An example event for `flow` looks as following:

```json
{
    "@timestamp": "2023-10-16T22:40:20.005Z",
    "agent": {
        "ephemeral_id": "005dde79-7459-4b47-ae00-972086b4f5db",
        "id": "f923dfe0-3acb-4f62-9ab4-1fabb8e8e112",
        "name": "docker-fleet-agent",
        "type": "packetbeat",
        "version": "8.6.2"
    },
    "data_stream": {
        "dataset": "endace.flow",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 64,
        "ip": "::1",
        "packets": 1,
        "port": 8000
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f923dfe0-3acb-4f62-9ab4-1fabb8e8e112",
        "snapshot": false,
        "version": "8.6.2"
    },
    "event": {
        "action": "network_flow",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "endace.flow",
        "duration": 73561,
        "end": "2023-10-16T22:39:45.677Z",
        "ingested": "2023-10-16T22:40:21Z",
        "kind": "event",
        "start": "2023-10-16T22:39:45.677Z",
        "type": [
            "connection",
            "end"
        ]
    },
    "flow": {
        "final": true,
        "id": "QAT///////8A////IP8AAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAUAfeMg"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "f91b175388d443fca5c155815dfc2279",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02-42-AC-13-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.49-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "network": {
        "bytes": 152,
        "community_id": "1:5y9AkdbV9U8xqD9dhlj6obkubHg=",
        "packets": 2,
        "transport": "tcp",
        "type": "ipv6"
    },
    "source": {
        "bytes": 88,
        "ip": "::1",
        "packets": 1,
        "port": 51320
    },
    "type": "flow"
}

```

## Licensing for Windows Systems

The Network Packet Capture Integration incorporates a bundled Npcap installation on Windows hosts. The installation is provided under an [OEM license](https://npcap.com/oem/redist.html) from Insecure.Com LLC ("The Nmap Project").