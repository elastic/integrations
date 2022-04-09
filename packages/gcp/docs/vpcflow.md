# VPC Flow

## Logs

The `vpcflow` dataset collects logs sent from and received by VM instances, including instances used as GKE nodes.

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
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
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
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| gcp.destination.instance.project_id | ID of the project containing the VM. | keyword |
| gcp.destination.instance.region | Region of the VM. | keyword |
| gcp.destination.instance.zone | Zone of the VM. | keyword |
| gcp.destination.vpc.project_id | ID of the project containing the VM. | keyword |
| gcp.destination.vpc.subnetwork_name | Subnetwork on which the VM is operating. | keyword |
| gcp.destination.vpc.vpc_name | VPC on which the VM is operating. | keyword |
| gcp.source.instance.project_id | ID of the project containing the VM. | keyword |
| gcp.source.instance.region | Region of the VM. | keyword |
| gcp.source.instance.zone | Zone of the VM. | keyword |
| gcp.source.vpc.project_id | ID of the project containing the VM. | keyword |
| gcp.source.vpc.subnetwork_name | Subnetwork on which the VM is operating. | keyword |
| gcp.source.vpc.vpc_name | VPC on which the VM is operating. | keyword |
| gcp.vpcflow.reporter | The side which reported the flow. Can be either 'SRC' or 'DEST'. | keyword |
| gcp.vpcflow.rtt.ms | Latency as measured (for TCP flows only) during the time interval. This is the time elapsed between sending a SEQ and receiving a corresponding ACK and it contains the network RTT as well as the application related delay. | long |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.name | Name given by operators to sections of their network. | keyword |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
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
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |


An example event for `vpcflow` looks as following:

```json
{
    "@timestamp": "2019-06-14T03:50:10.845Z",
    "agent": {
        "ephemeral_id": "e58d02a0-e7a0-45c0-aba6-a8c983782744",
        "id": "c53ddea2-61ac-4643-8676-0c70ebf51c91",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "gcp.vpcflow",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "67.43.156.13",
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
        "ip": "67.43.156.13",
        "port": 33478
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "c53ddea2-61ac-4643-8676-0c70ebf51c91",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "network",
        "created": "2021-12-31T03:12:25.823Z",
        "dataset": "gcp.vpcflow",
        "end": "2019-06-14T03:45:37.301953198Z",
        "id": "ut8lbrffooxyw",
        "ingested": "2021-12-31T03:12:26Z",
        "kind": "event",
        "start": "2019-06-14T03:45:37.186193305Z",
        "type": "connection"
    },
    "gcp": {
        "source": {
            "instance": {
                "project_id": "my-sample-project",
                "region": "us-east1",
                "zone": "us-east1-b"
            },
            "vpc": {
                "project_id": "my-sample-project",
                "subnetwork_name": "default",
                "vpc_name": "default"
            }
        },
        "vpcflow": {
            "reporter": "SRC",
            "rtt": {
                "ms": 36
            }
        }
    },
    "input": {
        "type": "gcp-pubsub"
    },
    "log": {
        "logger": "projects/my-sample-project/logs/compute.googleapis.com%2Fvpc_flows"
    },
    "network": {
        "bytes": 1776,
        "community_id": "1:Wa+aonxAQZ59AWtNdQD0CH6FnsM=",
        "direction": "outbound",
        "iana_number": "6",
        "packets": 7,
        "transport": "tcp",
        "type": "ipv4"
    },
    "related": {
        "ip": [
            "10.87.40.76",
            "67.43.156.13"
        ]
    },
    "source": {
        "address": "10.87.40.76",
        "bytes": 1776,
        "domain": "kibana",
        "ip": "10.87.40.76",
        "packets": 7,
        "port": 5601
    },
    "tags": [
        "forwarded",
        "gcp-vpcflow"
    ]
}
```
