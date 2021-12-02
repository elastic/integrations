# Firewall

Firewall Rules Logging lets you audit, verify, and analyze the effects of your firewall rules.
More information on the type of data included in the firewall logs can be found in the [documentation](https://cloud.google.com/vpc/docs/firewall-rules-logging)

## Logs

This is the `firewall` dataset.

An example event for `firewall` looks as following:

```json
{
    "log": {
        "logger": "projects/test-beats/logs/compute.googleapis.com%2Ffirewall"
    },
    "destination": {
        "geo": {
            "continent_name": "North America",
            "country_name": "United States",
            "location": {
                "lon": -97.822,
                "lat": 37.751
            },
            "country_iso_code": "US"
        },
        "as": {
            "number": 15169,
            "organization": {
                "name": "Google LLC"
            }
        },
        "address": "8.8.8.8",
        "port": 53,
        "ip": "8.8.8.8"
    },
    "rule": {
        "name": "network:default/firewall:adrian-test-1"
    },
    "source": {
        "address": "10.128.0.16",
        "port": 60094,
        "domain": "adrian-test",
        "ip": "10.128.0.16"
    },
    "network": {
        "name": "default",
        "community_id": "1:iiDdIEXnxwSiz/hJbVnseQ4SZVE=",
        "transport": "udp",
        "type": "ipv4",
        "iana_number": "17",
        "direction": "outbound"
    },
    "cloud": {
        "region": "us-central1",
        "availability_zone": "us-central1-a",
        "project": {
            "id": "test-beats"
        }
    },
    "@timestamp": "2019-11-12T12:35:17.214Z",
    "ecs": {
        "version": "1.8.0"
    },
    "related": {
        "ip": [
            "10.128.0.16",
            "8.8.8.8"
        ]
    },
    "gcp": {
        "firewall": {
            "rule_details": {
                "action": "DENY",
                "target_tag": [
                    "adrian-test"
                ],
                "priority": 1000,
                "destination_range": [
                    "8.8.8.0/24"
                ],
                "ip_port_info": [
                    {
                        "ip_protocol": "ALL"
                    }
                ],
                "direction": "EGRESS"
            }
        },
        "source": {
            "vpc": {
                "project_id": "test-beats",
                "subnetwork_name": "default",
                "vpc_name": "default"
            },
            "instance": {
                "region": "us-central1",
                "project_id": "test-beats",
                "zone": "us-central1-a"
            }
        }
    },
    "event": {
        "ingested": "2021-02-19T09:19:48.040375200Z",
        "original": "{\"insertId\":\"4zuj4nfn4llkb\",\"jsonPayload\":{\"connection\":{\"dest_ip\":\"8.8.8.8\",\"dest_port\":53,\"protocol\":17,\"src_ip\":\"10.128.0.16\",\"src_port\":60094},\"disposition\":\"DENIED\",\"instance\":{\"project_id\":\"test-beats\",\"region\":\"us-central1\",\"vm_name\":\"adrian-test\",\"zone\":\"us-central1-a\"},\"remote_location\":{\"continent\":\"America\",\"country\":\"usa\"},\"rule_details\":{\"action\":\"DENY\",\"destination_range\":[\"8.8.8.0/24\"],\"direction\":\"EGRESS\",\"ip_port_info\":[{\"ip_protocol\":\"ALL\"}],\"priority\":1000,\"reference\":\"network:default/firewall:adrian-test-1\",\"target_tag\":[\"adrian-test\"]},\"vpc\":{\"project_id\":\"test-beats\",\"subnetwork_name\":\"default\",\"vpc_name\":\"default\"}},\"logName\":\"projects/test-beats/logs/compute.googleapis.com%2Ffirewall\",\"receiveTimestamp\":\"2019-11-12T12:35:24.466374097Z\",\"resource\":{\"labels\":{\"location\":\"us-central1-a\",\"project_id\":\"test-beats\",\"subnetwork_id\":\"1266623735137648253\",\"subnetwork_name\":\"default\"},\"type\":\"gce_subnetwork\"},\"timestamp\":\"2019-11-12T12:35:17.214711274Z\"}",
        "kind": "event",
        "action": "firewall-rule",
        "id": "4zuj4nfn4llkb",
        "category": "network",
        "type": "connection"
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
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.domain | Destination domain. | keyword |
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
| gcp.firewall.rule_details.action | Action that the rule performs on match. | keyword |
| gcp.firewall.rule_details.destination_range | List of destination ranges that the firewall applies to. | keyword |
| gcp.firewall.rule_details.direction | Direction of traffic that matches this rule. | keyword |
| gcp.firewall.rule_details.ip_port_info | List of ip protocols and applicable port ranges for rules. | array |
| gcp.firewall.rule_details.priority | The priority for the firewall rule. | long |
| gcp.firewall.rule_details.reference | Reference to the firewall rule. | keyword |
| gcp.firewall.rule_details.source_range | List of source ranges that the firewall rule applies to. | keyword |
| gcp.firewall.rule_details.source_service_account | List of all the source service accounts that the firewall rule applies to. | keyword |
| gcp.firewall.rule_details.source_tag | List of all the source tags that the firewall rule applies to. | keyword |
| gcp.firewall.rule_details.target_service_account | List of all the target service accounts that the firewall rule applies to. | keyword |
| gcp.firewall.rule_details.target_tag | List of all the target tags that the firewall rule applies to. | keyword |
| gcp.source.instance.project_id | ID of the project containing the VM. | keyword |
| gcp.source.instance.region | Region of the VM. | keyword |
| gcp.source.instance.zone | Zone of the VM. | keyword |
| gcp.source.vpc.project_id | ID of the project containing the VM. | keyword |
| gcp.source.vpc.subnetwork_name | Subnetwork on which the VM is operating. | keyword |
| gcp.source.vpc.vpc_name | VPC on which the VM is operating. | keyword |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.name | Name given by operators to sections of their network. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
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
