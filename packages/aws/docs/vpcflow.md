# vpcflow

## Logs

Module for the AWS virtual private cloud (VPC) logs which captures information
about the IP traffic going to and from network interfaces in VPC. These logs can
help with:

* Diagnosing overly restrictive security group rules
* Monitoring the traffic that is reaching your instance
* Determining the direction of the traffic to and from the network interfaces

Implementation based on the description of the flow logs from the
documentation that can be found in:

* Default Flow Log Format: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
* Custom Format with Traffic Through a NAT Gateway: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html
* Custom Format with Traffic Through a Transit Gateway:
  https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.vpcflow.account_id | The AWS account ID for the flow log. | keyword |
| aws.vpcflow.action | The action that is associated with the traffic, ACCEPT or REJECT. | keyword |
| aws.vpcflow.instance_id | The ID of the instance that's associated with network interface for which the traffic is recorded, if the instance is owned by you. | keyword |
| aws.vpcflow.interface_id | The ID of the network interface for which the traffic is recorded. | keyword |
| aws.vpcflow.log_status | The logging status of the flow log, OK, NODATA or SKIPDATA. | keyword |
| aws.vpcflow.pkt_dstaddr | The packet-level (original) destination IP address for the traffic. | ip |
| aws.vpcflow.pkt_srcaddr | The packet-level (original) source IP address of the traffic. | ip |
| aws.vpcflow.subnet_id | The ID of the subnet that contains the network interface for which the traffic is recorded. | keyword |
| aws.vpcflow.tcp_flags | The bitmask value for the following TCP flags: 2=SYN,18=SYN-ACK,1=FIN,4=RST | keyword |
| aws.vpcflow.tcp_flags_array | List of TCP flags: 'fin, syn, rst, psh, ack, urg' | keyword |
| aws.vpcflow.type | The type of traffic: IPv4, IPv6, or EFA. | keyword |
| aws.vpcflow.version | The VPC Flow Logs version. If you use the default format, the version is 2. If you specify a custom format, the version is 3. | keyword |
| aws.vpcflow.vpc_id | The ID of the VPC that contains the network interface for which the traffic is recorded. | keyword |
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
| event.dataset | Event dataset | constant_keyword |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
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
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |


An example event for `vpcflow` looks as following:

```json
{
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "aws.vpcflow"
    },
    "destination": {
        "port": 22,
        "address": "2001:db8:1234:a102:3304:8879:34cf:4071",
        "ip": "2001:db8:1234:a102:3304:8879:34cf:4071"
    },
    "source": {
        "address": "2001:db8:1234:a100:8d6e:3477:df66:f105",
        "port": 34892,
        "bytes": 8855,
        "packets": 54,
        "ip": "2001:db8:1234:a100:8d6e:3477:df66:f105"
    },
    "tags": [
        "preserve_original_event"
    ],
    "network": {
        "community_id": "1:hXZclvxUJScaVf0xMIJR6yW6tBQ=",
        "transport": "tcp",
        "type": "ipv6",
        "bytes": 8855,
        "iana_number": "6",
        "packets": 54
    },
    "cloud": {
        "provider": "aws",
        "account": {
            "id": "123456789010"
        }
    },
    "@timestamp": "2016-10-31T11:37:00.000Z",
    "ecs": {
        "version": "1.12.0"
    },
    "related": {
        "ip": [
            "2001:db8:1234:a100:8d6e:3477:df66:f105",
            "2001:db8:1234:a102:3304:8879:34cf:4071"
        ]
    },
    "event": {
        "ingested": "2021-09-28T19:10:43.075027100Z",
        "original": "2 123456789010 eni-1235b8ca123456789 2001:db8:1234:a100:8d6e:3477:df66:f105 2001:db8:1234:a102:3304:8879:34cf:4071 34892 22 6 54 8855 1477913708 1477913820 ACCEPT OK",
        "kind": "event",
        "start": "2016-10-31T11:35:08.000Z",
        "end": "2016-10-31T11:37:00.000Z",
        "type": "flow",
        "category": "network_traffic",
        "outcome": "allow"
    },
    "aws": {
        "vpcflow": {
            "action": "ACCEPT",
            "account_id": "123456789010",
            "log_status": "OK",
            "interface_id": "eni-1235b8ca123456789",
            "version": "2"
        }
    }
}
```
