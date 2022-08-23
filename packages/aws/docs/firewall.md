# AWS Network Firewall

This integration is used to fetch logs and metrics from [AWS Network Firewall](https://aws.amazon.com/network-firewall/)—a network protections service for Amazon VPCs.

Use the AWS Network Firewall integration to monitor the traffic entering and passing through your AWS Network Firewall. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs and metrics when troubleshooting an issue.

For example, you could use this integration to view and track when firewall rules are triggered, the top firewall source and destination countries, and the total number of events by firewall.

## Data streams

The AWS Network Firewall integration collects two types of data: logs and metrics.

**Logs** help you keep a record of events happening in AWS Network Firewall.
Logs collected by the AWS Network Firewall integration include the observer name, source and destination IP, port, country, event type, and more. See more details in the [Logs reference](#logs-reference).

**Metrics** give you insight into the state of Network Firewall.
Metrics collected by the AWS Network Firewall integration include the number of packets received, passed, and blocked by the AWS Network Firewall, and more. See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS Network Firewall service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Logs reference

The `firewall_logs` dataset collects AWS Network Firewall logs. Users can use these logs to
monitor network activity.

An example event for `firewall` looks as following:

```json
{
    "destination": {
        "geo": {
            "continent_name": "North America",
            "region_iso_code": "US-ID",
            "city_name": "Salmon",
            "country_iso_code": "US",
            "country_name": "United States",
            "region_name": "Idaho",
            "location": {
                "lon": -113.8784,
                "lat": 45.1571
            }
        },
        "as": {
            "number": 209,
            "organization": {
                "name": "CenturyLink Communications, LLC"
            }
        },
        "address": "216.160.83.57",
        "port": 80,
        "ip": "216.160.83.57",
        "domain": "216.160.83.57"
    },
    "rule": {
        "name": "Deny all",
        "id": "1024"
    },
    "source": {
        "geo": {
            "continent_name": "Europe",
            "region_iso_code": "GB-OXF",
            "city_name": "Abingdon",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "region_name": "Oxfordshire",
            "location": {
                "lon": -1.3614,
                "lat": 51.7095
            }
        },
        "as": {
            "number": 20712,
            "organization": {
                "name": "Andrews \u0026 Arnold Ltd"
            }
        },
        "address": "81.2.69.143",
        "port": 51254,
        "ip": "81.2.69.143"
    },
    "message": "",
    "url": {
        "path": "/",
        "original": "/"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "aws-firewall-logs"
    ],
    "network": {
        "protocol": "http",
        "community_id": "1:+Arv0tAf8Q00mJ6C2ho2P6pp0Io=",
        "transport": "tcp",
        "type": "ipv4"
    },
    "cloud": {
        "availability_zone": "us-east-2a",
        "provider": "aws",
        "region": "us-east-2"
    },
    "observer": {
        "name": "AWSNetworkFirewall",
        "product": "Network Firewall",
        "type": "firewall",
        "vendor": "AWS"
    },
    "@timestamp": "2021-11-18T17:27:38.039Z",
    "ecs": {
        "version": "8.0.0"
    },
    "related": {
        "ip": [
            "81.2.69.143",
            "216.160.83.57"
        ]
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "aws.firewall_logs"
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "version": "1.1"
    },
    "event": {
        "severity": 3,
        "ingested": "2021-11-18T17:14:15.243250800Z",
        "original": "{\"firewall_name\":\"AWSNetworkFirewall\",\"availability_zone\":\"us-east-2a\",\"event_timestamp\":\"1636381332\",\"event\":{\"timestamp\":\"2021-11-08T14:22:12.637611+0000\",\"flow_id\":706471429191862,\"event_type\":\"alert\",\"src_ip\":\"81.2.69.143\",\"src_port\":51254,\"dest_ip\":\"216.160.83.57\",\"dest_port\":80,\"proto\":\"TCP\",\"alert\":{\"action\":\"blocked\",\"signature_id\":1000003,\"rev\":1,\"signature\":\"Deny all other TCP traffic\",\"category\":\"\",\"severity\":3},\"http\":{\"hostname\":\"216.160.83.57\",\"url\":\"/\",\"http_user_agent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36\",\"http_method\":\"GET\",\"protocol\":\"HTTP/1.1\",\"length\":0},\"app_proto\":\"http\"}}",
        "category": [
            "network"
        ],
        "type": [
            "connection",
            "denied"
        ],
        "kind": "alert"
    },
    "aws": {
        "firewall": {
            "flow": {
                "id": "706471429191862"
            }
        }
    },
    "user_agent": {
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
        "os": {
            "name": "Mac OS X",
            "version": "10.15.7",
            "full": "Mac OS X 10.15.7"
        },
        "device": {
            "name": "Mac"
        },
        "version": "95.0.4638.69"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.firewall.flow.age | The age of the flow in seconds. | long |
| aws.firewall.flow.bytes | The number of bytes transferred in this flow. | long |
| aws.firewall.flow.end | The date/time when this flow ended. | date |
| aws.firewall.flow.id | The ID of the flow. | keyword |
| aws.firewall.flow.max_ttl | The maximum TTL for the flow. | short |
| aws.firewall.flow.min_ttl | The minimum TTL for the flow. | short |
| aws.firewall.flow.pkts | The number of packets sent in this flow. | long |
| aws.firewall.flow.start | The date/time when this flow started. | date |
| aws.firewall.tcp_flags | The bitmask value for the following TCP flags: 2=SYN,18=SYN-ACK,1=FIN,4=RST | keyword |
| aws.firewall.tcp_flags_array | List of TCP flags: 'fin, syn, rst, psh, ack, urg' | keyword |
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
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.bytes | Bytes sent from the destination to the source. | long |
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
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.version | HTTP version. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.changes.name | Short name or login of the user. | keyword |
| user.changes.name.text | Multi-field of `user.changes.name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |
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


## Metrics reference

The `firewall_metrics` dataset collects AWS Network Firewall metrics.

An example event for `firewall` looks as following:

```json
{
    "@timestamp": "2020-05-28T17:58:27.154Z",
    "service": {
        "type": "aws"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "aws": {
        "networkfirewall": {
            "metrics": {
                "PassedPackets": {
                    "sum": 0
                },
                "DroppedPackets": {
                    "sum": 4
                },
                "ReceivedPackets": {
                    "sum": 4
                }
            }
        },
        "cloudwatch": {
            "namespace": "AWS/NetworkFirewall"
        },
        "dimensions": {
            "FirewallName": "AWSNetworkFirewall",
            "AvailabilityZone": "us-east-2a",
            "Engine": "Stateful"
        }
    },
    "event": {
        "duration": 8925713800,
        "agent_id_status": "verified",
        "ingested": "2021-11-18T17:18:46Z",
        "module": "aws",
        "dataset": "aws.firewall_metrics"
    },
    "metricset": {
        "period": 60000,
        "name": "cloudwatch"
    },
    "cloud": {
        "provider": "aws",
        "region": "us-east-2",
        "account": {
            "name": "elastic-beats",
            "id": "428152502467"
        }
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "aws.firewall_metrics"
    },
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "88c94c53-cbfe-4657-9a08-527b09d94cee",
        "type": "metricbeat",
        "ephemeral_id": "d3f31d10-7f16-4834-ae22-0df946c61f92",
        "version": "7.15.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.\*.metrics.\*.\* | Metrics that returned from Cloudwatch API query. | object |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.\* | Metric dimensions. | object |
| aws.dimensions.AvailabilityZone | Availability Zone in the Region where the Network Firewall firewall is active. | keyword |
| aws.dimensions.CustomAction | Dimension for a publish metrics custom action that you defined. You can define this for a rule action in a stateless rule group or for a stateless default action in a firewall policy. | keyword |
| aws.dimensions.Engine | Rules engine that processed the packet. The value for this is either Stateful or Stateless. | keyword |
| aws.dimensions.FirewallName | Name that you specified for the Network Firewall firewall. | keyword |
| aws.networkfirewall.metrics.DroppedPackets.sum | The number of packets dropped by the Network Firewall. | long |
| aws.networkfirewall.metrics.Packets.sum | Number of packets inspected for a firewall policy or stateless rulegroup for which a custom action is defined. This metric is only used for the dimension CustomAction. | long |
| aws.networkfirewall.metrics.PassedPackets.sum | The number of packets passed by the Network Firewall. | long |
| aws.networkfirewall.metrics.ReceivedPackets.sum | The number of packets received by the Network Firewall. | long |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.tags.\* | Tag key value pairs from aws resources. | object |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |
| error.message | Error message. | match_only_text |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
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
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
