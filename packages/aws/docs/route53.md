# Route 53

This integration is used to fetch logs from [Route 53](https://aws.amazon.com/route53/).
## Logs

### Public Hosted Zone Logs

The `route53_public_logs` dataset collects information about public DNS queries that Route 53 receives.

Query logs contain only the queries that DNS resolvers forward to Route 53. If a DNS resolver has already cached the response to a query (such as the IP address for a load balancer for example.com), the resolver will continue to return the cached response without forwarding the query to Route 53 until the TTL for the corresponding record expires.

Depending on how many DNS queries are submitted for a domain name (example.com) or subdomain name (www.example.com), which resolvers your users are using, and the TTL for the record, query logs might contain information about only one query out of every several thousand queries that are submitted to DNS resolvers.

See [Route 53 Documentation](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html) for more information

An example event for `route53_public` looks as following:

```json
{
    "awscloudwatch": {
        "log_group": "test",
        "ingestion_time": "2021-12-06T02:18:20.000Z",
        "log_stream": "test"
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "c00f804f-7a02-441b-88f4-aeb9da6410d9",
        "type": "filebeat",
        "ephemeral_id": "1cf87179-f6b3-44b0-a46f-3aa6bc0f995f",
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "c00f804f-7a02-441b-88f4-aeb9da6410d9",
        "version": "8.0.0",
        "snapshot": true
    },
    "dns": {
        "response_code": "NOERROR",
        "question": {
            "registered_domain": "example.com",
            "top_level_domain": "com",
            "name": "txt.example.com",
            "subdomain": "txt",
            "type": "TXT"
        }
    },
    "source": {
        "as": {
            "number": 721,
            "organization": {
                "name": "DoD Network Information Center"
            }
        },
        "address": "55.36.5.7",
        "ip": "55.36.5.7"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "aws-route53-logs"
    ],
    "network": {
        "protocol": "dns",
        "transport": "udp",
        "type": "ipv4",
        "iana_number": "17"
    },
    "cloud": {
        "provider": "aws",
        "region": "us-east-1"
    },
    "input": {
        "type": "aws-cloudwatch"
    },
    "@timestamp": "2017-12-13T08:16:05.744Z",
    "ecs": {
        "version": "8.0.0"
    },
    "related": {
        "hosts": [
            "txt.example.com"
        ],
        "ip": [
            "55.36.5.7"
        ]
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "aws.route53_public_logs"
    },
    "log.file.path": "test/test",
    "event": {
        "agent_id_status": "verified",
        "ingested": "2021-12-06T02:37:25Z",
        "original": "1.0 2017-12-13T08:16:05.744Z Z123412341234 txt.example.com TXT NOERROR UDP JFK5 55.36.5.7 -",
        "kind": "event",
        "id": "36545504503447201576705984279898091551471012413796646912",
        "category": [
            "network"
        ],
        "type": [
            "protocol"
        ],
        "dataset": "aws.route53_public_logs",
        "outcome": "success"
    },
    "aws": {
        "route53": {
            "hosted_zone_id": "Z123412341234",
            "edge_location": "JFK5"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.edge_location | The edge location that served the request. Each edge location is identified by a three-letter code and an arbitrarily assigned number (for example, DFW3). The three-letter code typically corresponds with the International Air Transport Association (IATA) airport code for an airport near the edge location’s geographic location. | alias |
| aws.route53.edge_location | The Route 53 edge location that responded to the query. Each edge location is identified by a three-letter code and an arbitrary number, for example, DFW3. The three-letter code typically corresponds with the International Air Transport Association airport code for an airport near the edge location. (These abbreviations might change in the future.) | keyword |
| aws.route53.edns_client_subnet | A partial IP address for the client that the request originated from, if available from the DNS resolver. | keyword |
| aws.route53.hosted_zone_id | The ID of the hosted zone that is associated with all the DNS queries in this log. | keyword |
| awscloudwatch.ingestion_time | AWS CloudWatch ingest time | date |
| awscloudwatch.log_group | AWS CloudWatch Log Group name | keyword |
| awscloudwatch.log_stream | AWS CloudWatch Log Stream name | keyword |
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
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.response_code | The DNS response code. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |


### Resolver Logs

The `route53_resolver_logs` dataset collects all DNS queries & responses for:
* Queries that originate in Amazon Virtual Private Cloud VPCs that you specify, as well as the responses to those DNS queries.
* Queries from on-premises resources that use an inbound Resolver endpoint.
* Queries that use an outbound Resolver endpoint for recursive DNS resolution.
* Queries that use Route 53 Resolver DNS Firewall rules to block, allow, or monitor domain lists.

As is standard for DNS resolvers, resolvers cache DNS queries for a length of time determined by the time-to-live (TTL) for the resolver. The Route 53 Resolver caches queries that originate in your VPCs, and responds from the cache whenever possible to speed up responses. Resolver query logging logs only unique queries, not queries that Resolver is able to respond to from the cache.

For example, suppose that an EC2 instance in one of the VPCs that a query logging configuration is logging queries for, submits a request for accounting.example.com. Resolver caches the response to that query, and logs the query. If the same instance’s elastic network interface makes a query for accounting.example.com within the TTL of the Resolver’s cache, Resolver responds to the query from the cache. The second query is not logged.

See [Route 53 Documentation](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html) for more information

An example event for `route53_resolver` looks as following:

```json
{
    "@timestamp": "2021-02-04T17:51:55.000Z",
    "agent": {
        "name": "docker-fleet-agent",
        "id": "c00f804f-7a02-441b-88f4-aeb9da6410d9",
        "type": "filebeat",
        "ephemeral_id": "1cf87179-f6b3-44b0-a46f-3aa6bc0f995f",
        "version": "8.0.0"
    },
    "aws": {
        "route53": {
            "firewall": {
                "rule_group": {
                    "id": "rslvr-frg-01234567890abcdef"
                },
                "action": "BLOCK",
                "domain_list": {
                    "id": "rslvr-fdl-01234567890abcdef"
                }
            }
        },
        "vpc_id": "vpc-7example",
        "instance_id": "i-0d15cd0d3example"
    },
    "awscloudwatch": {
        "log_group": "test",
        "ingestion_time": "2021-12-06T02:18:20.000Z",
        "log_stream": "test"
    },
    "cloud": {
        "instance": {
            "id": "i-0d15cd0d3example"
        },
        "region": "us-east-1",
        "provider": "aws",
        "account": {
            "id": "111122223333"
        }
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "aws.route53_public_logs"
    },
    "dns": {
        "question": {
            "name": "15.3.4.32.in-addr.arpa",
            "subdomain": "15.3.4",
            "registered_domain": "32.in-addr.arpa",
            "type": "PTR",
            "top_level_domain": "in-addr.arpa",
            "class": "IN"
        },
        "answers": [
            {
                "data": "203.0.113.9",
                "type": "PTR",
                "class": "IN"
            }
        ],
        "response_code": "NOERROR"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "c00f804f-7a02-441b-88f4-aeb9da6410d9",
        "version": "8.0.0",
        "snapshot": true
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2021-12-12T00:28:02.201047005Z",
        "original": "{\"srcaddr\":\"4.5.64.102\",\"vpc_id\":\"vpc-7example\",\"answers\":[{\"Rdata\":\"203.0.113.9\",\"Type\":\"PTR\",\"Class\":\"IN\"}],\"firewall_rule_group_id\":\"rslvr-frg-01234567890abcdef\",\"firewall_rule_action\":\"BLOCK\",\"query_name\":\"15.3.4.32.in-addr.arpa.\",\"firewall_domain_list_id\":\"rslvr-fdl-01234567890abcdef\",\"query_class\":\"IN\",\"srcids\":{\"instance\":\"i-0d15cd0d3example\"},\"rcode\":\"NOERROR\",\"query_type\":\"PTR\",\"transport\":\"UDP\",\"version\":\"1.100000\",\"account_id\":\"111122223333\",\"srcport\":\"56067\",\"query_timestamp\":\"2021-02-04T17:51:55Z\",\"region\":\"us-east-1\"}",
        "category": [
            "network"
        ],
        "type": [
            "protocol"
        ],
        "kind": "event",
        "outcome": "success",
        "dataset": "aws.route53_resolver_logs"
    },
    "input": {
        "type": "aws-cloudwatch"
    },
    "log.file.path": "test/test",
    "network": {
        "protocol": "dns",
        "transport": "udp",
        "type": "ipv4",
        "iana_number": "17"
    },
    "related": {
        "hosts": [
            "15.3.4.32.in-addr.arpa"
        ],
        "ip": [
            "4.5.64.102"
        ]
    },
    "source": {
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
            "number": 3356,
            "organization": {
                "name": "Level 3 Parent, LLC"
            }
        },
        "address": "4.5.64.102",
        "port": 56067,
        "ip": "4.5.64.102"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "aws-route53_resolver-logs"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.instance_id | The ID of the instance that's associated with network interface for which the traffic is recorded, if the instance is owned by you. | keyword |
| aws.route53.firewall.action | The action specified by the rule that matched the domain name in the query. This is populated only if DNS Firewall found a match for a rule with action set to alert or block. | keyword |
| aws.route53.firewall.domain_list.id | The domain list used by the rule that matched the domain name in the query. This is populated only if DNS Firewall found a match for a rule with action set to alert or block. | keyword |
| aws.route53.firewall.rule_group.id | The ID of the DNS Firewall rule group that matched the domain name in the query. This is populated only if DNS Firewall found a match for a rule with action set to alert or block. | keyword |
| aws.vpc_id | The ID of the VPC that contains the network interface for which the traffic is recorded. | keyword |
| awscloudwatch.ingestion_time | AWS CloudWatch ingest time | date |
| awscloudwatch.log_group | AWS CloudWatch Log Group name | keyword |
| awscloudwatch.log_stream | AWS CloudWatch Log Stream name | keyword |
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
| dns.answers | An array containing an object for each answer section returned by the server. The main keys that should be present in these objects are defined by ECS. Records that have more information may contain more keys than what ECS defines. Not all DNS data sources give all details about DNS answers. At minimum, answer objects must contain the `data` key. If more information is available, map as much of it to ECS as possible, and add any additional fields to the answer objects as custom fields. | object |
| dns.question.class | The class of records being queried. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.response_code | The DNS response code. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
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

