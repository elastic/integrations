# DNS

## Logs

The `dns` dataset collects queries that name servers resolve for your Virtual Private Cloud (VPC) networks, as well as queries from an external entity directly to a public zone.

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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| dns.answers | An array containing an object for each answer section returned by the server. The main keys that should be present in these objects are defined by ECS. Records that have more information may contain more keys than what ECS defines. Not all DNS data sources give all details about DNS answers. At minimum, answer objects must contain the `data` key. If more information is available, map as much of it to ECS as possible, and add any additional fields to the answer objects as custom fields. | object |
| dns.answers.class | The class of DNS data contained in this resource record. | keyword |
| dns.answers.data | The data describing the resource. The meaning of this data depends on the type and class of the resource record. | keyword |
| dns.answers.name | The domain name to which this resource record pertains. If a chain of CNAME is being resolved, each answer's `name` should be the one that corresponds with the answer's `data`. It should not simply be the original `question.name` repeated. | keyword |
| dns.answers.ttl | The time interval in seconds that this resource record may be cached before it should be discarded. Zero values mean that the data should not be cached. | long |
| dns.answers.type | The type of data contained in this resource record. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.resolved_ip | Array containing all IPs seen in `answers.data`. The `answers` array can be difficult to use, because of the variety of data formats it can contain. Extracting all IP addresses seen in there to `dns.resolved_ip` makes it possible to index them as IP addresses, and makes them easier to visualize and query for. | ip |
| dns.response_code | The DNS response code. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| gcp.dns.auth_answer | Authoritative answer. | boolean |
| gcp.dns.destination_ip | Destination IP address, only applicable for forwarding cases. | ip |
| gcp.dns.egress_error | Egress proxy error. | keyword |
| gcp.dns.protocol | Protocol TCP or UDP. | keyword |
| gcp.dns.query_name | DNS query name. | keyword |
| gcp.dns.query_type | DNS query type. | keyword |
| gcp.dns.rdata | DNS answer in presentation format, truncated to 260 bytes. | keyword |
| gcp.dns.response_code | Response code. | keyword |
| gcp.dns.server_latency | Server latency. | integer |
| gcp.dns.source_ip | Source IP address of the query. | ip |
| gcp.dns.source_network | Source network of the query. | keyword |
| gcp.dns.source_type | Type of source generating the DNS query: private-zone, public-zone, forwarding-zone, forwarding-policy, peering-zone, internal, external, internet | keyword |
| gcp.dns.target_type | Type of target resolving the DNS query: private-zone, public-zone, forwarding-zone, forwarding-policy, peering-zone, internal, external, internet | keyword |
| gcp.dns.vm_instance_id | Compute Engine VM instance ID, only applicable to queries initiated by Compute Engine VMs. | keyword |
| gcp.dns.vm_instance_name | Compute Engine VM instance name, only applicable to queries initiated by Compute Engine VMs. | keyword |
| gcp.dns.vm_project_id | Google Cloud project ID, only applicable to queries initiated by Compute Engine VMs. | keyword |
| gcp.dns.vm_zone_name | Google Cloud VM zone, only applicable to queries initiated by Compute Engine VMs. | keyword |
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
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |


An example event for `dns` looks as following:

```json
{
    "@timestamp": "2022-01-23T09:16:05.341Z",
    "agent": {
        "ephemeral_id": "0b86920e-9dac-4b22-91c8-e594b22a00b4",
        "id": "08bce509-f1bf-4b71-8b6b-b8965e7a733b",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.3"
    },
    "cloud": {
        "availability_zone": "europe-west2-a",
        "instance": {
            "id": "8340998530665147",
            "name": "instance"
        },
        "project": {
            "id": "project"
        },
        "provider": "gcp",
        "region": "europe-west2"
    },
    "data_stream": {
        "dataset": "gcp.dns",
        "namespace": "ep",
        "type": "logs"
    },
    "dns": {
        "answers": [
            {
                "class": "IN",
                "data": "127.0.0.1",
                "name": "elastic.co",
                "ttl": "300",
                "type": "A"
            }
        ],
        "question": {
            "name": "elastic.co",
            "registered_domain": "elastic.co",
            "top_level_domain": "co",
            "type": "A"
        },
        "resolved_ip": [
            "127.0.0.1"
        ],
        "response_code": "NOERROR"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "08bce509-f1bf-4b71-8b6b-b8965e7a733b",
        "snapshot": false,
        "version": "8.2.3"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-06-28T02:46:41.230Z",
        "dataset": "gcp.dns",
        "id": "vwroyze8pg7y",
        "ingested": "2022-06-28T02:46:42Z",
        "kind": "event",
        "outcome": "success"
    },
    "gcp": {
        "dns": {
            "auth_answer": true,
            "protocol": "UDP",
            "query_name": "elastic.co.",
            "query_type": "A",
            "rdata": "elastic.co.\t300\tIN\ta\t127.0.0.1",
            "response_code": "NOERROR",
            "server_latency": 14,
            "source_ip": "10.154.0.3",
            "source_network": "default",
            "vm_instance_id": "8340998530665147",
            "vm_instance_name": "694119234537.instance",
            "vm_project_id": "project",
            "vm_zone_name": "europe-west2-a"
        }
    },
    "input": {
        "type": "gcp-pubsub"
    },
    "log": {
        "logger": "projects/project/logs/dns.googleapis.com%2Fdns_queries"
    },
    "network": {
        "transport": "udp"
    },
    "source": {
        "address": "10.154.0.3",
        "ip": "10.154.0.3"
    },
    "tags": [
        "forwarded",
        "gcp-dns"
    ]
}
```