# FireEye Integration

This integration periodically fetches logs from [FireEye Network Security](https://www.fireeye.com/products/network-security.html) devices. 

## Compatibility

The FireEye `nx` integration has been developed against FireEye Network Security 9.0.0.916432 but is expected to work with other versions.

## Logs

### NX

The `nx` integration ingests network security logs from FireEye NX through TCP/UDP and file.

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
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| dns.answers.ttl | The time interval in seconds that this resource record may be cached before it should be discarded. Zero values mean that the data should not be cached. | long |
| dns.id | The DNS packet identifier assigned by the program that generated the query. The identifier is copied to the response. | float |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.response_code | The DNS response code. | keyword |
| dns.type | The type of DNS event captured, query or answer. If your source of DNS events only gives you DNS queries, you should only create dns events of type `dns.type:query`. If your source of DNS events gives you answers as well, you should create one event per query (optionally as soon as the query is seen). And a second event containing all query details as well as an array of answers. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| fireeye.nx.fileinfo.filename | File name. | keyword |
| fireeye.nx.fileinfo.magic | Fileinfo magic. | keyword |
| fireeye.nx.fileinfo.md5 | File hash. | keyword |
| fireeye.nx.fileinfo.size | File size. | long |
| fireeye.nx.fileinfo.state | File state. | keyword |
| fireeye.nx.fileinfo.stored | File stored or not. | boolean |
| fireeye.nx.flow.age | Flow age. | long |
| fireeye.nx.flow.alerted | Flow alerted or not. | boolean |
| fireeye.nx.flow.endtime | Flow endtime. | date |
| fireeye.nx.flow.reason | Flow reason. | keyword |
| fireeye.nx.flow.starttime | Flow start time. | date |
| fireeye.nx.flow.state | Flow state. | keyword |
| fireeye.nx.flow_id | Flow ID of the event. | long |
| fireeye.nx.tcp.ack | TCP acknowledgement. | boolean |
| fireeye.nx.tcp.psh | TCP PSH. | boolean |
| fireeye.nx.tcp.state | TCP connectin state. | keyword |
| fireeye.nx.tcp.syn | TCP SYN. | boolean |
| fireeye.nx.tcp.tcp_flags | TCP flags. | keyword |
| fireeye.nx.tcp.tcp_flags_tc | TCP flags. | keyword |
| fireeye.nx.tcp.tcp_flags_ts | TCP flags. | keyword |
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
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.mime_type | Mime type of the body of the request. This value must only be populated based on the content of the request body, not on the `Content-Type` header. Comparing the mime type of a request with the request's Content-Type header can be helpful in detecting threats or misconfigured clients. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| interface.name | Interface name as reported by the system. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| log.source.address | Logs Source Raw address. | keyword |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.iana_number | IANA Protocol Number. | float |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
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
| tls.client.ciphersuites | TLS cipher suites by client. | array |
| tls.client.fingerprint | TLS fingerprint. | keyword |
| tls.client.issuer | Distinguished name of subject of the issuer of the x.509 certificate presented by the client. | keyword |
| tls.client.ja3 | A hash that identifies clients based on how they perform an SSL/TLS handshake. | keyword |
| tls.client.ja3_string | A hash that identifies clients based on how they perform an SSL/TLS handshake. | keyword |
| tls.client.not_after | Date/Time indicating when client certificate is no longer considered valid. | date |
| tls.client.not_before | Date/Time indicating when client certificate is first considered valid. | date |
| tls.client.server_name | Also called an SNI, this tells the server which hostname to which the client is attempting to connect to. When this value is available, it should get copied to `destination.domain`. | keyword |
| tls.client.subject | Distinguished name of subject of the x.509 certificate presented by the client. | keyword |
| tls.client.tls_exts | TLS extensions set by client. | array |
| tls.public_keylength | TLS public key length. | long |
| tls.server.ciphersuite | TLS cipher suites by server. | array |
| tls.server.ja3s | A hash that identifies servers based on how they perform an SSL/TLS handshake. | keyword |
| tls.server.ja3s_string | A hash that identifies servers based on how they perform an SSL/TLS handshake. | keyword |
| tls.server.tls_exts | TLS extensions set by server. | array |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.path | Path of the request, such as "/search". | wildcard |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


An example event for `nx` looks as following:

```json
{
    "@timestamp": "2020-09-22T08:34:44.991Z",
    "agent": {
        "ephemeral_id": "be283a73-21df-40fd-8483-99dece22034a",
        "id": "c53ddea2-61ac-4643-8676-0c70ebf51c91",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "fireeye.nx",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "ff02:0000:0000:0000:0000:0000:0000:0001",
        "bytes": 0,
        "ip": "ff02:0000:0000:0000:0000:0000:0000:0001",
        "packets": 0,
        "port": 10001
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
        "dataset": "fireeye.nx",
        "ingested": "2021-12-31T02:15:18Z",
        "original": "{\"rawmsg\":\"{\\\"timestamp\\\":\\\"2020-09-22T08:34:44.991339+0000\\\",\\\"flow_id\\\":721570461162990,\\\"event_type\\\":\\\"flow\\\",\\\"src_ip\\\":\\\"fe80:0000:0000:0000:feec:daff:fe31:b706\\\",\\\"src_port\\\":45944,\\\"dest_ip\\\":\\\"ff02:0000:0000:0000:0000:0000:0000:0001\\\",\\\"dest_port\\\":10001,\\\"proto\\\":\\\"UDP\\\",\\\"proto_number\\\":17,\\\"ip_tc\\\":0,\\\"app_proto\\\":\\\"failed\\\",\\\"flow\\\":{\\\"pkts_toserver\\\":8,\\\"pkts_toclient\\\":0,\\\"bytes_toserver\\\":1680,\\\"bytes_toclient\\\":0,\\\"start\\\":\\\"2020-09-22T08:34:12.761326+0000\\\",\\\"end\\\":\\\"2020-09-22T08:34:12.761348+0000\\\",\\\"age\\\":0,\\\"state\\\":\\\"new\\\",\\\"reason\\\":\\\"timeout\\\",\\\"alerted\\\":false}}\\n\",\"meta_sip4\":\"192.168.1.99\",\"meta_oml\":520,\"deviceid\":\"860665216674\",\"meta_cbname\":\"fireeye-7e0de1\"}\n",
        "timezone": "+00:00",
        "type": "flow"
    },
    "fireeye": {
        "nx": {
            "flow": {
                "age": 0,
                "alerted": false,
                "endtime": "2020-09-22T08:34:12.761348+0000",
                "reason": "timeout",
                "starttime": "2020-09-22T08:34:12.761326+0000",
                "state": "new"
            },
            "flow_id": 721570461162990
        }
    },
    "host": {
        "name": "docker-fleet-agent"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "172.22.0.7:49275"
        }
    },
    "network": {
        "community_id": "1:McNAQcsUcKZYOHHZYm0sD8JiBLc=",
        "iana_number": 17,
        "protocol": "failed",
        "transport": "udp"
    },
    "observer": {
        "product": "NX",
        "vendor": "Fireeye"
    },
    "related": {
        "ip": [
            "fe80:0000:0000:0000:feec:daff:fe31:b706",
            "ff02:0000:0000:0000:0000:0000:0000:0001"
        ]
    },
    "source": {
        "address": "fe80:0000:0000:0000:feec:daff:fe31:b706",
        "bytes": 1680,
        "ip": "fe80:0000:0000:0000:feec:daff:fe31:b706",
        "packets": 8,
        "port": 45944
    },
    "tags": [
        "fireeye-nx",
        "forwarded"
    ]
}
```