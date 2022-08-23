# Load Balancing

## Logs

The `loadbalancing_logs` dataset collects logs of the requests sent to and handled by GCP Load Balancers.

An example event for `loadbalancing` looks as following:

```json
{
    "@timestamp": "2020-06-08T23:41:30.078Z",
    "agent": {
        "ephemeral_id": "1f7633a7-3410-4684-bb55-14b0bd0e2bd4",
        "hostname": "docker-fleet-agent",
        "id": "df142714-8028-4ef0-a80c-4eb03051c084",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "cloud": {
        "project": {
            "id": "PROJECT_ID"
        },
        "region": "global"
    },
    "data_stream": {
        "dataset": "gcp.loadbalancing_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "81.2.69.193",
        "ip": "81.2.69.193",
        "nat": {
            "ip": "10.5.3.1",
            "port": 9090
        },
        "port": 8080
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "df142714-8028-4ef0-a80c-4eb03051c084",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "category": "network",
        "created": "2020-06-08T23:41:30.588Z",
        "id": "1oek5rg3l3fxj7",
        "kind": "event",
        "original": "{\"insertId\":\"1oek5rg3l3fxj7\",\"jsonPayload\":{\"@type\":\"type.googleapis.com/google.cloud.loadbalancin,g.type.LoadBalancerLogEntry\",\"cacheId\":\"SFO-fbae48ad\",\"statusDetails\":\"response_from_cache\"},\"httpRequest\":{\"requestMethod\":\"GET\",\"requestUrl\":\"http://81.2.69.193:8080/static/us/three-cats.jpg\",\"requestSize\":\"577\",\"status\":304,\"responseSize\":\"157\",\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36\",\"remoteIp\":\"89.160.20.156:9989\",\"cacheHit\":true,\"cacheLookup\":true,\"serverIp\":\"10.5.3.1:9090\",\"protocol\":\"HTTP/2.0\",\"referer\":\"https://developer.mozilla.org/en-US/docs/Web/JavaScript\"},\"resource\":{\"type\":\"http_load_balancer\",\"labels\":{\"zone\":\"global\",\"url_map_name\":\"URL_MAP_NAME\",\"forwarding_rule_name\":\"FORWARDING_RULE_NAME\",\"target_proxy_name\":\"TARGET_PROXY_NAME\",\"backend_service_name\":\"\",\"project_id\":\"PROJECT_ID\"}},\"timestamp\":\"2020-06-08T23:41:30.078651Z\",\"severity\":\"INFO\",\"logName\":\"projects/PROJECT_ID/logs/requests\",\"trace\":\"projects/PROJECT_ID/traces/241d69833e64b3bf83fabac8c873d992\",\"receiveTimestamp\":\"2020-06-08T23:41:30.588272510Z\",\"spanId\":\"7b6537d3672e08e1\"}",
        "type": "info"
    },
    "gcp": {
        "load_balancer": {
            "backend_service_name": "",
            "cache_hit": true,
            "cache_id": "SFO-fbae48ad",
            "cache_lookup": true,
            "forwarding_rule_name": "FORWARDING_RULE_NAME",
            "status_details": "response_from_cache",
            "target_proxy_name": "TARGET_PROXY_NAME",
            "url_map_name": "URL_MAP_NAME"
        }
    },
    "http": {
        "request": {
            "bytes": 577,
            "method": "GET",
            "referrer": "https://developer.mozilla.org/en-US/docs/Web/JavaScript"
        },
        "response": {
            "bytes": 157,
            "status_code": 304
        },
        "version": "2.0"
    },
    "input": {
        "type": "gcp-pubsub"
    },
    "log": {
        "level": "INFO",
        "logger": "projects/PROJECT_ID/logs/requests"
    },
    "network": {
        "protocol": "http"
    },
    "related": {
        "ip": [
            "89.160.20.156",
            "81.2.69.193",
            "10.5.3.1"
        ]
    },
    "source": {
        "address": "89.160.20.156",
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.156",
        "port": 9989
    },
    "tags": [
        "forwarded",
        "gcp-firewall"
    ],
    "url": {
        "domain": "81.2.69.193",
        "extension": "jpg",
        "original": "http://81.2.69.193:8080/static/us/three-cats.jpg",
        "path": "/static/us/three-cats.jpg",
        "port": 8080,
        "scheme": "http"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36",
        "os": {
            "full": "Mac OS X 10.14.6",
            "name": "Mac OS X",
            "version": "10.14.6"
        },
        "version": "83.0.4103.61"
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gcp.load_balancer.backend_service_name | The backend service to which the load balancer is sending traffic | keyword |
| gcp.load_balancer.cache_hit | Whether or not an entity was served from cache (with or without validation). | boolean |
| gcp.load_balancer.cache_id | Indicates the location and cache instance that the cache response was served from. For example, a cache response served from a cache in Amsterdam would have a cacheId value of AMS-85e2bd4b, where AMS is the IATA code, and 85e2bd4b is an opaque identifier of the cache instance  (because some Cloud CDN locations have multiple discrete caches). | keyword |
| gcp.load_balancer.cache_lookup | Whether or not a cache lookup was attempted. | boolean |
| gcp.load_balancer.forwarding_rule_name | The name of the forwarding rule | keyword |
| gcp.load_balancer.status_details | Explains why the load balancer returned the HTTP status that it did. See https://cloud.google.com/cdn/docs/cdn-logging-monitoring#statusdetail_http_success_messages for specific messages. | keyword |
| gcp.load_balancer.target_proxy_name | The target proxy name | keyword |
| gcp.load_balancer.url_map_name | The URL map name | keyword |
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
| http.request.bytes | Total size in bytes of the request (body and headers). | long |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
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
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
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


## Metrics

The `loadbalancing_metrics` dataset fetches HTTPS, HTTP, and Layer 3 metrics from [Load Balancing](https://cloud.google.com/load-balancing/) in Google Cloud Platform. It contains all metrics exported from the [GCP Load Balancing Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-loadbalancing).

An example event for `loadbalancing` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-observability"
        },
        "provider": "gcp",
        "region": "us-central1",
        "availability_zone": "us-central1-a"
    },
    "event": {
        "dataset": "gcp.loadbalancing_metrics",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "labels": {
            "metrics": {
                "client_network": "ocp-be-c5kjr-network",
                "client_subnetwork": "ocp-be-c5kjr-worker-subnet",
                "client_zone": "us-central1-a"
            },
            "resource": {
                "backend_name": "ocp-be-c5kjr-master-us-central1-a",
                "backend_scope": "us-central1-a",
                "backend_scope_type": "ZONE",
                "backend_subnetwork_name": "ocp-be-c5kjr-master-subnet",
                "backend_target_name": "ocp-be-c5kjr-api-internal",
                "backend_target_type": "BACKEND_SERVICE",
                "backend_type": "INSTANCE_GROUP",
                "forwarding_rule_name": "ocp-be-c5kjr-api-internal",
                "load_balancer_name": "ocp-be-c5kjr-api-internal",
                "network_name": "ocp-be-c5kjr-network",
                "region": "us-central1"
            }
        },
        "loadbalancing": {
            "l3": {
                "internal": {
                    "egress_packets": {
                        "count": 100
                    },
                    "egress": {
                        "bytes": 1247589
                    }
                }
            }
        }
    },
    "metricset": {
        "name": "loadbalancing",
        "period": 10000
    },
    "service": {
        "type": "gcp"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |
| error.message | Error message. | match_only_text |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gcp.labels.metadata.\* |  | object |
| gcp.labels.metrics.\* |  | object |
| gcp.labels.resource.\* |  | object |
| gcp.labels.system.\* |  | object |
| gcp.labels.user.\* |  | object |
| gcp.loadbalancing.https.backend_request.bytes | The number of bytes sent as requests from HTTP/S load balancer to backends. | long |
| gcp.loadbalancing.https.backend_request.count | The number of requests served by backends of HTTP/S load balancer. | long |
| gcp.loadbalancing.https.backend_response.bytes | The number of bytes sent as responses from backends (or cache) to external HTTP(S) load balancer. | long |
| gcp.loadbalancing.https.request.bytes | The number of bytes sent as requests from clients to HTTP/S load balancer. | long |
| gcp.loadbalancing.https.request.count | The number of requests served by HTTP/S load balancer. | long |
| gcp.loadbalancing.https.response.bytes | The number of bytes sent as responses from HTTP/S load balancer to clients. | long |
| gcp.loadbalancing.l3.external.egress.bytes | The number of bytes sent from external TCP/UDP network load balancer backend to client of the flow. For TCP flows it's counting bytes on application stream only. | long |
| gcp.loadbalancing.l3.external.egress_packets.count | The number of packets sent from external TCP/UDP network load balancer backend to client of the flow. | long |
| gcp.loadbalancing.l3.external.ingress.bytes | The number of bytes sent from client to external TCP/UDP network load balancer backend. For TCP flows it's counting bytes on application stream only. | long |
| gcp.loadbalancing.l3.external.ingress_packets.count | The number of packets sent from client to external TCP/UDP network load balancer backend. | long |
| gcp.loadbalancing.l3.internal.egress.bytes | The number of bytes sent from ILB backend to client (for TCP flows it's counting bytes on application stream only). | long |
| gcp.loadbalancing.l3.internal.egress_packets.count | The number of packets sent from ILB backend to client of the flow. | long |
| gcp.loadbalancing.l3.internal.ingress.bytes | The number of bytes sent from client to ILB backend (for TCP flows it's counting bytes on application stream only). | long |
| gcp.loadbalancing.l3.internal.ingress_packets.count | The number of packets sent from client to ILB backend. | long |
| gcp.loadbalancing.tcp_ssl_proxy.closed_connections.value | Number of connections that were terminated over TCP/SSL proxy. | long |
| gcp.loadbalancing.tcp_ssl_proxy.egress.bytes | Number of bytes sent from VM to client using proxy. | long |
| gcp.loadbalancing.tcp_ssl_proxy.ingress.bytes | Number of bytes sent from client to VM using proxy. | long |
| gcp.loadbalancing.tcp_ssl_proxy.new_connections.value | Number of connections that were created over TCP/SSL proxy. | long |
| gcp.loadbalancing.tcp_ssl_proxy.open_connections.value | Current number of outstanding connections through the TCP/SSL proxy. | long |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |
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
