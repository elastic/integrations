# Traefik Integration

This integration periodically fetches metrics from [Traefik](https://traefik.io/) servers. It also ingests access
logs created by the Traefik server.

## Compatibility

The Traefik datasets were tested with Traefik 1.6.

## Logs

### Access Logs

The `access` data stream collects Traefik access logs.

An example event for `access` looks as following:

```$json
{
    "@timestamp": "2021-03-18T20:39:44.000Z",
    "agent": {
        "ephemeral_id": "e500ecee-9e3f-4056-94ff-1cb0d411d7fe",
        "hostname": "docker-fleet-agent",
        "id": "945634fb-af88-4ace-ab8e-58c7177e751c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.13.0"
    },
    "data_stream": {
        "dataset": "traefik.access",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.8.0"
    },
    "elastic_agent": {
        "id": "3fe93adb-3018-49ae-933f-252502b43737",
        "snapshot": true,
        "version": "7.13.0"
    },
    "event": {
        "category": [
            "web"
        ],
        "created": "2021-03-18T20:39:53.657Z",
        "dataset": "traefik.access",
        "duration": 9000000,
        "ingested": "2021-03-18T20:39:54.688854100Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "access"
        ]
    },
    "http": {
        "request": {
            "method": "GET",
            "referrer": "-"
        },
        "response": {
            "body": {
                "bytes": 415
            },
            "status_code": 200
        },
        "version": "1.1"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/access-common.log"
        },
        "offset": 0
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "source": {
        "address": "127.0.0.1",
        "ip": "127.0.0.1"
    },
    "traefik": {
        "access": {
            "backend_url": "http://172.26.0.2:80",
            "frontend_name": "Host-backend-elastic-package-service-docker-localhost-0",
            "request_count": 1,
            "user_identifier": "-"
        }
    },
    "url": {
        "original": "/"
    },
    "user": {
        "name": "-"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "curl",
        "original": "curl/7.67.0",
        "version": "7.67.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | wildcard |
| destination.domain | Destination domain. | wildcard |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location, at the level of granularity they care about. | wildcard |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version | keyword |
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.file.path | Log path | keyword |
| log.offset | Log offset | long |
| network.community_id | A hash of source and destination IPs and ports. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
| source.port | Port of the source. | long |
| traefik.access.backend_url | The url of the backend where request is forwarded | keyword |
| traefik.access.frontend_name | The name of the frontend used | keyword |
| traefik.access.request_count | The number of requests | long |
| traefik.access.user_agent.os |  | alias |
| traefik.access.user_identifier | Is the RFC 1413 identity of the client | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string | keyword |
| user_agent.version | Version of the user agent | keyword |


## Metrics

### Health Metrics

The `health` data stream collects metrics from the Traefik server.

An example event for `health` looks as following:

```$json
{
    "@timestamp": "2021-03-18T20:40:18.823Z",
    "agent": {
        "ephemeral_id": "7679e46c-fb2a-4862-a5cb-dd23154a73c7",
        "hostname": "docker-fleet-agent",
        "id": "16ad4a02-aaa8-4069-8adf-28759817fa07",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "7.13.0"
    },
    "data_stream": {
        "dataset": "traefik.health",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "1.8.0"
    },
    "elastic_agent": {
        "id": "3fe93adb-3018-49ae-933f-252502b43737",
        "snapshot": true,
        "version": "7.13.0"
    },
    "event": {
        "dataset": "traefik.health",
        "duration": 12419800,
        "module": "traefik"
    },
    "metricset": {
        "name": "health",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_traefik_format_common_1:8080/health",
        "name": "traefik",
        "type": "traefik"
    },
    "traefik": {
        "health": {
            "response": {
                "avg_time": {
                    "us": 1708
                },
                "count": 9,
                "status_codes": {
                    "200": 9
                }
            },
            "uptime": {
                "sec": 10
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version | keyword |
| service.address | Service address | keyword |
| service.name | Name of the service data is collected from. | keyword |
| service.type | Service type | keyword |
| traefik.health.response.avg_time.us | Average response time in microseconds | long |
| traefik.health.response.count | Number of responses | long |
| traefik.health.response.status_codes.* | Number of responses per status code | object |
| traefik.health.uptime.sec | Uptime of Traefik instance in seconds | long |

