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
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "d9e5539e-58b7-4ef6-8cc4-bae2cc2bd371",
        "ephemeral_id": "ac31f6be-4cf8-41a6-b75c-fae75b037989",
        "type": "filebeat",
        "version": "7.13.0"
    },
    "temp": {},
    "log": {
        "file": {
            "path": "/tmp/service_logs/access.log"
        },
        "offset": 0
    },
    "traefik": {
        "access": {
            "user_identifier": "-",
            "frontend_name": "Host-backend-elastic-package-service-docker-localhost-0",
            "backend_url": "http://192.168.208.2:80",
            "request_count": 1
        }
    },
    "elastic_agent": {
        "id": "d74021a0-8077-11eb-ba68-77484ad090e2",
        "version": "7.13.0",
        "snapshot": true
    },
    "source": {
        "address": "127.0.0.1",
        "ip": "127.0.0.1"
    },
    "url": {
        "original": "/"
    },
    "input": {
        "type": "log"
    },
    "@timestamp": "2021-03-09T01:41:40.000Z",
    "ecs": {
        "version": "1.8.0"
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "data_stream": {
        "namespace": "ep",
        "type": "logs",
        "dataset": "traefik.access"
    },
    "http": {
        "request": {
            "referrer": "-",
            "method": "GET"
        },
        "response": {
            "status_code": 200,
            "body": {
                "bytes": 421
            }
        },
        "version": "1.1"
    },
    "event": {
        "duration": 3000000,
        "ingested": "2021-03-09T01:41:51.629660600Z",
        "created": "2021-03-09T01:41:50.601Z",
        "kind": "event",
        "category": [
            "web"
        ],
        "type": [
            "access"
        ],
        "dataset": "traefik.access",
        "outcome": "success"
    },
    "user": {
        "name": "-"
    },
    "user_agent": {
        "original": "curl/7.61.1",
        "name": "curl",
        "device": {
            "name": "Other"
        },
        "version": "7.61.1"
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
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.file.path | Log path | keyword |
| log.offset | Log offset | long |
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
| traefik.access.backend_url | The url of the backend where request is forwarded | keyword |
| traefik.access.frontend_name | The name of the frontend used | keyword |
| traefik.access.request_count | The number of requests | long |
| traefik.access.user_agent.os |  | alias |
| traefik.access.user_identifier | Is the RFC 1413 identity of the client | keyword |
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
    "@timestamp": "2021-03-09T00:52:36.203Z",
    "metricset": {
        "period": 10000,
        "name": "health"
    },
    "traefik": {
        "health": {
            "uptime": {
                "sec": 11
            },
            "response": {
                "count": 0,
                "avg_time": {
                    "us": 0
                }
            }
        }
    },
    "elastic_agent": {
        "id": "16f7c7e0-806d-11eb-99bd-6d359cadd994",
        "snapshot": true,
        "version": "7.13.0"
    },
    "ecs": {
        "version": "1.8.0"
    },
    "service": {
        "name": "traefik",
        "address": "http://elastic-package-service_traefik_1:8080/health",
        "type": "traefik"
    },
    "event": {
        "duration": 32470600,
        "dataset": "traefik.health",
        "module": "traefik"
    },
    "data_stream": {
        "type": "metrics",
        "dataset": "traefik.health",
        "namespace": "ep"
    },
    "agent": {
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "7.13.0",
        "hostname": "docker-fleet-agent",
        "ephemeral_id": "f7110082-cb5f-48b9-9385-b4cf5088c857",
        "id": "da7e3ada-935e-4e55-94ea-d9a99eb12308"
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

