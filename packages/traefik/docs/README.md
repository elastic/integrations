# Traefik Integration

## Overview

[Traefik](https://traefik.io/) is a modern reverse proxy and load balancer that helps to manage and route incoming web traffic to the user's applications. It is designed to dynamically adjust to the changes in user's infrastructure, making it easy to deploy and scale user's services. Traefik integrates well with containerized environments and provides features like automatic SSL certificate management and support for multiple backends.

Use the Traefik integration to:

- Collect logs related to access.
- Create informative visualizations to track usage trends, measure key logs, and derive actionable business insights.
- Set up alerts to minimize Mean Time to Detect (MTTD) and Mean Time to Resolve (MTTR) by quickly referencing relevant logs during troubleshooting.

## Data streams

The Traefik integration collects logs data.

Logs help User keep a record of events that happen on user's machine. Users can monitor and troubleshoot the performance of their Traefik instance by accessing the `Log` data stream, which includes client IP, host, username, request address, duration, and content.

Data streams:
- `access`: Collects information related to the client IP, host, username, request address, duration, and content.

Note:
- Users can monitor and see the log inside the ingested documents for Traefik in the `logs-*` index pattern from `Discover`.

## Compatibility

The Traefik datasets were tested with Traefik 1.6, 1.7 and 2.9 versions.

## Prerequisites

User need Elasticsearch for storing and searching user's data and Kibana for visualizing and managing it. User can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on user's own hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Traefik Integration should display a list of available dashboards. Click on the dashboard available for user's configured data stream. It should be populated with the required data.

## Metrics
Note:
- The `/health` API endpoint which is used to collect the metrics is removed from Traefik `v2` version. Please refer this [issue](https://github.com/traefik/traefik/issues/7629) for more information.
- We are currently working on the metrics collection using the suggested [alternative](https://doc.traefik.io/traefik/v2.3/observability/metrics/prometheus/). Keep a watch on this [issue](https://github.com/elastic/integrations/issues/9820) for more updates.

## Logs

### Access Logs

The `access` data stream collects Traefik access logs. This data stream collects logs related to client IP, host, username, request address, duration, and content.

An example event for `access` looks as following:

An example event for `access` looks as following:

```json
{
    "@timestamp": "2024-02-09T11:53:32.609696286Z",
    "destination": {
        "address": "10.1.25.243",
        "ip": "10.1.25.243",
        "port": 80
    },
    "ecs": {
        "version": "8.5.1"
    },
    "event": {
        "category": [
            "web"
        ],
        "created": "2020-04-28T11:07:58.223Z",
        "duration": 59518533,
        "ingested": "2024-02-13T16:08:40.190327617Z",
        "kind": "event",
        "original": "{\"ClientAddr\": \"10.10.8.105:48376\",\"ClientHost\": \"175.16.199.10\",\"ClientPort\": \"48376\",\"ClientUsername\": \"-\",\"DownstreamContentSize\": 88,\"DownstreamStatus\": 200,\"Duration\": 59518533,\"OriginContentSize\": 88,\"OriginDuration\": 59428568,\"OriginStatus\": 200,\"Overhead\": 89965,\"RequestAddr\": \"api-students.unpad.ac.id\",\"RequestContentSize\": 0,\"RequestCount\": 75,\"RequestHost\": \"api-students.unpad.ac.id\",\"RequestMethod\": \"GET\",\"RequestPath\": \"/api/v1/study/140410210038/card/comment\",\"RequestPort\": \"-\",\"RequestProtocol\": \"HTTP/1.0\",\"RequestScheme\": \"http\",\"RetryAttempts\": 0,\"RouterName\": \"app-unpad-students-api-prod-app-unpad-students-api-api-students-unpad-ac-id-api@kubernetes\",\"ServiceAddr\": \"10.1.25.243:80\",\"ServiceName\": \"app-unpad-students-api-prod-app-unpad-students-api-80@kubernetes\",\"ServiceURL\": {\"Scheme\": \"http\",\"Opaque\": \"\",\"User\": null,\"Host\": \"10.1.25.243:80\",\"Path\": \"\",\"RawPath\": \"\",\"OmitHost\": false,\"ForceQuery\": false,\"RawQuery\": \"\",\"Fragment\": \"\",\"RawFragment\": \"\"},\"StartLocal\": \"2024-02-09T11:53:32.609696286Z\",\"StartUTC\": \"2024-02-09T11:53:32.609696286Z\",\"entryPointName\": \"web\",\"level\": \"info\",\"msg\": \"\",\"time\": \"2024-02-09T11:53:32Z\"}",
        "outcome": "success",
        "type": [
            "access"
        ]
    },
    "http": {
        "request": {
            "body": {
                "bytes": 0
            },
            "method": "GET"
        },
        "response": {
            "body": {
                "bytes": 88
            },
            "status_code": 200
        },
        "version": "1.0"
    },
    "log": {
        "level": "info"
    },
    "network": {
        "community_id": "1:Mgo2d5qbyedZ2JnxvcBh0BuPcWk=",
        "transport": "tcp"
    },
    "observer": {
        "egress": {
            "interface": {
                "name": "app-unpad-students-api-prod-app-unpad-students-api-80@kubernetes"
            }
        },
        "ingress": {
            "interface": {
                "name": "web"
            }
        },
        "product": "traefik",
        "type": "proxy",
        "vendor": "traefik"
    },
    "related": {
        "ip": [
            "10.10.8.105",
            "10.1.25.243"
        ]
    },
    "source": {
        "address": "10.10.8.105:48376",
        "ip": "10.10.8.105",
        "port": 48376
    },
    "tags": [
        "preserve_original_event"
    ],
    "traefik": {
        "access": {
            "origin": {
                "content_size": 88,
                "duration": 59428568,
                "status_code": 200
            },
            "overhead": 89965,
            "request_count": 75,
            "retry_attempts": 0,
            "router": {
                "name": "app-unpad-students-api-prod-app-unpad-students-api-api-students-unpad-ac-id-api@kubernetes"
            },
            "service": {
                "url": {
                    "domain": "10.1.25.243:80",
                    "force_query": false,
                    "fragment": "",
                    "opaque": "",
                    "path": "",
                    "raw_path": "",
                    "raw_query": "",
                    "user": null
                }
            }
        }
    },
    "url": {
        "domain": "api-students.unpad.ac.id",
        "original": "/api/v1/study/140410210038/card/comment",
        "scheme": "http"
    },
    "user": {
        "name": "-"
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
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| http.request.headers.\* | The canonical headers of the monitored HTTP request. | object |
| http.response.headers.\* | The canonical headers of the monitored HTTP response. | object |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| traefik.access.origin.content_size | The content length specified by the origin server, or 0 if unspecified. | long |
| traefik.access.origin.duration | The time taken (in nanoseconds) by the origin server ('upstream') to return its response. | long |
| traefik.access.origin.headers.\* | The canonical headers of the monitored HTTP request. | object |
| traefik.access.origin.status_code | The HTTP status code returned by the origin server. If the request was handled by this Traefik instance (e.g. with a redirect), then this value will be absent (0). | long |
| traefik.access.origin.status_line | OriginStatus + Status code explanation | keyword |
| traefik.access.overhead | The processing time overhead (in nanoseconds) caused by Traefik | long |
| traefik.access.request_count | The number of requests received since the Traefik instance started. | long |
| traefik.access.retry_attempts | The amount of attempts the request was retried | long |
| traefik.access.router.name | The name of the Traefik router | keyword |
| traefik.access.service.address | The IP:port of the Traefik backend (extracted from ServiceURL) | keyword |
| traefik.access.service.duration | The time taken (in nanoseconds) by the origin server ('upstream') to return its response. | long |
| traefik.access.service.url.domain | Domain of the url | keyword |
| traefik.access.service.url.force_query | Traefik specific url field | boolean |
| traefik.access.service.url.fragment | The fragment of the url | keyword |
| traefik.access.service.url.opaque | Traefik specific url field | keyword |
| traefik.access.service.url.original | Traefik url as used in common log format | keyword |
| traefik.access.service.url.path | The path of the url | keyword |
| traefik.access.service.url.query | The query string of the url | keyword |
| traefik.access.service.url.raw_path | Traefik specific url field | keyword |
| traefik.access.service.url.raw_query | Traefik specific url field | keyword |
| traefik.access.service.url.scheme | The scheme of the url | keyword |
| traefik.access.service.url.username | The username of the url | keyword |
| traefik.access.user_identifier | Is the RFC 1413 identity of the client | keyword |

