# PPBGDI Integration

This integration parses logs and metrics created by PPBGDI applications.

## Compatibility

PPBGDI logs and metrics

## Logs

### Python Logs

The `python_logs` data stream collects python logs.

An example event for `python` looks as following:

```json
{
    "@timestamp": "2024-02-27T14:28:15.178647Z",
    "data_stream": {
        "dataset": "ppbgdi.service_wmts",
        "namespace": "dev",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "created": "2024-02-27T14:28:15.178647Z",
        "duration": 18429994,
        "id": "YBwAGuD7B5sKc-TtDyAbLmdoioLi8_2dli2onGX_EC9umDKBSJPueQ==",
        "ingested": "2024-02-27T14:33:20.567053094Z",
        "module": "routes",
        "original": "{\"time\": \"2024-02-27T14:28:15.178647Z\", \"level\": \"INFO\", \"logger\": \"app.routes\", \"module\": \"routes\", \"function\": \"log_response\", \"pidTid\": \"23/7fcb07c8aea0\", \"excInfo\": false, \"request\": {\"id\": \"YBwAGuD7B5sKc-TtDyAbLmdoioLi8_2dli2onGX_EC9umDKBSJPueQ==\", \"path\": \"/1.0.0/ch.swisstopo.pixelkarte-farbe/default/current/2056/17/14/6.jpeg\", \"method\": \"GET\", \"headers\": {\"Host\": \"sys-wmts.dev.bgdi.ch\", \"User-Agent\": \"curl/7.81.0\", \"Accept\": \"*/*\", \"Cloudfront-Forwarded-Proto\": \"https\", \"If-None-Match\": \"711f45b0-d57c-11ee-8470-4f724fc49d55\", \"Via\": \"2.0 2aefdd231d9806ea2eced3399f411f80.cloudfront.net (CloudFront)\", \"X-Amz-Cf-Id\": \"YBwAGuD7B5sKc-TtDyAbLmdoioLi8_2dli2onGX_EC9umDKBSJPueQ==\", \"X-Forwarded-For\": \"10.220.53.58\", \"X-Forwarded-Host\": \"sys-wmts.dev.bgdi.ch\", \"X-Forwarded-Port\": \"80\", \"X-Forwarded-Proto\": \"http\", \"X-Forwarded-Server\": \"traefik-ingress-controller-c45nn\", \"X-Real-Ip\": \"10.220.53.58\", \"Accept-Encoding\": \"gzip\"}, \"remoteAddr\": \"10.220.52.30\"}, \"response\": {\"statusCode\": 200, \"duration\": \"0.018429994583129883\", \"headers\": {\"X-Tiles-S3-Cache\": \"miss\", \"Content-Type\": \"image/jpeg\", \"Etag\": \"\\\"d2f8aab2153c4f31d4bec0da6888bdb8\\\"\", \"X-WMS-Time\": \"0.01285\", \"X-Tile-Generation-Time\": \"0.015199\", \"Cache-Control\": \"public, max-age=3600, s-maxage=31556952\", \"Content-Length\": \"27369\"}}, \"ppbgdi\": {\"app\": {\"crs\": 2056, \"api\": {\"version\": \"1.0.0\"}, \"layer\": {\"id\": \"ch.swisstopo.pixelkarte-farbe\", \"time\": \"current\", \"column\": 14, \"row\": 6, \"zoom\": 17}}}, \"message\": \"GET /1.0.0/ch.swisstopo.pixelkarte-farbe/default/current/2056/17/14/6.jpeg - 200 OK\", \"event\": {\"created\": \"2024-02-27T14:28:15.178647Z\", \"duration\": 0.018429994583129883, \"module\": \"routes\", \"severity\": 20}, \"http\": {\"request\": {\"headers\": {\"Host\": \"sys-wmts.dev.bgdi.ch\", \"User-Agent\": \"curl/7.81.0\", \"Accept\": \"*/*\", \"Cloudfront-Forwarded-Proto\": \"https\", \"If-None-Match\": \"711f45b0-d57c-11ee-8470-4f724fc49d55\", \"Via\": \"2.0 2aefdd231d9806ea2eced3399f411f80.cloudfront.net (CloudFront)\", \"X-Amz-Cf-Id\": \"YBwAGuD7B5sKc-TtDyAbLmdoioLi8_2dli2onGX_EC9umDKBSJPueQ==\", \"X-Forwarded-For\": \"10.220.53.58\", \"X-Forwarded-Host\": \"sys-wmts.dev.bgdi.ch\", \"X-Forwarded-Port\": \"80\", \"X-Forwarded-Proto\": \"http\", \"X-Forwarded-Server\": \"traefik-ingress-controller-c45nn\", \"X-Real-Ip\": \"10.220.53.58\", \"Accept-Encoding\": \"gzip\"}, \"method\": \"GET\"}, \"response\": {\"headers\": {\"X-Tiles-S3-Cache\": \"miss\", \"Content-Type\": \"image/jpeg\", \"Etag\": \"\\\"d2f8aab2153c4f31d4bec0da6888bdb8\\\"\", \"X-WMS-Time\": \"0.01285\", \"X-Tile-Generation-Time\": \"0.015199\", \"Cache-Control\": \"public, max-age=3600, s-maxage=31556952\", \"Content-Length\": \"27369\"}, \"status_code\": 200}}, \"log\": {\"level\": \"INFO\", \"logger\": \"app.routes\", \"origin\": {\"file\": {\"line\": 34, \"name\": \"routes\"}, \"function\": \"log_response\"}}, \"url\": {\"original\": \"https://sys-wmts.dev.bgdi.ch/1.0.0/ch.swisstopo.pixelkarte-farbe/default/current/2056/17/14/6.jpeg\"}, \"process\": {\"pid\": 35, \"thread\": {\"id\": 140509985681056}}, \"service\": {\"type\": \"flask\"}}",
        "outcome": "success",
        "severity": 20
    },
    "http": {
        "request": {
            "headers": {
                "accept": "*/*",
                "accept-encoding": "gzip",
                "cloudfront-forwarded-proto": "https",
                "host": "sys-wmts.dev.bgdi.ch",
                "if-none-match": "711f45b0-d57c-11ee-8470-4f724fc49d55",
                "via": "2.0 2aefdd231d9806ea2eced3399f411f80.cloudfront.net (CloudFront)",
                "x-forwarded-for": "10.220.53.58",
                "x-forwarded-host": "sys-wmts.dev.bgdi.ch",
                "x-forwarded-port": "80",
                "x-forwarded-proto": "http",
                "x-forwarded-server": "traefik-ingress-controller-c45nn",
                "x-real-ip": "10.220.53.58"
            },
            "method": "GET"
        },
        "response": {
            "bytes": 27369,
            "headers": {
                "cache-control": "public, max-age=3600, s-maxage=31556952",
                "etag": "\"d2f8aab2153c4f31d4bec0da6888bdb8\"",
                "x-tile-generation-time": "0.015199",
                "x-tiles-s3-cache": "miss",
                "x-wms-time": "0.01285"
            },
            "mime_type": "image/jpeg",
            "status_code": 200
        }
    },
    "kubernetes": {
        "namespace_labels": {
            "env": "dev",
            "service": "service-wmts",
            "system": "wmts"
        }
    },
    "log": {
        "level": "info",
        "logger": "app.routes",
        "origin": {
            "file": {
                "line": 34,
                "name": "routes"
            },
            "function": "log_response"
        }
    },
    "message": "GET /1.0.0/ch.swisstopo.pixelkarte-farbe/default/current/2056/17/14/6.jpeg - 200 OK",
    "ppbgdi": {
        "app": {
            "api": {
                "version": "1.0.0"
            },
            "crs": 2056,
            "layer": {
                "column": 14,
                "id": "ch.swisstopo.pixelkarte-farbe",
                "row": 6,
                "time": "current",
                "zoom": 17
            },
            "system": "wmts"
        }
    },
    "process": {
        "pid": 35,
        "thread": {
            "id": 140509985681056
        }
    },
    "related": {
        "hosts": [
            "sys-wmts.dev.bgdi.ch"
        ]
    },
    "service": {
        "environment": "dev",
        "name": "service-wmts",
        "type": "flask"
    },
    "source": {
        "address": "10.220.52.30",
        "ip": "10.220.52.30"
    },
    "tags": [
        "preserve_original_event"
    ],
    "url": {
        "domain": "sys-wmts.dev.bgdi.ch",
        "extension": "jpeg",
        "original": "https://sys-wmts.dev.bgdi.ch/1.0.0/ch.swisstopo.pixelkarte-farbe/default/current/2056/17/14/6.jpeg",
        "path": "/1.0.0/ch.swisstopo.pixelkarte-farbe/default/current/2056/17/14/6.jpeg",
        "scheme": "https"
    },
    "user_agent": {
        "device": {
            "name": "Other",
            "type": "Other"
        },
        "name": "curl",
        "original": "curl/7.81.0",
        "version": "7.81.0"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| http.request.headers.\* | Not yet but already in use ecs fields | keyword |
| http.response.headers.\* | Not yet but already in use ecs fields | keyword |
| kubernetes.namespace_labels.\* | Used to set the ppbgdi.app.system field | keyword |
| kubernetes.namespace_labels.env | Used to set the service.environment field | keyword |
| kubernetes.namespace_labels.service | Used to set the service.name field | keyword |
| ppbgdi.app.crs | The projection type of the layer | long |
| ppbgdi.app.layer.column | The easting orientation of a tile | long |
| ppbgdi.app.layer.extension | The file extention | keyword |
| ppbgdi.app.layer.id | The id / name of the layer | keyword |
| ppbgdi.app.layer.row | The northing orientation of the tile | long |
| ppbgdi.app.layer.time | The publication time of the resource | keyword |
| ppbgdi.app.layer.zoom | The zoom level of the tile | long |
| ppbgdi.app.system | The BGDI system | keyword |
| user_agent.device.type | ECS beta field | keyword |

