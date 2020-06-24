# Kubernetes integration

This integration is used to collect metrics from 
[Kubernetes clusters](https://kubernetes.io/).

## Compatibility

The Kubernetes package is tested with Kubernetes 1.13.x, 1.14.x, 1.15.x, 1.16.x, 1.17.x, and 1.18.x

## Metrics

### apiserver

This is the `apiserver` dataset of the Kubernetes package, in charge of retrieving metrics
from the Kubernetes API (available at `/metrics`).

This metricset needs access to the `apiserver` component of Kubernetes, accessible typically
by any POD via the `kubernetes.default` service or via environment
variables (`KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT`).

When the API uses https, the pod will need to authenticate using its default token and trust
the server using the appropiate CA file.

Configuration example using https and token based authentication:


In order to access the `/metrics` path of the API service, some Kubernetes environments might
require the following permission to be added to a ClusterRole.

```yaml
rules:
- nonResourceURLs:
  - /metrics
  verbs:
  - get
```

An example event for `apiserver` looks as following:

```$json
{
    "@timestamp": "2019-03-01T08:05:34.853Z",
    "event": {
        "dataset": "kubernetes.apiserver",
        "duration": 115000,
        "module": "kubernetes"
    },
    "kubernetes": {
        "apiserver": {
            "etcd": {
                "object": {
                    "count": 0
                }
            },
            "request": {
                "resource": "certificatesigningrequests.certificates.k8s.io"
            }
        }
    },
    "metricset": {
        "name": "apiserver",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:55555",
        "type": "kubernetes"
    }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.apiserver.audit.event.count | Number of audit events | long |
| kubernetes.apiserver.audit.rejected.count | Number of audit rejected events | long |
| kubernetes.apiserver.client.request.count | Number of requests as client | long |
| kubernetes.apiserver.etcd.object.count | Number of kubernetes objects at etcd | long |
| kubernetes.apiserver.http.request.count | Request count for response | long |
| kubernetes.apiserver.http.request.duration.us.count | Request count for duration | long |
| kubernetes.apiserver.http.request.duration.us.percentile.* | Request duration microseconds percentiles | object |
| kubernetes.apiserver.http.request.duration.us.sum | Request duration microseconds cumulative sum | double |
| kubernetes.apiserver.http.request.size.bytes.count | Request count for size | long |
| kubernetes.apiserver.http.request.size.bytes.percentile.* | Request size percentiles | object |
| kubernetes.apiserver.http.request.size.bytes.sum | Request size cumulative sum | long |
| kubernetes.apiserver.http.response.size.bytes.count | Response count | long |
| kubernetes.apiserver.http.response.size.bytes.percentile.* | Response size percentiles | object |
| kubernetes.apiserver.http.response.size.bytes.sum | Response size cumulative sum | long |
| kubernetes.apiserver.process.cpu.sec | CPU seconds | double |
| kubernetes.apiserver.process.fds.open.count | Number of open file descriptors | long |
| kubernetes.apiserver.process.memory.resident.bytes | Bytes in resident memory | long |
| kubernetes.apiserver.process.memory.virtual.bytes | Bytes in virtual memory | long |
| kubernetes.apiserver.process.started.sec | Seconds since the process started | double |
| kubernetes.apiserver.request.client | Client executing requests | keyword |
| kubernetes.apiserver.request.code | HTTP code | keyword |
| kubernetes.apiserver.request.component | Component handling the request | keyword |
| kubernetes.apiserver.request.content_type | Request HTTP content type | keyword |
| kubernetes.apiserver.request.count | Number of requests | long |
| kubernetes.apiserver.request.current.count | Inflight requests | long |
| kubernetes.apiserver.request.dry_run | Wether the request uses dry run | keyword |
| kubernetes.apiserver.request.duration.us.bucket.* | Request duration, histogram buckets | object |
| kubernetes.apiserver.request.duration.us.count | Request duration, number of operations | long |
| kubernetes.apiserver.request.duration.us.sum | Request duration, sum in microseconds | long |
| kubernetes.apiserver.request.group | API group for the resource | keyword |
| kubernetes.apiserver.request.handler | Request handler | keyword |
| kubernetes.apiserver.request.host | Request host | keyword |
| kubernetes.apiserver.request.kind | Kind of request | keyword |
| kubernetes.apiserver.request.latency.bucket.* | Request latency histogram buckets | object |
| kubernetes.apiserver.request.latency.count | Request latency, number of requests | long |
| kubernetes.apiserver.request.latency.sum | Requests latency, sum of latencies in microseconds | long |
| kubernetes.apiserver.request.longrunning.count | Number of requests active long running requests | long |
| kubernetes.apiserver.request.method | HTTP method | keyword |
| kubernetes.apiserver.request.resource | Requested resource | keyword |
| kubernetes.apiserver.request.scope | Request scope (cluster, namespace, resource) | keyword |
| kubernetes.apiserver.request.subresource | Requested subresource | keyword |
| kubernetes.apiserver.request.verb | HTTP verb | keyword |
| kubernetes.apiserver.request.version | version for the group | keyword |
