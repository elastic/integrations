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

{{fields "apiserver"}}