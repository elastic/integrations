# kube-apiserver

## Metrics

### apiserver

This is the `apiserver` dataset of the Kubernetes package, in charge of retrieving metrics
from the Kubernetes API (available at `/metrics`).

This metricset needs access to the `apiserver` component of Kubernetes, accessible typically
by any POD via the `kubernetes.default` service or via environment
variables (`KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT`).

If Leader Election is activated (default behaviour) only the `elastic agent` which holds the leadership lock
will retrieve metrics from the `apiserver`.
This is relevant in multi-node kubernetes cluster and prevents duplicate data.

When the API uses https, the pod will need to authenticate using its default token and trust
the server using the appropriate CA file.

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

{{event "apiserver"}}

{{fields "apiserver"}}