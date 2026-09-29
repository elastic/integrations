# access-logs

access-logs datastream collects and parses access logs of Istio proxy containers.

It requires access to the log files in each Kubernetes node where the container logs are stored.
This defaults to `/var/log/pods/*/istio-proxy/*.log` so that we only process logs from the sidecar container `istio-proxy` that runs inside each pod.

By default only (container parser)[https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-filestream.html#_parsers] is enabled. Additional log parsers can be added as an advanced options configuration.

The Filestream input ID includes the Kubernetes pod and container IDs:
`filestream-istio.access_logs-${kubernetes.pod.name}-${kubernetes.container.id}`.
This ensures that each Istio proxy container on a node has a unique input ID.
