# container-logs

container-logs integration collects and parses logs of Kubernetes containers.

It requires access to the log files in each Kubernetes node where the container logs are stored.
This defaults to `/var/log/containers/*${kubernetes.container.id}.log`.

By default only {{ url "filebeat-input-filestream-parsers" "container parser" }} is enabled. Additional log parsers can be added as an advanced options configuration.

## Rerouting based on pod labels

You can customize the routing of the container logs by using Kubernetes labels applied to pods.

The integration can use Kubernetes labels on pods to reroute the logs document to a different dataset or namespace without writing a custom pipeline.

To route the document logs to a different dataset, you can set the `kubernetes.labels.elastic.co/dataset` label with the value of the desired dataset.

To route the document logs to a different namespace, you can set the `kubernetes.labels.elastic.co/namespace` label with the value of the desired namespace.
