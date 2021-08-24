# container-logs

container-logs integration collects and parses logs of Kubernetes containers.

It requires access to the log files in each Kubernetes node where the container logs are stored.
This defaults to `/var/log/containers/*${kubernetes.container.id}.log`.