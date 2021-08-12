# kube-pod-logs

kube-pod-logs integration collects and parses logs of Kubernetes pods.

It requires access to the log files in each Kubernetes node where the pod logs are stored.
This defaults to `/var/log/containers/*${kubernetes.container.id}.log`.