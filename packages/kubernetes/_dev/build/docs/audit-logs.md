# audit-logs

audit-logs integration collects and parses Kubernetes audit logs.

It requires access to the log files in each Kubernetes node where the container logs are stored.
This defaults to `/var/log/kubernetes/kube-apiserver-audit.log`.