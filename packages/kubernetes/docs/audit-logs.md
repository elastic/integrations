# audit-logs

audit-logs integration collects and parses Kubernetes audit logs.

It requires access to the log files on each Kubernetes node where the audit logs are stored.
This defaults to `/var/log/kubernetes/kube-apiserver-audit.log`.