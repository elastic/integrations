# audit-logs

Audit logs integration collects and parses Kubernetes audit logs.

Audit logs can be collected from managed Kubernetes services in cloud providers:

- Amazon EKS: Configure the aws-cloudwatch input to collect audit logs from a CloudWatch log group where EKS audit logs are published.
- Azure AKS: Use the azure-eventhub input to receive audit logs from an Event Hub configured to stream AKS diagnostic logs.
- Google GKE: Use the gcp-pubsub input to subscribe to a Pub/Sub topic that receives GKE audit logs via Log Router sinks.

To enable these, configure the corresponding input with access credentials and the appropriate log stream or topic.

To collect audit logs from local k8s deployments, it requires access to the log files on each Kubernetes node where the audit logs are stored.
This defaults to `/var/log/kubernetes/kube-apiserver-audit.log`.

{{event "audit_logs"}}

{{fields "audit_logs"}}
