# Amazon EKS

The Amazon EKS integration collects Kubernetes API audit events from Amazon CloudWatch Logs into the fixed `aws.eks_audit` dataset.

Enable EKS control-plane audit logging before starting collection. The default discovery prefix is `/aws/eks/`, and the stream filter defaults to `kube-apiserver-audit`.

## What data does this integration collect?

The Amazon EKS integration collects Kubernetes API audit logs from the EKS control plane.

## What do I need to use this integration?

The AWS principal used by Elastic Agent needs permission to discover and read the selected CloudWatch log groups, including `logs:DescribeLogGroups` and `logs:FilterLogEvents`. When prefix discovery is used across linked accounts, configure the corresponding CloudWatch cross-account access as well.

## Setup

Configure either a log group ARN, a log group name, or the `/aws/eks/` log group prefix. The Region setting is required for name and prefix modes, including the default prefix mode. ARN mode ignores the Region setting because the ARN already identifies the Region. Keep the audit stream prefix unless the EKS stream naming in the target account requires a compatible override.

Do not enable this data stream and `kubernetes.audit_logs` against the same EKS audit log groups. Duplicate collection creates duplicate audit events and can cause duplicate alerts.

Kubernetes audit request and response objects are retained in document `_source` and can contain sensitive API payloads. For Secret resources, this integration removes `data` and `stringData` from parsed request and response objects. It also removes `data`, `stringData`, and metadata annotations from every item returned by Secret list/watch responses, while retaining each item's metadata name. The `preserve_original_event` option is disabled by default; enabling it retains the unredacted raw audit JSON in `event.original`, including Secret values removed from parsed fields. Unsupported records also retain `event.original` for troubleshooting. Restrict access to `_source` and enable original-event preservation only when its diagnostic value outweighs the exposure and storage costs.

Authorization decision, authorization reason, and Pod Security audit-violation annotations have explicit searchable mappings. Other string-valued Kubernetes audit annotations are dynamically indexed as keywords after dots in annotation keys are replaced by underscores.

## Logs reference

{{event "eks_audit"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "eks_audit"}}
