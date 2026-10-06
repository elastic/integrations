# Amazon EKS

The Amazon EKS integration collects Kubernetes API audit logs from [Amazon Elastic Kubernetes Service (Amazon EKS)](https://aws.amazon.com/eks/) control-plane logging in Amazon CloudWatch Logs.

Use this integration to collect and parse the `kube-apiserver` audit trail of your EKS clusters. Visualize that data in Kibana, build detection rules on who did what to which Kubernetes resource, and reference the audit trail when investigating an incident.

## What data does this integration collect?

The Amazon EKS integration collects one type of data: logs.

**Logs** are the Kubernetes API server audit events that EKS publishes to CloudWatch Logs when the `audit` control-plane log type is enabled on a cluster. Each event records the authenticated user, the verb, the target resource, the authorization decision, the HTTP response status, and, depending on the cluster audit policy level, the request and response bodies.

The integration reads the `kube-apiserver-audit-*` log streams of EKS control-plane log groups with the `aws-cloudwatch` input, parses each record into `aws.eks.audit.*`, and projects the common security fields into ECS (`user.*`, `source.ip`, `user_agent.original`, `orchestrator.*`, `event.*`).

See more details in the [Logs reference](#logs-reference).

## What do I need to use this integration?

### Elastic Managed Enabled Integration

Elastic Managed integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Elastic Managed integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent Based Installation

- Elastic Agent must be installed
- You can install only one Elastic Agent per host.
- Elastic Agent is required to read the CloudWatch log streams and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, refer to the [AWS integration documentation](https://docs.elastic.co/integrations/aws#requirements).

The AWS principal used by Elastic Agent needs permission to discover and read the selected CloudWatch log groups: `logs:DescribeLogGroups` and `logs:FilterLogEvents`. When prefix discovery is used across linked accounts, configure the corresponding CloudWatch cross-account access as well.

## Setup

Use this integration if you only need to collect Kubernetes API audit logs from Amazon EKS.

### Enable EKS control-plane audit logging

1. Open the [Amazon EKS console](https://console.aws.amazon.com/eks/) and select the cluster.
2. On the **Observability** tab, under **Control plane logs**, select **Manage logging**.
3. Turn on the **Audit** log type and save. EKS creates the log group `/aws/eks/<cluster-name>/cluster` in CloudWatch Logs and writes audit events to `kube-apiserver-audit-*` log streams.

Alternatively, run `aws eks update-cluster-config --name <cluster-name> --logging '{"clusterLogging":[{"types":["audit"],"enabled":true}]}'`.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Amazon EKS`.
3. Select the "Amazon EKS" integration from the search results.
4. Select "Add Amazon EKS" to add the integration.
5. Configure how the EKS log groups are selected: a single **Log Group ARN**, a single **Log Group Name** (under **Advanced options**), or the **Log Group Name Prefix** (default `/aws/eks/`, which discovers every EKS cluster in the Region). ARN takes precedence over name, and name over prefix.
6. Set the **Region Name** when collecting by name or prefix, including the default prefix. If it is left empty, the integration-level **Default AWS Region** is used. ARN mode ignores the Region because the ARN already identifies it.
7. Keep the **Log Stream Prefix** at `kube-apiserver-audit` unless the stream naming in the target account differs; other control-plane streams are not Kubernetes audit events and are reported as `pipeline_error` documents.
8. Select "Save and continue" to save the integration.

### Operational notes

Do not enable this data stream and `kubernetes.audit_logs` against the same EKS audit log groups. Duplicate collection creates duplicate audit events and can cause duplicate alerts.

`cloud.region` is populated by the input in every mode. `cloud.account.id` is populated only when collecting by **Log Group ARN**, because the ARN is the only place the input exposes the account ID; name and prefix modes do not carry it.

`event.outcome` is derived from the HTTP response status when `responseStatus.code` is a positive value: codes below 400 are `success` and codes of 400 or above are `failure`. A code of `0`, which Kubernetes reports when no HTTP status was set, is ignored. This takes precedence over the `authorization.k8s.io/decision` annotation, because an authorized request can still fail with a 404, 409, or 5xx response. The annotation is used only when no response status is recorded, such as `RequestReceived` stage events.

The Kubernetes core API group is reported as `core` in `aws.eks.audit.objectRef.apiGroup` and in RBAC `rules[].apiGroups`, where the API server emits an absent key or an empty string respectively.

### Sensitive data and mapping

Kubernetes audit request and response objects are retained in document `_source` and can contain sensitive API payloads. The top-level `metadata` block is removed from every request and response object, and each item of a list response keeps only its `metadata.name`; labels, annotations, managed fields, and owner references are not retained. For Secret resources, this integration also removes `data` and `stringData` from parsed request and response objects and from every item returned by Secret list/watch responses. Request and response bodies are kept only when `objectRef.resource` identifies the resource as a single value; records whose `objectRef.resource` is missing or malformed have their bodies dropped because they cannot be redacted reliably. The `preserve_original_event` option is disabled by default; enabling it retains the unredacted raw audit JSON in `event.original`, including Secret values removed from parsed fields. Unsupported records also retain `event.original` for troubleshooting. Restrict access to `_source` and enable original-event preservation only when its diagnostic value outweighs the exposure and storage costs.

Authorization decision, authorization reason, and Pod Security audit-violation annotations have explicit searchable mappings. Other Kubernetes audit annotations are retained in `_source` with dots in annotation keys replaced by underscores, but are not indexed; to search an additional annotation, map it in a `logs-aws.eks_audit@custom` component template. `user.extra` and `impersonatedUser.extra` are mapped as `flattened` fields, with the same key normalization, so their keys stay searchable without growing the mapping.

Request and response objects are not dynamically mapped. Only the security-relevant `aws.eks.audit.requestObject.*` and `aws.eks.audit.responseObject.*` fields listed in the field reference are indexed and searchable; the rest of each API object is retained in `_source` but cannot be queried or aggregated. This keeps the field count bounded on clusters that use many custom resource definitions, where dynamically mapping arbitrary object bodies would otherwise exhaust the index field limit and cause indexing failures. To query an additional body field, add it to a `logs-aws.eks_audit@custom` component template.

## Logs reference

### EKS audit

This is the `eks_audit` dataset.

#### Example

{{event "eks_audit"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

#### Exported fields

{{fields "eks_audit"}}
