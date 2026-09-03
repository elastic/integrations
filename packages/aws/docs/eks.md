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

Request and response objects are not dynamically mapped. Only the security-relevant `aws.eks.audit.requestObject.*` and `aws.eks.audit.responseObject.*` fields listed in the field reference are indexed and searchable; the rest of each API object is retained in `_source` but cannot be queried or aggregated. This keeps the field count bounded on clusters that use many custom resource definitions, where dynamically mapping arbitrary object bodies would otherwise exhaust the index field limit and cause indexing failures. To query an additional body field, add it to a `logs-aws.eks_audit@custom` component template.

## Logs reference

An example event for `eks_audit` looks as following:

```json
{
    "@timestamp": "2026-08-05T08:00:00.000Z",
    "aws": {
        "cloudwatch": {
            "log_group": "/aws/eks/prod-cluster/cluster",
            "log_stream": "kube-apiserver-audit-123",
            "region": "us-east-1",
            "account_id": "123456789012"
        },
        "eks": {
            "cluster": {
                "name": "prod-cluster"
            },
            "log_type": "audit",
            "component": "kube-apiserver",
            "audit": {
                "apiVersion": "audit.k8s.io/v1",
                "kind": "Event",
                "level": "RequestResponse",
                "stage": "ResponseComplete",
                "requestReceivedTimestamp": "2026-08-05T08:00:00Z",
                "stageTimestamp": "2026-08-05T08:00:01Z",
                "sourceIPs": [
                    "198.51.100.10"
                ],
                "userAgent": "kubectl/v1.31.0",
                "user": {
                    "username": "arn:aws:iam::123456789012:user/alice",
                    "uid": "aws-iam-authenticator:123456789012:alice",
                    "groups": [
                        "system:authenticated"
                    ]
                },
                "auditID": "allowed-secret",
                "verb": "get",
                "requestURI": "/api/v1/secrets",
                "objectRef": {
                    "resource": "secrets",
                    "namespace": "default",
                    "name": "app-secret"
                },
                "responseStatus": {
                    "code": 200
                },
                "annotations": {
                    "authorization_k8s_io/decision": "allow",
                    "authorization_k8s_io/reason": "RBAC decision"
                }
            }
        }
    },
    "client": {
        "ip": [
            "198.51.100.10"
        ]
    },
    "cloud": {
        "account": {
            "id": "123456789012"
        },
        "provider": "aws",
        "region": "us-east-1"
    },
    "data_stream": {
        "dataset": "aws.eks_audit",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "get",
        "category": [
            "configuration"
        ],
        "dataset": "aws.eks_audit",
        "end": "2026-08-05T08:00:01.000Z",
        "id": "allowed-secret",
        "ingested": "2026-08-05T08:00:02.000Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "access"
        ]
    },
    "input": {
        "type": "aws-cloudwatch"
    },
    "orchestrator": {
        "api_version": "audit.k8s.io/v1",
        "cluster": {
            "name": "prod-cluster"
        },
        "namespace": "default",
        "resource": {
            "name": "app-secret",
            "type": "secrets"
        },
        "type": "kubernetes"
    },
    "related": {
        "ip": [
            "198.51.100.10"
        ],
        "user": [
            "aws-iam-authenticator:123456789012:alice",
            "arn:aws:iam::123456789012:user/alice"
        ]
    },
    "source": {
        "ip": [
            "198.51.100.10"
        ]
    },
    "tags": [
        "forwarded",
        "aws-eks-audit"
    ],
    "user": {
        "group": {
            "name": [
                "system:authenticated"
            ]
        },
        "id": "aws-iam-authenticator:123456789012:alice",
        "name": "arn:aws:iam::123456789012:user/alice"
    },
    "user_agent": {
        "original": "kubectl/v1.31.0"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
| aws.cloudwatch.account_id | AWS account ID that owns the CloudWatch Logs log group. | keyword |
| aws.cloudwatch.log_group | Name of the CloudWatch Logs log group from which the event was collected. | keyword |
| aws.cloudwatch.log_stream | Name of the CloudWatch Logs log stream from which the event was collected. | keyword |
| aws.cloudwatch.region | AWS Region containing the CloudWatch Logs log group. | keyword |
| aws.eks.audit.annotations | Additional string-valued Kubernetes audit annotations dynamically indexed as keywords, with dots in annotation keys replaced by underscores. | object |
| aws.eks.audit.annotations.authorization_k8s_io/decision | Kubernetes authorization decision for the request, such as allow or forbid. | keyword |
| aws.eks.audit.annotations.authorization_k8s_io/reason | Reason reported by the Kubernetes authorizer for its decision. | text |
| aws.eks.audit.annotations.pod-security_kubernetes_io/audit-violations | Pod Security admission violations reported in audit mode. | text |
| aws.eks.audit.apiVersion | Kubernetes audit API version of the event. | keyword |
| aws.eks.audit.auditID | Unique audit ID generated for the request. | keyword |
| aws.eks.audit.impersonatedUser.extra | Additional information supplied for the impersonated user. Dots in keys are replaced with underscores. | object |
| aws.eks.audit.impersonatedUser.groups | Groups to which the impersonated user belongs. | keyword |
| aws.eks.audit.impersonatedUser.uid | Unique identifier of the impersonated user. | keyword |
| aws.eks.audit.impersonatedUser.username | Name that identifies the impersonated user. | keyword |
| aws.eks.audit.kind | Kubernetes object kind of the audit event. | keyword |
| aws.eks.audit.level | Audit policy level at which the event was generated. | keyword |
| aws.eks.audit.objectRef.apiGroup | API group that contains the targeted object. The empty Kubernetes core API group is normalized to `core`. | keyword |
| aws.eks.audit.objectRef.apiVersion | Version of the API group that contains the targeted object. | keyword |
| aws.eks.audit.objectRef.name | Name of the targeted Kubernetes object. | keyword |
| aws.eks.audit.objectRef.namespace | Kubernetes namespace of the targeted object. | keyword |
| aws.eks.audit.objectRef.resource | Kubernetes resource type targeted by the request. | keyword |
| aws.eks.audit.objectRef.resourceVersion | Resource version of the targeted Kubernetes object. | keyword |
| aws.eks.audit.objectRef.subresource | Kubernetes subresource targeted by the request. | keyword |
| aws.eks.audit.objectRef.uid | Unique identifier of the targeted Kubernetes object. | keyword |
| aws.eks.audit.requestObject.apiVersion | API version of the Kubernetes object supplied in the request. | keyword |
| aws.eks.audit.requestObject.kind | Kind of the Kubernetes object supplied in the request. | keyword |
| aws.eks.audit.requestObject.roleRef.name | Name of the role referenced by the Kubernetes API request object. | keyword |
| aws.eks.audit.requestObject.rules.apiGroups | Kubernetes API groups to which the rule applies. The empty Kubernetes core API group is normalized to `core`. Because rule objects are non-nested, arrays flatten across rules and predicates on separate rule fields may match different rule objects. | keyword |
| aws.eks.audit.requestObject.rules.nonResourceURLs | Non-resource URLs to which the rule applies. | keyword |
| aws.eks.audit.requestObject.rules.resourceNames | Kubernetes resource names to which the rule applies. | keyword |
| aws.eks.audit.requestObject.rules.resources | Kubernetes resources to which the rule applies. Because rule objects are non-nested, arrays flatten across rules and predicates on separate rule fields may match different rule objects. | keyword |
| aws.eks.audit.requestObject.rules.verbs | Kubernetes verbs allowed by the rule. Because rule objects are non-nested, arrays flatten across rules and predicates on separate rule fields may match different rule objects. | keyword |
| aws.eks.audit.requestObject.spec.containers.command | Entrypoint command specified for the requested container. | text |
| aws.eks.audit.requestObject.spec.containers.image | Container image specified by the request. | keyword |
| aws.eks.audit.requestObject.spec.containers.name | Name of the requested container. | keyword |
| aws.eks.audit.requestObject.spec.containers.securityContext.allowPrivilegeEscalation | Whether the requested container allows privilege escalation. | boolean |
| aws.eks.audit.requestObject.spec.containers.securityContext.capabilities.add | Linux capabilities added to the requested container. | keyword |
| aws.eks.audit.requestObject.spec.containers.securityContext.privileged | Whether the requested container runs in privileged mode. | boolean |
| aws.eks.audit.requestObject.spec.containers.securityContext.procMount | Proc filesystem mount type configured for the requested container. | keyword |
| aws.eks.audit.requestObject.spec.containers.securityContext.runAsGroup | Primary group ID configured for processes in the requested container. | integer |
| aws.eks.audit.requestObject.spec.containers.securityContext.runAsNonRoot | Whether the requested container must run as a non-root user. | boolean |
| aws.eks.audit.requestObject.spec.containers.securityContext.runAsUser | User ID configured for processes in the requested container. | integer |
| aws.eks.audit.requestObject.spec.containers.securityContext.seccompProfile.type | Seccomp profile type configured for the requested container. | keyword |
| aws.eks.audit.requestObject.spec.containers.volumeMounts | Volume mounts specified for the requested container. | flattened |
| aws.eks.audit.requestObject.spec.extra | Additional user information supplied in an authorization review request. Dots in keys are replaced with underscores. | flattened |
| aws.eks.audit.requestObject.spec.groups | User groups evaluated by an authorization review request. | keyword |
| aws.eks.audit.requestObject.spec.hostIPC | Whether the requested workload uses the host IPC namespace. | boolean |
| aws.eks.audit.requestObject.spec.hostNetwork | Whether the requested workload uses the host network namespace. | boolean |
| aws.eks.audit.requestObject.spec.hostPID | Whether the requested workload uses the host PID namespace. | boolean |
| aws.eks.audit.requestObject.spec.resourceAttributes.group | API group evaluated by an authorization review request. | keyword |
| aws.eks.audit.requestObject.spec.resourceAttributes.name | Resource name evaluated by an authorization review request. | keyword |
| aws.eks.audit.requestObject.spec.resourceAttributes.namespace | Namespace evaluated by an authorization review request. | keyword |
| aws.eks.audit.requestObject.spec.resourceAttributes.resource | Resource type evaluated by an authorization review request. | keyword |
| aws.eks.audit.requestObject.spec.resourceAttributes.subresource | Subresource evaluated by an authorization review request. | keyword |
| aws.eks.audit.requestObject.spec.resourceAttributes.verb | Kubernetes verb evaluated by an authorization review request. | keyword |
| aws.eks.audit.requestObject.spec.resourceAttributes.version | API version evaluated by an authorization review request. | keyword |
| aws.eks.audit.requestObject.spec.restartPolicy | Restart policy specified for the requested workload. | keyword |
| aws.eks.audit.requestObject.spec.securityContext.runAsGroup | Primary group ID configured for processes in the requested workload. | integer |
| aws.eks.audit.requestObject.spec.securityContext.runAsNonRoot | Whether the requested workload requires processes to run as a non-root user. | boolean |
| aws.eks.audit.requestObject.spec.securityContext.runAsUser | User ID configured for processes in the requested workload. | integer |
| aws.eks.audit.requestObject.spec.serviceAccountName | Service account assigned to the requested workload. | keyword |
| aws.eks.audit.requestObject.spec.type | Type specified by the Kubernetes API request object. | keyword |
| aws.eks.audit.requestObject.spec.uid | User identifier evaluated by an authorization review request. | keyword |
| aws.eks.audit.requestObject.spec.user | User name evaluated by an authorization review request. | keyword |
| aws.eks.audit.requestObject.spec.volumes.hostPath | Host path volume definitions in the Kubernetes API request object. | flattened |
| aws.eks.audit.requestObject.status.allowed | Whether the authorization review request was allowed. | boolean |
| aws.eks.audit.requestObject.status.denied | Whether the authorization review request was denied. | boolean |
| aws.eks.audit.requestObject.status.evaluationError | Error encountered while evaluating the authorization review request. | text |
| aws.eks.audit.requestObject.status.reason | Reason for the authorization review decision. | text |
| aws.eks.audit.requestObject.subjects.kind | Kind of subject in the requested role binding. | keyword |
| aws.eks.audit.requestObject.subjects.name | Name of the subject in the requested role binding. | keyword |
| aws.eks.audit.requestObject.subjects.namespace | Namespace of the subject in the requested role binding. | keyword |
| aws.eks.audit.requestReceivedTimestamp | Time when the request reached the Kubernetes API server. | date |
| aws.eks.audit.requestURI | Request URI sent by the client to the Kubernetes API server. | keyword |
| aws.eks.audit.responseObject.apiVersion | API version of the Kubernetes object returned in the response. | keyword |
| aws.eks.audit.responseObject.items.metadata.name | Name of the returned Kubernetes object. | keyword |
| aws.eks.audit.responseObject.kind | Kind of the Kubernetes object returned in the response. | keyword |
| aws.eks.audit.responseObject.roleRef.kind | Kind of role referenced by the Kubernetes API response object. | keyword |
| aws.eks.audit.responseObject.roleRef.name | Name of the role referenced by the Kubernetes API response object. | keyword |
| aws.eks.audit.responseObject.rules.apiGroups | Kubernetes API groups to which the returned rule applies. The empty Kubernetes core API group is normalized to `core`. Because rule objects are non-nested, arrays flatten across rules and predicates on separate rule fields may match different rule objects. | keyword |
| aws.eks.audit.responseObject.rules.nonResourceURLs | Non-resource URLs to which the returned rule applies. | keyword |
| aws.eks.audit.responseObject.rules.resourceNames | Kubernetes resource names to which the returned rule applies. | keyword |
| aws.eks.audit.responseObject.rules.resources | Kubernetes resources to which the returned rule applies. Because rule objects are non-nested, arrays flatten across rules and predicates on separate rule fields may match different rule objects. | keyword |
| aws.eks.audit.responseObject.rules.verbs | Kubernetes verbs allowed by the returned rule. Because rule objects are non-nested, arrays flatten across rules and predicates on separate rule fields may match different rule objects. | keyword |
| aws.eks.audit.responseObject.spec.containers.securityContext.allowPrivilegeEscalation | Whether the returned container allows privilege escalation. | boolean |
| aws.eks.audit.responseObject.spec.containers.securityContext.privileged | Whether the returned container runs in privileged mode. | boolean |
| aws.eks.audit.responseObject.spec.containers.securityContext.runAsUser | User ID configured for processes in the returned container. | integer |
| aws.eks.audit.responseObject.spec.containers.volumeMounts | Volume mounts returned for the container. | flattened |
| aws.eks.audit.responseObject.spec.extra | Additional user information returned in an authorization review response. Dots in keys are replaced with underscores. | flattened |
| aws.eks.audit.responseObject.spec.groups | User groups evaluated by an authorization review response. | keyword |
| aws.eks.audit.responseObject.spec.hostIPC | Whether the returned workload uses the host IPC namespace. | boolean |
| aws.eks.audit.responseObject.spec.hostNetwork | Whether the returned workload uses the host network namespace. | boolean |
| aws.eks.audit.responseObject.spec.hostPID | Whether the returned workload uses the host PID namespace. | boolean |
| aws.eks.audit.responseObject.spec.resourceAttributes.group | API group evaluated by an authorization review response. | keyword |
| aws.eks.audit.responseObject.spec.resourceAttributes.name | Resource name evaluated by an authorization review response. | keyword |
| aws.eks.audit.responseObject.spec.resourceAttributes.namespace | Namespace evaluated by an authorization review response. | keyword |
| aws.eks.audit.responseObject.spec.resourceAttributes.resource | Resource type evaluated by an authorization review response. | keyword |
| aws.eks.audit.responseObject.spec.resourceAttributes.subresource | Subresource evaluated by an authorization review response. | keyword |
| aws.eks.audit.responseObject.spec.resourceAttributes.verb | Kubernetes verb evaluated by an authorization review response. | keyword |
| aws.eks.audit.responseObject.spec.resourceAttributes.version | API version evaluated by an authorization review response. | keyword |
| aws.eks.audit.responseObject.spec.restartPolicy | Restart policy in the returned workload specification. | keyword |
| aws.eks.audit.responseObject.spec.uid | User identifier evaluated by an authorization review response. | keyword |
| aws.eks.audit.responseObject.spec.user | User name evaluated by an authorization review response. | keyword |
| aws.eks.audit.responseObject.spec.volumes.hostPath | Host path volume definitions in the Kubernetes API response object. | flattened |
| aws.eks.audit.responseObject.status.allowed | Whether the authorization review response allowed the request. | boolean |
| aws.eks.audit.responseObject.status.denied | Whether the authorization review response denied the request. | boolean |
| aws.eks.audit.responseObject.status.evaluationError | Error encountered while evaluating the authorization review response. | text |
| aws.eks.audit.responseObject.status.reason | Reason for the authorization review decision. | text |
| aws.eks.audit.responseObject.subjects.kind | Kind of subject in the returned role binding. | keyword |
| aws.eks.audit.responseObject.subjects.name | Name of the subject in the returned role binding. | keyword |
| aws.eks.audit.responseObject.subjects.namespace | Namespace of the subject in the returned role binding. | keyword |
| aws.eks.audit.responseStatus.code | Suggested HTTP response code for the status, or 0 when not set. | integer |
| aws.eks.audit.responseStatus.details.causes.field | Field associated with the status cause. | keyword |
| aws.eks.audit.responseStatus.details.causes.message | Human-readable description of the status cause. | text |
| aws.eks.audit.responseStatus.details.causes.reason | Machine-readable reason for the status cause. | keyword |
| aws.eks.audit.responseStatus.details.group | API group associated with the status details. | keyword |
| aws.eks.audit.responseStatus.details.kind | Resource kind associated with the status details. | keyword |
| aws.eks.audit.responseStatus.details.name | Resource name associated with the status details. | keyword |
| aws.eks.audit.responseStatus.details.uid | Resource identifier associated with the status details. | keyword |
| aws.eks.audit.responseStatus.message | Human-readable description of the operation status. | text |
| aws.eks.audit.responseStatus.reason | Machine-readable reason for a failed operation. | keyword |
| aws.eks.audit.responseStatus.retryAfterSeconds | Number of seconds to wait before retrying the operation. | integer |
| aws.eks.audit.responseStatus.status | Status of the Kubernetes API operation. | keyword |
| aws.eks.audit.sourceIPs | Source IP addresses from which the request originated, including intermediate proxies. | keyword |
| aws.eks.audit.stage | Request-handling stage at which this audit event was generated. | keyword |
| aws.eks.audit.stageTimestamp | Time when the request reached the audit stage recorded by this event. | date |
| aws.eks.audit.user.extra | Additional information supplied by the authenticator for the authenticated user. Dots in keys are replaced with underscores. | object |
| aws.eks.audit.user.groups | Groups to which the authenticated user belongs. | keyword |
| aws.eks.audit.user.uid | Unique identifier of the authenticated user. | keyword |
| aws.eks.audit.user.username | Name that identifies the authenticated user. | keyword |
| aws.eks.audit.userAgent | User agent string reported by the client. This value is client supplied and must not be trusted. | text |
| aws.eks.audit.verb | Kubernetes verb associated with the request, or the lowercase HTTP method for a non-resource request. | keyword |
| aws.eks.cluster.name | Amazon EKS cluster name extracted from the CloudWatch log group. | keyword |
| aws.eks.component | Amazon EKS control-plane component. | keyword |
| aws.eks.log_type | Amazon EKS control-plane log type. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of Filebeat input. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| orchestrator.api_version | API version being used to carry out the action | keyword |
| orchestrator.cluster.name | Name of the cluster. | keyword |
| orchestrator.namespace | Namespace in which the action is taking place. | keyword |
| orchestrator.resource.name | Name of the resource being acted upon. | keyword |
| orchestrator.resource.type | Type of resource being acted upon. | keyword |
| orchestrator.type | Orchestrator cluster type (e.g. kubernetes, nomad or cloudfoundry). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.effective.group.name | Name of the group. | keyword |
| user.effective.id | Unique identifier of the user. | keyword |
| user.effective.name | Short name or login of the user. | keyword |
| user.effective.name.text | Multi-field of `user.effective.name`. | match_only_text |
| user.group.name | Name of the group. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
