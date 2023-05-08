# audit-logs

audit-logs integration collects and parses Kubernetes audit logs.

It requires access to the log files on each Kubernetes node where the audit logs are stored.
This defaults to `/var/log/kubernetes/kube-apiserver-audit.log`.

An example event for `audit` looks as following:

```json
{
    "kubernetes": {
        "audit": {
            "auditID": "bcacfeaa-5ab5-48de-8bac-3a87d1474b6a",
            "requestReceivedTimestamp": "2022-08-31T08:09:39.660940Z",
            "level": "RequestResponse",
            "kind": "Event",
            "verb": "get",
            "annotations": {
                "authorization_k8s_io/decision": "allow",
                "authorization_k8s_io/reason": "RBAC: allowed by ClusterRoleBinding \"system:public-info-viewer\" of ClusterRole \"system:public-info-viewer\" to Group \"system:unauthenticated\""
            },
            "userAgent": "kube-probe/1.24",
            "requestURI": "/readyz",
            "responseStatus": {
                "metadata": {},
                "code": 200
            },
            "stageTimestamp": "2022-08-31T08:09:39.662241Z",
            "sourceIPs": [
                "172.18.0.2"
            ],
            "apiVersion": "audit.k8s.io/v1",
            "stage": "ResponseComplete",
            "user": {
                "groups": [
                    "system:unauthenticated"
                ],
                "username": "system:anonymous"
            }
        }
    },
    "input": {
        "type": "filestream"
    },
    "agent": {
        "name": "kind-control-plane",
        "id": "6e730a0c-7da5-48ff-b4c9-f6c63844975d",
        "type": "filebeat",
        "ephemeral_id": "d27511c8-9cd1-402c-8b1b-234abbd9dcae",
        "version": "8.4.0"
    },
    "@timestamp": "2022-08-31T08:09:57.520Z",
    "ecs": {
        "version": "8.0.0"
    },
    "log": {
        "file": {
            "path": "/var/log/kubernetes/kube-apiserver-audit-1.log"
        },
        "offset": 20995
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "kubernetes.audit_logs"
    },
    "host": {
        "hostname": "kind-control-plane",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "20.04.4 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "10.244.0.1",
            "10.244.0.1",
            "10.244.0.1",
            "172.30.0.3",
            "172.18.0.2",
            "fc00:f853:ccd:e793::2",
            "fe80::42:acff:fe12:2"
        ],
        "name": "kind-control-plane",
        "id": "5016511f0829451ea244f458eebf2212",
        "mac": [
            "02:42:ac:12:00:02",
            "02:42:ac:1e:00:03",
            "3a:ba:49:df:78:35",
            "86:c7:fe:c8:fa:22",
            "d6:48:c1:a2:a4:15"
        ],
        "architecture": "x86_64"
    },
    "elastic_agent": {
        "id": "6e730a0c-7da5-48ff-b4c9-f6c63844975d",
        "version": "8.4.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2022-08-31T08:09:58Z",
        "dataset": "kubernetes.audit_logs"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. If no name is given, the name is often left empty. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.dataset | Event Dataset. | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of input. | keyword |
| kubernetes.audit.annotations.authorization_k8s_io/decision |  | keyword |
| kubernetes.audit.annotations.authorization_k8s_io/reason |  | text |
| kubernetes.audit.apiVersion | Audit event api version | keyword |
| kubernetes.audit.auditID | Unique audit ID, generated for each request | keyword |
| kubernetes.audit.impersonatedUser.extra.\* | Any additional information provided by the authenticator | object |
| kubernetes.audit.impersonatedUser.groups | The names of groups this user is a part of | text |
| kubernetes.audit.impersonatedUser.uid | A unique value that identifies this user across time. If this user is deleted and another user by the same name is added, they will have different UIDs | keyword |
| kubernetes.audit.impersonatedUser.username | The name that uniquely identifies this user among all active users | keyword |
| kubernetes.audit.kind | Kind of the audit event | keyword |
| kubernetes.audit.level | AuditLevel at which event was generated | keyword |
| kubernetes.audit.objectRef.apiGroup | The name of the API group that contains the referred object. The empty string represents the core API group. | keyword |
| kubernetes.audit.objectRef.apiVersion | The version of the API group that contains the referred object | keyword |
| kubernetes.audit.objectRef.name |  | keyword |
| kubernetes.audit.objectRef.namespace |  | keyword |
| kubernetes.audit.objectRef.resource |  | keyword |
| kubernetes.audit.objectRef.resourceVersion |  | keyword |
| kubernetes.audit.objectRef.subresource |  | keyword |
| kubernetes.audit.objectRef.uid |  | keyword |
| kubernetes.audit.requestObject.rules |  | nested |
| kubernetes.audit.requestObject.spec.containers.image |  | text |
| kubernetes.audit.requestObject.spec.containers.securityContext.allowPrivilegeEscalation |  | boolean |
| kubernetes.audit.requestObject.spec.containers.securityContext.capabilities.add |  | keyword |
| kubernetes.audit.requestObject.spec.containers.securityContext.privileged |  | boolean |
| kubernetes.audit.requestObject.spec.containers.securityContext.procMount |  | keyword |
| kubernetes.audit.requestObject.spec.containers.securityContext.runAsGroup |  | integer |
| kubernetes.audit.requestObject.spec.containers.securityContext.runAsNonRoot |  | boolean |
| kubernetes.audit.requestObject.spec.containers.securityContext.runAsUser |  | integer |
| kubernetes.audit.requestObject.spec.containers.volumeMounts |  | flattened |
| kubernetes.audit.requestObject.spec.hostIPC |  | boolean |
| kubernetes.audit.requestObject.spec.hostNetwork |  | boolean |
| kubernetes.audit.requestObject.spec.hostPID |  | boolean |
| kubernetes.audit.requestObject.spec.restartPolicy |  | keyword |
| kubernetes.audit.requestObject.spec.securityContext.runAsGroup |  | integer |
| kubernetes.audit.requestObject.spec.securityContext.runAsNonRoot |  | boolean |
| kubernetes.audit.requestObject.spec.securityContext.runAsUser |  | integer |
| kubernetes.audit.requestObject.spec.serviceAccountName |  | keyword |
| kubernetes.audit.requestObject.spec.type |  | keyword |
| kubernetes.audit.requestObject.spec.volumes.hostPath |  | flattened |
| kubernetes.audit.requestReceivedTimestamp | Time the request reached the apiserver | date |
| kubernetes.audit.requestURI | RequestURI is the request URI as sent by the client to a server | keyword |
| kubernetes.audit.responseObject.roleRef.kind |  | keyword |
| kubernetes.audit.responseObject.rules |  | nested |
| kubernetes.audit.responseObject.spec.containers.securityContext.allowPrivilegeEscalation |  | boolean |
| kubernetes.audit.responseObject.spec.containers.securityContext.privileged |  | boolean |
| kubernetes.audit.responseObject.spec.containers.securityContext.runAsUser |  | integer |
| kubernetes.audit.responseObject.spec.containers.volumeMounts |  | flattened |
| kubernetes.audit.responseObject.spec.hostIPC |  | boolean |
| kubernetes.audit.responseObject.spec.hostNetwork |  | boolean |
| kubernetes.audit.responseObject.spec.hostPID |  | boolean |
| kubernetes.audit.responseObject.spec.restartPolicy |  | keyword |
| kubernetes.audit.responseObject.spec.volumes.hostPath |  | flattened |
| kubernetes.audit.responseStatus.code | Suggested HTTP return code for this status, 0 if not set | integer |
| kubernetes.audit.responseStatus.message | A human-readable description of the status of this operation | text |
| kubernetes.audit.responseStatus.reason | A machine-readable description of why this operation is in the "Failure" status. If this value is empty there is no information available. A Reason clarifies an HTTP status code but does not override it | keyword |
| kubernetes.audit.responseStatus.status | Status of the operation | keyword |
| kubernetes.audit.sourceIPs | Source IPs, from where the request originated and intermediate proxies | text |
| kubernetes.audit.stage | Stage of the request handling when this event instance was generated | keyword |
| kubernetes.audit.stageTimestamp | Time the request reached current audit stage | date |
| kubernetes.audit.user.extra.\* | Any additional information provided by the authenticator | object |
| kubernetes.audit.user.groups | The names of groups this user is a part of | text |
| kubernetes.audit.user.uid | A unique value that identifies this user across time. If this user is deleted and another user by the same name is added, they will have different UIDs | keyword |
| kubernetes.audit.user.username | The name that uniquely identifies this user among all active users | keyword |
| kubernetes.audit.userAgent | UserAgent records the user agent string reported by the client. Note that the UserAgent is provided by the client, and must not be trusted | keyword |
| kubernetes.audit.verb | Verb is the kubernetes verb associated with the request. For non-resource requests, this is the lower-cased HTTP method | keyword |
| log.file.path | Path to the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |

