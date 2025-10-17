# Audit

## Logs

The `audit` dataset collects audit logs of administrative activities and accesses within your Google Cloud resources.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| actor.entity.id | ID or multiple IDs of the entity performing the action described by the event. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gcp.audit.access.caller_ip_geo.region_code |  | keyword |
| gcp.audit.access.method_name |  | keyword |
| gcp.audit.access.principal_email |  | keyword |
| gcp.audit.access.principal_subject |  | keyword |
| gcp.audit.access.service_name |  | keyword |
| gcp.audit.access.user_agent |  | keyword |
| gcp.audit.action_time |  | date |
| gcp.audit.action_type |  | keyword |
| gcp.audit.affected_resources |  | keyword |
| gcp.audit.authentication_info.authority_selector | The authority selector specified by the requestor, if any. It is not guaranteed  that the principal was allowed to use this authority. | keyword |
| gcp.audit.authentication_info.principal_email | The email address of the authenticated user making the request. | keyword |
| gcp.audit.authentication_info.principal_subject | String representation of identity of requesting party. Populated for both first and third party identities. Only present for APIs that support third-party identities. | keyword |
| gcp.audit.authentication_info.service_account_delegation_info | Identity delegation history of an authenticated service account that makes the request. It contains information on the real authorities that try to access GCP resources by delegating on a service account. When multiple authorities present, they are guaranteed to be sorted based on the original ordering of the identity delegation events. | flattened |
| gcp.audit.authentication_info.service_account_key_name | The service account key that was used to request the OAuth 2.0 access token. This field identifies the service account key by its full resource name. | keyword |
| gcp.audit.authentication_info.third_party_principal | The third party identification (if any) of the authenticated user making the request. When the JSON object represented here has a proto equivalent, the proto name will be indicated in the @type property. | flattened |
| gcp.audit.authorization_info | Authorization information for the operation. | nested |
| gcp.audit.authorization_info.granted | Whether or not authorization for resource and permission was granted. | boolean |
| gcp.audit.authorization_info.permission | The required IAM permission. | keyword |
| gcp.audit.authorization_info.resource | The resource being accessed, as a REST-style string. | keyword |
| gcp.audit.authorization_info.resource_attributes.name | The name of the resource. | keyword |
| gcp.audit.authorization_info.resource_attributes.service | The name of the service. | keyword |
| gcp.audit.authorization_info.resource_attributes.type | The type of the resource. | keyword |
| gcp.audit.flattened | Contains the full audit document as sent by GCP. | flattened |
| gcp.audit.labels | A map of key, value pairs that provides additional information about the log entry. The labels can be user-defined or system-defined. | flattened |
| gcp.audit.learn_more_uri |  | keyword |
| gcp.audit.logentry_operation.first | Optional. Set this to True if this is the first log entry in the operation. | boolean |
| gcp.audit.logentry_operation.id | Optional. An arbitrary operation identifier. Log entries with the same identifier are assumed to be part of the same operation. | keyword |
| gcp.audit.logentry_operation.last | Optional. Set this to True if this is the last log entry in the operation. | boolean |
| gcp.audit.logentry_operation.producer | Optional. An arbitrary producer identifier. The combination of id and producer must be globally unique. | keyword |
| gcp.audit.metadata | Service-specific data about the request, response, and other information associated with the current audited event. | flattened |
| gcp.audit.method_name | The name of the service method or operation. For API calls, this  should be the name of the API method.  For example, 'google.datastore.v1.Datastore.RunQuery'. | keyword |
| gcp.audit.num_response_items | The number of items returned from a List or Query API method, if applicable. | long |
| gcp.audit.policy_violation_info.payload | Resource payload that is currently in scope and is subjected to orgpolicy conditions. | flattened |
| gcp.audit.policy_violation_info.resource_tags | Tags referenced on the resource at the time of evaluation. | flattened |
| gcp.audit.policy_violation_info.resource_type | Resource type that the orgpolicy is checked against. | keyword |
| gcp.audit.policy_violation_info.violations.checkedValue | Value that is being checked for the policy. | keyword |
| gcp.audit.policy_violation_info.violations.constraint | Constraint name. | keyword |
| gcp.audit.policy_violation_info.violations.errorMessage | Error message that policy is indicating. | keyword |
| gcp.audit.policy_violation_info.violations.policyType | Indicates the type of the policy. | keyword |
| gcp.audit.receive_timestamp |  | date |
| gcp.audit.request |  | flattened |
| gcp.audit.request_metadata.caller_ip | The IP address of the caller. | ip |
| gcp.audit.request_metadata.caller_supplied_user_agent | The user agent of the caller. This information is not authenticated and  should be treated accordingly. | keyword |
| gcp.audit.request_metadata.raw.caller_ip | The raw IP address of the caller. | keyword |
| gcp.audit.resource.labels.resource_container |  | keyword |
| gcp.audit.resource.type |  | keyword |
| gcp.audit.resource_location.current_locations | Current locations of the resource. | keyword |
| gcp.audit.resource_name | The resource or collection that is the target of the operation.  The name is a scheme-less URI, not including the API service name.  For example, 'shelves/SHELF_ID/books'. | keyword |
| gcp.audit.response |  | flattened |
| gcp.audit.service_name | The name of the API service performing the operation.  For example, datastore.googleapis.com. | keyword |
| gcp.audit.source_log_ids.insert_id |  | keyword |
| gcp.audit.source_log_ids.log_time |  | date |
| gcp.audit.source_log_ids.query_uri |  | keyword |
| gcp.audit.source_log_ids.resource_container |  | keyword |
| gcp.audit.status.code | The status code, which should be an enum value of google.rpc.Code. | integer |
| gcp.audit.status.details | A list of messages that carry the error details. | flattened |
| gcp.audit.status.message | A developer-facing error message, which should be in English. Any user-facing  error message should be localized and sent in the google.rpc.Status.details  field, or localized by the client. | keyword |
| gcp.audit.type | Type property. | keyword |
| gcp.destination.instance.project_id | ID of the project containing the VM. | keyword |
| gcp.destination.instance.region | Region of the VM. | keyword |
| gcp.destination.instance.zone | Zone of the VM. | keyword |
| gcp.destination.vpc.project_id | ID of the project containing the VM. | keyword |
| gcp.destination.vpc.subnetwork_name | Subnetwork on which the VM is operating. | keyword |
| gcp.destination.vpc.vpc_name | VPC on which the VM is operating. | keyword |
| gcp.source.instance.project_id | ID of the project containing the VM. | keyword |
| gcp.source.instance.region | Region of the VM. | keyword |
| gcp.source.instance.zone | Zone of the VM. | keyword |
| gcp.source.vpc.project_id | ID of the project containing the VM. | keyword |
| gcp.source.vpc.subnetwork_name | Subnetwork on which the VM is operating. | keyword |
| gcp.source.vpc.vpc_name | VPC on which the VM is operating. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| related.entity | A collection of all entity identifiers associated with the document. If the document  contains multiple entities, identifiers for each will be included. Example identifiers include (but not limited to) cloud resource IDs, email addresses, and hostnames. | keyword |
| target.entity.id | ID or multiple IDs of the entity targeted by the action described by the event. | keyword |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2019-12-19T00:44:25.051Z",
    "actor": {
        "entity": {
            "id": [
                "xxx@xxx.xxx"
            ]
        }
    },
    "agent": {
        "ephemeral_id": "c12ff10d-c028-4d1b-80b1-a8151b80a275",
        "id": "5bce43a4-737b-4c53-9db0-a4bff79e32d1",
        "name": "elastic-agent-10901",
        "type": "filebeat",
        "version": "8.18.7"
    },
    "client": {
        "user": {
            "email": "xxx@xxx.xxx"
        }
    },
    "cloud": {
        "availability_zone": "global",
        "project": {
            "id": "elastic-beats"
        },
        "provider": "gcp"
    },
    "data_stream": {
        "dataset": "gcp.audit",
        "namespace": "84187",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5bce43a4-737b-4c53-9db0-a4bff79e32d1",
        "snapshot": false,
        "version": "8.18.7"
    },
    "event": {
        "action": "beta.compute.instances.aggregatedList",
        "agent_id_status": "verified",
        "category": [
            "network",
            "configuration"
        ],
        "created": "2025-10-09T12:32:26.254Z",
        "dataset": "gcp.audit",
        "id": "yonau2dg2zi",
        "ingested": "2025-10-09T12:32:29Z",
        "kind": "event",
        "outcome": "success",
        "provider": "data_access",
        "type": [
            "access",
            "allowed"
        ]
    },
    "gcp": {
        "audit": {
            "authorization_info": [
                {
                    "granted": true,
                    "permission": "compute.instances.list",
                    "resource_attributes": {
                        "name": "projects/elastic-beats",
                        "service": "resourcemanager",
                        "type": "resourcemanager.projects"
                    }
                }
            ],
            "num_response_items": 61,
            "receive_timestamp": "2019-12-19T00:44:25.262Z",
            "request": {
                "@type": "type.googleapis.com/compute.instances.aggregatedList"
            },
            "resource": {
                "type": "api"
            },
            "resource_location": {
                "current_locations": [
                    "global"
                ]
            },
            "resource_name": "projects/elastic-beats/global/instances",
            "response": {
                "@type": "core.k8s.io/v1.Status",
                "apiVersion": "v1",
                "details": {
                    "group": "batch",
                    "kind": "jobs",
                    "name": "gsuite-exporter-1589294700",
                    "uid": "2beff34a-945f-11ea-bacf-42010a80007f"
                },
                "kind": "Status",
                "status_value": "Success"
            },
            "type": "type.googleapis.com/google.cloud.audit.AuditLog"
        }
    },
    "input": {
        "type": "gcp-pubsub"
    },
    "log": {
        "level": "INFO",
        "logger": "projects/elastic-beats/logs/cloudaudit.googleapis.com%2Fdata_access"
    },
    "related": {
        "entity": [
            "projects/elastic-beats/global/instances",
            "xxx@xxx.xxx"
        ],
        "ip": [
            "192.168.1.1"
        ],
        "user": [
            "xxx@xxx.xxx"
        ]
    },
    "service": {
        "name": "compute.googleapis.com"
    },
    "source": {
        "ip": "192.168.1.1"
    },
    "tags": [
        "forwarded",
        "gcp-audit"
    ],
    "target": {
        "entity": {
            "id": [
                "projects/elastic-beats/global/instances"
            ]
        }
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Firefox",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:71.0) Gecko/20100101 Firefox/71.0,gzip(gfe),gzip(gfe)",
        "os": {
            "full": "Mac OS X 10.15",
            "name": "Mac OS X",
            "version": "10.15"
        },
        "version": "71.0"
    }
}
```