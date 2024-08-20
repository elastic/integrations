# Wiz

Wiz continuously prioritizes critical risks based on a deep cloud analysis across misconfigurations, network exposure, secrets, vulnerabilities, malware, and identities to build a single prioritized view of risk for your cloud. This [Wiz](https://www.wiz.io/) integration enables you to consume and analyze Wiz data within Elastic Security, including issues, vulnerability data, cloud configuration findings and audit events, providing you with visibility and context for your cloud environments within Elastic Security.

## Data streams

The Wiz integration collects three types of data: Audit, Issue and Vulnerability.

Reference for [Graph APIs](https://integrate.wiz.io/reference/prerequisites) of Wiz.

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.10.1**.
This module has been tested against the **Wiz API Version v1**.

## Setup

### To collect data from Wiz, the following parameters from your Wiz instance are required:

1. Client ID
2. Client Secret
3. Token url
4. API Endpoint url
5. Required scopes for each data stream :

    | Data Stream   | Scope         |
    | ------------- | ------------- |
    | Audit         | admin:audit   |
    | Issue         | read:issues   |
    | Vulnerability | read:vulnerabilities |
    | Cloud Configuration Finding | read:cloud_configuration |

### To obtain the Wiz URL
1. Navigate to your user profile and copy the API Endpoint URL.

### Steps to obtain Client ID and Client Secret:

1. In the Wiz dashboard Navigate to Settings > Service Accounts.
2. Click Add Service Account.
3. Name the new service account, for example: Elastic Integration.
4. If you desire, narrow the scope of this service account to specific projects.
5. Select the permission read:resources and click Add Service Account.
6. Copy the Client Secret. Note that you won't be able to copy it after this stage.
7. Copy the Client ID, which is displayed under the Service Accounts page.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Wiz
3. Click on the "Wiz" integration from the search results.
4. Click on the "Add Wiz" button to add the integration.
5. Add all the required integration configuration parameters, such as Client ID, Client Secret, URL, and Token URL. For all data streams, these parameters must be provided in order to retrieve logs.
6. Save the integration.

**Note:**
  - Vulnerability data_stream pulls vulnerabilities from the previous day. For more information, refer to the link [here](https://integrate.wiz.io/reference/vulnerability-finding)

## Logs Reference

### Audit

This is the `Audit` dataset.

#### Example

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2023-07-21T07:07:21.105Z",
    "agent": {
        "ephemeral_id": "5c3096ee-b490-4b19-a848-bfed150c1bca",
        "id": "927b2eff-4394-4486-ab77-d6bfa7c529cf",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "wiz.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "927b2eff-4394-4486-ab77-d6bfa7c529cf",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "action": "login",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "dataset": "wiz.audit",
        "id": "hhd8ab9c-f1bf-4a80-a1e1-13bc8769caf4",
        "ingested": "2023-10-03T10:35:48Z",
        "kind": "event",
        "original": "{\"action\":\"Login\",\"actionParameters\":{\"clientID\":\"afsdafasmdgj5c\",\"groups\":null,\"name\":\"example\",\"products\":[\"*\"],\"role\":\"\",\"scopes\":[\"read:issues\",\"read:reports\",\"read:vulnerabilities\",\"update:reports\",\"create:reports\",\"admin:audit\"],\"userEmail\":\"\",\"userID\":\"afsafasdghbhdfg5t35fdgs\",\"userpoolID\":\"us-east-2_GQ3gwvxsQ\"},\"id\":\"hhd8ab9c-f1bf-4a80-a1e1-13bc8769caf4\",\"requestId\":\"hhd8ab9c-f1bf-4a80-a1e1-13bc8769caf4\",\"serviceAccount\":{\"id\":\"mlipebtwsndhxdmnzdwrxzmiolvzt6topjvv4nugzctcsyarazrhg\",\"name\":\"elastic\"},\"sourceIP\":null,\"status\":\"SUCCESS\",\"timestamp\":\"2023-07-21T07:07:21.105685Z\",\"user\":null,\"userAgent\":null}",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "http": {
        "request": {
            "id": "hhd8ab9c-f1bf-4a80-a1e1-13bc8769caf4"
        }
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "user": [
            "afsafasdghbhdfg5t35fdgs",
            "us-east-2_GQ3gwvxsQ"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "wiz-audit"
    ],
    "wiz": {
        "audit": {
            "action": "Login",
            "action_parameters": {
                "client_id": "afsdafasmdgj5c",
                "name": "example",
                "products": [
                    "*"
                ],
                "scopes": [
                    "read:issues",
                    "read:reports",
                    "read:vulnerabilities",
                    "update:reports",
                    "create:reports",
                    "admin:audit"
                ],
                "user": {
                    "id": "afsafasdghbhdfg5t35fdgs"
                },
                "userpool_id": "us-east-2_GQ3gwvxsQ"
            },
            "id": "hhd8ab9c-f1bf-4a80-a1e1-13bc8769caf4",
            "request_id": "hhd8ab9c-f1bf-4a80-a1e1-13bc8769caf4",
            "service_account": {
                "id": "mlipebtwsndhxdmnzdwrxzmiolvzt6topjvv4nugzctcsyarazrhg",
                "name": "elastic"
            },
            "status": "SUCCESS",
            "timestamp": "2023-07-21T07:07:21.105Z"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| wiz.audit.action |  | keyword |
| wiz.audit.action_parameters.client_id |  | keyword |
| wiz.audit.action_parameters.groups |  | flattened |
| wiz.audit.action_parameters.name |  | keyword |
| wiz.audit.action_parameters.products |  | keyword |
| wiz.audit.action_parameters.role |  | keyword |
| wiz.audit.action_parameters.scopes |  | keyword |
| wiz.audit.action_parameters.user.email |  | keyword |
| wiz.audit.action_parameters.user.id |  | keyword |
| wiz.audit.action_parameters.userpool_id |  | keyword |
| wiz.audit.id |  | keyword |
| wiz.audit.request_id |  | keyword |
| wiz.audit.service_account.id |  | keyword |
| wiz.audit.service_account.name |  | keyword |
| wiz.audit.source_ip |  | ip |
| wiz.audit.status |  | keyword |
| wiz.audit.timestamp |  | date |
| wiz.audit.user.id |  | keyword |
| wiz.audit.user.name |  | keyword |
| wiz.audit.user_agent |  | keyword |


### Cloud Configuration Finding

This is the `Cloud Configuration Finding` dataset.

#### Example

An example event for `cloud_configuration_finding` looks as following:

```json
{
    "@timestamp": "2023-06-12T11:38:07.900Z",
    "cloud": {
        "account": {
            "id": "cfd132be-3bc7-4f86-8efd-ed53ae498fec",
            "name": "Wiz - DEV Outpost"
        },
        "provider": "azure"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "configuration"
        ],
        "created": "2023-06-12T11:38:07.900Z",
        "id": "bdeba988-f41b-55e6-9b99-96b8d3dc67d4",
        "kind": "state",
        "original": "{\"id\":\"bdeba988-f41b-55e6-9b99-96b8d3dc67d4\",\"targetExternalId\":\"k8s/pod/da99fd668e64c2def251b1d48b7b69ad3129638787a0f9144a993fe30fd4554f/default/cluster-autoscaler-azure-cluster-autoscaler-8bc677d64-z2qfx\",\"targetObjectProviderUniqueId\":\"cd971d74-92db-495c-8244-82da9a988fd0\",\"firstSeenAt\":\"2023-06-12T11:38:07.900129Z\",\"analyzedAt\":\"2023-06-12T11:38:07.900129Z\",\"severity\":\"LOW\",\"result\":\"FAIL\",\"status\":\"OPEN\",\"remediation\":\"Follow the step below to ensure that each [Pod](https://kubernetes.io/docs/concepts/workloads/pods) should runs containers with allowed additional capabilities: \\r\\n* The following capabilities are not allowed : {{removeUnnecessaryCapabilities}} .  \\r\\n* `securityContext.capabilities.drop` key is set to `ALL`. \\r\\n\",\"resource\":{\"id\":\"0e814bb7-29e8-5c15-be9c-8da42c67ee99\",\"providerId\":\"provider-id-0e814bb7-29e8-5c15-be9c-8da42c67ee99\",\"name\":\"cluster-autoscaler-azure-cluster-autoscaler-8bc677d64-z2qfx\",\"nativeType\":\"Pod\",\"type\":\"POD\",\"region\":null,\"subscription\":{\"id\":\"a3a3cc43-1dfd-50f1-882e-692840d4a891\",\"name\":\"Wiz - DEV Outpost\",\"externalId\":\"cfd132be-3bc7-4f86-8efd-ed53ae498fec\",\"cloudProvider\":\"Azure\"},\"projects\":null,\"tags\":[{\"key\":\"pod-template-hash\",\"value\":\"8bc677d64\"},{\"key\":\"app.kubernetes.io/name\",\"value\":\"azure-cluster-autoscaler\"},{\"key\":\"app.kubernetes.io/instance\",\"value\":\"cluster-autoscaler\"}]},\"rule\":{\"id\":\"73553de7-f2ad-4ffb-b425-c69815033530\",\"shortId\":\"Pod-32\",\"graphId\":\"99ffeef7-75df-5c88-9265-5ab50ffbc2b9\",\"name\":\"Pod should run containers with authorized additional capabilities (PSS Restricted)\",\"description\":\"This rule is part of the Kubernetes [Pod Security Standards (PSS) restricted policies](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted).   \\nThis rule checks whether the pod is running containers with authorized additional capabilities.     \\nThis rule fails if the `securityContext.capabilities.add` contains any capability beyond `NET_BIND_SERVICE` and if `securityContext.capabilities.drop` is not set to `ALL`.  \\nBy default, if the `securityContext.capabilities.add` key is not set, the pod will not run with additional capabilities, and the rule will pass.   \\nLinux capabilities allow granting certain privileges to a container without granting any unnecessary ones intended for the root user.\",\"remediationInstructions\":\"Follow the step below to ensure that each [Pod](https://kubernetes.io/docs/concepts/workloads/pods) should runs containers with allowed additional capabilities: \\r\\n* The following capabilities are not allowed : {{removeUnnecessaryCapabilities}} .  \\r\\n* `securityContext.capabilities.drop` key is set to `ALL`. \\r\\n\",\"functionAsControl\":false},\"securitySubCategories\":[{\"id\":\"wsct-id-5206\",\"title\":\"Container Security\",\"category\":{\"id\":\"wct-id-423\",\"name\":\"9 Container Security\",\"framework\":{\"id\":\"wf-id-1\",\"name\":\"Wiz\"}}},{\"id\":\"wsct-id-8176\",\"title\":\"5.1 Containers should not run with additional capabilities\",\"category\":{\"id\":\"wct-id-1295\",\"name\":\"5 Capabilities\",\"framework\":{\"id\":\"wf-id-57\",\"name\":\"Kubernetes Pod Security Standards (Restricted)\"}}},{\"id\":\"wsct-id-8344\",\"title\":\"Cluster misconfiguration\",\"category\":{\"id\":\"wct-id-1169\",\"name\":\"2 Container & Kubernetes Security\",\"framework\":{\"id\":\"wf-id-53\",\"name\":\"Wiz Detailed\"}}}]}",
        "outcome": "failure",
        "type": [
            "info"
        ]
    },
    "message": "This rule is part of the Kubernetes [Pod Security Standards (PSS) restricted policies](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted).   \nThis rule checks whether the pod is running containers with authorized additional capabilities.     \nThis rule fails if the `securityContext.capabilities.add` contains any capability beyond `NET_BIND_SERVICE` and if `securityContext.capabilities.drop` is not set to `ALL`.  \nBy default, if the `securityContext.capabilities.add` key is not set, the pod will not run with additional capabilities, and the rule will pass.   \nLinux capabilities allow granting certain privileges to a container without granting any unnecessary ones intended for the root user.",
    "observer": {
        "vendor": "Wiz"
    },
    "resource": {
        "id": "provider-id-0e814bb7-29e8-5c15-be9c-8da42c67ee99",
        "name": "cluster-autoscaler-azure-cluster-autoscaler-8bc677d64-z2qfx",
        "sub_type": "Pod",
        "type": "POD"
    },
    "result": {
        "evaluation": "FAILED"
    },
    "rule": {
        "description": "This rule is part of the Kubernetes [Pod Security Standards (PSS) restricted policies](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted).   \nThis rule checks whether the pod is running containers with authorized additional capabilities.     \nThis rule fails if the `securityContext.capabilities.add` contains any capability beyond `NET_BIND_SERVICE` and if `securityContext.capabilities.drop` is not set to `ALL`.  \nBy default, if the `securityContext.capabilities.add` key is not set, the pod will not run with additional capabilities, and the rule will pass.   \nLinux capabilities allow granting certain privileges to a container without granting any unnecessary ones intended for the root user.",
        "id": "Pod-32",
        "name": "Pod should run containers with authorized additional capabilities (PSS Restricted)",
        "remediation": "Follow the step below to ensure that each [Pod](https://kubernetes.io/docs/concepts/workloads/pods) should runs containers with allowed additional capabilities: \r\n* The following capabilities are not allowed : {{removeUnnecessaryCapabilities}} .  \r\n* `securityContext.capabilities.drop` key is set to `ALL`. \r\n",
        "uuid": "73553de7-f2ad-4ffb-b425-c69815033530"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields"
    ],
    "wiz": {
        "cloud_configuration_finding": {
            "analyzed_at": "2023-06-12T11:38:07.900Z",
            "id": "bdeba988-f41b-55e6-9b99-96b8d3dc67d4",
            "resource": {
                "id": "0e814bb7-29e8-5c15-be9c-8da42c67ee99",
                "name": "cluster-autoscaler-azure-cluster-autoscaler-8bc677d64-z2qfx",
                "native_type": "Pod",
                "provider_id": "provider-id-0e814bb7-29e8-5c15-be9c-8da42c67ee99",
                "subscription": {
                    "cloud_provider": "Azure",
                    "external_id": "cfd132be-3bc7-4f86-8efd-ed53ae498fec",
                    "name": "Wiz - DEV Outpost"
                },
                "type": "POD"
            },
            "result": "FAIL",
            "rule": {
                "description": "This rule is part of the Kubernetes [Pod Security Standards (PSS) restricted policies](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted).   \nThis rule checks whether the pod is running containers with authorized additional capabilities.     \nThis rule fails if the `securityContext.capabilities.add` contains any capability beyond `NET_BIND_SERVICE` and if `securityContext.capabilities.drop` is not set to `ALL`.  \nBy default, if the `securityContext.capabilities.add` key is not set, the pod will not run with additional capabilities, and the rule will pass.   \nLinux capabilities allow granting certain privileges to a container without granting any unnecessary ones intended for the root user.",
                "id": "73553de7-f2ad-4ffb-b425-c69815033530",
                "name": "Pod should run containers with authorized additional capabilities (PSS Restricted)",
                "remediation_instructions": "Follow the step below to ensure that each [Pod](https://kubernetes.io/docs/concepts/workloads/pods) should runs containers with allowed additional capabilities: \r\n* The following capabilities are not allowed : {{removeUnnecessaryCapabilities}} .  \r\n* `securityContext.capabilities.drop` key is set to `ALL`. \r\n",
                "short_id": "Pod-32"
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.service.name | The cloud service name is intended to distinguish services running on different platforms within a provider, eg AWS EC2 vs Lambda, GCP GCE vs App Engine, Azure VM vs App Server. Examples: app engine, app service, cloud run, fargate, lambda. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | keyword |
| resource.id |  | keyword |
| resource.name |  | keyword |
| resource.sub_type |  | keyword |
| resource.type |  | keyword |
| result.evaluation |  | keyword |
| result.evidence |  | flattened |
| rule.description |  | text |
| rule.id |  | keyword |
| rule.name |  | keyword |
| rule.remediation |  | text |
| rule.uuid |  | keyword |
| tags | User defined tags. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| wiz.cloud_configuration_finding.analyzed_at |  | date |
| wiz.cloud_configuration_finding.evidence |  | flattened |
| wiz.cloud_configuration_finding.id |  | keyword |
| wiz.cloud_configuration_finding.resource.cloud_platform |  | keyword |
| wiz.cloud_configuration_finding.resource.id |  | keyword |
| wiz.cloud_configuration_finding.resource.name |  | keyword |
| wiz.cloud_configuration_finding.resource.native_type |  | keyword |
| wiz.cloud_configuration_finding.resource.provider_id |  | keyword |
| wiz.cloud_configuration_finding.resource.region |  | keyword |
| wiz.cloud_configuration_finding.resource.subscription.cloud_provider |  | keyword |
| wiz.cloud_configuration_finding.resource.subscription.external_id |  | keyword |
| wiz.cloud_configuration_finding.resource.subscription.name |  | keyword |
| wiz.cloud_configuration_finding.resource.type |  | keyword |
| wiz.cloud_configuration_finding.result |  | keyword |
| wiz.cloud_configuration_finding.rule.description |  | text |
| wiz.cloud_configuration_finding.rule.id |  | keyword |
| wiz.cloud_configuration_finding.rule.name |  | keyword |
| wiz.cloud_configuration_finding.rule.remediation_instructions |  | text |
| wiz.cloud_configuration_finding.rule.short_id |  | keyword |


### Issue

This is the `Issue` dataset.

#### Example

An example event for `issue` looks as following:

```json
{
    "@timestamp": "2023-07-31T06:26:08.708Z",
    "agent": {
        "ephemeral_id": "e74ac4d2-8565-45ee-8c61-c66b6f3151bf",
        "id": "927b2eff-4394-4486-ab77-d6bfa7c529cf",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "cloud": {
        "provider": "Kubernetes",
        "region": "us-01"
    },
    "data_stream": {
        "dataset": "wiz.issue",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "927b2eff-4394-4486-ab77-d6bfa7c529cf",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "created": "2023-08-23T07:56:09.903Z",
        "dataset": "wiz.issue",
        "id": "fff9cffd-64a7-412c-9535-cf837f4b0b40",
        "ingested": "2023-10-03T10:22:42Z",
        "kind": "event",
        "original": "{\"createdAt\":\"2023-08-23T07:56:09.903743Z\",\"dueAt\":\"2023-08-30T21:00:00Z\",\"entitySnapshot\":{\"cloudPlatform\":\"Kubernetes\",\"cloudProviderURL\":\"https://portal.az.com/#@sectest.on.com/resource//subscriptions/\",\"externalId\":\"k8s/clusterrole/aaa8e7ca2bf9bc85a75d5bbdd8ffd08d69f8852782a6341c3c3519sad45/system:aggregate-to-edit/12\",\"id\":\"e507d472-b7da-5f05-9b25-72a271336b14\",\"name\":\"system:aggregate-to-edit\",\"nativeType\":\"ClusterRole\",\"providerId\":\"k8s/clusterrole/aaa8e7ca2bf9bc85a75d5bbdd8ffd08d69f8852782a6341c3c3519bac0f24ae9/system:aggregate-to-edit/12\",\"region\":\"us-01\",\"resourceGroupExternalId\":\"/subscriptions/cfd132be-3bc7-4f86-8efd-ed53ae498fec/resourcegroups/test-selfmanaged-eastus\",\"status\":\"Active\",\"subscriptionExternalId\":\"998231069301\",\"subscriptionName\":\"demo-integrations\",\"subscriptionTags\":{},\"tags\":{\"kubernetes.io/bootstrapping\":\"rbac-defaults\",\"rbac.authorization.k8s.io/aggregate-to-edit\":\"true\"},\"type\":\"ACCESS_ROLE\"},\"id\":\"fff9cffd-64a7-412c-9535-cf837f4b0b40\",\"notes\":[{\"createdAt\":\"2023-08-23T07:56:09.903743Z\",\"serviceAccount\":{\"name\":\"rev-ke\"},\"text\":\"updated\",\"updatedAt\":\"2023-08-09T23:10:22.588721Z\"},{\"createdAt\":\"2023-08-09T23:08:49.918941Z\",\"serviceAccount\":{\"name\":\"rev-ke2\"},\"text\":\"updated\",\"updatedAt\":\"2023-08-09T23:10:22.591487Z\"}],\"projects\":[{\"businessUnit\":\"\",\"id\":\"83b76efe-a7b6-5762-8a53-8e8f59e68bd8\",\"name\":\"Project 2\",\"riskProfile\":{\"businessImpact\":\"MBI\"},\"slug\":\"project-2\"},{\"businessUnit\":\"Dev\",\"id\":\"af52828c-4eb1-5c4e-847c-ebc3a5ead531\",\"name\":\"project 4\",\"riskProfile\":{\"businessImpact\":\"MBI\"},\"slug\":\"project-4\"},{\"businessUnit\":\"Dev\",\"id\":\"d6ac50bb-aec0-52fc-80ab-bacd7b02f178\",\"name\":\"Project1\",\"riskProfile\":{\"businessImpact\":\"MBI\"},\"slug\":\"project1\"}],\"resolvedAt\":\"2023-08-09T23:10:22.588721Z\",\"serviceTickets\":[{\"externalId\":\"638361121bbfdd10f6c1cbf3604bcb7e\",\"name\":\"SIR0010002\",\"url\":\"https://ven05658.testing.com/nav_to.do?uri=%2Fsn_si_incident.do%3Fsys_id%3D6385248sdsae421\"}],\"severity\":\"INFORMATIONAL\",\"sourceRule\":{\"__typename\":\"Control\",\"controlDescription\":\"These EKS principals assume roles that provide bind, escalate and impersonate permissions. \\n\\nThe `bind` permission allows users to create bindings to roles with rights they do not already have. The `escalate` permission allows users effectively escalate their privileges. The `impersonate` permission allows users to impersonate and gain the rights of other users in the cluster. Running containers with these permissions has the potential to effectively allow privilege escalation to the cluster-admin level.\",\"id\":\"wc-id-1335\",\"name\":\"EKS principals assume roles that provide bind, escalate and impersonate permissions\",\"resolutionRecommendation\":\"To follow the principle of least privilege and minimize the risk of unauthorized access and data breaches, it is recommended not to grant `bind`, `escalate` or `impersonate` permissions.\",\"securitySubCategories\":[{\"category\":{\"framework\":{\"name\":\"CIS EKS 1.2.0\"},\"name\":\"4.1 RBAC and Service Accounts\"},\"title\":\"4.1.8 Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster - Level 1 (Manual)\"},{\"category\":{\"framework\":{\"name\":\"Wiz for Risk Assessment\"},\"name\":\"Identity Management\"},\"title\":\"Privileged principal\"},{\"category\":{\"framework\":{\"name\":\"Wiz\"},\"name\":\"9 Container Security\"},\"title\":\"Container Security\"},{\"category\":{\"framework\":{\"name\":\"Wiz for Risk Assessment\"},\"name\":\"Container \\u0026 Kubernetes Security\"},\"title\":\"Cluster misconfiguration\"}]},\"status\":\"IN_PROGRESS\",\"statusChangedAt\":\"2023-07-31T06:26:08.708199Z\",\"updatedAt\":\"2023-08-14T06:06:18.331647Z\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "message": "These EKS principals assume roles that provide bind, escalate and impersonate permissions. \n\nThe `bind` permission allows users to create bindings to roles with rights they do not already have. The `escalate` permission allows users effectively escalate their privileges. The `impersonate` permission allows users to impersonate and gain the rights of other users in the cluster. Running containers with these permissions has the potential to effectively allow privilege escalation to the cluster-admin level.",
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "wiz-issue"
    ],
    "url": {
        "domain": "portal.az.com",
        "fragment": "@sectest.on.com/resource//subscriptions/",
        "original": "https://portal.az.com/#@sectest.on.com/resource//subscriptions/",
        "path": "/",
        "scheme": "https"
    },
    "wiz": {
        "issue": {
            "created_at": "2023-08-23T07:56:09.903Z",
            "due_at": "2023-08-30T21:00:00.000Z",
            "entity_snapshot": {
                "cloud": {
                    "platform": "Kubernetes",
                    "provider_url": "https://portal.az.com/#@sectest.on.com/resource//subscriptions/"
                },
                "external_id": "k8s/clusterrole/aaa8e7ca2bf9bc85a75d5bbdd8ffd08d69f8852782a6341c3c3519sad45/system:aggregate-to-edit/12",
                "id": "e507d472-b7da-5f05-9b25-72a271336b14",
                "name": "system:aggregate-to-edit",
                "native_type": "ClusterRole",
                "provider_id": "k8s/clusterrole/aaa8e7ca2bf9bc85a75d5bbdd8ffd08d69f8852782a6341c3c3519bac0f24ae9/system:aggregate-to-edit/12",
                "region": "us-01",
                "resource_group_external_id": "/subscriptions/cfd132be-3bc7-4f86-8efd-ed53ae498fec/resourcegroups/test-selfmanaged-eastus",
                "status": "Active",
                "subscription": {
                    "external_id": "998231069301",
                    "name": "demo-integrations"
                },
                "tags": {
                    "kubernetes.io/bootstrapping": "rbac-defaults",
                    "rbac.authorization.k8s.io/aggregate-to-edit": "true"
                },
                "type": "ACCESS_ROLE"
            },
            "id": "fff9cffd-64a7-412c-9535-cf837f4b0b40",
            "notes": [
                {
                    "created_at": "2023-08-23T07:56:09.903Z",
                    "service_account": {
                        "name": "rev-ke"
                    },
                    "text": "updated",
                    "updated_at": "2023-08-09T23:10:22.588Z"
                },
                {
                    "created_at": "2023-08-09T23:08:49.918Z",
                    "service_account": {
                        "name": "rev-ke2"
                    },
                    "text": "updated",
                    "updated_at": "2023-08-09T23:10:22.591Z"
                }
            ],
            "projects": [
                {
                    "id": "83b76efe-a7b6-5762-8a53-8e8f59e68bd8",
                    "name": "Project 2",
                    "risk_profile": {
                        "business_impact": "MBI"
                    },
                    "slug": "project-2"
                },
                {
                    "business_unit": "Dev",
                    "id": "af52828c-4eb1-5c4e-847c-ebc3a5ead531",
                    "name": "project 4",
                    "risk_profile": {
                        "business_impact": "MBI"
                    },
                    "slug": "project-4"
                },
                {
                    "business_unit": "Dev",
                    "id": "d6ac50bb-aec0-52fc-80ab-bacd7b02f178",
                    "name": "Project1",
                    "risk_profile": {
                        "business_impact": "MBI"
                    },
                    "slug": "project1"
                }
            ],
            "resolved_at": "2023-08-09T23:10:22.588Z",
            "service_tickets": [
                {
                    "external_id": "638361121bbfdd10f6c1cbf3604bcb7e",
                    "name": "SIR0010002",
                    "url": "https://ven05658.testing.com/nav_to.do?uri=%2Fsn_si_incident.do%3Fsys_id%3D6385248sdsae421"
                }
            ],
            "severity": "INFORMATIONAL",
            "source_rule": {
                "__typename": "Control",
                "control_description": "These EKS principals assume roles that provide bind, escalate and impersonate permissions. \n\nThe `bind` permission allows users to create bindings to roles with rights they do not already have. The `escalate` permission allows users effectively escalate their privileges. The `impersonate` permission allows users to impersonate and gain the rights of other users in the cluster. Running containers with these permissions has the potential to effectively allow privilege escalation to the cluster-admin level.",
                "id": "wc-id-1335",
                "name": "EKS principals assume roles that provide bind, escalate and impersonate permissions",
                "resolution_recommendation": "To follow the principle of least privilege and minimize the risk of unauthorized access and data breaches, it is recommended not to grant `bind`, `escalate` or `impersonate` permissions.",
                "security_sub_categories": [
                    {
                        "category": {
                            "framework": {
                                "name": "CIS EKS 1.2.0"
                            },
                            "name": "4.1 RBAC and Service Accounts"
                        },
                        "title": "4.1.8 Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster - Level 1 (Manual)"
                    },
                    {
                        "category": {
                            "framework": {
                                "name": "Wiz for Risk Assessment"
                            },
                            "name": "Identity Management"
                        },
                        "title": "Privileged principal"
                    },
                    {
                        "category": {
                            "framework": {
                                "name": "Wiz"
                            },
                            "name": "9 Container Security"
                        },
                        "title": "Container Security"
                    },
                    {
                        "category": {
                            "framework": {
                                "name": "Wiz for Risk Assessment"
                            },
                            "name": "Container \u0026 Kubernetes Security"
                        },
                        "title": "Cluster misconfiguration"
                    }
                ]
            },
            "status": {
                "changed_at": "2023-07-31T06:26:08.708Z",
                "value": "IN_PROGRESS"
            },
            "updated_at": "2023-08-14T06:06:18.331Z"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| wiz.issue.created_at |  | date |
| wiz.issue.due_at |  | date |
| wiz.issue.entity_snapshot.cloud.platform |  | keyword |
| wiz.issue.entity_snapshot.cloud.provider_url |  | keyword |
| wiz.issue.entity_snapshot.external_id |  | keyword |
| wiz.issue.entity_snapshot.id |  | keyword |
| wiz.issue.entity_snapshot.name |  | keyword |
| wiz.issue.entity_snapshot.native_type |  | keyword |
| wiz.issue.entity_snapshot.provider_id |  | keyword |
| wiz.issue.entity_snapshot.region |  | keyword |
| wiz.issue.entity_snapshot.resource_group_external_id |  | keyword |
| wiz.issue.entity_snapshot.status |  | keyword |
| wiz.issue.entity_snapshot.subscription.external_id |  | keyword |
| wiz.issue.entity_snapshot.subscription.name |  | keyword |
| wiz.issue.entity_snapshot.subscription.tags |  | flattened |
| wiz.issue.entity_snapshot.tags |  | flattened |
| wiz.issue.entity_snapshot.type |  | keyword |
| wiz.issue.id |  | keyword |
| wiz.issue.notes.created_at |  | date |
| wiz.issue.notes.service_account.name |  | keyword |
| wiz.issue.notes.text |  | keyword |
| wiz.issue.notes.updated_at |  | date |
| wiz.issue.notes.user.email |  | keyword |
| wiz.issue.notes.user.name |  | keyword |
| wiz.issue.projects.business_unit |  | keyword |
| wiz.issue.projects.id |  | keyword |
| wiz.issue.projects.name |  | keyword |
| wiz.issue.projects.risk_profile.business_impact |  | keyword |
| wiz.issue.projects.slug |  | keyword |
| wiz.issue.resolved_at |  | date |
| wiz.issue.service_tickets.external_id |  | keyword |
| wiz.issue.service_tickets.name |  | keyword |
| wiz.issue.service_tickets.url |  | keyword |
| wiz.issue.severity |  | keyword |
| wiz.issue.source_rule.__typename |  | keyword |
| wiz.issue.source_rule.control_description |  | keyword |
| wiz.issue.source_rule.id |  | keyword |
| wiz.issue.source_rule.name |  | keyword |
| wiz.issue.source_rule.resolution_recommendation |  | keyword |
| wiz.issue.source_rule.security_sub_categories.category.framework.name |  | keyword |
| wiz.issue.source_rule.security_sub_categories.category.name |  | keyword |
| wiz.issue.source_rule.security_sub_categories.title |  | keyword |
| wiz.issue.status.changed_at |  | date |
| wiz.issue.status.value |  | keyword |
| wiz.issue.type |  | keyword |
| wiz.issue.updated_at |  | date |


### Vulnerability

This is the `Vulnerability` dataset.

#### Example

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2023-08-16T18:40:57.000Z",
    "agent": {
        "ephemeral_id": "bd7b9b1e-3c24-48fb-ad27-fc8578793608",
        "id": "927b2eff-4394-4486-ab77-d6bfa7c529cf",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "cloud": {
        "provider": "AWS",
        "region": "us-east-1"
    },
    "data_stream": {
        "dataset": "wiz.vulnerability",
        "namespace": "ep",
        "type": "logs"
    },
    "device": {
        "id": "c828de0d-4c42-5b1c-946b-2edee094d0b3"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "927b2eff-4394-4486-ab77-d6bfa7c529cf",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "wiz.vulnerability",
        "ingested": "2023-10-03T10:23:54Z",
        "kind": "alert",
        "original": "{\"CVEDescription\":\"In LibTIFF, there is a memory malloc failure in tif_pixarlog.c. A crafted TIFF document can lead to an abort, resulting in a remote denial of service attack.\",\"CVSSSeverity\":\"MEDIUM\",\"dataSourceName\":\"data Source\",\"description\":\"Thepackage`libtiff`version`4.0.3-35.amzn2`wasdetectedin`YUMpackagemanager`onamachinerunning`Amazon2(Karoo)`isvulnerableto`CVE-2020-35522`,whichexistsinversions`\\u003c4.0.3-35.amzn2.0.1`.\\n\\nThevulnerabilitywasfoundinthe[OfficialAmazonLinuxSecurityAdvisories](https://alas.aws.amazon.com/AL2/ALAS-2022-1780.html)withvendorseverity:`Medium`([NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-35522)severity:`Medium`).\\n\\nThevulnerabilitycanberemediatedbyupdatingthepackagetoversion`4.0.3-35.amzn2.0.1`orhigher,using`yumupdatelibtiff`.\",\"detailedName\":\"libtiff\",\"detectionMethod\":\"PACKAGE\",\"epssPercentile\":46.2,\"epssProbability\":0.1,\"epssSeverity\":\"LOW\",\"exploitabilityScore\":1.8,\"firstDetectedAt\":\"2022-05-01T11:36:10.063767Z\",\"fixedVersion\":\"4.0.3-35.amzn2.0.1\",\"hasCisaKevExploit\":false,\"hasExploit\":false,\"id\":\"5e95ff50-5490-514e-87f7-11e56f3230ff\",\"ignoreRules\":{\"enabled\":true,\"expiredAt\":\"2023-08-16T18:40:57Z\",\"id\":\"aj3jqtvnaf\",\"name\":\"abc\"},\"impactScore\":3.6,\"lastDetectedAt\":\"2023-08-16T18:40:57Z\",\"layerMetadata\":{\"details\":\"xxxx\",\"id\":\"5e95ff50-5490-514e-87f7-11e56f3230ff\",\"isBaseLayer\":true},\"link\":\"https://alas.aws.amazon.com/AL2/ALAS-2022-1780.html\",\"locationPath\":\"package/library/file\",\"name\":\"CVE-2020-3333\",\"portalUrl\":\"https://app.wiz.io/explorer/vulnerability-findings#~(entity~(~'xxx-xxx*2cSECURITY_TOOL_FINDING))\",\"projects\":[{\"businessUnit\":\"\",\"id\":\"83b76efe-a7b6-5762-8a53-8e8f59e68bd8\",\"name\":\"Project2\",\"riskProfile\":{\"businessImpact\":\"MBI\"},\"slug\":\"project-2\"},{\"businessUnit\":\"Dev\",\"id\":\"af52828c-4eb1-5c4e-847c-ebc3a5ead531\",\"name\":\"project4\",\"riskProfile\":{\"businessImpact\":\"MBI\"},\"slug\":\"project-4\"},{\"businessUnit\":\"Dev\",\"id\":\"d6ac50bb-aec0-52fc-80ab-bacd7b02f178\",\"name\":\"Project1\",\"riskProfile\":{\"businessImpact\":\"MBI\"},\"slug\":\"project1\"}],\"remediation\":\"yumupdatelibtiff\",\"resolutionReason\":\"resolutionReason\",\"resolvedAt\":\"2023-08-16T18:40:57Z\",\"score\":5.5,\"status\":\"OPEN\",\"validatedInRuntime\":true,\"vendorSeverity\":\"MEDIUM\",\"version\":\"4.0.3-35.amzn2\",\"vulnerableAsset\":{\"cloudPlatform\":\"AWS\",\"cloudProviderURL\":\"https://us-east-1.console.aws.amazon.com/ec2/v2/home?region=us-east-1#InstanceDetails:instanceId=i-0a0f7e1451da5f4a3\",\"hasLimitedInternetExposure\":true,\"hasWideInternetExposure\":true,\"id\":\"c828de0d-4c42-5b1c-946b-2edee094d0b3\",\"ipAddresses\":[\"89.160.20.112\",\"89.160.20.128\"],\"isAccessibleFromOtherSubscriptions\":false,\"isAccessibleFromOtherVnets\":false,\"isAccessibleFromVPN\":false,\"name\":\"test-4\",\"operatingSystem\":\"Linux\",\"providerUniqueId\":\"arn:aws:ec2:us-east-1:998231069301:instance/i-0a0f7e1451da5f4a3\",\"region\":\"us-east-1\",\"status\":\"Active\",\"subscriptionExternalId\":\"998231069301\",\"subscriptionId\":\"94e76baa-85fd-5928-b829-1669a2ca9660\",\"subscriptionName\":\"wiz-integrations\",\"tags\":{\"Name\":\"test-4\"},\"type\":\"VIRTUAL_MACHINE\"}}",
        "type": [
            "info"
        ]
    },
    "host": {
        "os": {
            "family": "Linux"
        }
    },
    "input": {
        "type": "cel"
    },
    "message": "Thepackage`libtiff`version`4.0.3-35.amzn2`wasdetectedin`YUMpackagemanager`onamachinerunning`Amazon2(Karoo)`isvulnerableto`CVE-2020-35522`,whichexistsinversions`\u003c4.0.3-35.amzn2.0.1`.\n\nThevulnerabilitywasfoundinthe[OfficialAmazonLinuxSecurityAdvisories](https://alas.aws.amazon.com/AL2/ALAS-2022-1780.html)withvendorseverity:`Medium`([NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-35522)severity:`Medium`).\n\nThevulnerabilitycanberemediatedbyupdatingthepackagetoversion`4.0.3-35.amzn2.0.1`orhigher,using`yumupdatelibtiff`.",
    "related": {
        "ip": [
            "89.160.20.112",
            "89.160.20.128"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "wiz-vulnerability"
    ],
    "vulnerability": {
        "description": "In LibTIFF, there is a memory malloc failure in tif_pixarlog.c. A crafted TIFF document can lead to an abort, resulting in a remote denial of service attack.",
        "id": "CVE-2020-3333",
        "reference": "https://alas.aws.amazon.com/AL2/ALAS-2022-1780.html",
        "severity": "MEDIUM"
    },
    "wiz": {
        "vulnerability": {
            "cve_description": "In LibTIFF, there is a memory malloc failure in tif_pixarlog.c. A crafted TIFF document can lead to an abort, resulting in a remote denial of service attack.",
            "cvss_severity": "MEDIUM",
            "data_source_name": "data Source",
            "description": "Thepackage`libtiff`version`4.0.3-35.amzn2`wasdetectedin`YUMpackagemanager`onamachinerunning`Amazon2(Karoo)`isvulnerableto`CVE-2020-35522`,whichexistsinversions`\u003c4.0.3-35.amzn2.0.1`.\n\nThevulnerabilitywasfoundinthe[OfficialAmazonLinuxSecurityAdvisories](https://alas.aws.amazon.com/AL2/ALAS-2022-1780.html)withvendorseverity:`Medium`([NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-35522)severity:`Medium`).\n\nThevulnerabilitycanberemediatedbyupdatingthepackagetoversion`4.0.3-35.amzn2.0.1`orhigher,using`yumupdatelibtiff`.",
            "detailed_name": "libtiff",
            "detection_method": "PACKAGE",
            "epss": {
                "percentile": 46.2,
                "probability": 0.1,
                "severity": "LOW"
            },
            "exploitability_score": 1.8,
            "first_detected_at": "2022-05-01T11:36:10.063Z",
            "fixed_version": "4.0.3-35.amzn2.0.1",
            "has_cisa_kev_exploit": false,
            "has_exploit": false,
            "id": "5e95ff50-5490-514e-87f7-11e56f3230ff",
            "ignore_rules": {
                "enabled": true,
                "expired_at": "2023-08-16T18:40:57.000Z",
                "id": "aj3jqtvnaf",
                "name": "abc"
            },
            "impact_score": 3.6,
            "last_detected_at": "2023-08-16T18:40:57.000Z",
            "layer_metadata": {
                "details": "xxxx",
                "id": "5e95ff50-5490-514e-87f7-11e56f3230ff",
                "is_base_layer": true
            },
            "link": "https://alas.aws.amazon.com/AL2/ALAS-2022-1780.html",
            "location_path": "package/library/file",
            "name": "CVE-2020-3333",
            "portal_url": "https://app.wiz.io/explorer/vulnerability-findings#~(entity~(~'xxx-xxx*2cSECURITY_TOOL_FINDING))",
            "projects": [
                {
                    "id": "83b76efe-a7b6-5762-8a53-8e8f59e68bd8",
                    "name": "Project2",
                    "risk_profile": {
                        "business_impact": "MBI"
                    },
                    "slug": "project-2"
                },
                {
                    "business_unit": "Dev",
                    "id": "af52828c-4eb1-5c4e-847c-ebc3a5ead531",
                    "name": "project4",
                    "risk_profile": {
                        "business_impact": "MBI"
                    },
                    "slug": "project-4"
                },
                {
                    "business_unit": "Dev",
                    "id": "d6ac50bb-aec0-52fc-80ab-bacd7b02f178",
                    "name": "Project1",
                    "risk_profile": {
                        "business_impact": "MBI"
                    },
                    "slug": "project1"
                }
            ],
            "remedation": "yumupdatelibtiff",
            "resolution_reason": "resolutionReason",
            "resolved_at": "2023-08-16T18:40:57.000Z",
            "score": 5.5,
            "status": "OPEN",
            "validated_in_runtime": true,
            "vendor_severity": "MEDIUM",
            "version": "4.0.3-35.amzn2",
            "vulnerable_asset": {
                "cloud": {
                    "platform": "AWS",
                    "provider_url": "https://us-east-1.console.aws.amazon.com/ec2/v2/home?region=us-east-1#InstanceDetails:instanceId=i-0a0f7e1451da5f4a3"
                },
                "has_limited_internet_exposure": true,
                "has_wide_internet_exposure": true,
                "id": "c828de0d-4c42-5b1c-946b-2edee094d0b3",
                "ip_addresses": [
                    "89.160.20.112",
                    "89.160.20.128"
                ],
                "is_accessible_from": {
                    "other_subscriptions": false,
                    "other_vnets": false,
                    "vpn": false
                },
                "name": "test-4",
                "operating_system": "Linux",
                "provider_unique_id": "arn:aws:ec2:us-east-1:998231069301:instance/i-0a0f7e1451da5f4a3",
                "region": "us-east-1",
                "status": "Active",
                "subscription": {
                    "external_id": "998231069301",
                    "id": "94e76baa-85fd-5928-b829-1669a2ca9660",
                    "name": "wiz-integrations"
                },
                "tags": {
                    "name": "test-4"
                },
                "type": "VIRTUAL_MACHINE"
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| wiz.vulnerability.cve_description |  | keyword |
| wiz.vulnerability.cvss_severity |  | keyword |
| wiz.vulnerability.data_source_name |  | keyword |
| wiz.vulnerability.description |  | keyword |
| wiz.vulnerability.detailed_name |  | keyword |
| wiz.vulnerability.detection_method |  | keyword |
| wiz.vulnerability.epss.percentile |  | double |
| wiz.vulnerability.epss.probability |  | double |
| wiz.vulnerability.epss.severity |  | keyword |
| wiz.vulnerability.exploitability_score |  | double |
| wiz.vulnerability.first_detected_at |  | date |
| wiz.vulnerability.fixed_version |  | keyword |
| wiz.vulnerability.has_cisa_kev_exploit |  | boolean |
| wiz.vulnerability.has_exploit |  | boolean |
| wiz.vulnerability.id |  | keyword |
| wiz.vulnerability.ignore_rules.enabled |  | boolean |
| wiz.vulnerability.ignore_rules.expired_at |  | date |
| wiz.vulnerability.ignore_rules.id |  | keyword |
| wiz.vulnerability.ignore_rules.name |  | keyword |
| wiz.vulnerability.impact_score |  | double |
| wiz.vulnerability.last_detected_at |  | date |
| wiz.vulnerability.layer_metadata.details |  | keyword |
| wiz.vulnerability.layer_metadata.id |  | keyword |
| wiz.vulnerability.layer_metadata.is_base_layer |  | boolean |
| wiz.vulnerability.link |  | keyword |
| wiz.vulnerability.location_path |  | keyword |
| wiz.vulnerability.name |  | keyword |
| wiz.vulnerability.portal_url |  | keyword |
| wiz.vulnerability.projects.business_unit |  | keyword |
| wiz.vulnerability.projects.id |  | keyword |
| wiz.vulnerability.projects.name |  | keyword |
| wiz.vulnerability.projects.risk_profile.business_impact |  | keyword |
| wiz.vulnerability.projects.slug |  | keyword |
| wiz.vulnerability.remedation |  | keyword |
| wiz.vulnerability.resolution_reason |  | keyword |
| wiz.vulnerability.resolved_at |  | date |
| wiz.vulnerability.score |  | double |
| wiz.vulnerability.status |  | keyword |
| wiz.vulnerability.validated_in_runtime |  | boolean |
| wiz.vulnerability.vendor_severity |  | keyword |
| wiz.vulnerability.version |  | keyword |
| wiz.vulnerability.vulnerable_asset.cloud.platform |  | keyword |
| wiz.vulnerability.vulnerable_asset.cloud.provider_url |  | keyword |
| wiz.vulnerability.vulnerable_asset.has_limited_internet_exposure |  | boolean |
| wiz.vulnerability.vulnerable_asset.has_wide_internet_exposure |  | boolean |
| wiz.vulnerability.vulnerable_asset.id |  | keyword |
| wiz.vulnerability.vulnerable_asset.ip_addresses |  | ip |
| wiz.vulnerability.vulnerable_asset.is_accessible_from.other_subscriptions |  | boolean |
| wiz.vulnerability.vulnerable_asset.is_accessible_from.other_vnets |  | boolean |
| wiz.vulnerability.vulnerable_asset.is_accessible_from.vpn |  | boolean |
| wiz.vulnerability.vulnerable_asset.name |  | keyword |
| wiz.vulnerability.vulnerable_asset.operating_system |  | keyword |
| wiz.vulnerability.vulnerable_asset.provider_unique_id |  | keyword |
| wiz.vulnerability.vulnerable_asset.region |  | keyword |
| wiz.vulnerability.vulnerable_asset.status |  | keyword |
| wiz.vulnerability.vulnerable_asset.subscription.external_id |  | keyword |
| wiz.vulnerability.vulnerable_asset.subscription.id |  | keyword |
| wiz.vulnerability.vulnerable_asset.subscription.name |  | keyword |
| wiz.vulnerability.vulnerable_asset.tags.name |  | keyword |
| wiz.vulnerability.vulnerable_asset.type |  | keyword |

