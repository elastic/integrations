# Azure Integration

The azure integration retrieves different types of log data from Azure.
There are several requirements before using the module since the logs will actually be read from azure event hubs.

   - the logs have to be exported first to the event hubs https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create-kafka-enabled
   - to export activity logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-export
   - to export audit and sign-in logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/tutorial-azure-monitor-stream-logs-to-event-hub

The module contains the following filesets:

### activitylogs
Will retrieve azure activity logs. Control-plane events on Azure Resource Manager resources. Activity logs provide insight into the operations that were performed on resources in your subscription.

### platformlogs
Will retrieve azure platform logs. Platform logs provide detailed diagnostic and auditing information for Azure resources and the Azure platform they depend on.

### signinlogs 
Will retrieve azure Active Directory sign-in logs. The sign-ins report provides information about the usage of managed applications and user sign-in activities.

### auditlogs 
Will retrieve azure Active Directory audit logs. The audit logs provide traceability through logs for all changes done by various features within Azure AD. Examples of audit logs include changes made to any resources within Azure AD like adding or removing users, apps, groups, roles and policies.

### Credentials

`eventhub` :
  _string_
Is the fully managed, real-time data ingestion service.
Default value `insights-operational-logs`.

`consumer_group` :
_string_
 The publish/subscribe mechanism of Event Hubs is enabled through consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_
The connection string required to communicate with Event Hubs, steps here https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string.

A Blob Storage account is required in order to store/retrieve/update the offset or state of the eventhub messages. This means that after stopping the filebeat azure module it can start back up at the spot that it stopped processing messages.

`storage_account` :
_string_
The name of the storage account the state/offsets will be stored and updated.

`storage_account_key` :
_string_
The storage account key, this key will be used to authorize access to data in your storage account.

`resource_manager_endpoint` :
_string_
Optional, by default we are using the azure public environment, to override, users can provide a specific resource manager endpoint in order to use a different azure environment.
Ex:
https://management.chinacloudapi.cn/ for azure ChinaCloud
https://management.microsoftazure.de/ for azure GermanCloud
https://management.azure.com/ for azure PublicCloud
https://management.usgovcloudapi.net/ for azure USGovernmentCloud
Users can also use this in case of a Hybrid Cloud model, where one may define their own endpoints.


An example event for `activitylogs` looks as following:

```$json
{
  "_id": "bQlEe3UBm_qs2Y3aNZPq",
  "_index": ".ds-logs-azure.activitylogs-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-11-02T08:51:36.997Z",
    "azure": {
      "activitylogs": {
        "category": "Administrative",
        "event_category": "Administrative",
        "identity": {
          "authorization": {
            "action": "Microsoft.Resources/deployments/write",
            "evidence": {
              "principal_id": "68b1adf93eb744b08eb8ce96522a08d3",
              "principal_type": "User",
              "role": "Owner",
              "role_assignment_id": "7f06f09dd6764b44930adbec3f10e92b",
              "role_assignment_scope": "/providers/Microsoft.Management/managementGroups/5341238b-665c-4eb4-b259-b250371ae430",
              "role_definition_id": "8e3af657a8ff443ca75c2fe8c4bcb635"
            },
            "scope": "/subscriptions/3f041b6d-fc31-41d8-8ff6-e5f16e6747ff/resourceGroups/obs-test/providers/Microsoft.Resources/deployments/NoMarketplace"
          },
          "claims": {
            "aio": "ATQAy/8RAAAAsL67UQMOHZv3izTDRJfvJN5UyON9ktUszzPj08K8aURsbhxhR0niz9s1Pxm9U1lI",
            "appid": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
            "appidacr": "2",
            "aud": "https://management.core.windows.net/",
            "exp": "1604310019",
            "groups": "644c6686-9ef1-4b69-9410-107664a9e1f0,9ed1993c-ce9c-4915-a04d-58c6f5f7ee12",
            "http://schemas_microsoft_com/claims/authnclassreference": "1",
            "http://schemas_microsoft_com/claims/authnmethodsreferences": "pwd",
            "http://schemas_microsoft_com/identity/claims/objectidentifier": "68b1adf9-3eb7-44b0-8eb8-ce96522a08d3",
            "http://schemas_microsoft_com/identity/claims/scope": "user_impersonation",
            "http://schemas_microsoft_com/identity/claims/tenantid": "4fa94b7d-a743-486f-abcc-6c276c44cf4b",
            "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/givenname": "John",
            "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/name": "john@gmail.com",
            "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/nameidentifier": "a9L2WR3XZN5ANzAqwLx_4aamU49JG6kqaE5JZkXdeNs",
            "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/surname": "Doe",
            "http://schemas_xmlsoap_org/ws/2005/05/identity/claims/upn": "john@gmail.com",
            "iat": "1604306119",
            "ipaddr": "77.170.179.229",
            "iss": "https://sts.windows.net/4fa94b7d-a743-486f-abcc-6c276c44cf4b/",
            "nbf": "1604306119",
            "puid": "1003200045B17AD4",
            "rh": "0.AAAAfUupT0Onb0irzGwnbETPS4NAS8SwO8FJtH2XTlPL3zxRAA8.",
            "uti": "rqr63RW_Kk6ztuomENMQAA",
            "ver": "1.0",
            "wids": "5d6b6bb7-de71-4623-b4af-96380a352509",
            "xms_tcdt": "1469565974"
          },
          "claims_initiated_by_user": {
            "schema": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims"
          }
        },
        "operation_name": "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE",
        "properties": {
          "entity": "/subscriptions/3f041b6d-fc31-41d8-8ff6-e5f16e6747ff/resourceGroups/obs-test/providers/Microsoft.Resources/deployments/NoMarketplace",
          "eventCategory": "Administrative",
          "hierarchy": "",
          "message": "Microsoft.Resources/deployments/write"
        },
        "result_signature": "Succeeded.",
        "result_type": "Success"
      },
      "correlation_id": "876190b4-5b99-4a39-b725-4f5644911cf0",
      "resource": {
        "group": "OBS-TEST",
        "id": "/SUBSCRIPTIONS/3f041b6d-fc31-41d8-8ff6-e5f16e6747ff/RESOURCEGROUPS/OBS-TEST/PROVIDERS/MICROSOFT.RESOURCES/DEPLOYMENTS/NOMARKETPLACE",
        "name": "NOMARKETPLACE",
        "provider": "MICROSOFT.RESOURCES/DEPLOYMENTS"
      },
      "subscription_id": "3f041b6d-fc31-41d8-8ff6-e5f16e6747ff"
    },
    "azure-eventhub": {
      "consumer_group": "$Default",
      "enqueued_time": "2020-11-02T08:59:38.905Z",
      "eventhub": "insights-activity-logs",
      "offset": 107374182400,
      "sequence_number": 643
    },
    "cloud": {
      "provider": "azure"
    },
    "data_stream": {
      "dataset": "azure.activitylogs",
      "namespace": "default",
      "type": "logs"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "action": "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE",
      "dataset": "azure.activitylogs",
      "duration": "0",
      "ingested": "2020-10-30T20:47:48.123859400Z",
      "kind": "event",
      "outcome": "success"
    },
    "input": {
      "type": "azure-eventhub"
    },
    "log": {
      "level": "Information"
    },
    "tags": [
      "forwarded"
    ]
  },
  "_type": "_doc"
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.activitylogs.category | Category | keyword |
| azure.activitylogs.event_category | Event Category | keyword |
| azure.activitylogs.identity.authorization.action | Action | keyword |
| azure.activitylogs.identity.authorization.evidence.principal_id | Principal ID | keyword |
| azure.activitylogs.identity.authorization.evidence.principal_type | Principal type | keyword |
| azure.activitylogs.identity.authorization.evidence.role | Role | keyword |
| azure.activitylogs.identity.authorization.evidence.role_assignment_id | Role assignment ID | keyword |
| azure.activitylogs.identity.authorization.evidence.role_assignment_scope | Role assignment scope | keyword |
| azure.activitylogs.identity.authorization.evidence.role_definition_id | Role definition ID | keyword |
| azure.activitylogs.identity.authorization.scope | Scope | keyword |
| azure.activitylogs.identity.claims.* | Claims | object |
| azure.activitylogs.identity.claims_initiated_by_user.fullname | Fullname | keyword |
| azure.activitylogs.identity.claims_initiated_by_user.givenname | Givenname | keyword |
| azure.activitylogs.identity.claims_initiated_by_user.name | Name | keyword |
| azure.activitylogs.identity.claims_initiated_by_user.schema | Schema | keyword |
| azure.activitylogs.identity.claims_initiated_by_user.surname | Surname | keyword |
| azure.activitylogs.operation_name | Operation name | keyword |
| azure.activitylogs.properties.service_request_id | Service Request Id | keyword |
| azure.activitylogs.properties.status_code | Status code | keyword |
| azure.activitylogs.result_signature | Result signature | keyword |
| azure.activitylogs.result_type | Result type | keyword |
| azure.correlation_id | Correlation ID | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |


An example event for `platformlogs` looks as following:

```$json
{
  "_id": "oQRumHUBvB2moownKezJ",
  "_index": "filebeat-8.0.0-2020.11.05-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-11-05T12:41:49.000Z",
    "agent": {
      "ephemeral_id": "a6339387-a2fe-4db0-9d13-ca3123f92366",
      "id": "17cead09-57ad-4668-8a0e-b9025f8b0cb0",
      "name": "DESKTOP-RFOOE09",
      "type": "filebeat",
      "version": "8.0.0"
    },
    "azure": {
      "platformlogs": {
        "Cloud": "AzureCloud",
        "Environment": "prod",
        "UnderlayClass": "hcp-underlay",
        "UnderlayName": "hcp-underlay-westeurope-cx-316",
        "attrs": "{\"annotation.io.kubernetes.container.hash\"=\u003e\"b74d7ef3\", \"annotation.io.kubernetes.container.ports\"=\u003e\"[{\"name\":\"https\",\"containerPort\":4444,\"protocol\":\"TCP\"}]\", \"annotation.io.kubernetes.container.preStopHandler\"=\u003e\"{\"exec\":{\"command\":[\"/bin/bash\",\"-c\",\"sleep 20\"]}}\"}",
        "category": "kube-apiserver",
        "ccpNamespace": "5e4bf4baee195b00017cdbfa",
        "event_category": "Administrative",
        "operation_name": "Microsoft.ContainerService/managedClusters/diagnosticLogs/Read",
        "properties": {
          "containerID": "ca7ca3b15f428368fabab4dff0c14879a838f8653f84312833d5024547a008f4",
          "pod": "kube-apiserver-666bd4b459-vgc5h",
          "stream": "stderr"
        }
      },
      "resource": {
        "group": "OBS-INFRASTRUCTURE",
        "id": "/SUBSCRIPTIONS/70BD6E77-4B1E-4835-8896-DB77B8EEF364/RESOURCEGROUPS/OBS-INFRASTRUCTURE/PROVIDERS/MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/OBSKUBE",
        "name": "OBSKUBE",
        "provider": "MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS"
      },
      "subscription_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53"
    },
    "azure-eventhub": {
      "consumer_group": "$Default",
      "enqueued_time": "2020-11-05T12:42:14.453Z",
      "eventhub": "insights-logs-kube-apiserver",
      "offset": 100168,
      "sequence_number": 45
    },
    "cloud": {
      "provider": "azure"
    },
    "ecs": {
      "version": "1.6.0"
    },
    "event": {
      "action": "Microsoft.ContainerService/managedClusters/diagnosticLogs/Read",
      "dataset": "azure.platformlogs",
      "ingested": "2020-11-05T12:42:37.895235200Z",
      "kind": "event",
      "module": "azure"
    },
    "fileset": {
      "name": "platformlogs"
    },
    "input": {
      "type": "azure-eventhub"
    },
    "message": "I1105 12:41:49.339404       1 controller.go:107] OpenAPI AggregationController: Processing item v1beta1.metrics.k8s.io",
    "service": {
      "type": "azure"
    },
    "tags": [
      "forwarded"
    ]
  },
  "_type": "_doc"
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.activitylogs.category | Category | keyword |
| azure.activitylogs.event_category | Event Category | keyword |
| azure.activitylogs.operation_name | Operation name | keyword |
| azure.activitylogs.properties.service_request_id | Service Request Id | keyword |
| azure.activitylogs.properties.status_code | Status code | keyword |
| azure.activitylogs.result_signature | Result signature | keyword |
| azure.activitylogs.result_type | Result type | keyword |
| azure.correlation_id | Correlation ID | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |


An example event for `auditlogs` looks as following:

```$json
{
  "_id": "bQlEe3UBm_qs2Y3aNZPq",
  "_index": ".ds-logs-azure.auditlogs-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-11-02T08:51:36.997Z",
    "azure-eventhub": {
      "consumer_group": "$Default",
      "enqueued_time": "2020-11-02T08:59:38.905Z",
      "eventhub": "insights-auditlogs-logs",
      "offset": 107374182400,
      "sequence_number": 643
    },
    "azure.auditlogs.category": "AuditLogs",
    "azure.auditlogs.identity": "Device Registration Service",
    "azure.auditlogs.operation_name": "Update device",
    "azure.auditlogs.operation_version": "1.0",
    "azure.auditlogs.properties.activity_datetime": "2019-10-18T15:30:51.0273716+00:00",
    "azure.auditlogs.properties.activity_display_name": "Update device",
    "azure.auditlogs.properties.category": "Device",
    "azure.auditlogs.properties.correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.auditlogs.properties.id": "Directory_ESQ",
    "azure.auditlogs.properties.initiated_by.app.appId": null,
    "azure.auditlogs.properties.initiated_by.app.displayName": "Device Registration Service",
    "azure.auditlogs.properties.initiated_by.app.servicePrincipalId": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.auditlogs.properties.initiated_by.app.servicePrincipalName": null,
    "azure.auditlogs.properties.logged_by_service": "Core Directory",
    "azure.auditlogs.properties.operation_type": "Update",
    "azure.auditlogs.properties.result_reason": "",
    "azure.auditlogs.properties.target_resources.0.display_name": "LAPTOP-12",
    "azure.auditlogs.properties.target_resources.0.id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.auditlogs.properties.target_resources.0.modified_properties.0.display_name": "Included Updated Properties",
    "azure.auditlogs.properties.target_resources.0.modified_properties.0.new_value": "\"\"",
    "azure.auditlogs.properties.target_resources.0.modified_properties.0.old_value": null,
    "azure.auditlogs.properties.target_resources.0.type": "Device",
    "azure.auditlogs.result_signature": "None",
    "azure.correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.resource.id": "/tenants/8a4de8b5-095c-47d0-a96f-a75130c61d53/providers/Microsoft.aadiam",
    "azure.resource.provider": "Microsoft.aadiam",
    "azure.tenant_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "cloud": {
      "provider": "azure"
    },
    "data_stream": {
      "dataset": "azure.auditlogs",
      "namespace": "default",
      "type": "logs"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "action": "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE",
      "dataset": "azure.auditlogs",
      "duration": "0",
      "ingested": "2020-10-30T20:47:48.123859400Z",
      "kind": "event",
      "outcome": "success"
    },
    "input": {
      "type": "azure-eventhub"
    },
    "log": {
      "level": "Information"
    },
    "tags": [
      "forwarded"
    ]
  },
  "_type": "_doc"
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.auditlogs.category | The category of the operation.  Currently, Audit is the only supported value. | keyword |
| azure.auditlogs.identity | Identity | keyword |
| azure.auditlogs.operation_name | The operation name | keyword |
| azure.auditlogs.operation_version | The operation version | keyword |
| azure.auditlogs.properties.activity_datetime | Activity timestamp | date |
| azure.auditlogs.properties.activity_display_name | Activity display name | keyword |
| azure.auditlogs.properties.category | category | keyword |
| azure.auditlogs.properties.correlation_id | Correlation ID | keyword |
| azure.auditlogs.properties.id | ID | keyword |
| azure.auditlogs.properties.initiated_by.app.appId | App ID | keyword |
| azure.auditlogs.properties.initiated_by.app.displayName | Display name | keyword |
| azure.auditlogs.properties.initiated_by.app.servicePrincipalId | Service principal ID | keyword |
| azure.auditlogs.properties.initiated_by.app.servicePrincipalName | Service principal name | keyword |
| azure.auditlogs.properties.initiated_by.user.displayName | Display name | keyword |
| azure.auditlogs.properties.initiated_by.user.id | ID | keyword |
| azure.auditlogs.properties.initiated_by.user.ipAddress | ip Address | keyword |
| azure.auditlogs.properties.initiated_by.user.userPrincipalName | User principal name | keyword |
| azure.auditlogs.properties.logged_by_service | Logged by service | keyword |
| azure.auditlogs.properties.operation_type | Operation type | keyword |
| azure.auditlogs.properties.result | Log result | keyword |
| azure.auditlogs.properties.result_reason | Reason for the log result | keyword |
| azure.auditlogs.properties.target_resources.*.display_name | Display name | keyword |
| azure.auditlogs.properties.target_resources.*.id | ID | keyword |
| azure.auditlogs.properties.target_resources.*.ip_address | ip Address | keyword |
| azure.auditlogs.properties.target_resources.*.modified_properties.*.display_name | Display value | keyword |
| azure.auditlogs.properties.target_resources.*.modified_properties.*.new_value | New value | keyword |
| azure.auditlogs.properties.target_resources.*.modified_properties.*.old_value | Old value | keyword |
| azure.auditlogs.properties.target_resources.*.type | Type | keyword |
| azure.auditlogs.properties.target_resources.*.user_principal_name | User principal name | keyword |
| azure.auditlogs.result_signature | Result signature | keyword |
| azure.auditlogs.tenant_id | Tenant ID | keyword |
| azure.correlation_id | Correlation ID | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |


An example event for `signinlogs` looks as following:

```$json
{
  "_id": "bQlEe3UBm_qs2Y3aNZPq",
  "_index": ".ds-logs-azure.signinlogs-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-11-02T08:51:36.997Z",
    "azure-eventhub": {
      "consumer_group": "$Default",
      "enqueued_time": "2020-11-02T08:59:38.905Z",
      "eventhub": "insights-signinlogs-logs",
      "offset": 107374182400,
      "sequence_number": 643
    },
    "azure.correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.resource.id": "/tenants/8a4de8b5-095c-47d0-a96f-a75130c61d53/providers/Microsoft.aadiam",
    "azure.resource.provider": "Microsoft.aadiam",
    "azure.signinlogs.category": "SignInLogs",
    "azure.signinlogs.identity": "Test LTest",
    "azure.signinlogs.operation_name": "Sign-in activity",
    "azure.signinlogs.operation_version": "1.0",
    "azure.signinlogs.properties.app_display_name": "Office 365",
    "azure.signinlogs.properties.app_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.signinlogs.properties.client_app_used": "Browser",
    "azure.signinlogs.properties.conditional_access_status": "notApplied",
    "azure.signinlogs.properties.correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.signinlogs.properties.created_at": "2019-10-18T04:45:48.0729893-05:00",
    "azure.signinlogs.properties.device_detail.browser": "Chrome 77.0.3865",
    "azure.signinlogs.properties.device_detail.device_id": "",
    "azure.signinlogs.properties.device_detail.operating_system": "MacOs",
    "azure.signinlogs.properties.id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.signinlogs.properties.ip_address": "81.171.241.231",
    "azure.signinlogs.properties.is_interactive": false,
    "azure.signinlogs.properties.original_request_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.signinlogs.properties.processing_time_ms": 239,
    "azure.signinlogs.properties.risk_detail": "none",
    "azure.signinlogs.properties.risk_level_aggregated": "none",
    "azure.signinlogs.properties.risk_level_during_signin": "none",
    "azure.signinlogs.properties.risk_state": "none",
    "azure.signinlogs.properties.service_principal_id": "",
    "azure.signinlogs.properties.status.error_code": 50140,
    "azure.signinlogs.properties.token_issuer_name": "",
    "azure.signinlogs.properties.token_issuer_type": "AzureAD",
    "azure.signinlogs.properties.user_display_name": "Test LTest",
    "azure.signinlogs.properties.user_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.signinlogs.properties.user_principal_name": "test@elastic.co",
    "azure.signinlogs.result_description": "This error occurred due to 'Keep me signed in' interrupt when the user was signing-in.",
    "azure.signinlogs.result_signature": "None",
    "azure.signinlogs.result_type": "50140",
    "azure.tenant_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "cloud": {
      "provider": "azure"
    },
    "cloud.provider": "azure",
    "data_stream": {
      "dataset": "azure.auditlogs",
      "namespace": "default",
      "type": "logs"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event.action": "Sign-in activity",
    "event.category": [
      "authentication"
    ],
    "input": {
      "type": "azure-eventhub"
    },
    "log": {
      "level": "Information"
    },
    "tags": [
      "forwarded"
    ]
  },
  "_type": "_doc"
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.correlation_id | Correlation ID | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.signinlogs.category | Category | keyword |
| azure.signinlogs.identity | Identity | keyword |
| azure.signinlogs.operation_name | The operation name | keyword |
| azure.signinlogs.operation_version | The operation version | keyword |
| azure.signinlogs.properties.app_display_name | App display name | keyword |
| azure.signinlogs.properties.app_id | App ID | keyword |
| azure.signinlogs.properties.client_app_used | Client app used | keyword |
| azure.signinlogs.properties.conditional_access_status | Conditional access status | keyword |
| azure.signinlogs.properties.correlation_id | Correlation ID | keyword |
| azure.signinlogs.properties.created_at | Created date time | date |
| azure.signinlogs.properties.device_detail.browser | Browser | keyword |
| azure.signinlogs.properties.device_detail.device_id | Device ID | keyword |
| azure.signinlogs.properties.device_detail.display_name | Display name | keyword |
| azure.signinlogs.properties.device_detail.operating_system | Operating system | keyword |
| azure.signinlogs.properties.device_detail.trust_type | Trust type | keyword |
| azure.signinlogs.properties.id | ID | keyword |
| azure.signinlogs.properties.ip_address | Ip address | keyword |
| azure.signinlogs.properties.is_interactive | Is interactive | keyword |
| azure.signinlogs.properties.original_request_id | Original request ID | keyword |
| azure.signinlogs.properties.processing_time_ms | Processing time in milliseconds | float |
| azure.signinlogs.properties.resource_display_name | Resource display name | keyword |
| azure.signinlogs.properties.risk_detail | Risk detail | keyword |
| azure.signinlogs.properties.risk_level_aggregated | Risk level aggregated | keyword |
| azure.signinlogs.properties.risk_level_during_signin | Risk level during signIn | keyword |
| azure.signinlogs.properties.risk_state | Risk state | keyword |
| azure.signinlogs.properties.service_principal_id | Status | keyword |
| azure.signinlogs.properties.status.error_code | Error code | keyword |
| azure.signinlogs.properties.token_issuer_name | Token issuer name | keyword |
| azure.signinlogs.properties.token_issuer_type | Token issuer type | keyword |
| azure.signinlogs.properties.user_display_name | User display name | keyword |
| azure.signinlogs.properties.user_id | User ID | keyword |
| azure.signinlogs.properties.user_principal_name | User principal name | keyword |
| azure.signinlogs.result_description | Result description | keyword |
| azure.signinlogs.result_signature | Result signature | keyword |
| azure.signinlogs.result_type | Result type | keyword |
| azure.signinlogs.tenant_id | Tenant ID | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |







