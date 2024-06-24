# Microsoft Entra ID Logs

Microsoft Entra ID logs are records of events and activities that occur within a Microsoft Entra ID environment of an organization.

These logs capture important information such as user sign-ins, changes to user accounts, and more. They can be used to monitor and track user activity, identify security threats, troubleshoot issues, and generate reports for compliance purposes.

The Microsoft Entra ID logs integration contain several data streams:

* **Sign-in logs** – Information about sign-ins and how your users use your resources.
* **Identity Protection logs** - Information about user risk status and the events that change it.
* **Provisioning logs** - Information about users and group synchronization to and from external enterprise applications.
* **Audit logs** – Information about changes to your tenant, such as users and group management, or updates to your tenant's resources.

Supported Azure log categories:

| Data Stream         | Log Category                                                                                                                          |
|:-------------------:|:-------------------------------------------------------------------------------------------------------------------------------------:|
| Sign-in             | SignInLogs                                                                                                                            |
| Sign-in             | [NonInteractiveUserSignInLogs](https://docs.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs) |
| Sign-in             | [ServicePrincipalSignInLogs](https://docs.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs)     |
| Sign-in             | [ManagedIdentitySignInLogs](https://docs.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs)       |
| Audit               | [AuditLogs](https://docs.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)                                          |
| Identity Protection | [RiskyUsers](https://docs.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadriskyusers)                                     |
| Identity Protection | [UserRiskEvents](https://docs.microsoft.com/en-us/azure/azure-monitor/reference/tables/aaduserriskevents)                             |
| Provisioning        | [ProvisioningLogs](https://docs.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadprovisioninglogs)                         |

## Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

## Settings

`eventhub` :
  _string_
This setting expects the name of a single Event Hub (see the [difference between a namespace and an Event Hub](https://docs.elastic.co/integrations/azure#event-hub-namespace-vs-event-hub)). It is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You can use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
Default value `insights-operational-logs`.

`consumer_group` :
_string_
 The publish/subscribe mechanism of Event Hubs is enabled through consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_
The connection string required to communicate with the specified Event Hub, steps here https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string.

A Blob Storage account is required in order to store/retrieve/update the offset or state of the eventhub messages. This means that after stopping the filebeat azure module it can start back up at the spot that it stopped processing messages.

`storage_account` :
_string_
The name of the storage account the state/offsets will be stored and updated.

`storage_account_key` :
_string_
The storage account key, this key will be used to authorize access to data in your storage account.

`storage_account_container` :
_string_
The storage account container where the integration stores the checkpoint data for the consumer group. It is an advanced option to use with extreme care. You MUST use a dedicated storage account container for each Azure log type (activity, sign-in, audit logs, and others). DO NOT REUSE the same container name for more than one Azure log type. See [Container Names](https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata#container-names) for details on naming rules from Microsoft. The integration generates a default container name if not specified.

`resource_manager_endpoint` :
_string_
Optional, by default we are using the azure public environment, to override, users can provide a specific resource manager endpoint in order to use a different azure environment.

Resource manager endpoints:

```text
# Azure ChinaCloud
https://management.chinacloudapi.cn/

# Azure GermanCloud
https://management.microsoftazure.de/

# Azure PublicCloud 
https://management.azure.com/

# Azure USGovernmentCloud
https://management.usgovcloudapi.net/
```

## Logs

### Sign-in logs

Retrieves Microsoft Entra ID sign-in logs. The sign-ins report provides information about the usage of managed applications and user sign-in activities.

{{event "signinlogs"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "signinlogs"}}

### Identity Protection logs

Retrieves Microsoft Entra ID Protection logs. The [Microsoft Entra ID Protection](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection) service analyzes events from Microsoft Entra ID users' behavior, detects risk situations, and can respond by reporting only or even blocking users at risk, according to policy configurations.

{{event "identity_protection"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "identity_protection"}}

### Provisioning logs

Retrieves Microsoft Entra ID Provisioning logs. The [Microsoft Entra ID Provisioning](https://docs.microsoft.com/en-us/azure/active-directory/app-provisioning/how-provisioning-works) service syncs Microsoft Entra ID users and groups to and from external enterprise applications. For example, you can configure the provisioning service to replicate all existing Microsoft Entra ID users and groups to an external Dropbox Business account or vice versa.

The Provisioning Logs contain a lot of details about a inbound/outbound sync activity, like:

* User or group details.
* Source and target systems (for ex., from Microsoft Entra ID to Dropbox).
* Provisioning status.
* Provisioning steps (with details for each step).

{{event "provisioning"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "provisioning"}}

### Audit logs

Retrieves Microsoft Entra ID audit logs. The audit logs provide traceability through logs for all changes done by various features within Microsoft Entra ID. Examples of audit logs include changes made to any resources within Microsoft Entra ID like adding or removing users, apps, groups, roles and policies.

{{event "auditlogs"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "auditlogs"}}
