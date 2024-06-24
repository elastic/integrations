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

An example event for `signinlogs` looks as following:

```json
{
    "@timestamp": "2019-10-18T09:45:48.072Z",
    "azure": {
        "correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "resource": {
            "id": "/tenants/8a4de8b5-095c-47d0-a96f-a75130c61d53/providers/Microsoft.aadiam",
            "provider": "Microsoft.aadiam"
        },
        "signinlogs": {
            "category": "SignInLogs",
            "identity": "Test LTest",
            "operation_name": "Sign-in activity",
            "operation_version": "1.0",
            "properties": {
                "app_display_name": "Office 365",
                "app_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
                "client_app_used": "Browser",
                "conditional_access_status": "notApplied",
                "correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
                "created_at": "2019-10-18T04:45:48.0729893-05:00",
                "device_detail": {
                    "browser": "Chrome 77.0.3865",
                    "device_id": "",
                    "operating_system": "MacOs"
                },
                "id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
                "is_interactive": false,
                "original_request_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
                "processing_time_ms": 239,
                "risk_detail": "none",
                "risk_level_aggregated": "none",
                "risk_level_during_signin": "none",
                "risk_state": "none",
                "service_principal_id": "",
                "status": {
                    "error_code": 50140
                },
                "token_issuer_name": "",
                "token_issuer_type": "AzureAD",
                "user_display_name": "Test LTest",
                "user_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
                "user_principal_name": "test@elastic.co"
            },
            "result_description": "This error occurred due to 'Keep me signed in' interrupt when the user was signing-in.",
            "result_signature": "None",
            "result_type": "50140"
        },
        "tenant_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53"
    },
    "client": {
        "ip": "1.1.1.1"
    },
    "cloud": {
        "provider": "azure"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "Sign-in activity",
        "category": [
            "authentication"
        ],
        "duration": 0,
        "id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "ingested": "2021-09-14T17:20:47.736433526Z",
        "kind": "event",
        "original": "{\"Level\":\"4\",\"callerIpAddress\":\"1.1.1.1\",\"category\":\"SignInLogs\",\"correlationId\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"durationMs\":0,\"identity\":\"Test LTest\",\"location\":\"FR\",\"operationName\":\"Sign-in activity\",\"operationVersion\":\"1.0\",\"properties\":{\"appDisplayName\":\"Office 365\",\"appId\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"clientAppUsed\":\"Browser\",\"conditionalAccessStatus\":\"notApplied\",\"correlationId\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"createdDateTime\":\"2019-10-18T04:45:48.0729893-05:00\",\"deviceDetail\":{\"browser\":\"Chrome 77.0.3865\",\"deviceId\":\"\",\"operatingSystem\":\"MacOs\"},\"id\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"ipAddress\":\"1.1.1.1\",\"isInteractive\":false,\"location\":{\"city\":\"Champs-Sur-Marne\",\"countryOrRegion\":\"FR\",\"geoCoordinates\":{\"latitude\":48.12341234,\"longitude\":2.12341234},\"state\":\"Seine-Et-Marne\"},\"originalRequestId\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"processingTimeInMilliseconds\":239,\"riskDetail\":\"none\",\"riskLevelAggregated\":\"none\",\"riskLevelDuringSignIn\":\"none\",\"riskState\":\"none\",\"servicePrincipalId\":\"\",\"status\":{\"errorCode\":50140,\"failureReason\":\"This error occurred due to 'Keep me signed in' interrupt when the user was signing-in.\"},\"tokenIssuerName\":\"\",\"tokenIssuerType\":\"AzureAD\",\"userDisplayName\":\"Test LTest\",\"userId\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"userPrincipalName\":\"test@elastic.co\"},\"resourceId\":\"/tenants/8a4de8b5-095c-47d0-a96f-a75130c61d53/providers/Microsoft.aadiam\",\"resultDescription\":\"This error occurred due to 'Keep me signed in' interrupt when the user was signing-in.\",\"resultSignature\":\"None\",\"resultType\":\"50140\",\"tenantId\":\"8a4de8b5-095c-47d0-a96f-a75130c61d53\",\"time\":\"2019-10-18T09:45:48.0729893Z\"}",
        "outcome": "failure",
        "type": [
            "info"
        ]
    },
    "geo": {
        "city_name": "Champs-Sur-Marne",
        "country_iso_code": "FR",
        "country_name": "Seine-Et-Marne",
        "location": {
            "lat": 48.12341234,
            "lon": 2.12341234
        }
    },
    "log": {
        "level": "4"
    },
    "message": "This error occurred due to 'Keep me signed in' interrupt when the user was signing-in.",
    "related": {
        "ip": [
            "1.1.1.1"
        ]
    },
    "source": {
        "address": "1.1.1.1",
        "as": {
            "number": 13335,
            "organization": {
                "name": "Cloudflare, Inc."
            }
        },
        "geo": {
            "continent_name": "Oceania",
            "country_iso_code": "AU",
            "country_name": "Australia",
            "location": {
                "lat": -33.494,
                "lon": 143.2104
            }
        },
        "ip": "1.1.1.1"
    },
    "tags": [
        "preserve_original_event"
    ],
    "user": {
        "domain": "elastic.co",
        "full_name": "Test LTest",
        "id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
        "name": "test"
    }
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
| azure.signinlogs.caller_ip_address | The IP address of the client that made the request. | ip |
| azure.signinlogs.category | Category | keyword |
| azure.signinlogs.identity | Identity | keyword |
| azure.signinlogs.operation_name | The operation name | keyword |
| azure.signinlogs.operation_version | The operation version | keyword |
| azure.signinlogs.properties.app_display_name | App display name | keyword |
| azure.signinlogs.properties.app_id | App ID | keyword |
| azure.signinlogs.properties.applied_conditional_access_policies | A list of conditional access policies that are triggered by the corresponding sign-in activity. | flattened |
| azure.signinlogs.properties.authentication_details | The result of the authentication attempt and additional details on the authentication method. | flattened |
| azure.signinlogs.properties.authentication_processing_details | Additional authentication processing details, such as the agent name in case of PTA/PHS or Server/farm name in case of federated authentication. | flattened |
| azure.signinlogs.properties.authentication_protocol | Authentication protocol type. | keyword |
| azure.signinlogs.properties.authentication_requirement | This holds the highest level of authentication needed through all the sign-in steps, for sign-in to succeed. | keyword |
| azure.signinlogs.properties.authentication_requirement_policies | Set of CA policies that apply to this sign-in, each as CA: policy name, and/or MFA: Per-user | flattened |
| azure.signinlogs.properties.autonomous_system_number | Autonomous system number. | long |
| azure.signinlogs.properties.client_app_used | Client app used | keyword |
| azure.signinlogs.properties.conditional_access_status | Conditional access status | keyword |
| azure.signinlogs.properties.correlation_id | Correlation ID | keyword |
| azure.signinlogs.properties.created_at | Date and time (UTC) the sign-in was initiated. | date |
| azure.signinlogs.properties.cross_tenant_access_type |  | keyword |
| azure.signinlogs.properties.device_detail.browser | Browser | keyword |
| azure.signinlogs.properties.device_detail.device_id | Device ID | keyword |
| azure.signinlogs.properties.device_detail.display_name | Display name | keyword |
| azure.signinlogs.properties.device_detail.is_compliant | If the device is compliant | boolean |
| azure.signinlogs.properties.device_detail.is_managed | If the device is managed | boolean |
| azure.signinlogs.properties.device_detail.operating_system | Operating system | keyword |
| azure.signinlogs.properties.device_detail.trust_type | Trust type | keyword |
| azure.signinlogs.properties.flagged_for_review |  | boolean |
| azure.signinlogs.properties.home_tenant_id |  | keyword |
| azure.signinlogs.properties.id | Unique ID representing the sign-in activity. | keyword |
| azure.signinlogs.properties.incoming_token_type | Incoming token type. | keyword |
| azure.signinlogs.properties.is_interactive | Is interactive | boolean |
| azure.signinlogs.properties.is_tenant_restricted |  | boolean |
| azure.signinlogs.properties.network_location_details | The network location details including the type of network used and its names. | flattened |
| azure.signinlogs.properties.original_request_id | Original request ID | keyword |
| azure.signinlogs.properties.processing_time_ms | Processing time in milliseconds | float |
| azure.signinlogs.properties.resource_display_name | Resource display name | keyword |
| azure.signinlogs.properties.resource_id | The identifier of the resource that the user signed in to. | keyword |
| azure.signinlogs.properties.resource_tenant_id |  | keyword |
| azure.signinlogs.properties.risk_detail | Risk detail | keyword |
| azure.signinlogs.properties.risk_event_types | The list of risk event types associated with the sign-in. Possible values: unlikelyTravel, anonymizedIPAddress, maliciousIPAddress, unfamiliarFeatures, malwareInfectedIPAddress, suspiciousIPAddress, leakedCredentials, investigationsThreatIntelligence, generic, or unknownFutureValue. | keyword |
| azure.signinlogs.properties.risk_event_types_v2 | The list of risk event types associated with the sign-in. Possible values: unlikelyTravel, anonymizedIPAddress, maliciousIPAddress, unfamiliarFeatures, malwareInfectedIPAddress, suspiciousIPAddress, leakedCredentials, investigationsThreatIntelligence, generic, or unknownFutureValue. | keyword |
| azure.signinlogs.properties.risk_level_aggregated | Risk level aggregated | keyword |
| azure.signinlogs.properties.risk_level_during_signin | Risk level during signIn | keyword |
| azure.signinlogs.properties.risk_state | Risk state | keyword |
| azure.signinlogs.properties.service_principal_credential_key_id | Key id of the service principal that initiated the sign-in. | keyword |
| azure.signinlogs.properties.service_principal_id | The application identifier used for sign-in. This field is populated when you are signing in using an application. | keyword |
| azure.signinlogs.properties.service_principal_name | The application name used for sign-in. This field is populated when you are signing in using an application. | keyword |
| azure.signinlogs.properties.sso_extension_version |  | keyword |
| azure.signinlogs.properties.status.error_code | Error code | long |
| azure.signinlogs.properties.token_issuer_name | Token issuer name | keyword |
| azure.signinlogs.properties.token_issuer_type | Token issuer type | keyword |
| azure.signinlogs.properties.unique_token_identifier | Unique token identifier for the request. | keyword |
| azure.signinlogs.properties.user_display_name | User display name | keyword |
| azure.signinlogs.properties.user_id | User ID | keyword |
| azure.signinlogs.properties.user_principal_name | User principal name | keyword |
| azure.signinlogs.properties.user_type |  | keyword |
| azure.signinlogs.result_description | Result description | keyword |
| azure.signinlogs.result_signature | Result signature | keyword |
| azure.signinlogs.result_type | Result type | keyword |
| azure.signinlogs.tenant_id | Tenant ID | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |


### Identity Protection logs

Retrieves Microsoft Entra ID Protection logs. The [Microsoft Entra ID Protection](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection) service analyzes events from Microsoft Entra ID users' behavior, detects risk situations, and can respond by reporting only or even blocking users at risk, according to policy configurations.

An example event for `identity_protection` looks as following:

```json
{
    "@timestamp": "2022-08-22T18:07:16.000Z",
    "azure": {
        "correlation_id": "ce0ed07f9ccf5be15e4b97d2979af6569b1f67db87ddc9b88b5bb743ea091e47",
        "identityprotection": {
            "category": "UserRiskEvents",
            "operation_name": "User Risk Detection",
            "operation_version": "1.0",
            "properties": {
                "activity": "signin",
                "activity_datetime": "2022-08-22T18:05:06.133Z",
                "additional_info": [
                    {
                        "Key": "userAgent",
                        "Value": "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"
                    }
                ],
                "correlation_id": "266133c2-fabb-492f-9ebf-bdf12317b817",
                "detected_datetime": "2022-08-22T18:05:06.133Z",
                "detection_timing_type": "realtime",
                "id": "ce0ed07f9ccf5be15e4b97d2979af6569b1f67db87ddc9b88b5bb743ea091e47",
                "ip_address": "67.43.156.42",
                "location": {
                    "city": "Dresden",
                    "countryOrRegion": "DE",
                    "geoCoordinates": {
                        "altitude": 0,
                        "latitude": 51.0714,
                        "longitude": 13.7399
                    },
                    "state": "Sachsen"
                },
                "request_id": "e1b6d9d7-5fc0-4638-ae1a-e0abceb92200",
                "risk_detail": "none",
                "risk_event_type": "anonymizedIPAddress",
                "risk_last_updated_datetime": "2022-08-22T18:07:16.894Z",
                "risk_level": "high",
                "risk_state": "atRisk",
                "risk_type": "anonymizedIPAddress",
                "source": "IdentityProtection",
                "token_issuer_type": "AzureAD",
                "user_display_name": "Joe Danger",
                "user_id": "51e26eae-d07b-44e5-bb0b-249f49569a8c",
                "user_principal_name": "joe.danger@contoso.onmicrosoft.com",
                "user_type": "member"
            },
            "result_signature": "None"
        },
        "resource": {
            "id": "/tenants/5611623b-9128-461e-9d7f-a0d9c270ead2/providers/microsoft.aadiam",
            "provider": "microsoft.aadiam"
        },
        "tenant_id": "5611623b-9128-461e-9d7f-a0d9c270ead2"
    },
    "cloud": {
        "provider": "azure"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "User Risk Detection",
        "duration": 0,
        "kind": "event"
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.42"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.correlation_id | Correlation ID | keyword |
| azure.identityprotection.category | Category | keyword |
| azure.identityprotection.operation_name | Operation name | keyword |
| azure.identityprotection.operation_version | Operation version | keyword |
| azure.identityprotection.properties.activity | Indicates the activity type the detected risk is linked to. Possible values are: signin, user, unknownFutureValue. | keyword |
| azure.identityprotection.properties.activity_datetime | Date and time that the risky activity occurred. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is look like this: 2014-01-01T00:00:00Z. | date |
| azure.identityprotection.properties.additional_info | Additional information associated with the risk detection. Possible keys in the additionalInfo JSON string are: userAgent, alertUrl, relatedEventTimeInUtc, relatedUserAgent, deviceInformation, relatedLocation, requestId, correlationId, lastActivityTimeInUtc, malwareName, clientLocation, clientIp, riskReasons. For more information about riskReasons and possible values, see https://docs.microsoft.com/en-us/graph/api/resources/riskdetection?view=graph-rest-1.0#riskreasons-values. | flattened |
| azure.identityprotection.properties.correlation_id | Correlation ID of the sign-in associated with the risk detection. This property is null if the risk detection is not associated with a sign-in. | keyword |
| azure.identityprotection.properties.cross_tenant_access_type |  | keyword |
| azure.identityprotection.properties.detected_datetime | Date and time that the risk was detected. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like this: 2014-01-01T00:00:00Z. | date |
| azure.identityprotection.properties.detection_timing_type | Timing of the detected risk (real-time/offline). Possible values are: notDefined, realtime, nearRealtime, offline, unknownFutureValue. | keyword |
| azure.identityprotection.properties.home_tenant_id |  | keyword |
| azure.identityprotection.properties.id | Unique ID of the risk detection. | keyword |
| azure.identityprotection.properties.ip_address | Provides the IP address of the client from where the risk occurred. | ip |
| azure.identityprotection.properties.is_deleted | Indicates whether the user is deleted. | boolean |
| azure.identityprotection.properties.is_guest |  | boolean |
| azure.identityprotection.properties.is_processing | Indicates whether a user's risky state is being processed by the backend. | boolean |
| azure.identityprotection.properties.last_updated_datetime | Date and time when the risk detection was last updated. | date |
| azure.identityprotection.properties.location | Location of the sign-in. | flattened |
| azure.identityprotection.properties.request_id | Request ID of the sign-in associated with the risk detection. This property is null if the risk detection is not associated with a sign-in. | keyword |
| azure.identityprotection.properties.resource_tenant_id |  | keyword |
| azure.identityprotection.properties.risk_detail | Details of the detected risk. Possible values are: none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, unknownFutureValue. | keyword |
| azure.identityprotection.properties.risk_event_type | The type of risk event detected. The possible values are unlikelyTravel, anonymizedIPAddress, maliciousIPAddress, unfamiliarFeatures, malwareInfectedIPAddress, suspiciousIPAddress, leakedCredentials, investigationsThreatIntelligence, generic,adminConfirmedUserCompromised, passwordSpray, impossibleTravel, newCountry, anomalousToken, tokenIssuerAnomaly,suspiciousBrowser, riskyIPAddress, mcasSuspiciousInboxManipulationRules, suspiciousInboxForwarding, and unknownFutureValue. If the risk detection is a premium detection, will show generic. For more information about each value, see https://docs.microsoft.com/en-us/graph/api/resources/riskdetection?view=graph-rest-1.0#riskeventtype-values values. | keyword |
| azure.identityprotection.properties.risk_last_updated_datetime | The date and time that the risky user was last updated. | date |
| azure.identityprotection.properties.risk_level | Level of the detected risk. Possible values are: low, medium, high, hidden, none, unknownFutureValue. | keyword |
| azure.identityprotection.properties.risk_state | The state of a detected risky user or sign-in. Possible values are: none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised, unknownFutureValue. | keyword |
| azure.identityprotection.properties.risk_type |  | keyword |
| azure.identityprotection.properties.source | Source of the risk detection. For example, activeDirectory. | keyword |
| azure.identityprotection.properties.token_issuer_type | Indicates the type of token issuer for the detected sign-in risk. Possible values are: AzureAD, ADFederationServices, UnknownFutureValue. | keyword |
| azure.identityprotection.properties.user_display_name | The user display name of the user. | keyword |
| azure.identityprotection.properties.user_id | Unique ID of the user. | keyword |
| azure.identityprotection.properties.user_principal_name | The user principal name (UPN) of the user. | keyword |
| azure.identityprotection.properties.user_type | The type of the user (for example, "member"). | keyword |
| azure.identityprotection.result_signature | Result signature | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| geo.region_iso_code | Region ISO code. | keyword |
| geo.region_name | Region name. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |


### Provisioning logs

Retrieves Microsoft Entra ID Provisioning logs. The [Microsoft Entra ID Provisioning](https://docs.microsoft.com/en-us/azure/active-directory/app-provisioning/how-provisioning-works) service syncs Microsoft Entra ID users and groups to and from external enterprise applications. For example, you can configure the provisioning service to replicate all existing Microsoft Entra ID users and groups to an external Dropbox Business account or vice versa.

The Provisioning Logs contain a lot of details about a inbound/outbound sync activity, like:

* User or group details.
* Source and target systems (for ex., from Microsoft Entra ID to Dropbox).
* Provisioning status.
* Provisioning steps (with details for each step).

An example event for `provisioning` looks as following:

```json
{
    "@timestamp": "2022-08-23T13:36:50.353Z",
    "azure": {
        "correlation_id": "54416401-eef2-461c-8de7-385dde2b3cba",
        "provisioning": {
            "category": "ProvisioningLogs",
            "identity": "d6cbb0bd-c3ec-6455-bd3e-4282141ce369",
            "level": 4,
            "operation_name": "Provisioning activity",
            "operation_version": "1.0",
            "properties": {
                "action": "Create",
                "activity_datetime": "2022-08-23T13:36:50.3538931Z",
                "change_id": "54416401-eef2-461c-8de7-385dde2b3cba",
                "cycle_id": "cc305635-a28e-4139-a056-42b5102933fe",
                "duration_ms": 828,
                "id": "d6cbb0bd-c3ec-6455-bd3e-4282141ce369",
                "initiated_by": {
                    "id": "",
                    "name": "Azure AD Provisioning Service",
                    "type": "system"
                },
                "job_id": "DropboxSCIMOutDelta.5611623b9128461e9d7fa0d9c270ead2.d6163622-bdf8-4b26-976f-7d573c638e2a",
                "modified_properties": [],
                "provisioning_action": "create",
                "provisioning_status_info": {
                    "status": "skipped"
                },
                "provisioning_steps": [
                    {
                        "description": "Received User 'ellie@contoso.onmicrosoft.com' change of type (Add) from Azure Active Directory",
                        "details": {
                            "IsSoftDeleted": "False",
                            "accountEnabled": "True",
                            "appRoleAssignments": "User",
                            "displayName": "Ellie",
                            "givenName": "Ellie",
                            "mailNickname": "ellie",
                            "objectId": "7383d412-41f2-478f-a317-7396cc32ce9e",
                            "userPrincipalName": "ellie@contoso.onmicrosoft.com"
                        },
                        "name": "EntryImportAdd",
                        "provisioning_step_type": 0,
                        "status": 0
                    },
                    {
                        "description": "Determine if User in scope by evaluating against each scoping filter",
                        "details": {
                            "Active in the source system": "True",
                            "Assigned to the application": "True",
                            "ScopeEvaluationResult": "{}",
                            "Scoping filter evaluation passed": "True",
                            "User has the required role": "True"
                        },
                        "name": "EntrySynchronizationScoping",
                        "provisioning_step_type": 1,
                        "status": 0
                    },
                    {
                        "description": "User 'ellie@contoso.onmicrosoft.com' will be created in Dropbox (User is active and assigned in Azure Active Directory, but no matching User was found in Dropbox)",
                        "details": {},
                        "name": "EntrySynchronizationAdd",
                        "provisioning_step_type": 2,
                        "status": 0
                    },
                    {
                        "description": "urn:ietf:params:scim:schemas:core:2.0:User 'ellie@contoso.onmicrosoft.com' will be skipped because the value of the property name.familyName is missing or invalid. Please update the value of the property name.familyName on the object in the source system.",
                        "details": {
                            "PropertyName": "name.familyName",
                            "ReportableIdentifier": "ellie@contoso.onmicrosoft.com",
                            "SkipReason": "AttributeValidationFailed"
                        },
                        "name": "EntrySynchronizationSkip",
                        "provisioning_step_type": 3,
                        "status": 2
                    }
                ],
                "service_principal": {
                    "id": "74866461-3754-40ed-a743-9c88ff29643e",
                    "name": "Dropbox Business"
                },
                "source_identity": {
                    "details": {
                        "display_name": "Ellie",
                        "id": "7383d412-41f2-478f-a317-7396cc32ce9e",
                        "odatatype": "User",
                        "user_principal_name": "ellie@contoso.onmicrosoft.com"
                    },
                    "id": "7383d412-41f2-478f-a317-7396cc32ce9e",
                    "identity_type": "User",
                    "name": "Ellie"
                },
                "source_system": {
                    "details": {},
                    "id": "bab3751f-8f21-4657-8fce-698f7391dbdd",
                    "name": "Azure Active Directory"
                },
                "target_identity": {
                    "details": {},
                    "id": "",
                    "identity_type": "urn:ietf:params:scim:schemas:core:2.0:User",
                    "name": ""
                },
                "target_system": {
                    "details": {
                        "application_id": "97e0a159-74ec-4db1-918a-c03a9c3b6b81",
                        "dervice_principal_display_name": "Dropbox Business",
                        "service_principal_id": "74866461-3754-40ed-a743-9c88ff29643e"
                    },
                    "id": "011a448f-1441-4336-8c20-e2d2cef9c410",
                    "name": "Dropbox"
                },
                "tenant_id": "5611623b-9128-461e-9d7f-a0d9c270ead2"
            },
            "result_type": "Skipped"
        },
        "resource": {
            "id": "/tenants/5611623b-9128-461e-9d7f-a0d9c270ead2/providers/Microsoft.aadiam",
            "provider": "Microsoft.aadiam"
        },
        "tenant_id": "5611623b-9128-461e-9d7f-a0d9c270ead2"
    },
    "cloud": {
        "provider": "azure"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "Provisioning activity",
        "duration": 828000000,
        "kind": "event"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.correlation_id | Correlation ID | keyword |
| azure.provisioning.category | Category | keyword |
| azure.provisioning.identity | Describes the identity of the user or application that performed the operation | keyword |
| azure.provisioning.level | The severity level of the event | long |
| azure.provisioning.operation_name | Operation name | keyword |
| azure.provisioning.operation_version | Operation version | keyword |
| azure.provisioning.properties.action | Indicates the activity name or the operation name. | keyword |
| azure.provisioning.properties.activity_datetime | Indicates the date and time the activity was performed. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | date |
| azure.provisioning.properties.change_id | Unique ID of this change in this cycle | keyword |
| azure.provisioning.properties.cycle_id | Unique ID per job iteration | keyword |
| azure.provisioning.properties.duration_ms | Indicates how long this provisioning action took to finish. Measured in milliseconds. | long |
| azure.provisioning.properties.id | Indicates the unique ID for the activity | keyword |
| azure.provisioning.properties.initiated_by.id | Uniquely identifies the person or service that initiated the provisioning event. | keyword |
| azure.provisioning.properties.initiated_by.name | Name of the person or service that initiated the provisioning event. | keyword |
| azure.provisioning.properties.initiated_by.type | Type of initiator. Possible values are: user, application, system, unknownFutureValue. | keyword |
| azure.provisioning.properties.job_id | The unique ID for the whole provisioning job. | keyword |
| azure.provisioning.properties.modified_properties | Details of each property that was modified in this provisioning action on this object. | flattened |
| azure.provisioning.properties.provisioning_action | Indicates the activity name or the operation name. Possible values are: create, update, delete, stageddelete, disable, other and unknownFutureValue. For a list of activities logged, refer to Microsoft Entra ID activity list. | keyword |
| azure.provisioning.properties.provisioning_status_info.error_information.additional_details | Additional details in case of error. | keyword |
| azure.provisioning.properties.provisioning_status_info.error_information.error_category | Categorizes the error code. Possible values are failure, nonServiceFailure, success, unknownFutureValue. | keyword |
| azure.provisioning.properties.provisioning_status_info.error_information.error_code | Unique error code if any occurred. To learn more, visit https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-provisioning-logs#error-codes | keyword |
| azure.provisioning.properties.provisioning_status_info.error_information.reason | Summarizes the status and describes why the status happened. | keyword |
| azure.provisioning.properties.provisioning_status_info.error_information.recommended_action | Provides the resolution for the corresponding error. | keyword |
| azure.provisioning.properties.provisioning_status_info.status | Possible values are: success, warning, failure, skipped, unknownFutureValue. | keyword |
| azure.provisioning.properties.provisioning_steps.description | Summary of what occurred during the step. | keyword |
| azure.provisioning.properties.provisioning_steps.details | Details of what occurred during the step. | flattened |
| azure.provisioning.properties.provisioning_steps.name | Name of the step. | keyword |
| azure.provisioning.properties.provisioning_steps.provisioning_step_type | Type of step. | long |
| azure.provisioning.properties.provisioning_steps.status | Status of the step. | long |
| azure.provisioning.properties.service_principal.id | Uniquely identifies the servicePrincipal used for provisioning. | keyword |
| azure.provisioning.properties.service_principal.name | Customer-defined name for the servicePrincipal. | keyword |
| azure.provisioning.properties.source_identity.details | Details of the identity. | flattened |
| azure.provisioning.properties.source_identity.id | Uniquely identifies the identity. | keyword |
| azure.provisioning.properties.source_identity.identity_type | Type of identity that has been provisioned, such as 'user' or 'group'. | keyword |
| azure.provisioning.properties.source_identity.name | Display name of the identity. | keyword |
| azure.provisioning.properties.source_system.details.application_id |  | keyword |
| azure.provisioning.properties.source_system.details.dervice_principal_display_name |  | keyword |
| azure.provisioning.properties.source_system.details.service_principal_id |  | keyword |
| azure.provisioning.properties.source_system.id | Identifier of the system that a user was provisioned to or from. | keyword |
| azure.provisioning.properties.source_system.name | Name of the system that a user was provisioned to or from. | keyword |
| azure.provisioning.properties.target_identity.details | Details of the identity. | flattened |
| azure.provisioning.properties.target_identity.id | Uniquely identifies the identity. | keyword |
| azure.provisioning.properties.target_identity.identity_type | Type of identity that has been provisioned, such as 'user' or 'group'. | keyword |
| azure.provisioning.properties.target_identity.name | Display name of the identity. | keyword |
| azure.provisioning.properties.target_system.details.application_id |  | keyword |
| azure.provisioning.properties.target_system.details.dervice_principal_display_name |  | keyword |
| azure.provisioning.properties.target_system.details.service_principal_id |  | keyword |
| azure.provisioning.properties.target_system.id | Identifier of the system that a user was provisioned to or from. | keyword |
| azure.provisioning.properties.target_system.name | Name of the system that a user was provisioned to or from. | keyword |
| azure.provisioning.properties.tenant_id | Unique Microsoft Entra ID tenant ID | keyword |
| azure.provisioning.result_signature | Result signature | keyword |
| azure.provisioning.result_type | Result type | keyword |
| azure.provisioning.tenant_id | Unique Microsoft Entra ID tenant ID | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| geo.region_iso_code | Region ISO code. | keyword |
| geo.region_name | Region name. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |


### Audit logs

Retrieves Microsoft Entra ID audit logs. The audit logs provide traceability through logs for all changes done by various features within Microsoft Entra ID. Examples of audit logs include changes made to any resources within Microsoft Entra ID like adding or removing users, apps, groups, roles and policies.

An example event for `auditlogs` looks as following:

```json
{
    "@timestamp": "2020-11-02T08:51:36.997Z",
    "azure.auditlogs.category": "AuditLogs",
    "azure.auditlogs.identity": "Device Registration Service",
    "azure.auditlogs.operation_name": "Update device",
    "azure.auditlogs.operation_version": "1.0",
    "azure.auditlogs.properties.activity_datetime": "2019-10-18T15:30:51.0273716+00:00",
    "azure.auditlogs.properties.activity_display_name": "Update device",
    "azure.auditlogs.properties.category": "Device",
    "azure.auditlogs.properties.correlation_id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.auditlogs.properties.id": "Directory_ESQ",
    "azure.auditlogs.properties.initiated_by.app.displayName": "Device Registration Service",
    "azure.auditlogs.properties.initiated_by.app.servicePrincipalId": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.auditlogs.properties.logged_by_service": "Core Directory",
    "azure.auditlogs.properties.operation_type": "Update",
    "azure.auditlogs.properties.result_reason": "",
    "azure.auditlogs.properties.target_resources.0.display_name": "LAPTOP-12",
    "azure.auditlogs.properties.target_resources.0.id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
    "azure.auditlogs.properties.target_resources.0.modified_properties.0.new_value": "\"\"",
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
        "version": "8.11.0"
    },
    "event": {
        "action": "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE",
        "dataset": "azure.auditlogs",
        "duration": 0,
        "ingested": "2020-10-30T20:47:48.123859400Z",
        "kind": "event",
        "outcome": "success"
    },
    "log": {
        "level": "Information"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.auditlogs.category | The category of the operation.  Currently, Audit is the only supported value. | keyword |
| azure.auditlogs.identity | Identity | keyword |
| azure.auditlogs.level | Value for level. | float |
| azure.auditlogs.operation_name | The operation name | keyword |
| azure.auditlogs.operation_version | The operation version | keyword |
| azure.auditlogs.properties.activity_datetime | Activity timestamp | date |
| azure.auditlogs.properties.activity_display_name | Activity display name | keyword |
| azure.auditlogs.properties.additional_details.key | Additional details key | keyword |
| azure.auditlogs.properties.additional_details.user_agent | User agent name. | keyword |
| azure.auditlogs.properties.additional_details.value | Additional details value | keyword |
| azure.auditlogs.properties.authentication_protocol | Authentication protocol type. | keyword |
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
| azure.auditlogs.properties.initiated_by.user.roles | User roles | keyword |
| azure.auditlogs.properties.initiated_by.user.userPrincipalName | User principal name | keyword |
| azure.auditlogs.properties.logged_by_service | Logged by service | keyword |
| azure.auditlogs.properties.operation_type | Operation type | keyword |
| azure.auditlogs.properties.result | Log result | keyword |
| azure.auditlogs.properties.result_reason | Reason for the log result | keyword |
| azure.auditlogs.properties.target_resources.\*.display_name | Display name | keyword |
| azure.auditlogs.properties.target_resources.\*.id | ID | keyword |
| azure.auditlogs.properties.target_resources.\*.ip_address | ip Address | keyword |
| azure.auditlogs.properties.target_resources.\*.modified_properties.\*.display_name | Display value | keyword |
| azure.auditlogs.properties.target_resources.\*.modified_properties.\*.new_value | New value | keyword |
| azure.auditlogs.properties.target_resources.\*.modified_properties.\*.old_value | Old value | keyword |
| azure.auditlogs.properties.target_resources.\*.type | Type | keyword |
| azure.auditlogs.properties.target_resources.\*.user_principal_name | User principal name | keyword |
| azure.auditlogs.result_description | Result description | keyword |
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
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |

