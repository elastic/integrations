# Microsoft Entra ID Integration  

This integration is for [Microsoft Entra ID](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id). It supports directory audit, sign-in, and provisioning data streams from Microsoft Entra ID activity logs.  

## Prerequisites  
Before setting up this integration, ensure the following:  
- You have **Microsoft Entra ID P1 or P2** licensing (required for sign-in logs).  
- You have access to **Microsoft Entra ID Admin Center**.  
- You have **Global Admin** or **Security Admin** privileges to grant API permissions.  

## Setup  

To use this integration, you must:  
1. **Enable Audit Logs** in your Microsoft Entra ID tenant.  
2. **Register an application** in [Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=certificate%2Cexpose-a-web-api).  

### Register an Application  
1. In the Microsoft Entra ID portal, navigate to **App registrations** and register a new application.  
2. **Note the following details** from the **Overview** page:  
   - `Application (client) ID`  
   - `Directory (tenant) ID`  

### Configure Authentication  
1. Navigate to **Certificates & Secrets** → **New client secret**.  
2. Provide a description and create a new secret.  
3. **Copy and save the `Value`** of the secret. This is required for authentication.  

### Assign API Permissions
1. Navigate to **API permissions** → **Add a permission** → **Microsoft Graph**.  
2. Select **Application permissions** and add the following:  
   - **Sign-in Logs** → `AuditLog.Read.All`  
   - **Provisioning Logs** → `AuditLog.Read.All`  
   - **Directory Audit Logs** → `AuditLog.Read.All`  
   - (Optional) `Directory.Read.All` (for additional user directory data)  
3. Click **Add permissions** and **Grant admin consent**. 

### Integrate with Elastic Agent  
Once the secret is created and permissions are granted:  
1. Click **Add Microsoft Entra ID (CEL)** in Elastic Agent.  
2. Enable **Collect Microsoft Entra ID logs from Microsoft Graph APIs (v1) via Elastic Agent**.  
3. Provide the following details:  
   - **Directory (tenant) ID** (from the Overview page)  
   - **Application (client) ID**  
   - **Client Secret Value**  
   - **OAuth2 Token URL** (optional; defaults to the provided tenant ID)  
4. Modify additional parameters as needed.  

This setup enables secure access to Microsoft Entra ID logs via the Microsoft Graph API.

## Logs

### Directory Audit Logs

Uses the Microsoft Graph APIs (v1) to fetch directory audit logs

An example event for `directory_audit` looks as following:

```json
{
    "@timestamp": "2025-03-10T08:57:22.668Z",
    "agent": {
        "ephemeral_id": "8b4b20cc-3acb-4b43-8c97-4fa0cf074aa9",
        "id": "f5bfb8c6-72d1-42e3-8fe2-364d2fd2e9ed",
        "name": "elastic-agent-14259",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "microsoft_entra_id.directory_audit",
        "namespace": "42871",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f5bfb8c6-72d1-42e3-8fe2-364d2fd2e9ed",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "microsoft_entra_id.directory_audit",
        "ingested": "2025-03-10T08:57:25Z",
        "kind": "event",
        "original": "{\"activityDateTime\":\"2025-02-26T12:07:49.6393364Z\",\"activityDisplayName\":\"Update user\",\"additionalDetails\":[{\"key\":\"UserType\",\"value\":\"Guest\"}],\"category\":\"UserManagement\",\"correlationId\":\"ff629cc2-4337-405c-b348-18741a03da47\",\"id\":\"Directory_ff629cc2-4337-405c-b348-18741a03da47_8H5XV_265040778\",\"initiatedBy\":{\"app\":{\"appId\":null,\"displayName\":\"Azure MFA StrongAuthenticationService\",\"servicePrincipalId\":\"f2ee4c91-32e3-4966-93b3-4b3fcbab60f9\",\"servicePrincipalName\":null},\"user\":null},\"loggedByService\":\"Core Directory\",\"operationType\":\"Update\",\"result\":\"success\",\"resultReason\":\"\",\"targetResources\":[{\"displayName\":null,\"groupType\":null,\"id\":\"4b7ef3e3-3d38-4006-a7bf-898c57dc9c23\",\"modifiedProperties\":[{\"displayName\":\"StrongAuthenticationPhoneAppDetail\",\"newValue\":\"[{\\\"DeviceName\\\":\\\"NO_DEVICE\\\",\\\"DeviceToken\\\":\\\"NO_DEVICE_TOKEN\\\",\\\"DeviceTag\\\":\\\"SoftwareTokenActivated\\\",\\\"PhoneAppVersion\\\":\\\"NO_PHONE_APP_VERSION\\\",\\\"OathTokenTimeDrift\\\":0,\\\"DeviceId\\\":\\\"00000000-0000-0000-0000-000000000000\\\",\\\"Id\\\":\\\"aa4ced83-e369-4d28-ba00-f205838ecdc3\\\",\\\"TimeInterval\\\":0,\\\"AuthenticationType\\\":2,\\\"NotificationType\\\":1,\\\"LastAuthenticatedTimestamp\\\":\\\"2025-02-26T12:07:49.4933291Z\\\",\\\"AuthenticatorFlavor\\\":\\\"Authenticator\\\",\\\"HashFunction\\\":\\\"hmacsha1\\\",\\\"TenantDeviceId\\\":null,\\\"SecuredPartitionId\\\":20072,\\\"SecuredKeyId\\\":7}]\",\"oldValue\":\"[{\\\"DeviceName\\\":\\\"NO_DEVICE\\\",\\\"DeviceToken\\\":\\\"NO_DEVICE_TOKEN\\\",\\\"DeviceTag\\\":\\\"SoftwareTokenActivated\\\",\\\"PhoneAppVersion\\\":\\\"NO_PHONE_APP_VERSION\\\",\\\"OathTokenTimeDrift\\\":0,\\\"DeviceId\\\":\\\"00000000-0000-0000-0000-000000000000\\\",\\\"Id\\\":\\\"aa4ced83-e369-4d28-ba00-f205838ecdc3\\\",\\\"TimeInterval\\\":0,\\\"AuthenticationType\\\":2,\\\"NotificationType\\\":1,\\\"LastAuthenticatedTimestamp\\\":\\\"2025-02-24T10:46:04.0400521Z\\\",\\\"AuthenticatorFlavor\\\":\\\"Authenticator\\\",\\\"HashFunction\\\":\\\"hmacsha1\\\",\\\"TenantDeviceId\\\":null,\\\"SecuredPartitionId\\\":20072,\\\"SecuredKeyId\\\":7}]\"},{\"displayName\":\"Included Updated Properties\",\"newValue\":\"\\\"StrongAuthenticationPhoneAppDetail\\\"\",\"oldValue\":null},{\"displayName\":\"TargetId.UserType\",\"newValue\":\"\\\"Guest\\\"\",\"oldValue\":null},{\"displayName\":\"ActorId.ServicePrincipalNames\",\"newValue\":\"\\\"b5a60e17-278b-4c92-a4e2-b9262e66bb28\\\"\",\"oldValue\":null},{\"displayName\":\"SPN\",\"newValue\":\"\\\"b5a60e17-278b-4c92-a4e2-b9262e66bb28\\\"\",\"oldValue\":null}],\"type\":\"User\",\"userPrincipalName\":\"maurizio.branca_elastic.co#EXT#@azure2elasticsearch.onmicrosoft.com\"}]}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "microsoft_entra_id": {
        "directory_audit": {
            "activity_date_time": "2025-02-26T12:07:49.639Z",
            "activity_display_name": "Update user",
            "additional_details": [
                {
                    "key": "UserType",
                    "value": "Guest"
                }
            ],
            "category": "UserManagement",
            "correlation_id": "ff629cc2-4337-405c-b348-18741a03da47",
            "id": "Directory_ff629cc2-4337-405c-b348-18741a03da47_8H5XV_265040778",
            "initiated_by": {
                "app": {
                    "display_name": "Azure MFA StrongAuthenticationService",
                    "service_principal_id": "f2ee4c91-32e3-4966-93b3-4b3fcbab60f9"
                }
            },
            "logged_by_service": "Core Directory",
            "operation_type": "Update",
            "result": "success",
            "target_resources": [
                {
                    "id": "4b7ef3e3-3d38-4006-a7bf-898c57dc9c23",
                    "modified_properties": [
                        {
                            "display_name": "StrongAuthenticationPhoneAppDetail",
                            "new_value": "[{\"DeviceName\":\"NO_DEVICE\",\"DeviceToken\":\"NO_DEVICE_TOKEN\",\"DeviceTag\":\"SoftwareTokenActivated\",\"PhoneAppVersion\":\"NO_PHONE_APP_VERSION\",\"OathTokenTimeDrift\":0,\"DeviceId\":\"00000000-0000-0000-0000-000000000000\",\"Id\":\"aa4ced83-e369-4d28-ba00-f205838ecdc3\",\"TimeInterval\":0,\"AuthenticationType\":2,\"NotificationType\":1,\"LastAuthenticatedTimestamp\":\"2025-02-26T12:07:49.4933291Z\",\"AuthenticatorFlavor\":\"Authenticator\",\"HashFunction\":\"hmacsha1\",\"TenantDeviceId\":null,\"SecuredPartitionId\":20072,\"SecuredKeyId\":7}]",
                            "old_value": "[{\"DeviceName\":\"NO_DEVICE\",\"DeviceToken\":\"NO_DEVICE_TOKEN\",\"DeviceTag\":\"SoftwareTokenActivated\",\"PhoneAppVersion\":\"NO_PHONE_APP_VERSION\",\"OathTokenTimeDrift\":0,\"DeviceId\":\"00000000-0000-0000-0000-000000000000\",\"Id\":\"aa4ced83-e369-4d28-ba00-f205838ecdc3\",\"TimeInterval\":0,\"AuthenticationType\":2,\"NotificationType\":1,\"LastAuthenticatedTimestamp\":\"2025-02-24T10:46:04.0400521Z\",\"AuthenticatorFlavor\":\"Authenticator\",\"HashFunction\":\"hmacsha1\",\"TenantDeviceId\":null,\"SecuredPartitionId\":20072,\"SecuredKeyId\":7}]"
                        },
                        {
                            "display_name": "Included Updated Properties",
                            "new_value": "\"StrongAuthenticationPhoneAppDetail\""
                        },
                        {
                            "display_name": "TargetId.UserType",
                            "new_value": "\"Guest\""
                        },
                        {
                            "display_name": "ActorId.ServicePrincipalNames",
                            "new_value": "\"b5a60e17-278b-4c92-a4e2-b9262e66bb28\""
                        },
                        {
                            "display_name": "SPN",
                            "new_value": "\"b5a60e17-278b-4c92-a4e2-b9262e66bb28\""
                        }
                    ],
                    "type": "User",
                    "user_principal_name": "maurizio.branca_elastic.co#EXT#@azure2elasticsearch.onmicrosoft.com"
                }
            ]
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "microsoft-entra-id-cel",
        "microsoft-entra-id-directory-audit-cel"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| microsoft_entra_id.directory_audit.activity_date_time | Timestamp of when the activity occurred. | date |
| microsoft_entra_id.directory_audit.activity_display_name | Name of the activity performed. | text |
| microsoft_entra_id.directory_audit.additional_details.key | Key of the additional detail. | keyword |
| microsoft_entra_id.directory_audit.additional_details.value | Value of the additional detail. | text |
| microsoft_entra_id.directory_audit.category | Category of the event, e.g., user_management. | keyword |
| microsoft_entra_id.directory_audit.correlation_id | Correlation ID for tracking related events. | keyword |
| microsoft_entra_id.directory_audit.id | Unique identifier for the event. | keyword |
| microsoft_entra_id.directory_audit.initiated_by.app.app_id | Refers to the unique ID representing application in Microsoft Entra ID. | keyword |
| microsoft_entra_id.directory_audit.initiated_by.app.display_name | Refers to the application name displayed in the Microsoft Entra admin center. | text |
| microsoft_entra_id.directory_audit.initiated_by.app.service_principal_id | Refers to the unique ID for the service principal in Microsoft Entra ID. | keyword |
| microsoft_entra_id.directory_audit.initiated_by.app.service_principal_name | Refers to the Service Principal Name is the Application name in the tenant. | keyword |
| microsoft_entra_id.directory_audit.initiated_by.user.display_name | Display name of the user. | text |
| microsoft_entra_id.directory_audit.initiated_by.user.id | Unique identifier of the user. | keyword |
| microsoft_entra_id.directory_audit.initiated_by.user.ip_address | IP address of the user. | ip |
| microsoft_entra_id.directory_audit.initiated_by.user.user_principal_name | User principal name (email format). | keyword |
| microsoft_entra_id.directory_audit.logged_by_service | Service responsible for logging the event. | keyword |
| microsoft_entra_id.directory_audit.operation_type | Indicates the type of operation that was performed. | keyword |
| microsoft_entra_id.directory_audit.result | Outcome of the activity, e.g., success or failure. | keyword |
| microsoft_entra_id.directory_audit.result_reason | Detailed reason for the result. | text |
| microsoft_entra_id.directory_audit.target_resources.display_name | Display name of the target resource. | text |
| microsoft_entra_id.directory_audit.target_resources.group_type | Type of group, e.g., unified_groups. | keyword |
| microsoft_entra_id.directory_audit.target_resources.id | Unique identifier of the target resource. | keyword |
| microsoft_entra_id.directory_audit.target_resources.modified_properties.display_name | Name of the modified property. | text |
| microsoft_entra_id.directory_audit.target_resources.modified_properties.new_value | Updated value of the property. | text |
| microsoft_entra_id.directory_audit.target_resources.modified_properties.old_value | Previous value of the property. | text |
| microsoft_entra_id.directory_audit.target_resources.type | Type of the target resource, e.g., group or user. | keyword |
| microsoft_entra_id.directory_audit.target_resources.user_principal_name | User principal name if the target is a user. | keyword |
