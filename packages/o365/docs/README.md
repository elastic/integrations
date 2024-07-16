# Microsoft Office 365 Integration

This integration is for [Microsoft Office 365](https://docs.microsoft.com/en-us/previous-versions/office/office-365-api/). It currently supports user, admin, system, and policy actions and events from Office 365 and Azure AD activity logs exposed by the Office 365 Management Activity API.

## Setup

To use this package you need to [enable `Audit Log`](https://learn.microsoft.com/en-us/purview/audit-log-enable-disable) and register an application in [Microsoft Entra ID (formerly known as Azure Active Directory)](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id).

Once the application is registered, configure and/or note the following to setup O365 Elastic integration:
1. Note `Application (client) ID` and the `Directory (tenant) ID` in the registered application's `Overview` page.
2. Create a new secret to configure the authentication of your application. 
    - Navigate to `Certificates & Secrets` section.
    - Click `New client secret` and provide some description to create new secret.
    - Note the `Value` which is required for the integration setup.
3. Add permissions to your registered application. Please check [O365 Management API permissions](https://learn.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis#specify-the-permissions-your-app-requires-to-access-the-office-365-management-apis) for more details.
    - Navigate to `API permissions` page and click `Add a permission`
    - Select `Office 365 Management APIs` tile from the listed tiles.
    - Click `Application permissions`.
    - Under `ActivityFeed`, select `ActivityFeed.Read` permission. This is minimum required permissions to read audit logs of your organization as [provided in the documentation](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference). Optionally, select `ActivityFeed.ReadDlp` to read DLP policy events.
    - Click `Add permissions`. 
    - If `User.Read` permission under `Microsoft.Graph` tile is not added by default, add this permission.
    - After the permissions are added, the admin has to grant consent for these permissions.

Once the secret is created and permissions are granted by admin, setup Elastic Agent's Microsoft O365 integration:
- Click `Add Microsoft Office 365`.
- Enable `Collect Office 365 audit logs via Management Activity API using CEL Input`.
- Add `Directory (tenant) ID` noted in Step 1 into `Directory (tenant) ID` parameter. This is required field.
- Add `Application (client) ID` noted in Step 1 into `Application (client) ID` parameter. This is required field.
- Add the secret `Value` noted in Step 2 into `Client Secret` parameter. This is required field.
- Oauth2 Token URL can be added to generate the tokens during the oauth2 flow. If not provided, above `Directory (tenant) ID` will be used for oauth2 token generation.
- Modify any other parameters as necessary.


**NOTE:** As Microsoft is no longer supporting Azure Active Directory Authentication Library (ADAL), the existing o365audit input has been deprecated in favor of the [CEL](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html) input in version `1.18.0`. Hence for versions `>= 1.18.0`, certificate based authentication (provided by earlier o365audit input) is no longer supported. 

We request users upgrading from integration version `< 1.18.0` to `>= 1.18.0` to follow these steps:

1. Upgrade the Elastic Stack version to `>= 8.7.1`.
2. Upgrade the integration navigating via `Integrations -> Microsoft Office 365 -> Settings -> Upgrade`
3. Upgrade the integration policy navigating via `Integrations -> Microsoft Office 365 -> integration policies -> Version (Upgrade)`. If `Upgrade` option doesn't appear under the `Version`, that means the policy is already upgraded in the previous step. Please go to the next step.
4. Modify the integration policy:
    
    * Disable existing configuration (marked as `Deprecated`) and enable `Collect Office 365 audit logs via CEL` configuration.
    * Add the required parameters such as `Directory (tenant) ID`, `Application (client) ID`, `Client Secret` based on the previous configuration.
    * Verify/Update `Initial Interval` configuration parameter to start fetching events from. This defaults to 7 days. Even if there is overlap in times, the events are not duplicated.
    * Update the other configuration parameters as required and hit `Save Integration`.

Please refer [Upgrade an integration](https://www.elastic.co/guide/en/fleet/current/upgrade-integration.html) in case of any issues while performing integration upgrade.

## Compatibility

The `ingest-geoip` and `ingest-user_agent` Elasticsearch plugins are required to run this module.

## Logs

### Audit

Uses the Office 365 Management Activity API to retrieve audit messages from Office 365 and Azure AD activity logs. These are the same logs that are available under Audit Log Search in the Security and Compliance Center.

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2020-02-07T16:43:53.000Z",
    "agent": {
        "ephemeral_id": "50dde7f7-f3a3-4597-9ce3-fd6c21fbe6df",
        "id": "a6ce2e4c-5271-405f-acc5-cb378534481d",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "client": {
        "address": "213.97.47.133",
        "ip": "213.97.47.133"
    },
    "data_stream": {
        "dataset": "o365.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a6ce2e4c-5271-405f-acc5-cb378534481d",
        "snapshot": false,
        "version": "8.12.1"
    },
    "event": {
        "action": "PageViewed",
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "code": "SharePoint",
        "dataset": "o365.audit",
        "id": "99d005e6-a4c6-46fd-117c-08d7abeceab5",
        "ingested": "2024-04-01T12:10:04Z",
        "kind": "event",
        "original": "{Site=d5180cfc-3479-44d6-b410-8c985ac894e3, ObjectId=https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/_layouts/15/onedrive.aspx, UserKey=i:0h.f|membership|1003200096971f55@live.com, ItemType=Page, OrganizationId=b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd, Operation=PageViewed, ClientIP=213.97.47.133, Workload=OneDrive, EventSource=SharePoint, RecordType=4, Version=1, UserId=asr@testsiem.onmicrosoft.com, WebId=8c5c94bb-8396-470c-87d7-8999f440cd30, CreationTime=2020-02-07T16:43:53, UserAgent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0, CustomUniqueId=true, Id=99d005e6-a4c6-46fd-117c-08d7abeceab5, CorrelationId=622b339f-4000-a000-f25f-92b3478c7a25, ListItemUniqueId=59a8433d-9bb8-cfef-6edc-4c0fc8b86875, UserType=0}",
        "outcome": "success",
        "provider": "OneDrive",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd",
        "name": "testsiem.onmicrosoft.com"
    },
    "input": {
        "type": "cel"
    },
    "network": {
        "type": "ipv4"
    },
    "o365": {
        "audit": {
            "CorrelationId": "622b339f-4000-a000-f25f-92b3478c7a25",
            "CreationTime": "2020-02-07T16:43:53",
            "CustomUniqueId": true,
            "EventSource": "SharePoint",
            "ItemType": "Page",
            "ListItemUniqueId": "59a8433d-9bb8-cfef-6edc-4c0fc8b86875",
            "ObjectId": "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/_layouts/15/onedrive.aspx",
            "RecordType": "4",
            "Site": "d5180cfc-3479-44d6-b410-8c985ac894e3",
            "UserId": "asr@testsiem.onmicrosoft.com",
            "UserKey": "i:0h.f|membership|1003200096971f55@live.com",
            "UserType": "0",
            "Version": "1",
            "WebId": "8c5c94bb-8396-470c-87d7-8999f440cd30"
        }
    },
    "organization": {
        "id": "b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd"
    },
    "related": {
        "ip": [
            "213.97.47.133"
        ],
        "user": [
            "asr"
        ]
    },
    "source": {
        "ip": "213.97.47.133"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "o365-cel"
    ],
    "user": {
        "domain": "testsiem.onmicrosoft.com",
        "email": "asr@testsiem.onmicrosoft.com",
        "id": "asr@testsiem.onmicrosoft.com",
        "name": "asr"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Firefox",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0",
        "os": {
            "full": "Mac OS X 10.14",
            "name": "Mac OS X",
            "version": "10.14"
        },
        "version": "72.0."
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| o365.audit.Activity |  | keyword |
| o365.audit.Actor.ID |  | keyword |
| o365.audit.Actor.Type |  | keyword |
| o365.audit.ActorContextId |  | keyword |
| o365.audit.ActorIpAddress |  | keyword |
| o365.audit.ActorUserId |  | keyword |
| o365.audit.ActorYammerUserId |  | keyword |
| o365.audit.AdditionalInfo.\* |  | object |
| o365.audit.AlertEntityId |  | keyword |
| o365.audit.AlertId |  | keyword |
| o365.audit.AlertLinks |  | flattened |
| o365.audit.AlertType |  | keyword |
| o365.audit.AppAccessContext.\* |  | object |
| o365.audit.AppId |  | keyword |
| o365.audit.ApplicationDisplayName |  | keyword |
| o365.audit.ApplicationId |  | keyword |
| o365.audit.AzureActiveDirectoryEventType |  | keyword |
| o365.audit.Category |  | keyword |
| o365.audit.ClientAppId |  | keyword |
| o365.audit.ClientIP |  | keyword |
| o365.audit.ClientIPAddress |  | keyword |
| o365.audit.ClientInfoString |  | keyword |
| o365.audit.ClientRequestId |  | keyword |
| o365.audit.Comments |  | text |
| o365.audit.CorrelationId |  | keyword |
| o365.audit.CreationTime |  | keyword |
| o365.audit.CustomUniqueId |  | boolean |
| o365.audit.Data.ad |  | keyword |
| o365.audit.Data.af |  | keyword |
| o365.audit.Data.aii |  | keyword |
| o365.audit.Data.ail |  | keyword |
| o365.audit.Data.alk |  | keyword |
| o365.audit.Data.als |  | keyword |
| o365.audit.Data.an |  | keyword |
| o365.audit.Data.at |  | date |
| o365.audit.Data.cid |  | keyword |
| o365.audit.Data.cpid |  | keyword |
| o365.audit.Data.dm |  | keyword |
| o365.audit.Data.dpn |  | keyword |
| o365.audit.Data.eid |  | keyword |
| o365.audit.Data.etps |  | keyword |
| o365.audit.Data.etype |  | keyword |
| o365.audit.Data.f3u |  | keyword |
| o365.audit.Data.flattened | The full Data document. | flattened |
| o365.audit.Data.fvs |  | keyword |
| o365.audit.Data.imsgid |  | keyword |
| o365.audit.Data.lon |  | keyword |
| o365.audit.Data.mat |  | keyword |
| o365.audit.Data.md |  | date |
| o365.audit.Data.ms |  | keyword |
| o365.audit.Data.od |  | keyword |
| o365.audit.Data.op |  | keyword |
| o365.audit.Data.ot |  | keyword |
| o365.audit.Data.plk |  | keyword |
| o365.audit.Data.pud |  | keyword |
| o365.audit.Data.reid |  | keyword |
| o365.audit.Data.rid |  | keyword |
| o365.audit.Data.sev |  | keyword |
| o365.audit.Data.sict |  | keyword |
| o365.audit.Data.sid |  | keyword |
| o365.audit.Data.sip |  | ip |
| o365.audit.Data.sitmi |  | keyword |
| o365.audit.Data.srt |  | keyword |
| o365.audit.Data.ssic |  | keyword |
| o365.audit.Data.suid |  | keyword |
| o365.audit.Data.tdc |  | keyword |
| o365.audit.Data.te |  | date |
| o365.audit.Data.thn |  | keyword |
| o365.audit.Data.tht |  | keyword |
| o365.audit.Data.tid |  | keyword |
| o365.audit.Data.tpid |  | keyword |
| o365.audit.Data.tpt |  | keyword |
| o365.audit.Data.trc |  | keyword |
| o365.audit.Data.ts |  | date |
| o365.audit.Data.tsd |  | keyword |
| o365.audit.Data.ttdt |  | date |
| o365.audit.Data.ttr |  | keyword |
| o365.audit.Data.upfc |  | keyword |
| o365.audit.Data.upfv |  | keyword |
| o365.audit.Data.ut |  | keyword |
| o365.audit.Data.von |  | keyword |
| o365.audit.Data.wl |  | keyword |
| o365.audit.Data.zfh |  | keyword |
| o365.audit.Data.zfn |  | keyword |
| o365.audit.Data.zmfh |  | keyword |
| o365.audit.Data.zmfn |  | keyword |
| o365.audit.Data.zu |  | keyword |
| o365.audit.DataType |  | keyword |
| o365.audit.EntityType |  | keyword |
| o365.audit.ErrorNumber |  | keyword |
| o365.audit.EventData |  | keyword |
| o365.audit.EventSource |  | keyword |
| o365.audit.ExceptionInfo.\* |  | object |
| o365.audit.ExchangeMetaData.\* |  | object |
| o365.audit.Experience |  | keyword |
| o365.audit.ExtendedProperties.\* |  | object |
| o365.audit.ExternalAccess |  | boolean |
| o365.audit.FileSizeBytes |  | long |
| o365.audit.GroupName |  | keyword |
| o365.audit.Id |  | keyword |
| o365.audit.ImplicitShare |  | keyword |
| o365.audit.IncidentId |  | keyword |
| o365.audit.InterSystemsId |  | keyword |
| o365.audit.InternalLogonType |  | keyword |
| o365.audit.IntraSystemId |  | keyword |
| o365.audit.Item.\* |  | object |
| o365.audit.Item.\*.\* |  | object |
| o365.audit.ItemName |  | keyword |
| o365.audit.ItemType |  | keyword |
| o365.audit.ListBaseType |  | keyword |
| o365.audit.ListId |  | keyword |
| o365.audit.ListItemUniqueId |  | keyword |
| o365.audit.LogonError |  | keyword |
| o365.audit.LogonType |  | keyword |
| o365.audit.LogonUserSid |  | keyword |
| o365.audit.MailboxGuid |  | keyword |
| o365.audit.MailboxOwnerMasterAccountSid |  | keyword |
| o365.audit.MailboxOwnerSid |  | keyword |
| o365.audit.MailboxOwnerUPN |  | keyword |
| o365.audit.Members |  | flattened |
| o365.audit.ModifiedProperties.\*.\* |  | object |
| o365.audit.Name |  | keyword |
| o365.audit.NewValue |  | keyword |
| o365.audit.ObjectDisplayName |  | keyword |
| o365.audit.ObjectId |  | keyword |
| o365.audit.ObjectType |  | keyword |
| o365.audit.Operation |  | keyword |
| o365.audit.OperationId |  | keyword |
| o365.audit.OperationProperties |  | object |
| o365.audit.OrganizationId |  | keyword |
| o365.audit.OrganizationName |  | keyword |
| o365.audit.OriginatingServer |  | keyword |
| o365.audit.Parameters.\* |  | object |
| o365.audit.Platform |  | keyword |
| o365.audit.PolicyDetails |  | flattened |
| o365.audit.PolicyId |  | keyword |
| o365.audit.RecordType |  | keyword |
| o365.audit.RequestId |  | keyword |
| o365.audit.ResultStatus |  | keyword |
| o365.audit.SensitiveInfoDetectionIsIncluded |  | boolean |
| o365.audit.SessionId |  | keyword |
| o365.audit.Severity |  | keyword |
| o365.audit.SharePointMetaData.\* |  | object |
| o365.audit.Site |  | keyword |
| o365.audit.SiteUrl |  | keyword |
| o365.audit.Source |  | keyword |
| o365.audit.SourceFileExtension |  | keyword |
| o365.audit.SourceFileName |  | keyword |
| o365.audit.SourceRelativeUrl |  | keyword |
| o365.audit.Status |  | keyword |
| o365.audit.SupportTicketId |  | keyword |
| o365.audit.Target.ID |  | keyword |
| o365.audit.Target.Type |  | keyword |
| o365.audit.TargetContextId |  | keyword |
| o365.audit.TargetUserOrGroupName |  | keyword |
| o365.audit.TargetUserOrGroupType |  | keyword |
| o365.audit.TeamGuid |  | keyword |
| o365.audit.TeamName |  | keyword |
| o365.audit.Timestamp |  | keyword |
| o365.audit.UniqueSharingId |  | keyword |
| o365.audit.UserAgent |  | keyword |
| o365.audit.UserId |  | keyword |
| o365.audit.UserKey |  | keyword |
| o365.audit.UserType |  | keyword |
| o365.audit.Version |  | keyword |
| o365.audit.WebId |  | keyword |
| o365.audit.Workload |  | keyword |
| o365.audit.WorkspaceId |  | keyword |
| o365.audit.WorkspaceName |  | keyword |
| o365.audit.YammerNetworkId |  | keyword |

