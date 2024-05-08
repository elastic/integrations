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

Once the secret is created and permissions are granted by admin, setup Elastic Agent's O365 integration:
- Click `Add Microsoft 365`.
- Enable `Collect Office 365 audit logs via Management Activity API using CEL Input`.
- Add `Directory (tenant) ID` noted in Step 1 into `Directory (tenant) ID` parameter. This is required field.
- Add `Application (client) ID` noted in Step 1 into `Application (client) ID` parameter. This is required field.
- Add the secret `Value` noted in Step 2 into `Client Secret` parameter. This is required field.
- Oauth2 Token URL can be added to generate the tokens during the oauth2 flow. If not provided, above `Directory (tenant) ID` will be used for oauth2 token generation.
- Modify any other parameters as necessary.


**NOTE:** As Microsoft is no longer supporting Azure Active Directory Authentication Library (ADAL), the existing o365audit input is being deprecated in favor of new [CEL](https://www.elastic.co/guide/en/beats/filebeat/8.6/filebeat-input-cel.html) input in version `1.18.0`. Hence for versions `>= 1.18.0`, certificate based authentication (provided by earlier o365audit input) is no longer supported. 

We request users upgrading from integration version `< 1.18.0` to `>= 1.18.0` to follow these steps:

1. Upgrade the Elastic Stack version to `>= 8.7.1`.
2. Upgrade the integration navigating via `Integrations -> Microsoft 365 -> Settings -> Upgrade`
3. Upgrade the integration policy navigating via `Integrations -> Microsoft 365 -> integration policies -> Version (Upgrade)`. If `Upgrade` option doesn't appear under the `Version`, that means the policy is already upgraded in the previous step. Please go to the next step.
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
| client.address | Some event client addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| client.domain | The domain name of the client system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.user.email | User email address. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.mtime | Last time the file content was modified. | date |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.owner | File owner's username. | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
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
| organization.id | Unique identifier for the organization. | keyword |
| organization.name | Organization name. | keyword |
| organization.name.text | Multi-field of `organization.name`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.description | The description of the rule generating the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.reference | Reference URL to additional information about the rule used to generate this event. The URL can point to the vendor's documentation about the rule. If that's not available, it can also be a link to a more general page describing this type of alert. | keyword |
| rule.ruleset | Name of the ruleset, policy, group, or parent category in which the rule used to generate this event is a member. | keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| source.user.email | User email address. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.technique.id | The id of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.full_name | User's full name, if available. | keyword |
| user.target.full_name.text | Multi-field of `user.target.full_name`. | match_only_text |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

