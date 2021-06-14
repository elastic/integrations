# Microsoft Office 365 Integration

This integration is for Microsoft Office 365. It currently supports user, admin, system, and policy actions and events from Office 365 and Azure AD activity logs exposed by the Office 365 Management Activity API.

## Configuration

To use this package you need to enable _Audit Log Search_ and register an application in Azure AD.

Once this application is registered note the _Application (client) ID_ and the _Directory (tenant) ID._ Then configure the authentication in the _Certificates & Secrets_ section.

To use client-secret authentication, add you secret to the _Client Secret (API key)_ field.

To use certificate-based authentication, set the paths to the certificate and private key files. If the key file is protected with a passphrase, set this passphrase in the _Private key passphrase_ field. Paths must be absolute and files must exist in the host where _Elastic Agent_ is running.


Add your tenant ID(s) to the _Directory (tenant) IDs_ field, then add the hostname that this tenant identifies to the _Directory (tenant) domains_ field. For example:
- Directory IDs: `my-id-a` `my-id-b`
- Directory domains: `a.onmicrosoft.com` `b.onmicrosoft.com`

## Compatibility

The `ingest-geoip` and `ingest-user_agent` Elasticsearch plugins are required to run this module.

## Logs

### Audit

Uses the Office 365 Management Activity API to retrieve audit messages from Office 365 and Azure AD activity logs. These are the same logs that are available under Audit Log Search in the Security and Compliance Center.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.address | Client network address. | keyword |
| client.domain | Client network domain. | keyword |
| client.ip | IP address of the client. | ip |
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
| destination.ip | IP address of the destination. | ip |
| destination.user.email | User email address. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| event.action | The action captured by the event. | keyword |
| event.category | Event category. The second categorization field in the hierarchy. | keyword |
| event.code | Identification code for this event. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | The kind of the event. The highest categorization field in the hierarchy. | keyword |
| event.outcome | The outcome of the event. The lowest level categorization field in the hierarchy. | keyword |
| event.provider | Source of the event. | keyword |
| event.severity | Numeric severity of the event. | long |
| event.type | Event type. The third categorization field in the hierarchy. | keyword |
| file.directory | Directory where the file is located. | keyword |
| file.extension | File extension. | keyword |
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
| host.name | Name of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | Log message optimized for viewing in a log viewer. | text |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc | keyword |
| o365.audit.Actor.ID |  | keyword |
| o365.audit.Actor.Type |  | keyword |
| o365.audit.ActorContextId |  | keyword |
| o365.audit.ActorIpAddress |  | keyword |
| o365.audit.ActorUserId |  | keyword |
| o365.audit.ActorYammerUserId |  | keyword |
| o365.audit.AlertEntityId |  | keyword |
| o365.audit.AlertId |  | keyword |
| o365.audit.AlertLinks |  | array |
| o365.audit.AlertType |  | keyword |
| o365.audit.AppId |  | keyword |
| o365.audit.ApplicationDisplayName |  | keyword |
| o365.audit.ApplicationId |  | keyword |
| o365.audit.AzureActiveDirectoryEventType |  | keyword |
| o365.audit.Category |  | keyword |
| o365.audit.ClientAppId |  | keyword |
| o365.audit.ClientIP |  | keyword |
| o365.audit.ClientIPAddress |  | keyword |
| o365.audit.ClientInfoString |  | keyword |
| o365.audit.Comments |  | text |
| o365.audit.CorrelationId |  | keyword |
| o365.audit.CreationTime |  | keyword |
| o365.audit.CustomUniqueId |  | boolean |
| o365.audit.Data |  | keyword |
| o365.audit.DataType |  | keyword |
| o365.audit.EntityType |  | keyword |
| o365.audit.EventData |  | keyword |
| o365.audit.EventSource |  | keyword |
| o365.audit.ExceptionInfo.* |  | object |
| o365.audit.ExchangeMetaData.* |  | object |
| o365.audit.ExtendedProperties.* |  | object |
| o365.audit.ExternalAccess |  | boolean |
| o365.audit.GroupName |  | keyword |
| o365.audit.Id |  | keyword |
| o365.audit.ImplicitShare |  | keyword |
| o365.audit.IncidentId |  | keyword |
| o365.audit.InterSystemsId |  | keyword |
| o365.audit.InternalLogonType |  | keyword |
| o365.audit.IntraSystemId |  | keyword |
| o365.audit.Item.* |  | object |
| o365.audit.Item.*.* |  | object |
| o365.audit.ItemName |  | keyword |
| o365.audit.ItemType |  | keyword |
| o365.audit.ListId |  | keyword |
| o365.audit.ListItemUniqueId |  | keyword |
| o365.audit.LogonError |  | keyword |
| o365.audit.LogonType |  | keyword |
| o365.audit.LogonUserSid |  | keyword |
| o365.audit.MailboxGuid |  | keyword |
| o365.audit.MailboxOwnerMasterAccountSid |  | keyword |
| o365.audit.MailboxOwnerSid |  | keyword |
| o365.audit.MailboxOwnerUPN |  | keyword |
| o365.audit.Members |  | array |
| o365.audit.Members.* |  | object |
| o365.audit.ModifiedProperties.*.* |  | object |
| o365.audit.Name |  | keyword |
| o365.audit.ObjectId |  | keyword |
| o365.audit.Operation |  | keyword |
| o365.audit.OrganizationId |  | keyword |
| o365.audit.OrganizationName |  | keyword |
| o365.audit.OriginatingServer |  | keyword |
| o365.audit.Parameters.* |  | object |
| o365.audit.PolicyDetails |  | array |
| o365.audit.PolicyId |  | keyword |
| o365.audit.RecordType |  | keyword |
| o365.audit.ResultStatus |  | keyword |
| o365.audit.SensitiveInfoDetectionIsIncluded |  | boolean |
| o365.audit.SessionId |  | keyword |
| o365.audit.Severity |  | keyword |
| o365.audit.SharePointMetaData.* |  | object |
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
| o365.audit.UniqueSharingId |  | keyword |
| o365.audit.UserAgent |  | keyword |
| o365.audit.UserId |  | keyword |
| o365.audit.UserKey |  | keyword |
| o365.audit.UserType |  | keyword |
| o365.audit.Version |  | keyword |
| o365.audit.WebId |  | keyword |
| o365.audit.Workload |  | keyword |
| o365.audit.YammerNetworkId |  | keyword |
| organization.id | Unique identifier for the organization. | keyword |
| organization.name | Organization name. | keyword |
| process.name | Process name. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| rule.category | Rule category | keyword |
| rule.description | Rule description | keyword |
| rule.id | Rule ID | keyword |
| rule.name | Rule name | keyword |
| rule.reference | Rule reference URL | keyword |
| rule.ruleset | Rule ruleset | keyword |
| server.address | Server network address. | keyword |
| server.domain | Server network domain. | keyword |
| server.ip | IP address of the server. | ip |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
| source.port | Port of the source. | long |
| source.user.email | User email address. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.technique.id | Threat technique id. | keyword |
| url.original | Unmodified original url as seen in the event source. | keyword |
| user.domain | Name of the directory the user is a member of. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. | keyword |
| user.target.email | User email address. | keyword |
| user.target.full_name | User's full name, if available. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

