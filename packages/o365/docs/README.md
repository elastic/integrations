# Microsoft Office 365 Integration

This integration is for Microsoft Office 365. It currently supports user, admin, system, and policy actions and events from Office 365 and Azure AD activity logs exposed by the Office 365 Management Activity API.

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
| client.ip | IP address of the client. | ip |
| container.id | Unique container id. | keyword |
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
| host.id | Unique host id. | keyword |
| host.name | Name of the host. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | Log message optimized for viewing in a log viewer. | text |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc | keyword |
| o365.o365.audit.Actor.ID |  | keyword |
| o365.o365.audit.Actor.Type |  | keyword |
| o365.o365.audit.ActorContextId |  | keyword |
| o365.o365.audit.ActorIpAddress |  | keyword |
| o365.o365.audit.ActorUserId |  | keyword |
| o365.o365.audit.ActorYammerUserId |  | keyword |
| o365.o365.audit.AlertEntityId |  | keyword |
| o365.o365.audit.AlertId |  | keyword |
| o365.o365.audit.AlertLinks |  | array |
| o365.o365.audit.AlertType |  | keyword |
| o365.o365.audit.AppId |  | keyword |
| o365.o365.audit.ApplicationDisplayName |  | keyword |
| o365.o365.audit.ApplicationId |  | keyword |
| o365.o365.audit.AzureActiveDirectoryEventType |  | keyword |
| o365.o365.audit.Category |  | keyword |
| o365.o365.audit.ClientAppId |  | keyword |
| o365.o365.audit.ClientIP |  | keyword |
| o365.o365.audit.ClientIPAddress |  | keyword |
| o365.o365.audit.ClientInfoString |  | keyword |
| o365.o365.audit.Comments |  | text |
| o365.o365.audit.CorrelationId |  | keyword |
| o365.o365.audit.CreationTime |  | keyword |
| o365.o365.audit.CustomUniqueId |  | keyword |
| o365.o365.audit.Data |  | keyword |
| o365.o365.audit.DataType |  | keyword |
| o365.o365.audit.EntityType |  | keyword |
| o365.o365.audit.EventData |  | keyword |
| o365.o365.audit.EventSource |  | keyword |
| o365.o365.audit.ExceptionInfo.* |  | object |
| o365.o365.audit.ExchangeMetaData.* |  | object |
| o365.o365.audit.ExtendedProperties.* |  | object |
| o365.o365.audit.ExternalAccess |  | keyword |
| o365.o365.audit.GroupName |  | keyword |
| o365.o365.audit.Id |  | keyword |
| o365.o365.audit.ImplicitShare |  | keyword |
| o365.o365.audit.IncidentId |  | keyword |
| o365.o365.audit.InterSystemsId |  | keyword |
| o365.o365.audit.InternalLogonType |  | keyword |
| o365.o365.audit.IntraSystemId |  | keyword |
| o365.o365.audit.Item.* |  | object |
| o365.o365.audit.Item.*.* |  | object |
| o365.o365.audit.ItemName |  | keyword |
| o365.o365.audit.ItemType |  | keyword |
| o365.o365.audit.ListId |  | keyword |
| o365.o365.audit.ListItemUniqueId |  | keyword |
| o365.o365.audit.LogonError |  | keyword |
| o365.o365.audit.LogonType |  | keyword |
| o365.o365.audit.LogonUserSid |  | keyword |
| o365.o365.audit.MailboxGuid |  | keyword |
| o365.o365.audit.MailboxOwnerMasterAccountSid |  | keyword |
| o365.o365.audit.MailboxOwnerSid |  | keyword |
| o365.o365.audit.MailboxOwnerUPN |  | keyword |
| o365.o365.audit.Members |  | array |
| o365.o365.audit.Members.* |  | object |
| o365.o365.audit.ModifiedProperties.*.* |  | object |
| o365.o365.audit.Name |  | keyword |
| o365.o365.audit.ObjectId |  | keyword |
| o365.o365.audit.Operation |  | keyword |
| o365.o365.audit.OrganizationId |  | keyword |
| o365.o365.audit.OrganizationName |  | keyword |
| o365.o365.audit.OriginatingServer |  | keyword |
| o365.o365.audit.Parameters.* |  | object |
| o365.o365.audit.PolicyDetails |  | array |
| o365.o365.audit.PolicyId |  | keyword |
| o365.o365.audit.RecordType |  | keyword |
| o365.o365.audit.ResultStatus |  | keyword |
| o365.o365.audit.SensitiveInfoDetectionIsIncluded |  | keyword |
| o365.o365.audit.SessionId |  | keyword |
| o365.o365.audit.Severity |  | keyword |
| o365.o365.audit.SharePointMetaData.* |  | object |
| o365.o365.audit.Site |  | keyword |
| o365.o365.audit.SiteUrl |  | keyword |
| o365.o365.audit.Source |  | keyword |
| o365.o365.audit.SourceFileExtension |  | keyword |
| o365.o365.audit.SourceFileName |  | keyword |
| o365.o365.audit.SourceRelativeUrl |  | keyword |
| o365.o365.audit.Status |  | keyword |
| o365.o365.audit.SupportTicketId |  | keyword |
| o365.o365.audit.Target.ID |  | keyword |
| o365.o365.audit.Target.Type |  | keyword |
| o365.o365.audit.TargetContextId |  | keyword |
| o365.o365.audit.TargetUserOrGroupName |  | keyword |
| o365.o365.audit.TargetUserOrGroupType |  | keyword |
| o365.o365.audit.TeamGuid |  | keyword |
| o365.o365.audit.TeamName |  | keyword |
| o365.o365.audit.UniqueSharingId |  | keyword |
| o365.o365.audit.UserAgent |  | keyword |
| o365.o365.audit.UserId |  | keyword |
| o365.o365.audit.UserKey |  | keyword |
| o365.o365.audit.UserType |  | keyword |
| o365.o365.audit.Version |  | keyword |
| o365.o365.audit.WebId |  | keyword |
| o365.o365.audit.Workload |  | keyword |
| o365.o365.audit.YammerNetworkId |  | keyword |
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
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

