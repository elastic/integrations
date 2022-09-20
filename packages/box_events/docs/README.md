# Box Events Integration

The Box Events integration allows you to monitor [Box](https://app.box.com/). Box is a secure cloud storage and collaboration service that allows businesses and individuals to easily share files. 

Use the Box Events integration to ingest the activity logs which are generated each time files are uploaded, accessed, or modified in Box, enabling you to monitor data movement to the cloud. If you have [opted-in to receive additional events](https://developer.box.com/guides/events/event-triggers/shield-alert-events/), the Box Events integration will ingest context-rich alerts on potential threats, such as compromised accounts and data theft, based on anomalous user behavior. Combining this data with other events can lead to the detection of data exfiltration attacks.

Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference `box_events.events` when troubleshooting an issue.

For example, if you wanted to set up notifications for incoming Box Shield alerts you could verify that this data is being ingested from the `Box Shield Alerts` Dashboard. Then, go to `Alerts and Insights / Rules and Connectors` in the sidebar and set up a Rule using an Elasticsearch Query against index `*box*alert*` with time field `@timestamp` and DSL 

```
{
  "query":{
    "match" : {
      "event.kind": "alert"
    }
  }
}
```

to match incoming box alerts during your desired timeframe and notify you using your preferred connector.

## Compatibility

The Box Web Application does not feature version numbers, see this [Community Post](https://support.box.com/hc/en-us/community/posts/1500000033881/comments/1500000038001). This integration was configured and tested against Box in the second quarter of 2022.

### Box Events

The Box events API enables subscribing to live events across the enterprise or for a particular user, or querying historical events across the enterprise.

The API Returns up to a year of past events for a given user or for the entire enterprise.

By default this returns events for the authenticated user. 

#### Elastic Integration for Box Events Settings

To retrieve events for the entire enterprise, set the `stream_type` in the Elastic Integration Settings page to `admin_logs_streaming` for live monitoring of new events, or `admin_logs` for querying across historical events. 

Events will be returned in batches of up to 100, with successive calls on expiry of the configured `interval` so you may wish to specify a lower interval when a substantial number of events are expected.

#### Target Repository Authentication Settings

The Elastic Integration for Box Events connects using OAuth 2.0 to interact with a Box Custom App. To configure a Box Custom App see [Setup with OAuth 2.0](https://developer.box.com/guides/authentication/oauth2/oauth2-setup/).

Your app will need:

- A Custom Application using Server Authentication (with Client Credentials Grant) authentication in the Box Developer Console
- [2FA](https://support.box.com/hc/en-us/articles/360043697154-Two-Factor-Authentication-Set-Up-for-Your-Account) enabled on your Box account for viewing and copying the application's client secret from the configuration tab
- The application is [authorized](https://developer.box.com/guides/authorization/custom-app-approval/) in the Box Admin Console

#### Target Repository User Privileges

To access the `events` endpoint, the user making the API call will need to have `admin` privileges, and the application will need to have the scope `manage enterprise properties` checked. Changes to these settings may require you to repeat the `Custom App Approval` authorisation.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| box.created_at | When the event object was created | date |
| box.created_by.id | The unique identifier for the connection user | keyword |
| box.created_by.login | The primary email address of the connection user. Maps from \*\*.login |  |
| box.created_by.name | The display name of the connection user. Maps from \*\*.name | keyword |
| box.created_by.type | E.g. `user` |  |
| box.recorded_at | The date and time at which this event occurred | date |
| box.session.id | The session of the user that performed the action. Not all events will populate this attribute | keyword |
| box.source.created_at | The date and time at which this folder was originally created | date |
| box.source.created_by | The user who created this folder | object |
| box.source.created_by.id | The unique identifier for this user | keyword |
| box.source.created_by.login | The primary email address of this user. Maps from \*\*.login | keyword |
| box.source.created_by.name | The display name of this user. Maps from \*\*.name | keyword |
| box.source.created_by.type | Value is always `user` | keyword |
| box.source.description | The optional description of this folder | text |
| box.source.etag | The HTTP etag of this folder | keyword |
| box.source.file_version | The information about the current version of the file | object |
| box.source.file_version.id | The unique identifier that represent a file version | keyword |
| box.source.file_version.type | Value is always `file_version` | keyword |
| box.source.id | The unique identifier that represent a folder | keyword |
| box.source.item_status | Defines if this item has been deleted or not. active when the item has is not in the trash trashed when the item has been moved to the trash but not deleted deleted when the item has been permanently deleted. Value is one of `active`, `trashed`, `deleted` | keyword |
| box.source.modified_at | The date and time at which this folder was last updated | date |
| box.source.modified_by | The user who last modified this folder | object |
| box.source.modified_by.id | The unique identifier for this user | keyword |
| box.source.modified_by.login | The primary email address of this user. Maps from \*\*.login | keyword |
| box.source.modified_by.name | The display name of this user. Maps from \*\*.name | keyword |
| box.source.modified_by.type | Value is always `user` | keyword |
| box.source.owned_by | The user who owns this folder | keyword |
| box.source.owned_by.id | The unique identifier for this user | keyword |
| box.source.owned_by.login | The primary email address of this user. Maps from \*\*.login | keyword |
| box.source.owned_by.name | The display name of this user. Maps from \*\*.name | keyword |
| box.source.owned_by.type | Value is always `user` | keyword |
| box.source.parent | The optional folder that this folder is located within. This value may be null for some folders such as the root folder or the trash folder | object |
| box.source.parent.etag | The HTTP etag of this folder | keyword |
| box.source.parent.id | The unique identifier that represent a folder | keyword |
| box.source.parent.name | The name of the folder | keyword |
| box.source.parent.sequence_id | A numeric identifier that represents the most recent user event that has been applied to this item (parent) | keyword |
| box.source.parent.type | Value is always `folder` | keyword |
| box.source.path_collection | The tree of folders that this folder is contained in, starting at the root | object |
| box.source.path_collection.entries | The parent folders for this item | object |
| box.source.path_collection.entries.id | The unique identifier that represent a folder. This field is an array | array |
| box.source.path_collection.entries.name | The name of the folder. This field is an array | array |
| box.source.path_collection.entries.type | Value is always `folder`. This field is an array | array |
| box.source.path_collection.total_count | The number of folders in this list | long |
| box.source.purged_at | The time at which this file is expected to be purged from the trash | boolean |
| box.source.sequence_id | A numeric identifier that represents the most recent user event that has been applied to this item | keyword |
| box.source.sha1 | SHA1 hash of the item concerned | keyword |
| box.source.synced | Legacy property for compatibility with Box Desktop | boolean |
| box.source.trashed_at | The time at which this file was put in the trash | boolean |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.user.email | User email address. | keyword |
| client.user.full_name | User's full name, if available. | keyword |
| client.user.full_name.text | Multi-field of `client.user.full_name`. | match_only_text |
| client.user.id | Unique identifier of the user. | keyword |
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.created | File creation time. Note that not all filesystems store the creation time. | date |
| file.ctime | Last time the file attributes or metadata changed. Note that changes to the file content will update `mtime`. This implies `ctime` will be adjusted at the same time, since `mtime` is an attribute of the file. | date |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.mtime | Last time the file content was modified. | date |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.type | File type (file, dir, or symlink). | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.cpu.pct | Percent CPU used. This value is normalized by the number of CPU cores and it ranges from 0 to 1. | scaled_float |
| host.disk.read.bytes | The total number of bytes read successfully in a given period of time. | long |
| host.disk.write.bytes | The total number of bytes write successfully in a given period of time. | long |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.network.in.bytes | The number of bytes received on all network interfaces by the host in a given period of time. | long |
| host.network.in.packets | The number of packets received on all network interfaces by the host in a given period of time. | long |
| host.network.out.bytes | The number of bytes sent out on all network interfaces by the host in a given period of time. | long |
| host.network.out.packets | The number of packets sent out on all network interfaces by the host in a given period of time. | long |
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
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |

