# Box Integration

This integration periodically fetches events from [Box](https://app.box.com/). It can parse events created by Box on behalf of the user or enterprise. 

## Compatibility

The Box Web Application does not feature version numbers, see this [Community Post](https://support.box.com/hc/en-us/community/posts/1500000033881/comments/1500000038001). This integration was configured and tested against Box in the second quarter of 2022.

### Box Events

The Box events API enables subscribing to live events across the enterprise or for a particular user, or querying historical events across the enterprise.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| box.session.id | The session of the user that performed the action. Not all events will populate this attribute. | keyword |
| box.source.content_created_at | The date and time at which this folder was originally created. | date |
| box.source.content_modified_at | The date and time at which this folder was last updated. | date |
| box.source.created_by | The user who created this folder. | object |
| box.source.created_by.id | The unique identifier for this user. | keyword |
| box.source.created_by.login | The primary email address of this user. Maps from \*\*.login. | keyword |
| box.source.created_by.name | The display name of this user. Maps from \*\*.name. | keyword |
| box.source.created_by.type | Value is always `user`. | keyword |
| box.source.description | The optional description of this folder. | text |
| box.source.etag | The HTTP etag of this folder. | keyword |
| box.source.file_version | The information about the current version of the file. | object |
| box.source.file_version.id | The unique identifier that represent a file version. | keyword |
| box.source.file_version.type | Value is always `file_version` | keyword |
| box.source.id | The unique identifier that represent a folder. | keyword |
| box.source.item_status | Defines if this item has been deleted or not. active when the item has is not in the trash trashed when the item has been moved to the trash but not deleted deleted when the item has been permanently deleted. Value is one of `active`, `trashed`, `deleted`. | keyword |
| box.source.modified_by | The user who last modified this folder. | object |
| box.source.modified_by.id | The unique identifier for this user. | keyword |
| box.source.modified_by.login | The primary email address of this user. Maps from \*\*.login. | keyword |
| box.source.modified_by.name | The display name of this user. Maps from \*\*.name. | keyword |
| box.source.modified_by.type | Value is always `user`. | keyword |
| box.source.owned_by | The user who owns this folder. | keyword |
| box.source.owned_by.id | The unique identifier for this user. | keyword |
| box.source.owned_by.login | The primary email address of this user. Maps from \*\*.login. | keyword |
| box.source.owned_by.name | The display name of this user. Maps from \*\*.name. | keyword |
| box.source.owned_by.type | Value is always `user`. | keyword |
| box.source.parent | The optional folder that this folder is located within. This value may be null for some folders such as the root folder or the trash folder. | object |
| box.source.parent.id | The unique identifier that represent a folder. | keyword |
| box.source.parent.name | The name of the folder. | keyword |
| box.source.parent.type | Value is always `folder`. | keyword |
| box.source.path_collection | The tree of folders that this folder is contained in, starting at the root. | object |
| box.source.path_collection.entries | The parent folders for this item. | object |
| box.source.path_collection.entries.id | The unique identifier that represent a folder. This field is an array. | array |
| box.source.path_collection.entries.name | The name of the folder. This field is an array. | array |
| box.source.path_collection.entries.type | Value is always `folder`. This field is an array. | array |
| box.source.path_collection.total_count | The number of folders in this list. | long |
| box.source.purged_at | The time at which this file is expected to be purged from the trash. | boolean |
| box.source.synced | Box Dev | boolean |
| box.source.trashed_at | The time at which this file was put in the trash. | boolean |
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
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.created | File creation time. Note that not all filesystems store the creation time. | date |
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
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |

