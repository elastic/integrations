# Box Integration

This integration periodically fetches events from [Box](https://app.box.com/). It can parse events created 
by Box on behalf of the user or enterprise. 

## Compatibility

The Box Web Application does not feature version numbers, see this [Community Post](https://support.box.com/hc/en-us/community/posts/1500000033881/comments/1500000038001). This integration was configured and tested against Box in the second quarter of 2022.

## Events

### User Events

Some Common User Events include:

- ITEM_PREVIEW
- ITEM_DOWNLOAD
- ITEM_UPLOAD

There are also User Events of specific interest to the Security Analyst such as:

- FILE_MARKED_MALICIOUS
- DEVICE_TRUST_CHECK_FAILED
- FAILED_LOGIN

A full list of allowed values can be found in the [Box Developer Documentation for the Event Endpoint](https://developer.box.com/reference/resources/event/#param-event_type)

An example event for an `ITEM_UPLOAD` might be:

```json
{
  "type" : "event",
  "event_id" : "b3fa44bdaeb9a775f6d9936d1928c432c8e85e60",
  "created_by" : {
    "type" : "user",
    "id" : "19530772260",
    "name" : "Elastic Employee",
    "login" : "info@elastic.co"
  },
  "created_at" : "2022-05-30T04:17:37-07:00",
  "recorded_at" : "2022-05-30T04:17:38-07:00",
  "event_type" : "ITEM_UPLOAD",
  "session_id" : "zbthgth2qncbt7nv",
  "source" : {
    "type" : "file",
    "id" : "964464833976",
    "file_version" : {
      "type" : "file_version",
      "id" : "1042004977176",
      "sha1" : "4932af3aa02d12a2b7c7002d4fb69691453d110c"
    },
    "sequence_id" : "0",
    "etag" : "0",
    "sha1" : "4932af3aa02d12a2b7c7002d4fb69691453d110c",
    "name" : "test.c",
    "description" : "",
    "size" : 71,
    "path_collection" : {
      "total_count" : 2,
      "entries" : [
{
  "type" : "folder",
  "id" : "0",
  "sequence_id" : null,
  "etag" : null,
  "name" : "All Files"
},
{
  "type" : "folder",
  "id" : "164104403360",
  "sequence_id" : "0",
  "etag" : "0",
  "name" : "box-test"
}
      ]
    },
    "created_at" : "2022-05-30T04:17:37-07:00",
    "modified_at" : "2022-05-30T04:17:37-07:00",
    "trashed_at" : null,
    "purged_at" : null,
    "content_created_at" : "2022-05-30T04:15:29-07:00",
    "content_modified_at" : "2022-05-30T04:15:29-07:00",
    "created_by" : {
      "type" : "user",
      "id" : "19530772260",
      "name" : "Elastic Employee",
      "login" : "info@elastic.co"
    },
    "modified_by" : {
      "type" : "user",
      "id" : "19530772260",
      "name" : "Elastic Employee",
      "login" : "info@elastic.co"
    },
    "owned_by" : {
      "type" : "user",
      "id" : "19530772260",
      "name" : "Elastic Employee",
      "login" : "info@elastic.co"
    },
    "shared_link" : null,
    "parent" : {
      "type" : "folder",
      "id" : "164104403360",
      "sequence_id" : "0",
      "etag" : "0",
      "name" : "box-test"
    },
    "item_status" : "active",
    "synced" : false
  }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|

| @timestamp | Event timestamp. | date |
| client.user.id | Unique identifier of the user. | keyword |
| client.user.full_name | User's full name, if available. | keyword |
| client.user.email | User email address. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. (Generic Examples) are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer (for example, Box-specific examples are `ITEM_PREVIEW`, `ITEM_DOWNLOAD`, `ITEM_UPLOAD`) | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| file.type | File type (file, dir, or symlink). | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.created | File creation time. Note that not all filesystems store the creation time. | date |
| file.mtime | Last time the file content was modified. | date |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.hash.sha1 | SHA1 hash. | keyword |
| box.session.id | The session of the user that performed the action. Not all events will populate this attribute. | keyword |
| box.source.id | The unique identifier that represent a folder. | keyword |
| box.source.etag | The HTTP etag of this folder. | keyword |
| box.source.description | The optional description of this folder. | text |
| box.source.path_collection | The tree of folders that this folder is contained in, starting at the root. | object |
| box.source.path_collection.total_count | The number of folders in this list. | long |
| box.source.path_collection.entries | The parent folders for this item. | object |
| box.source.path_collection.entries.type[] | Value is always `folder`. This field is an array. | keyword |
| box.source.path_collection.entries.id[] | The unique identifier that represent a folder. This field is an array. | keyword |
| box.source.path_collection.entries.name[] | The name of the folder. This field is an array. | keyword |
| box.source.created_by | The user who created this folder. | object |
| box.source.created_by.type | Value is always `user`. | keyword |
| box.source.created_by.user | A representation of a user. | object |
| box.source.created_by.user.id | The unique identifier for this user. | keyword |
| box.source.created_by.user.full_name | The display name of this user. Maps from **.name. | keyword |
| box.source.created_by.user.email | The primary email address of this user. Maps from **.login. | keyword |
| box.source.modified_by | The user who last modified this folder. | object |
| box.source.modified_by.type | Value is always `user`. | keyword |
| box.source.modified_by.user | A representation of a user. | object |
| box.source.modified_by.user.id | The unique identifier for this user. | keyword |
| box.source.modified_by.user.full_name | The display name of this user. Maps from **.name. | keyword |
| box.source.modified_by.user.email | The primary email address of this user. Maps from **.login. | keyword |
| box.source.content_created_at | The date and time at which this folder was originally created. | date |
| box.source.content_modified_at | The date and time at which this folder was last updated. | date |
| box.source.owned_by | The user who owns this folder. | keyword |
| box.source.owned_by.type | Value is always `user`. | keyword |
| box.source.owned_by.user | A representation of a user. | object |
| box.source.owned_by.user.id | The unique identifier for this user. | keyword |
| box.source.owned_by.user.full_name | The display name of this user. Maps from **.name. | keyword |
| box.source.owned_by.user.email | The primary email address of this user. Maps from **.login. | keyword |
| box.source.parent | The optional folder that this folder is located within. This value may be null for some folders such as the root folder or the trash folder. | object |
| box.source.parent.type | Value is always `folder`. | keyword |
| box.source.parent.id | The unique identifier that represent a folder. | keyword 
| box.source.parent.name | The name of the folder. | keyword |
| box.source.item_status | Defines if this item has been deleted or not. active when the item has is not in the trash trashed when the item has been moved to the trash but not deleted deleted when the item has been permanently deleted. Value is one of `active`, `trashed`, `deleted`. | keyword |
| box.source.file_version | The information about the current version of the file. | object |
| box.source.file_version.type | Value is always `file_version` | keyword |
| box.source.file_version.id | The unique identifier that represent a file version. | keyword |