# Zoom Webhook Integration

This integration creates an HTTP listener that accepts incoming webhook
callbacks from Zoom.

To configure Zoom to send webhooks to this integration, please follow the
[Zoom Documentation](https://marketplace.zoom.us/docs/guides/build/webhook-only-app).

The agent running this integration must be able to accept requests from the
Internet in order for Zoom to be able connect. Zoom requires that the webhook
accept requests over HTTPS. So you must either configure the integration with
a valid TLS certificate or use a reverse proxy in front of the integration.

## Compatibility

This integration is compatible with the Zoom Platform API as of September 2020.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| observer.product | The product name of the observer. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | keyword |
| user.changes.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.changes.email | User email address. | keyword |
| user.changes.full_name | User's full name, if available. | keyword |
| user.changes.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.changes.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.changes.group.name | Name of the group. | keyword |
| user.changes.id | Unique identifier of the user. | keyword |
| user.changes.name | Short name or login of the user. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.full_name | User's full name, if available. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| zoom.account.account_alias | When an account alias is updated, this is the new value set | keyword |
| zoom.account.account_name | When an account name is updated, this is the new value set | keyword |
| zoom.account.account_support_email | When an account support_email is updated, this is the new value set | keyword |
| zoom.account.account_support_name | When an account support_name is updated, this is the new value set | keyword |
| zoom.account.email | Email related to the user the action was performed on | keyword |
| zoom.account.owner_email | Email of the user whose sub account was created/disassociated | keyword |
| zoom.account.owner_id | UserID of the user whose sub account was created/disassociated | keyword |
| zoom.account_id | Related accountID to the event | keyword |
| zoom.chat_channel.id | The ID of the channel that has been added/modified/deleted | keyword |
| zoom.chat_channel.name | The name of the channel that has been added/modified/deleted | keyword |
| zoom.chat_channel.type | Type of channel related to the event. Can be 1(Invite-Only), 2(Private) or 3(Public) | keyword |
| zoom.chat_message.channel_id | ChannelID related to the message | keyword |
| zoom.chat_message.channel_name | Channel name related to the message | keyword |
| zoom.chat_message.contact_email | Email address related to the user sending the message | keyword |
| zoom.chat_message.contact_id | UserID belonging to the user receiving a message | keyword |
| zoom.chat_message.id | Unique ID of the related chat message | keyword |
| zoom.chat_message.message | A string containing the full message that was sent | keyword |
| zoom.chat_message.session_id | SessionID for the channel related to the message | keyword |
| zoom.chat_message.type | Type of message, can be either "to_contact" or "to_channel" | keyword |
| zoom.creation_type | Creation type | keyword |
| zoom.master_account_id | Master Account related to a specific Sub Account | keyword |
| zoom.meeting.duration | The duration of a meeting in minutes | long |
| zoom.meeting.host_id | The UserID of the configured meeting host | keyword |
| zoom.meeting.id | Unique ID of the related meeting | keyword |
| zoom.meeting.issues | When a user reports an issue with the meeting, for example: "Unstable audio quality" | keyword |
| zoom.meeting.password | Password related to the meeting | keyword |
| zoom.meeting.start_time | Date and time the meeting started | date |
| zoom.meeting.timezone | Which timezone is used for the meeting timestamps | keyword |
| zoom.meeting.topic | Topic of the related meeting | keyword |
| zoom.meeting.type | Type of meeting created | keyword |
| zoom.meeting.uuid | The UUID of the related meeting | keyword |
| zoom.old_values | Includes the old values when updating a object like user, meeting, account or webinar | flattened |
| zoom.operator | Username/Email related to the user that triggered the event | keyword |
| zoom.operator_id | UserID that triggered the event | keyword |
| zoom.participant.id | Unique ID of the participant related to a meeting | keyword |
| zoom.participant.join_time | The date and time a participant joined a meeting | date |
| zoom.participant.leave_time | The date and time a participant left a meeting | date |
| zoom.participant.sharing_details.content | Type of content that was shared | keyword |
| zoom.participant.sharing_details.date_time | Timestamp the sharing started | keyword |
| zoom.participant.sharing_details.file_link | The file link that was shared | keyword |
| zoom.participant.sharing_details.link_source | Method of sharing with dropbox integration | keyword |
| zoom.participant.sharing_details.source | The file source that was share | keyword |
| zoom.participant.user_id | UserID of the participant related to a meeting | keyword |
| zoom.participant.user_name | Username of the participant related to a meeting | keyword |
| zoom.phone.answer_start_time | The date and time when the call was answered | date |
| zoom.phone.call_end_time | The date and time when the call ended | date |
| zoom.phone.call_id | Unique ID of the related call | keyword |
| zoom.phone.callee.device_type | Device type used by the callee related to the call | keyword |
| zoom.phone.callee.extension_number | Extension number of the callee related to the call | keyword |
| zoom.phone.callee.extension_type | Extension type of the callee number, can be user, callQueue, autoReceptionist or shareLineGroup | keyword |
| zoom.phone.callee.id | UserID of the callee related to the voicemail/call | keyword |
| zoom.phone.callee.name | The name of the related callee | keyword |
| zoom.phone.callee.number_type | The type of number, can be 1(Internal) or 2(External) | keyword |
| zoom.phone.callee.phone_number | Phone Number of the callee related to the call | keyword |
| zoom.phone.callee.timezone | Timezone of the callee related to the call | keyword |
| zoom.phone.callee.user_id | UserID of the related callee of a voicemail/call | keyword |
| zoom.phone.caller.device_type | Device type used by the caller | keyword |
| zoom.phone.caller.extension_number | Extension number of the caller | keyword |
| zoom.phone.caller.extension_type | Extension type of the caller number, can be user, callQueue, autoReceptionist or shareLineGroup | keyword |
| zoom.phone.caller.id | UserID of the caller related to the voicemail/call | keyword |
| zoom.phone.caller.name | The name of the related callee | keyword |
| zoom.phone.caller.number_type | The type of number, can be 1(Internal) or 2(External) | keyword |
| zoom.phone.caller.phone_number | Phone Number of the caller related to the call | keyword |
| zoom.phone.caller.timezone | Timezone of the caller | keyword |
| zoom.phone.caller.user_id | UserID of the person which initiated the call | keyword |
| zoom.phone.connected_start_time | The date and time when a ringtone was established to the callee | date |
| zoom.phone.date_time | Date and time of the related phone event | date |
| zoom.phone.download_url | Download URL for the voicemail | keyword |
| zoom.phone.duration | Duration of a voicemail in minutes | long |
| zoom.phone.id | Unique ID for the phone or conversation | keyword |
| zoom.phone.ringing_start_time | The timestamp when a ringtone was established to the callee | date |
| zoom.phone.user_id | UserID for the phone owner related to a Call Log being completed | keyword |
| zoom.recording.duration | Duration of the recording in minutes | long |
| zoom.recording.host_email | Email address of the host related to the meeting that was recorded | keyword |
| zoom.recording.host_id | UserID of the host of the meeting that was recorded | keyword |
| zoom.recording.id | Unique ID of the related recording | keyword |
| zoom.recording.recording_count | Number of recording files related to the recording | long |
| zoom.recording.recording_file.recording_end | The date and time the recording finished | date |
| zoom.recording.recording_file.recording_start | The date and time the recording started | date |
| zoom.recording.share_url | The URL to access the recording | keyword |
| zoom.recording.start_time | The date and time when the recording started | date |
| zoom.recording.timezone | The timezone used for the recording date | keyword |
| zoom.recording.topic | Topic of the meeting related to the recording | keyword |
| zoom.recording.total_size | Total size of the recording in bytes | long |
| zoom.recording.type | Type of recording, can be multiple type of values, please check Zoom documentation | keyword |
| zoom.recording.uuid | UUID of the related recording | keyword |
| zoom.registrant.address | Address of the user registering to a meeting or webinar | keyword |
| zoom.registrant.city | City of the user registering to a meeting or webinar | keyword |
| zoom.registrant.comments | Comments left by the user registering to a meeting or webinar | keyword |
| zoom.registrant.country | Country of the user registering to a meeting or webinar | keyword |
| zoom.registrant.email | Email of the user registering to a meeting or webinar | keyword |
| zoom.registrant.first_name | First name of the user registering to a meeting or webinar | keyword |
| zoom.registrant.id | Unique ID of the user registering to a meeting or webinar | keyword |
| zoom.registrant.industry | Related industry of the user registering to a meeting or webinar | keyword |
| zoom.registrant.job_title | Job title of the user registering to a meeting or webinar | keyword |
| zoom.registrant.join_url | The URL that the registrant can use to join the webinar | keyword |
| zoom.registrant.last_name | Last name of the user registering to a meeting or webinar | keyword |
| zoom.registrant.no_of_employees | Number of employees choosen by the user registering to a meeting or webinar | keyword |
| zoom.registrant.org | Organization related to the user registering to a meeting or webinar | keyword |
| zoom.registrant.phone | Phone number of the user registering to a meeting or webinar | keyword |
| zoom.registrant.purchasing_time_frame | Choosen purchase timeframe of the user registering to a meeting or webinar | keyword |
| zoom.registrant.role_in_purchase_process | Choosen role in a purchase process related to the user registering to a meeting or webinar | keyword |
| zoom.registrant.state | State of the user registering to a meeting or webinar | keyword |
| zoom.registrant.status | Status of the specific user registration | keyword |
| zoom.registrant.zip | Zip code of the user registering to a meeting or webinar | keyword |
| zoom.settings | The current active settings related to a object like user, meeting, account or webinar | flattened |
| zoom.sub_account_id | Related Sub Account | keyword |
| zoom.timestamp | Timestamp related to the event | date |
| zoom.user.client_type | Type of client used by the user. Can be browser, mac, win, iphone or android | keyword |
| zoom.user.company | User company related to the user event | keyword |
| zoom.user.dept | The configured departement for the user | keyword |
| zoom.user.email | User email related to the user event | keyword |
| zoom.user.first_name | User first name related to the user event | keyword |
| zoom.user.host_key | Host key set for the user | keyword |
| zoom.user.id | UserID related to the user event | keyword |
| zoom.user.language | Language configured for the user | keyword |
| zoom.user.last_name | User last name related to the user event | keyword |
| zoom.user.personal_notes | Personal notes for the User | keyword |
| zoom.user.phone_country | User country code related to the user event | keyword |
| zoom.user.phone_number | User phone number related to the user event | keyword |
| zoom.user.pic_url | Full URL to the profile picture used by the user | keyword |
| zoom.user.pmi | User personal meeting ID related to the user event | keyword |
| zoom.user.presence_status | Current presence status of user | keyword |
| zoom.user.role | The configured role for the user | keyword |
| zoom.user.timezone | Timezone configured for the user | keyword |
| zoom.user.type | User type related to the user event | keyword |
| zoom.user.use_pmi | If a user has PMI enabled | boolean |
| zoom.user.vanity_name | Name of the personal meeting room related to the user event | keyword |
| zoom.user.version | Version of the client used by the user | keyword |
| zoom.webinar.agenda | The configured agenda of the webinar | keyword |
| zoom.webinar.duration | Duration of the webinar in minutes | long |
| zoom.webinar.host_id | UserID for the configured host of the webinar | keyword |
| zoom.webinar.id | Unique ID for the related webinar | keyword |
| zoom.webinar.issues | Any reported issues about a webinar is reported in this field | keyword |
| zoom.webinar.join_url | The URL configured to join the webinar | keyword |
| zoom.webinar.password | Password configured to access the webinar | keyword |
| zoom.webinar.start_time | The date and time when the webinar started | date |
| zoom.webinar.timezone | Timezone used for the dates related to the webinar | keyword |
| zoom.webinar.topic | Meeting topic of the related webinar | keyword |
| zoom.webinar.type | Type of webinar created. Can be either 5(Webinar), 6(Recurring webinar without fixed time) or 9(Recurring webinar with fixed time) | keyword |
| zoom.webinar.uuid | UUID for the related webinar | keyword |
| zoom.zoomroom.alert_kind | An integer value showing if the Zoom room alert has been either 1(Triggered) or 2(Cleared) | keyword |
| zoom.zoomroom.alert_type | An integer value representing the type of alert. The list of alert types can be found in the Zoom documentation | keyword |
| zoom.zoomroom.calendar_id | Unique ID of the calendar used by the Zoom room | keyword |
| zoom.zoomroom.calendar_name | Calendar name of the Zoom room | keyword |
| zoom.zoomroom.change_key | Key used by Microsoft products integration that represents a specific version of a calendar | keyword |
| zoom.zoomroom.component | An integer value representing the type of equipment or component, The list of component types can be found in the Zoom documentation | keyword |
| zoom.zoomroom.email | Email address associated with the Zoom room itself | keyword |
| zoom.zoomroom.event_id | Unique ID of the calendar event associated with the Zoom Room | keyword |
| zoom.zoomroom.id | Unique ID of the Zoom room | keyword |
| zoom.zoomroom.issue | Any reported alerts or issues related to the Zoom room or its equipment | keyword |
| zoom.zoomroom.resource_email | Email address associated with the calendar in use by the Zoom room | keyword |
| zoom.zoomroom.room_name | The configured name of the Zoom room | keyword |

