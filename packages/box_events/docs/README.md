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

## Box Events

The Box events API enables subscribing to live events across the enterprise or for a particular user, or querying historical events across the enterprise.

The API Returns up to a year of past events for configurable to the `admin` user (default) or for the entire enterprise.

### Elastic Integration for Box Events Settings

The Elastic Integration for Box Events requires the following Authentication Settings in order to connect to the Target service:
  - Client ID
  - Client Secret
  - Box Subject ID
  - Box Subject Type
  - Grant Type

The Elastic Integration for Box Events requires the following Data Stream Settings to configure the request to the Target API:
  - Interval
  - Stream Type
  - Preserve Original Event

Here is a brief guide to help you generate these settings

### Target Repository Authentication Settings Prerequisites
The Elastic Integration for Box Events connects using OAuth 2.0 to interact with a Box Custom App. As prerequisites you will need to:
  - Enable `MFA/2FA` on your admin account by following the instructions in [MFA Setup on Box Support](https://support.box.com/hc/en-us/articles/360043697154-Multi-Factor-Authentication-Set-Up-for-Your-Account)
  - Configure a `Box Custom Application using Server Authentication `    
  `(with Client Credentials Grant)`. A suggested workflow is provided below, see [Setup with OAuth 2.0](https://developer.box.com/guides/authentication/oauth2/oauth2-setup/) for additional information.

### Authorized User
It is important to login to the [Box Developer Console](https://app.box.com/developers/console) as an `admin` and not `co-admin`.

## A suggested workflow is as follows:

### Create a `Custom Application using Server Authentication (with Client Credentials Grant) authentication`
  1. Open the [Box Developer Console](https://app.box.com/developers/console)
  2. Click on `Create new App`
  3. Click on `Custom App`
  4. Select `Server Authentication (Client Credentials Grant)`
  5. Provide an App name, for example `elastic-box-integration`
  6. Click on `Create App` 
  7. When your App has been created, scroll down and under `App Access Level` select `App + Enterprise Access`
  8. Scroll down to `Application Scopes` and under `Administrative Actions` select 
    - `Manage users`
    - `Manage enterprise properties`
  9. Scroll down to `Advanced Features` and select 
    - `Generate user access tokens`
  10. Click on `Save Changes`

### Submit the application for Authorization from the [Box Developer Console](https://app.box.com/developers/console)
  1. In the left side bar, at the bottom, click on `</> Dev Console`
  2. Click on your application, which should now have an extra `Authorization` tab, so click on this
  3. Click on `Review and Submit`, add a comment to explain your changes then click on `Submit`.

### Authorize the Application from the [Box Admin Console](https://app.box.com/master)
If you are the `admin` user you can do this yourself, otherwise reach out to the admin to confirm your motives and request that they authorize your request, since there may be some delay before they are aware of your request.

To authorize the App ensure you are logged in to the [Admin Console](https://app.box.com/master) and follow these steps:

  1. In the left side bar click on [Apps](https://app.box.com/master/settings/apps)
  2. Click on the [Custom Apps Manager](https://app.box.com/master/custom-apps) tab, you should see your App under `Server Authentication Apps` and the `Authorisation Status` should be `Pending Reauth`
  3. Click on your App, it should have the following `App Details`:
    - Last Activity
      - `<date>`
    - Developer Email
      - `<your email>`
    - Authorization Status
      - `Pending Reauthorization`
    - Enablement Status
      - `Enabled`
    - Client ID
      - `<alphanumeric id>`
    - App Access
      - `All Users`
    - App Scopes
      - `Read and write all files and folders stored in Box`
      - `Manage enterprise properties`
      - `Manage users`
      - `Manage app users`
      - `Generate user access tokens`
    - Authentication Type
      - `OAuth 2.0 with Client Credentials Grant`
  4. Click on `Authorize` - a pop up will reconfirm these details
  5. Click on `Authorize` - the Authorization Status should update to 
    - Authorized

### Locate the Elastic Integration for Box Events Settings

#### Client ID
Click on your App in the [Box Developer Console](https://app.box.com/developers/console), under the `Configuration` tab, scroll down to `OAuth 2.0 Credentials` and copy the `Client ID`

####  Client Secret
Have your 2FA device prepared and to hand. Click on your App in the [Box Developer Console](https://app.box.com/developers/console), under the `Configuration` tab, scroll down to `OAuth 2.0 Credentials` and click on `Fetch Client Secret`. Complete the 2FA challenge to copy the `Client Secret`

####  Box Subject ID
Click on your App in the [Box Developer Console](https://app.box.com/developers/console), under the `General Settings` tab, scroll down to `App Info`. If you intend to harvest events solely for the `admin` user copy the `User ID` otherwise copy the `Enterprise ID`

####  Box Subject Type
If you intend to harvest events solely for the `admin` user set this to `user` otherwise set to `enterprise`

####  Grant Type
Use the provided default `client_credentials`

####  Interval
This sets the interval between requests to the Target Service, for example `300s` will send a request every 300 seconds. Events will be returned in batches of up to 100, with successive calls on expiry of the configured `interval` so you may wish to specify a lower interval when a substantial number of events are expected, however, we suggest to consider bandwidth when using lower settings

####  Stream Type
To retrieve events for a single user, set stream type to `all` (default). To select only events that may cause file tree changes such as file updates or collaborations, use `changes`. To select a subset of `changes` for synced folders, use `sync`. To retrieve events for the entire enterprise, set the stream_type to `admin_logs_streaming` for live monitoring of new events, or `admin_logs` for querying across historical events.

####  Preserve Original Event
Preserves a raw copy of the original event, added to the field `event.original`.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| box.additional_details.shield_alert.alert_id | Box Shield alert ID | long |
| box.additional_details.shield_alert.alert_summary.anomaly_period.date_range.end_date | When the anomaly was last observed | keyword |
| box.additional_details.shield_alert.alert_summary.anomaly_period.date_range.start_date | When the anomaly was last observed | keyword |
| box.additional_details.shield_alert.alert_summary.anomaly_period.download_size | Volume of Anomalous Downloads detected by Box Shield relating to an account holder who may be stealing sensitive content | keyword |
| box.additional_details.shield_alert.alert_summary.anomaly_period.downloaded_files_count | Number of Anomalous Downloads detected by Box Shield relating to an account holder who may be stealing sensitive content | long |
| box.additional_details.shield_alert.alert_summary.description | Description of Alert | keyword |
| box.additional_details.shield_alert.alert_summary.download_delta_percent | Anomaly delta percentage relative to historical expectation | long |
| box.additional_details.shield_alert.alert_summary.download_delta_size | Anomaly delta size relative to historical expectation | keyword |
| box.additional_details.shield_alert.alert_summary.download_ips.ip | IP address | ip |
| box.additional_details.shield_alert.alert_summary.historical_period.date_range.end_date | End of historical period for calculation of historical expectation | keyword |
| box.additional_details.shield_alert.alert_summary.historical_period.date_range.start_date | Start of historical period for calculation of historical expectation | keyword |
| box.additional_details.shield_alert.alert_summary.historical_period.download_size | Volume of Anomalous Downloads detected by Box Shield relating to an account holder who may be stealing sensitive content | keyword |
| box.additional_details.shield_alert.alert_summary.historical_period.downloaded_files_count | Number of Anomalous Downloads detected by Box Shield relating to an account holder who may be stealing sensitive content | long |
| box.additional_details.shield_alert.alert_summary.upload_activity.event_type | Type of event, e.g. `Upload` | keyword |
| box.additional_details.shield_alert.alert_summary.upload_activity.ip_info.ip | IP address | ip |
| box.additional_details.shield_alert.alert_summary.upload_activity.ip_info.registrant | Registrant of IP | keyword |
| box.additional_details.shield_alert.alert_summary.upload_activity.item_id | ID of item | keyword |
| box.additional_details.shield_alert.alert_summary.upload_activity.item_name | Name of item | keyword |
| box.additional_details.shield_alert.alert_summary.upload_activity.item_path | Path to Item | keyword |
| box.additional_details.shield_alert.alert_summary.upload_activity.item_type | Type of Item | keyword |
| box.additional_details.shield_alert.alert_summary.upload_activity.occurred_at | Time of Upload | keyword |
| box.additional_details.shield_alert.alert_summary.upload_activity.service_name | Service used to upload the suspected Malware | keyword |
| box.additional_details.shield_alert.created_at | Time alert was created | date |
| box.additional_details.shield_alert.link | URL with information about this alert | keyword |
| box.additional_details.shield_alert.malware_info.categories | Array of Malware Categories e.g. `Adware`, `Spyware` | keyword |
| box.additional_details.shield_alert.malware_info.description | Describes the Malware | keyword |
| box.additional_details.shield_alert.malware_info.detail_link | URL with detail of Malware | keyword |
| box.additional_details.shield_alert.malware_info.family | Malware Family | keyword |
| box.additional_details.shield_alert.malware_info.file_created | Date of file creation | date |
| box.additional_details.shield_alert.malware_info.file_created_by.email | Email of file creator | keyword |
| box.additional_details.shield_alert.malware_info.file_created_by.id | ID of file creator. The Box Shield documentation example uses `long`, not `string` | long |
| box.additional_details.shield_alert.malware_info.file_created_by.name | Display name of file creator | keyword |
| box.additional_details.shield_alert.malware_info.file_hash | File hash | keyword |
| box.additional_details.shield_alert.malware_info.file_hash_type | Hash type, e.g. `SHA-1` | keyword |
| box.additional_details.shield_alert.malware_info.file_id | File ID | long |
| box.additional_details.shield_alert.malware_info.file_name | File name | keyword |
| box.additional_details.shield_alert.malware_info.file_size_bytes | File size in bytes | long |
| box.additional_details.shield_alert.malware_info.file_version | File version | long |
| box.additional_details.shield_alert.malware_info.file_version_uploaded | Date this version of file was uploaded | date |
| box.additional_details.shield_alert.malware_info.file_version_uploaded_by.email | Email of file uploader | keyword |
| box.additional_details.shield_alert.malware_info.file_version_uploaded_by.id | ID of file uploader | long |
| box.additional_details.shield_alert.malware_info.file_version_uploaded_by.name | Display name of file uploader | keyword |
| box.additional_details.shield_alert.malware_info.first_seen | Time Malware first observed | date |
| box.additional_details.shield_alert.malware_info.last_seen | Time Malware last observed | date |
| box.additional_details.shield_alert.malware_info.malware_name | Malware name | keyword |
| box.additional_details.shield_alert.malware_info.status | Malware status e.g. `Malicious` | keyword |
| box.additional_details.shield_alert.malware_info.tags | Array of Malware Tags e.g. `FILE_MALICIOUS_EXECUTION` | keyword |
| box.additional_details.shield_alert.priority | Box Shield priority of alert | keyword |
| box.additional_details.shield_alert.risk_score | Risk score as calculated by Box Shield | long |
| box.additional_details.shield_alert.rule_category | Rule Category as allocated by Box Shield | keyword |
| box.additional_details.shield_alert.rule_id | Box Shield rule ID | long |
| box.additional_details.shield_alert.rule_name | Box Shield rule name | keyword |
| box.additional_details.shield_alert.user.email | User email | keyword |
| box.additional_details.shield_alert.user.id | User ID | long |
| box.additional_details.shield_alert.user.name | User name | keyword |
| box.created_at | When the event object was created | date |
| box.created_by.id | The unique identifier for the connection user. | keyword |
| box.created_by.login | The primary email address of the connection user. Maps from \*\*.login | keyword |
| box.created_by.name | The display name of the connection user. Maps from \*\*.name | keyword |
| box.created_by.type | E.g. `user` | keyword |
| box.ip_address | IP Address | keyword |
| box.recorded_at | The date and time at which this event occurred | date |
| box.session.id | Box `session_id` field | keyword |
| box.source.address | Physical Address associated with the event | keyword |
| box.source.avatar_url | URL for user avatar | boolean |
| box.source.created_at | The date and time at which this folder was originally created | date |
| box.source.created_by.id | The unique identifier for this user | keyword |
| box.source.created_by.login | The primary email address of this user. Maps from \*\*.login | keyword |
| box.source.created_by.name | The display name of this user. Maps from \*\*.name | keyword |
| box.source.created_by.type | Value is always `user` | keyword |
| box.source.description | The optional description of this folder | text |
| box.source.etag | The HTTP etag of this folder | keyword |
| box.source.file_version.id | The unique identifier that represent a file version | keyword |
| box.source.file_version.type | Value is always `file_version` | keyword |
| box.source.id | The unique identifier that represent a folder | keyword |
| box.source.item_status | Defines if this item has been deleted or not. active when the item has is not in the trash trashed when the item has been moved to the trash but not deleted deleted when the item has been permanently deleted. Value is one of `active`, `trashed`, `deleted` | keyword |
| box.source.job_title | User job title | boolean |
| box.source.language | User preferred language | boolean |
| box.source.login | User login | boolean |
| box.source.max_upload_size | Max upload size | boolean |
| box.source.modified_at | The date and time at which this folder was last updated | date |
| box.source.modified_by.id | The unique identifier for this user that last modified the file. | keyword |
| box.source.modified_by.login | The primary email address of this user. Maps from \*\*.login | keyword |
| box.source.modified_by.name | The display name of this user. Maps from \*\*.name | keyword |
| box.source.modified_by.type | Value is always `user` | keyword |
| box.source.notification_email.email | Email to send notifications | boolean |
| box.source.notification_email.is_confirmed | True if `notification_email.email` has been confirmed else false | boolean |
| box.source.owned_by.id | The unique identifier for this user | keyword |
| box.source.owned_by.login | The primary email address of this user. Maps from \*\*.login | keyword |
| box.source.owned_by.name | The display name of this user. Maps from \*\*.name | keyword |
| box.source.owned_by.type | Value is always `user` | keyword |
| box.source.parent.etag | The HTTP etag of this folder | keyword |
| box.source.parent.id | The unique identifier that represent a folder | keyword |
| box.source.parent.name | The name of the folder | keyword |
| box.source.parent.sequence_id | A numeric identifier that represents the most recent user event that has been applied to this item (parent) | keyword |
| box.source.parent.type | Value is always `folder` | keyword |
| box.source.path_collection.entries.etag | The HTTP etag of this folder | keyword |
| box.source.path_collection.entries.id | The unique identifier that represent a folder. This field is an array | keyword |
| box.source.path_collection.entries.name | The name of the parent folder. This field is an array | keyword |
| box.source.path_collection.entries.sequence_id | A numeric identifier that represents the most recent user event that has been applied to this item | keyword |
| box.source.path_collection.entries.type | Value is always `folder`. This field is an array | keyword |
| box.source.path_collection.total_count | The number of folders in this list | long |
| box.source.phone | Phone number | boolean |
| box.source.purged_at | The time at which this file is expected to be purged from the trash | boolean |
| box.source.sequence_id | A numeric identifier that represents the most recent user event that has been applied to this item | keyword |
| box.source.sha1 | SHA1 hash of the item concerned | keyword |
| box.source.space_amount | Space amount | boolean |
| box.source.space_used | Space used | boolean |
| box.source.status | For example: `active` | boolean |
| box.source.synced | Legacy property for compatibility with Box Desktop | boolean |
| box.source.timezone | Timezone | boolean |
| box.source.trashed_at | The time at which this file was put in the trash | boolean |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.user.email | User email address. | keyword |
| client.user.full_name | User's full name, if available. | keyword |
| client.user.full_name.text | Multi-field of `client.user.full_name`. | match_only_text |
| client.user.id | Unique identifier of the user. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
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
| host.disk.read.bytes | The total number of bytes (gauge) read successfully (aggregated from all disks) since the last metric collection. | long |
| host.disk.write.bytes | The total number of bytes (gauge) written successfully (aggregated from all disks) since the last metric collection. | long |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.network.in.bytes | The number of bytes received on all network interfaces by the host in a given period of time. | long |
| host.network.in.packets | The number of packets received on all network interfaces by the host in a given period of time. | long |
| host.network.out.bytes | The number of bytes sent out on all network interfaces by the host in a given period of time. | long |
| host.network.out.packets | The number of packets sent out on all network interfaces by the host in a given period of time. | long |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| related.description | Array of `description` derived from `threat[.enrichments].indicator.description` | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.indicator_type | Array of `indicator_type` derived from `threat[.enrichments].indicator.type` | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.location | Array of `location` derived from `related.ip` | geo_point |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.uuid | A rule ID that is unique within the scope of a set or group of agents, observers, or other entities using the rule for detection of this event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.enrichments | A list of associated indicators objects enriching the event, and the context of that association/enrichment. | nested |
| threat.enrichments.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.enrichments.indicator.as.organization.name | Organization name. | keyword |
| threat.enrichments.indicator.as.organization.name.text | Multi-field of `threat.enrichments.indicator.as.organization.name`. | match_only_text |
| threat.enrichments.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.enrichments.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.enrichments.indicator.geo.city_name | City name. | keyword |
| threat.enrichments.indicator.geo.continent_name | Name of the continent. | keyword |
| threat.enrichments.indicator.geo.country_iso_code | Country ISO code. | keyword |
| threat.enrichments.indicator.geo.country_name | Country name. | keyword |
| threat.enrichments.indicator.geo.location | Longitude and latitude. | geo_point |
| threat.enrichments.indicator.geo.region_iso_code | Region ISO code. | keyword |
| threat.enrichments.indicator.geo.region_name | Region name. | keyword |
| threat.enrichments.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.enrichments.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.enrichments.indicator.provider | The name of the indicator's provider. | keyword |
| threat.enrichments.indicator.reference | Reference URL linking to additional information about this indicator. | keyword |
| threat.enrichments.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.indicator.as.organization.name | Organization name. | keyword |
| threat.indicator.as.organization.name.text | Multi-field of `threat.indicator.as.organization.name`. | match_only_text |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.geo.city_name | City name. | keyword |
| threat.indicator.geo.continent_name | Name of the continent. | keyword |
| threat.indicator.geo.country_iso_code | Country ISO code. | keyword |
| threat.indicator.geo.country_name | Country name. | keyword |
| threat.indicator.geo.location | Longitude and latitude. | geo_point |
| threat.indicator.geo.region_iso_code | Region ISO code. | keyword |
| threat.indicator.geo.region_name | Region name. | keyword |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.reference | Reference URL linking to additional information about this indicator. | keyword |
| threat.indicator.sightings | Number of times this indicator was observed conducting threat activity. | long |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| user.effective.email | User email address. | keyword |
| user.effective.id | Unique identifier of the user. | keyword |
| user.effective.name | Short name or login of the user. | keyword |
| user.effective.name.text | Multi-field of `user.effective.name`. | match_only_text |

