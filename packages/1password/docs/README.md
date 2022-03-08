1Password Events Reporting
==========================

With [1Password Business](https://support.1password.com/explore/business/), you can send your account activity to your security information and event management (SIEM) system using the 1Password Events API. Get reports about 1Password activity like sign-in attempts and item usage while you manage all your company’s applications and services from a central location.

With 1Password Events Reporting and Elastic SIEM, you can:

-	Control your 1Password data retention
-	Build custom graphs and dashboards
-	Set up custom alerts that trigger specific actions
-	Cross-reference 1Password events with the data from other services

You can set up Events Reporting if you’re an owner or administrator.  
Learn how to [obtain your 1Password Events API credentials](https://support.1password.com/events-reporting/#step-1-set-up-an-events-reporting-integration).

Events
------

### Sign-in Attempts

Uses the 1Password Events API to retrieve information about sign-in attempts. Events include the name and IP address of the user who attempted to sign in to the account, when the attempt was made, and – for failed attempts – the cause of the failure.

*Exported fields*

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Input type | keyword |
| onepassword.client.app_name | The name of the 1Password app that attempted to sign in to the account | keyword |
| onepassword.client.app_version | The version number of the 1Password app | keyword |
| onepassword.client.platform_name | The name of the platform running the 1Password app | keyword |
| onepassword.client.platform_version | The version of the browser or computer where the 1Password app is installed, or the CPU of the machine where the 1Password command-line tool is installed | keyword |
| onepassword.country | The country code of the event. Uses the ISO 3166 standard | keyword |
| onepassword.details | Additional information about the sign-in attempt, such as any firewall rules that prevent a user from signing in | object |
| onepassword.session_uuid | The UUID of the session that created the event | keyword |
| onepassword.type | Details about the sign-in attempt | keyword |
| onepassword.uuid | The UUID of the event | keyword |
| os.name | Operating system name, without the version. | keyword |
| os.version | Operating system version as a raw string. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.id | Unique identifier of the user. | keyword |


An example event for `signin_attempts` looks as following:

```json
{
    "@timestamp": "2021-08-11T14:28:03.000Z",
    "agent": {
        "ephemeral_id": "6a1b2121-406e-47fc-8ab0-3ab3b521f341",
        "id": "8652330e-4de6-4596-a16f-4463a6c56e9e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "1password.signin_attempts",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "8652330e-4de6-4596-a16f-4463a6c56e9e",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "action": "success",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "created": "2022-03-03T21:25:49.160Z",
        "dataset": "1password.signin_attempts",
        "ingested": "2022-03-03T21:25:52Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "docker-fleet-agent"
    },
    "input": {
        "type": "httpjson"
    },
    "onepassword": {
        "client": {
            "app_name": "1Password Browser Extension",
            "app_version": "1109",
            "platform_name": "Chrome",
            "platform_version": "93.0.4577.62"
        },
        "country": "AR",
        "details": null,
        "session_uuid": "UED4KFZ5BH37IQWTJ7LG4VPWK7",
        "type": "credentials_ok",
        "uuid": "HGIF4OEWXDTVWKEQDIWTKV26HU"
    },
    "os": {
        "name": "Android",
        "version": "10"
    },
    "related": {
        "ip": [
            "1.1.1.1"
        ],
        "user": [
            "OJQGU46KAPROEJLCK674RHSAY5",
            "email@1password.com",
            "Name"
        ]
    },
    "source": {
        "ip": "1.1.1.1"
    },
    "tags": [
        "forwarded",
        "1password-signin_attempts"
    ],
    "user": {
        "email": "email@1password.com",
        "full_name": "Name",
        "id": "OJQGU46KAPROEJLCK674RHSAY5"
    }
}
```

### Item Usages

Uses the 1Password Events API to retrieve information about items in shared vaults that have been modified, accessed, or used. Events include the name and IP address of the user who accessed the item, when it was accessed, and the vault where the item is stored.

*Exported fields*

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Input type | keyword |
| onepassword.client.app_name | The name of the 1Password app the item was accessed from | keyword |
| onepassword.client.app_version | The version number of the 1Password app | keyword |
| onepassword.client.platform_name | The name of the platform the item was accessed from | keyword |
| onepassword.client.platform_version | The version of the browser or computer where the 1Password app is installed, or the CPU of the machine where the 1Password command-line tool is installed | keyword |
| onepassword.item_uuid | The UUID of the item that was accessed | keyword |
| onepassword.used_version | The version of the item that was accessed | integer |
| onepassword.uuid | The UUID of the event | keyword |
| onepassword.vault_uuid | The UUID of the vault the item is in | keyword |
| os.name | Operating system name, without the version. | keyword |
| os.version | Operating system version as a raw string. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.id | Unique identifier of the user. | keyword |


An example event for `item_usages` looks as following:

```json
{
    "@timestamp": "2021-08-30T18:57:42.484Z",
    "agent": {
        "ephemeral_id": "cbcdd98f-456d-47bb-9f43-cf589ccd810d",
        "id": "8652330e-4de6-4596-a16f-4463a6c56e9e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "1password.item_usages",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "8652330e-4de6-4596-a16f-4463a6c56e9e",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "action": "reveal",
        "agent_id_status": "verified",
        "category": [
            "file"
        ],
        "created": "2022-03-03T21:25:12.198Z",
        "dataset": "1password.item_usages",
        "ingested": "2022-03-03T21:25:13Z",
        "kind": "event",
        "type": [
            "access"
        ]
    },
    "host": {
        "name": "docker-fleet-agent"
    },
    "input": {
        "type": "httpjson"
    },
    "onepassword": {
        "client": {
            "app_name": "1Password Browser Extension",
            "app_version": "1109",
            "platform_name": "Chrome",
            "platform_version": "93.0.4577.62"
        },
        "item_uuid": "bvwmmwxisuca7wbehrbyqhag54",
        "used_version": 1,
        "uuid": "MCQODBBWJD5HISKYNP3HJPV2DV",
        "vault_uuid": "jaqxqf5qylslqiitnduawrndc5"
    },
    "os": {
        "name": "Android",
        "version": "10"
    },
    "related": {
        "ip": [
            "1.1.1.1"
        ],
        "user": [
            "OJQGU46KAPROEJLCK674RHSAY5",
            "email@1password.com",
            "Name"
        ]
    },
    "source": {
        "ip": "1.1.1.1"
    },
    "tags": [
        "forwarded",
        "1password-item_usages"
    ],
    "user": {
        "email": "email@1password.com",
        "full_name": "Name",
        "id": "OJQGU46KAPROEJLCK674RHSAY5"
    }
}
```
