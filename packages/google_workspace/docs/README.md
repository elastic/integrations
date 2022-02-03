# Google Workspace Integration

The Google Workspace integration collects and parses data from the different Google Workspace audit reports APIs.

## Compatibility

It is compatible with a subset of applications under the [Google Reports API v1](https://developers.google.com/admin-sdk/reports/v1/get-start/getting-started). As of today it supports:

| Google Workspace Service | Description |
|---|---|
| [SAML](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/saml) [help](https://support.google.com/a/answer/7007375?hl=en&ref_topic=9027054) | View users’ successful and failed sign-ins to SAML applications. |
| [User Accounts](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/user-accounts) [help](https://support.google.com/a/answer/9022875?hl=en&ref_topic=9027054) | Audit actions carried out by users on their own accounts including password changes, account recovery details and 2-Step Verification enrollment. |
| [Login](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login) [help](https://support.google.com/a/answer/4580120?hl=en&ref_topic=9027054) | Track user sign-in activity to your domain. |
| [Admin](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-application-settings) [help](https://support.google.com/a/answer/4579579?hl=en&ref_topic=9027054) | View administrator activity performed within the Google Admin console. |
| [Drive](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive) [help](https://support.google.com/a/answer/4579696?hl=en&ref_topic=9027054) | Record user activity within Google Drive including content creation in such as Google Docs, as well as content created elsewhere that your users upload to Drive such as PDFs and Microsoft Word files. |
| [Groups](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups) [help](https://support.google.com/a/answer/6270454?hl=en&ref_topic=9027054) | Track changes to groups, group memberships and group messages. |

## Requirements

In order to ingest data from the Google Reports API you must:

- Have an *administrator account*.
- [Set up a ServiceAccount](https://support.google.com/workspacemigrate/answer/9222993?hl=en) using the administrator account.
- [Set up access to the Admin SDK API](https://support.google.com/workspacemigrate/answer/9222865?hl=en) for the ServiceAccount.
- [Enable Domain-Wide Delegation](https://developers.google.com/admin-sdk/reports/v1/guides/delegation) for your ServiceAccount.

This module will make use of the following *oauth2 scope*:

- `https://www.googleapis.com/auth/admin.reports.audit.readonly`

Once you have downloaded your service account credentials as a JSON file, you are ready to set up your integration.

## Logs

### Google Workspace Reports ECS fields

This is a list of Google Workspace Reports fields that are mapped to ECS that are common to al data sets.

| Google Workspace Reports     | ECS Fields                                                    |
|------------------------------|---------------------------------------------------------------|
| `items[].id.time`            | `@timestamp`                                                  |
| `items[].id.uniqueQualifier` | `event.id`                                                    |
| `items[].id.applicationName` | `event.provider`                                              |
| `items[].events[].name`      | `event.action`                                                |
| `items[].customerId`         | `organization.id`                                             |
| `items[].ipAddress`          | `source.ip`, `related.ip`, `source.as.*`, `source.geo.*`      |
| `items[].actor.email`        | `source.user.email`, `source.user.name`, `source.user.domain` |
| `items[].actor.profileId`    | `source.user.id`                                              |

### SAML

This is the `saml` dataset.

An example event for `saml` looks as following:

```json
{
    "@timestamp": "2022-02-02T12:27:23.000Z",
    "agent": {
        "ephemeral_id": "4ffa592e-b9c1-4a7e-8c91-78817747d073",
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "google_workspace.saml",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "login_failure",
        "agent_id_status": "verified",
        "category": [
            "authentication",
            "session"
        ],
        "created": "2022-02-03T12:27:23.007Z",
        "dataset": "google_workspace.saml",
        "id": "1",
        "ingested": "2022-02-03T12:27:24Z",
        "outcome": "failure",
        "provider": "saml",
        "type": [
            "start"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "event": {
            "type": "login"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        },
        "saml": {
            "application_name": "app",
            "failure_type": "failure_app_not_configured_for_user",
            "initiated_by": "idp",
            "orgunit_path": "ounit",
            "second_level_status_code": "SUCCESS_URI",
            "status_code": "SUCCESS_URI"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "source": {
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, Inc."
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "forwarded",
        "google-workspace-saml"
    ],
    "user": {
        "domain": "bar.com",
        "id": "1",
        "name": "foo"
    }
}
```

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
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| google_workspace.saml.application_name | Saml SP application name. | keyword |
| google_workspace.saml.failure_type | Login failure type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/saml. | keyword |
| google_workspace.saml.initiated_by | Requester of SAML authentication. | keyword |
| google_workspace.saml.orgunit_path | User orgunit. | keyword |
| google_workspace.saml.second_level_status_code | SAML second level status code. | keyword |
| google_workspace.saml.status_code | SAML status code. | keyword |
| group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
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
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.email | User email address. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |


### User Accounts

This is the `user_accounts` dataset.

An example event for `user_accounts` looks as following:

```json
{
    "@timestamp": "2022-02-02T12:28:15.000Z",
    "agent": {
        "ephemeral_id": "3242bd5f-5862-4205-97eb-6aaac7d3f3d5",
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "google_workspace.user_accounts",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "2sv_disable",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2022-02-03T12:28:15.402Z",
        "dataset": "google_workspace.user_accounts",
        "id": "1",
        "ingested": "2022-02-03T12:28:16Z",
        "provider": "user_accounts",
        "type": [
            "change",
            "user"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "event": {
            "type": "2sv_change"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "source": {
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, Inc."
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "forwarded",
        "google-workspace-user-accounts"
    ],
    "user": {
        "domain": "bar.com",
        "id": "1",
        "name": "foo"
    }
}
```

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
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
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
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.email | User email address. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |


### Login Accounts

This is the `login` dataset.

An example event for `login` looks as following:

```json
{
    "@timestamp": "2022-02-02T12:26:31.000Z",
    "agent": {
        "ephemeral_id": "0b8db1d7-2f2e-4e9d-84d8-f3b4409101ef",
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "google_workspace.login",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "account_disabled_password_leak",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "created": "2022-02-03T12:26:31.037Z",
        "dataset": "google_workspace.login",
        "id": "1",
        "ingested": "2022-02-03T12:26:32Z",
        "provider": "login",
        "type": [
            "user",
            "change"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "event": {
            "type": "account_warning"
        },
        "kind": "admin#reports#activity",
        "login": {
            "affected_email_address": "foo@elastic.co"
        },
        "organization": {
            "domain": "elastic.com"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo",
            "foo"
        ]
    },
    "source": {
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, Inc."
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "forwarded",
        "google-workspace-login"
    ],
    "user": {
        "domain": "bar.com",
        "id": "1",
        "name": "foo",
        "target": {
            "domain": "elastic.co",
            "name": "foo"
        }
    }
}
```

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
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.login.affected_email_address |  | keyword |
| google_workspace.login.challenge_method | Login challenge method. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login. | keyword |
| google_workspace.login.challenge_status | Login challenge status. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login. | keyword |
| google_workspace.login.failure_type | Login failure type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login. | keyword |
| google_workspace.login.is_second_factor |  | boolean |
| google_workspace.login.is_suspicious |  | boolean |
| google_workspace.login.timestamp | UNIX timestmap of login in microseconds. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login. | long |
| google_workspace.login.type | Login credentials type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login. | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
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
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.email | User email address. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |


### Admin

This is the `admin` dataset.

An example event for `admin` looks as following:

```json
{
    "@timestamp": "2022-02-02T12:23:57.000Z",
    "agent": {
        "ephemeral_id": "68cf8bd1-0ff1-4c77-a4e7-64ab24882a9c",
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "google_workspace.admin",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "CHANGE_APPLICATION_SETTING",
        "agent_id_status": "verified",
        "category": [
            "iam",
            "configuration"
        ],
        "created": "2022-02-03T12:23:57.797Z",
        "dataset": "google_workspace.admin",
        "id": "1",
        "ingested": "2022-02-03T12:23:58Z",
        "provider": "admin",
        "type": [
            "change"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "admin": {
            "application": {
                "edition": "basic",
                "name": "drive"
            },
            "group": {
                "email": "group@example.com"
            },
            "new_value": "new",
            "old_value": "old",
            "org_unit": {
                "name": "org"
            },
            "setting": {
                "name": "setting"
            }
        },
        "event": {
            "type": "APPLICATION_SETTINGS"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        }
    },
    "group": {
        "domain": "example.com",
        "name": "group"
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "source": {
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, Inc."
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "forwarded",
        "google-workspace-admin"
    ],
    "user": {
        "domain": "bar.com",
        "id": "1",
        "name": "foo",
        "target": {
            "group": {
                "domain": "example.com",
                "name": "group"
            }
        }
    }
}
```

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
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.admin.alert.name | The alert name. | keyword |
| google_workspace.admin.api.client.name | The API client name. | keyword |
| google_workspace.admin.api.scopes | The API scopes. | keyword |
| google_workspace.admin.application.asp_id | The application specific password ID. | keyword |
| google_workspace.admin.application.edition | The Google Workspace edition. | keyword |
| google_workspace.admin.application.enabled | The enabled application. | keyword |
| google_workspace.admin.application.id | The application ID. | keyword |
| google_workspace.admin.application.licences_order_number | Order number used to redeem licenses. | keyword |
| google_workspace.admin.application.licences_purchased | Number of licences purchased. | long |
| google_workspace.admin.application.name | The application's name. | keyword |
| google_workspace.admin.application.package_id | The mobile application package ID. | keyword |
| google_workspace.admin.bulk_upload.failed | Number of failed records in bulk upload operation. | long |
| google_workspace.admin.bulk_upload.total | Number of total records in bulk upload operation. | long |
| google_workspace.admin.chrome_licenses.allowed | Licences enabled. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-org-settings | keyword |
| google_workspace.admin.chrome_licenses.enabled | Licences enabled. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-org-settings | keyword |
| google_workspace.admin.chrome_os.session_type | Chrome OS session type. | keyword |
| google_workspace.admin.device.command_details | Command details. | keyword |
| google_workspace.admin.device.id |  | keyword |
| google_workspace.admin.device.serial_number | Device serial number. | keyword |
| google_workspace.admin.device.type | Device type. | keyword |
| google_workspace.admin.distribution.entity.name | The distribution entity value, which can be a group name or an org-unit name. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-mobile-settings | keyword |
| google_workspace.admin.distribution.entity.type | The distribution entity type, which can be a group or an org-unit. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-mobile-settings | keyword |
| google_workspace.admin.domain.alias | The domain alias. | keyword |
| google_workspace.admin.domain.name | The primary domain name. | keyword |
| google_workspace.admin.domain.secondary_name | The secondary domain name. | keyword |
| google_workspace.admin.email.log_search_filter.end_date | The log search filter's ending date. | date |
| google_workspace.admin.email.log_search_filter.message_id | The log search filter's email message ID. | keyword |
| google_workspace.admin.email.log_search_filter.recipient.ip | The log search filter's email recipient's IP address. | ip |
| google_workspace.admin.email.log_search_filter.recipient.value | The log search filter's email recipient. | keyword |
| google_workspace.admin.email.log_search_filter.sender.ip | The log search filter's email sender's IP address. | ip |
| google_workspace.admin.email.log_search_filter.sender.value | The log search filter's email sender. | keyword |
| google_workspace.admin.email.log_search_filter.start_date | The log search filter's start date. | date |
| google_workspace.admin.email.quarantine_name | The name of the quarantine. | keyword |
| google_workspace.admin.email_dump.include_deleted | Indicates if deleted emails are included in the export. | boolean |
| google_workspace.admin.email_dump.package_content | The contents of the mailbox package. | keyword |
| google_workspace.admin.email_dump.query | The search query used for the dump. | keyword |
| google_workspace.admin.email_monitor.dest_email | The destination address of the email monitor. | keyword |
| google_workspace.admin.email_monitor.level.chat | The chat email monitor level. | keyword |
| google_workspace.admin.email_monitor.level.draft | The draft email monitor level. | keyword |
| google_workspace.admin.email_monitor.level.incoming | The incoming email monitor level. | keyword |
| google_workspace.admin.email_monitor.level.outgoing | The outgoing email monitor level. | keyword |
| google_workspace.admin.field | The name of the field. | keyword |
| google_workspace.admin.gateway.name | Gateway name. Present on some chat settings. | keyword |
| google_workspace.admin.group.allowed_list | Names of allow-listed groups. | keyword |
| google_workspace.admin.group.email | The group's primary email address. | keyword |
| google_workspace.admin.group.priorities | Group priorities. | keyword |
| google_workspace.admin.info_type | This will be used to state what kind of information was changed. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-domain-settings | keyword |
| google_workspace.admin.managed_configuration | The name of the managed configuration. | keyword |
| google_workspace.admin.mdm.token | The MDM vendor enrollment token. | keyword |
| google_workspace.admin.mdm.vendor | The MDM vendor's name. | keyword |
| google_workspace.admin.mobile.action.id | The mobile device action's ID. | keyword |
| google_workspace.admin.mobile.action.type | The mobile device action's type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-mobile-settings | keyword |
| google_workspace.admin.mobile.certificate.name | The mobile certificate common name. | keyword |
| google_workspace.admin.mobile.company_owned_devices | The number of devices a company owns. | long |
| google_workspace.admin.new_value | The new value for the setting. | keyword |
| google_workspace.admin.non_featured_services_selection | Non-featured services selection. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-application-settings#FLASHLIGHT_EDU_NON_FEATURED_SERVICES_SELECTED | keyword |
| google_workspace.admin.oauth2.application.id | OAuth2 application ID. | keyword |
| google_workspace.admin.oauth2.application.name | OAuth2 application name. | keyword |
| google_workspace.admin.oauth2.application.type | OAuth2 application type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings | keyword |
| google_workspace.admin.oauth2.service.name | OAuth2 service name. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings | keyword |
| google_workspace.admin.old_value | The old value for the setting. | keyword |
| google_workspace.admin.org_unit.full | The org unit full path including the root org unit name. | keyword |
| google_workspace.admin.org_unit.name | The organizational unit name. | keyword |
| google_workspace.admin.print_server.name | The name of the print server. | keyword |
| google_workspace.admin.printer.name | The name of the printer. | keyword |
| google_workspace.admin.privilege.name | Privilege name. | keyword |
| google_workspace.admin.product.name | The product name. | keyword |
| google_workspace.admin.product.sku | The product SKU. | keyword |
| google_workspace.admin.request.id | The request ID. | keyword |
| google_workspace.admin.resource.id | The name of the resource identifier. | keyword |
| google_workspace.admin.role.id | Unique identifier for this role privilege. | keyword |
| google_workspace.admin.role.name | The role name. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-delegated-admin-settings | keyword |
| google_workspace.admin.rule.name | The rule name. | keyword |
| google_workspace.admin.service.name | The service name. | keyword |
| google_workspace.admin.setting.description | The setting name. | keyword |
| google_workspace.admin.setting.name | The setting name. | keyword |
| google_workspace.admin.url.name | The website name. | keyword |
| google_workspace.admin.user.birthdate | The user's birth date. | date |
| google_workspace.admin.user.email | The user's primary email address. | keyword |
| google_workspace.admin.user.nickname | The user's nickname. | keyword |
| google_workspace.admin.user_defined_setting.name | The name of the user-defined setting. | keyword |
| google_workspace.admin.verification_method | Related verification method. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings and https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-domain-settings | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.name | Name given by operators to sections of their network. | keyword |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
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
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.email | User email address. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| url.username | Username of the request. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |


### Drive

This is the `drive` dataset.

An example event for `drive` looks as following:

```json
{
    "@timestamp": "2022-02-02T12:24:50.000Z",
    "agent": {
        "ephemeral_id": "3160d231-025f-4e24-9581-72458c960fca",
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "google_workspace.drive",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "add_to_folder",
        "agent_id_status": "verified",
        "category": [
            "file"
        ],
        "created": "2022-02-03T12:24:50.101Z",
        "dataset": "google_workspace.drive",
        "id": "1",
        "ingested": "2022-02-03T12:24:51Z",
        "provider": "drive",
        "type": [
            "change"
        ]
    },
    "file": {
        "name": "document title",
        "owner": "owner",
        "type": "file"
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "drive": {
            "billable": false,
            "destination_folder_id": "1234",
            "destination_folder_title": "folder title",
            "file": {
                "id": "1234",
                "owner": {
                    "email": "owner@example.com",
                    "is_shared_drive": false
                },
                "type": "document"
            },
            "originating_app_id": "1234",
            "primary_event": true,
            "visibility": "people_with_link"
        },
        "event": {
            "type": "access"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "owner",
            "foo"
        ]
    },
    "source": {
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, Inc."
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "forwarded",
        "google-workspace-drive"
    ],
    "user": {
        "domain": "bar.com",
        "id": "1",
        "name": "foo"
    }
}
```

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
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.owner | File owner's username. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.type | File type (file, dir, or symlink). | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.drive.added_role | Added membership role of a user/group in a Team Drive. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.billable | Whether this activity is billable. | boolean |
| google_workspace.drive.destination_folder_id |  | keyword |
| google_workspace.drive.destination_folder_title |  | keyword |
| google_workspace.drive.file.id |  | keyword |
| google_workspace.drive.file.owner.email |  | keyword |
| google_workspace.drive.file.owner.is_shared_drive | Boolean flag denoting whether owner is a shared drive. | boolean |
| google_workspace.drive.file.type | Document Drive type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.membership_change_type | Type of change in Team Drive membership of a user/group. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.new_value | When a setting or property of the file changes, the new value for it will appear here. | keyword |
| google_workspace.drive.old_value | When a setting or property of the file changes, the old value for it will appear here. | keyword |
| google_workspace.drive.old_visibility | When visibility changes, this holds the old value. | keyword |
| google_workspace.drive.originating_app_id | The Google Cloud Project ID of the application that performed the action. | keyword |
| google_workspace.drive.primary_event | Whether this is a primary event. A single user action in Drive may generate several events. | boolean |
| google_workspace.drive.removed_role | Removed membership role of a user/group in a Team Drive. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.shared_drive_id | The unique identifier of the Team Drive. Only populated for for events relating to a Team Drive or item contained inside a Team Drive. | keyword |
| google_workspace.drive.shared_drive_settings_change_type | Type of change in Team Drive settings. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.sheets_import_range_recipient_doc | Doc ID of the recipient of a sheets import range. | keyword |
| google_workspace.drive.source_folder_id |  | keyword |
| google_workspace.drive.source_folder_title |  | keyword |
| google_workspace.drive.target | Target user or group. | keyword |
| google_workspace.drive.target_domain | The domain for which the acccess scope was changed. This can also be the alias all to indicate the access scope was changed for all domains that have visibility for this document. | keyword |
| google_workspace.drive.visibility | Visibility of target file. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.visibility_change | When visibility changes, this holds the new overall visibility of the file. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
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
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.email | User email address. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |


### Groups

This is the `groups` dataset.

An example event for `groups` looks as following:

```json
{
    "@timestamp": "2022-02-02T12:25:39.000Z",
    "agent": {
        "ephemeral_id": "a9599f5d-49a5-4339-9e5e-484f19370712",
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "google_workspace.groups",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "584f3aea-648c-4e58-aba4-32b8f88d4396",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "change_acl_permission",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2022-02-03T12:25:39.375Z",
        "dataset": "google_workspace.groups",
        "id": "1",
        "ingested": "2022-02-03T12:25:40Z",
        "provider": "groups",
        "type": [
            "group",
            "change"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "event": {
            "type": "acl_change"
        },
        "groups": {
            "acl_permission": "can_add_members",
            "email": "group@example.com",
            "new_value": [
                "managers",
                "members"
            ],
            "old_value": [
                "managers"
            ]
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        }
    },
    "group": {
        "domain": "example.com",
        "name": "group"
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "source": {
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, Inc."
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "forwarded",
        "google-workspace-groups"
    ],
    "user": {
        "domain": "bar.com",
        "id": "1",
        "name": "foo",
        "target": {
            "group": {
                "domain": "example.com",
                "name": "group"
            }
        }
    }
}
```

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
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.groups.acl_permission | Group permission setting updated. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups | keyword |
| google_workspace.groups.email | Group email. | keyword |
| google_workspace.groups.member.email | Member email. | keyword |
| google_workspace.groups.member.role | Member role. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups | keyword |
| google_workspace.groups.message.id | SMTP message Id of an email message. Present for moderation events. | keyword |
| google_workspace.groups.message.moderation_action | Message moderation action. Possible values are `approved` and `rejected`. | keyword |
| google_workspace.groups.new_value | New value(s) of the group setting. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups | keyword |
| google_workspace.groups.old_value | Old value(s) of the group setting. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups | keyword |
| google_workspace.groups.setting | Group setting updated. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups | keyword |
| google_workspace.groups.status | A status describing the output of an operation. Possible values are `failed` and `succeeded`. | keyword |
| google_workspace.groups.value | Value of the group setting. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
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
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.email | User email address. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |

