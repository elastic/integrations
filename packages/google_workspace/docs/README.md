# Google Workspace Integration

The Google Workspace integration collects and parses data from the different [Google Workspace audit reports APIs](https://developers.google.com/admin-sdk/reports).

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

This integration will make use of the following *oauth2 scope*:

- `https://www.googleapis.com/auth/admin.reports.audit.readonly`

Once you have downloaded your service account credentials as a JSON file, you are ready to set up your integration.

Click the Advanced option of Google Workspace Audit Reports. The default value of "API Host" is `https://www.googleapis.com`. The API Host will be used for collecting `admin`, `drive`, `groups`, `login`, `saml`, and `user accounts` logs.

# Google Workspace Alert

The [Google Workspace](https://developers.google.com/admin-sdk/alertcenter) Integration collects and parses data received from the Google Workspace Alert Center API using HTTP JSON Input.

## Compatibility

- Alert Data Stream has been tested against `Google Workspace Alert Center API (v1)`.

- Following Alert types have been supported in the current integration version:
    1. Customer takeout initiated
    2. Malware reclassification
    3. Misconfigured whitelist
    4. Phishing reclassification
    5. Suspicious message reported
    6. User reported phishing
    7. User reported spam spike
    8. Leaked password
    9. Suspicious login
    10. Suspicious login (less secure app)
    11. Suspicious programmatic login
    12. User suspended
    13. User suspended (spam)
    14. User suspended (spam through relay)
    15. User suspended (suspicious activity)
    16. Google Operations
    17. Configuration problem
    18. Government attack warning
    19. Device compromised
    20. Suspicious activity
    21. AppMaker Default Cloud SQL setup
    22. Activity Rule
    23. Data Loss Prevention
    24. Apps outage
    25. Primary admin changed
    26. SSO profile added
    27. SSO profile updated
    28. SSO profile deleted
    29. Super admin password reset
    30. Account suspension warning
    31. Calendar settings changed
    32. Chrome devices auto-update expiration warning
    33. Customer takeout initiated
    34. Drive settings changed
    35. Email settings changed
    36. Gmail potential employee spoofing
    37. Mobile settings changed
    38. New user added
    39. Reporting Rule
    40. Suspended user made active
    41. User deleted
    42. User granted Admin privilege
    43. User suspended (spam)
    44. User's Admin privileges revoked
    45. Users password changed
    46. Google Voice configuration problem detected


## Requirements

In order to ingest data from the Google Alert Center API, you must:

- Have an *administrator account*.
- [Set up a ServiceAccount](https://support.google.com/workspacemigrate/answer/9222993?hl=en) using the Administrator Account.
- [Set up access to the Admin SDK API](https://support.google.com/workspacemigrate/answer/9222865?hl=en) for the ServiceAccount.
- [Enable Domain-Wide Delegation](https://developers.google.com/admin-sdk/reports/v1/guides/delegation) for the ServiceAccount.

This integration will make use of the following *oauth2 scope*:

- `https://www.googleapis.com/auth/apps.alerts`

Once Service Account credentials are downloaded as a JSON file, then the integration can be setup to collect data.


>  Note: The default value of the "Page Size" is set to 1000. This option is available under 'Alert' Advance options. Set the parameter "Page Size" according to the requirement. For Alert Data Stream, The default value of "Alert Center API Host" is `https://alertcenter.googleapis.com`. The Alert Center API Host will be used for collecting alert logs only.

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
        "version": "8.5.0"
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
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
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
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
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |


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
        "version": "8.5.0"
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
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
| google_workspace.user_accounts.email_forwarding_destination_address | Out of domain email the actor has forwarded to. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
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
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
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
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |


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
        "version": "8.5.0"
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
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
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
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
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |


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
        "version": "8.5.0"
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
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
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
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
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
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
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |


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
        "version": "8.5.0"
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
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
| file.path.text | Multi-field of `file.path`. | match_only_text |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
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
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
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
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |


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
        "version": "8.5.0"
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
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
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
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
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |


### Alert

This is the `alert` dataset.

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2022-07-01T10:49:29.436Z",
    "agent": {
        "ephemeral_id": "b9cea70b-4beb-4d6f-8df8-f4bc6bfefc8a",
        "id": "c365aab8-f383-4f35-971f-0e22b72992a0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.0"
    },
    "data_stream": {
        "dataset": "google_workspace.alert",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "c365aab8-f383-4f35-971f-0e22b72992a0",
        "snapshot": false,
        "version": "8.4.0"
    },
    "email": {
        "attachments": {
            "file": {
                "hash": {
                    "sha256": [
                        "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
                        "228b48a56dbc2ecf10393227ac9c9dc943881fd7a55452e12a09107476bef2b2",
                        "5fb1679e08674059b72e271d8902c11a127bb5301b055dc77fa03932ada56a56"
                    ]
                }
            }
        },
        "delivery_timestamp": [
            "2022-07-01T10:38:13.194Z"
        ],
        "message_id": [
            "decedih843@example.com",
            "decedih@example.com"
        ],
        "subject": [
            "Sales",
            "RE: Example salesorderspca JSON request"
        ],
        "to": {
            "address": [
                "example@example.com"
            ]
        }
    },
    "event": {
        "action": "Gmail phishing",
        "agent_id_status": "verified",
        "category": [
            "email",
            "threat",
            "malware"
        ],
        "created": "2022-11-07T09:26:33.088Z",
        "dataset": "google_workspace.alert",
        "end": "2022-07-01T10:47:04.530Z",
        "id": "91840a82-3af0-46d7-95ec-625c1cf0c3f7",
        "ingested": "2022-11-07T09:26:36Z",
        "kind": "alert",
        "original": "{\"alertId\":\"91840a82-3af0-46d7-95ec-625c1cf0c3f7\",\"createTime\":\"2022-07-01T10:49:29.436394Z\",\"customerId\":\"02umwv6u\",\"data\":{\"@type\":\"type.googleapis.com/google.apps.alertcenter.type.MailPhishing\",\"domainId\":{\"customerPrimaryDomain\":\"example.com\"},\"isInternal\":true,\"maliciousEntity\":{\"displayName\":\"string\",\"entity\":{\"displayName\":\"example\",\"emailAddress\":\"example@example.com\"},\"fromHeader\":\"header@example.com\"},\"messages\":[{\"attachmentsSha256Hash\":[\"50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c\",\"228b48a56dbc2ecf10393227ac9c9dc943881fd7a55452e12a09107476bef2b2\"],\"date\":\"2022-07-01T10:38:13.194711Z\",\"md5HashMessageBody\":\"d29343907090dff4cec4a9a0efb80d20\",\"md5HashSubject\":\"a3708f8228384d932237f85980ff8283\",\"messageBodySnippet\":\" hi greetings from sales \",\"messageId\":\"decedih843@example.com\",\"recipient\":\"example@example.com\",\"subjectText\":\"Sales\"},{\"attachmentsSha256Hash\":[\"5fb1679e08674059b72e271d8902c11a127bb5301b055dc77fa03932ada56a56\"],\"md5HashMessageBody\":\"d29343907090dff4cec4a9a0efb80d20\",\"md5HashSubject\":\"a3708f8228384d932237f85980ff8283\",\"messageBodySnippet\":\" hi greetings \",\"messageId\":\"decedih@example.com\",\"recipient\":\"example@example.com\",\"subjectText\":\"RE: Example salesorderspca JSON request\"}],\"systemActionType\":\"NO_OPERATION\"},\"deleted\":false,\"endTime\":\"2022-07-01T10:47:04.530834Z\",\"etag\":\"wF2Ix2DWDv8=\",\"metadata\":{\"alertId\":\"91840a82-3af0-46d7-95ec-625c1cf0c3f7\",\"assignee\":\"example@example.com\",\"customerId\":\"02umwv6u\",\"etag\":\"wF2Ix2DWDv8=\",\"severity\":\"HIGH\",\"status\":\"NOT_STARTED\",\"updateTime\":\"2022-07-01T10:49:29.436394Z\"},\"securityInvestigationToolLink\":\"string\",\"source\":\"Gmail phishing\",\"startTime\":\"2022-07-01T10:38:13.194711Z\",\"type\":\"User reported phishing\",\"updateTime\":\"2022-07-01T10:49:29.436394Z\"}",
        "start": "2022-07-01T10:38:13.194Z",
        "type": [
            "info"
        ]
    },
    "google_workspace": {
        "alert": {
            "create_time": "2022-07-01T10:49:29.436Z",
            "customer": {
                "id": "02umwv6u"
            },
            "data": {
                "domain_id": {
                    "customer_primary_domain": "example.com"
                },
                "is_internal": true,
                "malicious_entity": {
                    "display_name": "string",
                    "entity": {
                        "display_name": "example",
                        "email_address": "example@example.com"
                    },
                    "from_header": "header@example.com"
                },
                "messages": [
                    {
                        "attachments_sha256_hash": [
                            "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
                            "228b48a56dbc2ecf10393227ac9c9dc943881fd7a55452e12a09107476bef2b2"
                        ],
                        "date": "2022-07-01T10:38:13.194Z",
                        "id": "decedih843@example.com",
                        "md5": {
                            "hash": {
                                "message_body": "d29343907090dff4cec4a9a0efb80d20",
                                "subject": "a3708f8228384d932237f85980ff8283"
                            }
                        },
                        "message_body_snippet": " hi greetings from sales ",
                        "recipient_email": "example@example.com",
                        "subject_text": "Sales"
                    },
                    {
                        "attachments_sha256_hash": [
                            "5fb1679e08674059b72e271d8902c11a127bb5301b055dc77fa03932ada56a56"
                        ],
                        "id": "decedih@example.com",
                        "md5": {
                            "hash": {
                                "message_body": "d29343907090dff4cec4a9a0efb80d20",
                                "subject": "a3708f8228384d932237f85980ff8283"
                            }
                        },
                        "message_body_snippet": " hi greetings ",
                        "recipient_email": "example@example.com",
                        "subject_text": "RE: Example salesorderspca JSON request"
                    }
                ],
                "system_action_type": "NO_OPERATION",
                "type": "type.googleapis.com/google.apps.alertcenter.type.MailPhishing"
            },
            "deleted": false,
            "end_time": "2022-07-01T10:47:04.530Z",
            "etag": "wF2Ix2DWDv8=",
            "id": "91840a82-3af0-46d7-95ec-625c1cf0c3f7",
            "metadata": {
                "alert": {
                    "id": "91840a82-3af0-46d7-95ec-625c1cf0c3f7"
                },
                "assignee": "example@example.com",
                "customer": {
                    "id": "02umwv6u"
                },
                "etag": "wF2Ix2DWDv8=",
                "severity": "HIGH",
                "status": "NOT_STARTED",
                "update_time": "2022-07-01T10:49:29.436Z"
            },
            "security_investigation_tool_link": "string",
            "source": "Gmail phishing",
            "start_time": "2022-07-01T10:38:13.194Z",
            "type": "User reported phishing",
            "update_time": "2022-07-01T10:49:29.436Z"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "02umwv6u"
    },
    "related": {
        "hash": [
            "a3708f8228384d932237f85980ff8283",
            "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
            "228b48a56dbc2ecf10393227ac9c9dc943881fd7a55452e12a09107476bef2b2",
            "5fb1679e08674059b72e271d8902c11a127bb5301b055dc77fa03932ada56a56"
        ],
        "user": [
            "example"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_workspace-alert"
    ],
    "user": {
        "domain": "example.com",
        "email": [
            "example@example.com"
        ],
        "name": "example"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.attachments.file.hash.sha256 | SHA256 hash. | keyword |
| email.delivery_timestamp | The date and time when the email message was received by the service or client. | date |
| email.message_id | Identifier from the RFC 5322 `Message-ID:` email header that refers to a particular email message. | wildcard |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| google_workspace.alert.create_time | The time this alert was created. | date |
| google_workspace.alert.customer.id | The unique identifier of the Google account of the customer. | keyword |
| google_workspace.alert.data.action.name | List of action names associated with the rule threshold. | keyword |
| google_workspace.alert.data.actor.email | Email of person who performed the action. | keyword |
| google_workspace.alert.data.affected.user_emails | The list of emails which correspond to the users directly affected by the incident. | keyword |
| google_workspace.alert.data.alert_details | alert details of google workspace alert. | keyword |
| google_workspace.alert.data.appeal_window | appeal window of alert. | keyword |
| google_workspace.alert.data.attachment.data.csv.data_rows.entries | The data entries in a CSV file row, as a string array rather than a single comma-separated string. | keyword |
| google_workspace.alert.data.attachment.data.csv.headers | The list of headers for data columns in a CSV file. | keyword |
| google_workspace.alert.data.create_time | Rule create timestamp. | date |
| google_workspace.alert.data.dashboard.uri | Link to the outage event in Google Workspace Status Dashboard. | keyword |
| google_workspace.alert.data.description | A detailed, freeform incident description. | text |
| google_workspace.alert.data.display.name | Alert display name. | keyword |
| google_workspace.alert.data.domain | Customer domain for email template personalization. | keyword |
| google_workspace.alert.data.domain_id.customer_primary_domain | The primary domain for the customer. | keyword |
| google_workspace.alert.data.email | The email of the user that this event belongs to. | keyword |
| google_workspace.alert.data.event_time | The time at which event occurred. | date |
| google_workspace.alert.data.events.device.id | The device ID. | keyword |
| google_workspace.alert.data.events.device.model | The model of the device. | keyword |
| google_workspace.alert.data.events.device.property | The device property which was changed. | keyword |
| google_workspace.alert.data.events.device.type | The type of the device. | keyword |
| google_workspace.alert.data.events.device_compromised_state | The device compromised state. Possible values are "Compromised" or "Not Compromised". | keyword |
| google_workspace.alert.data.events.ios_vendor.id | Required for iOS, empty for others. | keyword |
| google_workspace.alert.data.events.new_value | The new value of the device property after the change. | keyword |
| google_workspace.alert.data.events.old_value | The old value of the device property before the change. | keyword |
| google_workspace.alert.data.events.resource.id | The device resource ID. | keyword |
| google_workspace.alert.data.events.serial.number | The serial number of the device. | keyword |
| google_workspace.alert.data.header | A header to display above the incident message. Typically used to attach a localized notice on the timeline for followup comms translations. | keyword |
| google_workspace.alert.data.incident_tracking.id | Incident tracking ID. | keyword |
| google_workspace.alert.data.is_internal | If true, the email originated from within the organization. | boolean |
| google_workspace.alert.data.login_details.ip_address | The human-readable IP address that is associated with the warning event. | ip |
| google_workspace.alert.data.login_details.login_time | The successful login time that is associated with the warning event. This isn't present for blocked login attempts. | date |
| google_workspace.alert.data.malicious_entity.display_name | The header from display name. | keyword |
| google_workspace.alert.data.malicious_entity.entity.display_name | Display name of the user. | keyword |
| google_workspace.alert.data.malicious_entity.entity.email_address | Email address of the user. | keyword |
| google_workspace.alert.data.malicious_entity.from_header | The sender email address. | keyword |
| google_workspace.alert.data.merge_info.new_alert.id | New alert ID. Reference the `google.apps.alertcenter.Alert` with this ID for the current state. | keyword |
| google_workspace.alert.data.merge_info.new_incident_tracking.id | The new tracking ID from the parent incident. | keyword |
| google_workspace.alert.data.messages.attachments_sha256_hash | The SHA256 hash of email's attachment and all MIME parts. | keyword |
| google_workspace.alert.data.messages.date | The date of the event related to this email. | date |
| google_workspace.alert.data.messages.id | The message ID. | keyword |
| google_workspace.alert.data.messages.md5.hash.message_body | The hash of the message body text. | keyword |
| google_workspace.alert.data.messages.md5.hash.subject | The MD5 Hash of email's subject (only available for reported emails). | keyword |
| google_workspace.alert.data.messages.message_body_snippet | The snippet of the message body text (only available for reported emails). | keyword |
| google_workspace.alert.data.messages.recipient | The recipient of this email. | keyword |
| google_workspace.alert.data.messages.subject_text | The email subject text (only available for reported emails). | keyword |
| google_workspace.alert.data.name | Rule name. | keyword |
| google_workspace.alert.data.next_update_time | Timestamp by which the next update is expected to arrive. | date |
| google_workspace.alert.data.primary.admin.changed_event.domain | domain in which actioned occurred. | keyword |
| google_workspace.alert.data.primary.admin.changed_event.previous_admin_email | Email of person who was the primary admin before the action. | keyword |
| google_workspace.alert.data.primary.admin.changed_event.updated_admin_email | Email of person who is the primary admin after the action. | keyword |
| google_workspace.alert.data.products | List of products impacted by the outage. | keyword |
| google_workspace.alert.data.query | Query that is used to get the data from the associated source. | keyword |
| google_workspace.alert.data.request.info.app.developer_email | List of app developers who triggered notifications for above application. | keyword |
| google_workspace.alert.data.request.info.app.key | The application that requires the SQL setup. | keyword |
| google_workspace.alert.data.request.info.number_of_requests | Number of requests sent for this application to set up default SQL instance. | keyword |
| google_workspace.alert.data.resolution_time | Timestamp when the outage is expected to be resolved, or has confirmed resolution. Provided only when known. | date |
| google_workspace.alert.data.rule.violation_info.data.source | Source of the data. | keyword |
| google_workspace.alert.data.rule.violation_info.match_info.predefined_detector.name | Name that uniquely identifies the detector. | keyword |
| google_workspace.alert.data.rule.violation_info.match_info.user_defined_detector.display.name | Display name of the detector. | keyword |
| google_workspace.alert.data.rule.violation_info.match_info.user_defined_detector.resource.name | Resource name that uniquely identifies the detector. | keyword |
| google_workspace.alert.data.rule.violation_info.recipients | For Drive, they are grantees that the Drive file was shared with at the time of rule triggering. Valid values include user emails, group emails, domains, or 'anyone' if the file was publicly accessible. If the file was private the recipients list will be empty. For Gmail, they are emails of the users or groups that the Gmail message was sent to. | keyword |
| google_workspace.alert.data.rule.violation_info.resource_info.document.id | Drive file ID. | keyword |
| google_workspace.alert.data.rule.violation_info.resource_info.resource.title | Title of the resource, for example email subject, or document title. | keyword |
| google_workspace.alert.data.rule.violation_info.rule_info.display.name | User provided name of the rule. | keyword |
| google_workspace.alert.data.rule.violation_info.rule_info.resource.name | Resource name that uniquely identifies the rule. | keyword |
| google_workspace.alert.data.rule.violation_info.suppressed.action.types | Actions suppressed due to other actions with higher priority. | keyword |
| google_workspace.alert.data.rule.violation_info.trigger.user.email | Email of the user who caused the violation. Value could be empty if not applicable, for example, a violation found by drive continuous scan. | keyword |
| google_workspace.alert.data.rule.violation_info.trigger.value | Trigger of the rule. | keyword |
| google_workspace.alert.data.rule.violation_info.triggered.action.info | Metadata related to the triggered actions. | nested |
| google_workspace.alert.data.rule.violation_info.triggered.action.types | Actions applied as a consequence of the rule being triggered. | keyword |
| google_workspace.alert.data.rule_description | Description of the rule. | text |
| google_workspace.alert.data.source.ip | The source IP address of the malicious email. | ip |
| google_workspace.alert.data.sso_profile.created_event.inbound_sso.profile_name | sso profile name which got created. | keyword |
| google_workspace.alert.data.sso_profile.deleted_event.inbound_sso.profile_name | sso profile name which got deleted. | keyword |
| google_workspace.alert.data.sso_profile.updated_event.inbound_sso.profile_changes | changes made to sso profile. | keyword |
| google_workspace.alert.data.sso_profile.updated_event.inbound_sso.profile_name | sso profile name which got updated. | keyword |
| google_workspace.alert.data.state | state of alert. | keyword |
| google_workspace.alert.data.status | Current outage status. | keyword |
| google_workspace.alert.data.super_admin_password_reset_event.user.email | email of person whose password was reset. | keyword |
| google_workspace.alert.data.superseded_alerts | List of alert IDs superseded by this alert. It is used to indicate that this alert is essentially extension of superseded alerts and we found the relationship after creating these alerts. | keyword |
| google_workspace.alert.data.superseding_alert | Alert ID superseding this alert. It is used to indicate that superseding alert is essentially extension of this alert and we found the relationship after creating both alerts. | keyword |
| google_workspace.alert.data.suspension_details.abuse_reason | abuse reason for suspension details. | keyword |
| google_workspace.alert.data.suspension_details.product_name | product name for suspension details. | keyword |
| google_workspace.alert.data.system_action_type | System actions on the messages. | keyword |
| google_workspace.alert.data.takeout.request.id | The takeout request ID. | keyword |
| google_workspace.alert.data.threshold | Alert threshold is for example “COUNT \> 5”. | keyword |
| google_workspace.alert.data.title | A one-line incident description. | keyword |
| google_workspace.alert.data.trigger.source | The trigger sources for this rule. | keyword |
| google_workspace.alert.data.type | The type of the alert with alert data. | keyword |
| google_workspace.alert.data.update_time | The timestamp of the last update to the rule. | date |
| google_workspace.alert.data.window_size | Rule window size. Possible values are 1 hour or 24 hours. | keyword |
| google_workspace.alert.deleted | True if this alert is marked for deletion. | boolean |
| google_workspace.alert.end_time | The time the event that caused this alert ceased being active. If provided, the end time must not be earlier than the start time. If not provided, it indicates an ongoing alert. | date |
| google_workspace.alert.etag | etag is used for optimistic concurrency control as a way to help prevent simultaneous updates of an alert from overwriting each other. | keyword |
| google_workspace.alert.id | The unique identifier for the alert. | keyword |
| google_workspace.alert.metadata.alert.id | The alert identifier. | keyword |
| google_workspace.alert.metadata.assignee | The email address of the user assigned to the alert. | keyword |
| google_workspace.alert.metadata.customer.id | The unique identifier of the Google account of the customer. | keyword |
| google_workspace.alert.metadata.etag | etag is used for optimistic concurrency control as a way to help prevent simultaneous updates of an alert metadata from overwriting each other. | keyword |
| google_workspace.alert.metadata.severity | The severity value of the alert. Alert Center will set this field at alert creation time, default's to an empty string when it could not be determined. | keyword |
| google_workspace.alert.metadata.status | The current status of the alert. | keyword |
| google_workspace.alert.metadata.update_time | The time this metadata was last updated. | date |
| google_workspace.alert.security_investigation_tool_link | An optional Security Investigation Tool query for this alert. | keyword |
| google_workspace.alert.source | A unique identifier for the system that reported the alert. This is output only after alert is created. | keyword |
| google_workspace.alert.start_time | The time the event that caused this alert was started or detected. | date |
| google_workspace.alert.type | The type of the alert. This is output only after alert is created. | keyword |
| google_workspace.alert.update_time | The time this alert was last updated. | date |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host ID. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host IP addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.description | The description of the rule generating the event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.user.email | User email address. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

