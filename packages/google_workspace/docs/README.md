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

```$json
{
    "agent": {
        "hostname": "4cc571ab4c1e",
        "name": "4cc571ab4c1e",
        "id": "a0b95f8f-4ef9-4197-abc8-5daa58bb46dd",
        "ephemeral_id": "f418e019-108a-4137-bb16-6a37813d75c0",
        "type": "filebeat",
        "version": "7.11.0"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/saml-test.json.log"
        },
        "offset": 606
    },
    "elastic_agent": {
        "id": "e83750e0-3ec9-11eb-89ab-197fa6952ca2",
        "version": "7.11.0",
        "snapshot": true
    },
    "source": {
        "geo": {
            "continent_name": "North America",
            "region_iso_code": "US-PA",
            "city_name": "State College",
            "country_iso_code": "US",
            "country_name": "United States",
            "region_name": "Pennsylvania",
            "location": {
                "lon": -77.8618,
                "lat": 40.7957
            }
        },
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, LLC"
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "name": "foo",
            "id": "1",
            "email": "foo@bar.com"
        }
    },
    "tags": [
        "forwarded"
    ],
    "input": {
        "type": "log"
    },
    "@timestamp": "2020-10-02T15:00:01.000Z",
    "ecs": {
        "version": "1.7.0"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        },
        "saml": {
            "initiated_by": "idp",
            "application_name": "app",
            "status_code": 400,
            "orgunit_path": "ounit"
        },
        "event": {
            "type": "login"
        }
    },
    "data_stream": {
        "namespace": "ep",
        "type": "logs",
        "dataset": "google_workspace.saml"
    },
    "organization": {
        "id": "1"
    },
    "host": {
        "name": "4cc571ab4c1e"
    },
    "event": {
        "ingested": "2020-12-15T11:46:26.743219844Z",
        "original": "{\"kind\":\"admin#reports#activity\",\"id\":{\"time\":\"2020-10-02T15:00:01Z\",\"uniqueQualifier\":1,\"applicationName\":\"saml\",\"customerId\":\"1\"},\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"ownerDomain\":\"elastic.com\",\"ipAddress\":\"98.235.162.24\",\"events\":{\"type\":\"login\",\"name\":\"login_success\",\"parameters\":[{\"name\":\"application_name\",\"value\":\"app\"},{\"name\":\"initiated_by\",\"value\":\"idp\"},{\"name\":\"orgunit_path\",\"value\":\"ounit\"},{\"name\":\"saml_status_code\",\"value\":\"400\"}]}}",
        "provider": "saml",
        "action": "login_success",
        "id": "1",
        "type": [
            "start"
        ],
        "category": [
            "authentication"
        ],
        "dataset": "google_workspace.saml",
        "outcome": "success"
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
| ecs.version | ECS version | keyword |
| event.action | The action captured by the event. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. | keyword |
| event.dataset | Name of the dataset. | keyword |
| event.duration | Duration of the event in nanoseconds. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.original | Raw text message of entire event. Used to demonstrate log integrity. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| event.provider | Source of the event. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   *USER*: Another user in the same domain.   *EXTERNAL_USER*: A user outside the domain.   *KEY*: A non-human actor. | keyword |
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
| log.file.path | Log path | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
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
| user.domain | Name of the directory the user is a member of. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |


### User Accounts

This is the `user_accounts` dataset.

An example event for `user_accounts` looks as following:

```$json
{
    "agent": {
        "hostname": "4cc571ab4c1e",
        "name": "4cc571ab4c1e",
        "id": "a0b95f8f-4ef9-4197-abc8-5daa58bb46dd",
        "type": "filebeat",
        "ephemeral_id": "f418e019-108a-4137-bb16-6a37813d75c0",
        "version": "7.11.0"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/user_accounts-test.json.log"
        },
        "offset": 0
    },
    "elastic_agent": {
        "id": "e83750e0-3ec9-11eb-89ab-197fa6952ca2",
        "version": "7.11.0",
        "snapshot": true
    },
    "source": {
        "geo": {
            "continent_name": "North America",
            "region_iso_code": "US-PA",
            "city_name": "State College",
            "country_iso_code": "US",
            "country_name": "United States",
            "region_name": "Pennsylvania",
            "location": {
                "lon": -77.8618,
                "lat": 40.7957
            }
        },
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, LLC"
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "name": "foo",
            "id": "1",
            "email": "foo@bar.com"
        }
    },
    "tags": [
        "forwarded"
    ],
    "input": {
        "type": "log"
    },
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "ecs": {
        "version": "1.7.0"
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        },
        "event": {
            "type": "2sv_change"
        }
    },
    "data_stream": {
        "namespace": "ep",
        "type": "logs",
        "dataset": "google_workspace.user_accounts"
    },
    "organization": {
        "id": "1"
    },
    "host": {
        "name": "4cc571ab4c1e"
    },
    "event": {
        "ingested": "2020-12-15T11:52:18.378529535Z",
        "original": "{\"kind\":\"admin#reports#activity\",\"id\":{\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1,\"applicationName\":\"user_accounts\",\"customerId\":\"1\"},\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"ownerDomain\":\"elastic.com\",\"ipAddress\":\"98.235.162.24\",\"events\":{\"type\":\"2sv_change\",\"name\":\"2sv_disable\"}}",
        "provider": "user_accounts",
        "action": "2sv_disable",
        "id": "1",
        "type": [
            "change",
            "user"
        ],
        "category": [
            "iam"
        ],
        "dataset": "google_workspace.user_accounts"
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
| ecs.version | ECS version | keyword |
| event.action | The action captured by the event. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. | keyword |
| event.dataset | Name of the dataset. | keyword |
| event.duration | Duration of the event in nanoseconds. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.original | Raw text message of entire event. Used to demonstrate log integrity. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| event.provider | Source of the event. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   *USER*: Another user in the same domain.   *EXTERNAL_USER*: A user outside the domain.   *KEY*: A non-human actor. | keyword |
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
| log.file.path | Log path | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
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
| user.domain | Name of the directory the user is a member of. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |


### Login Accounts

This is the `login` dataset.

An example event for `login` looks as following:

```$json
{
    "agent": {
        "hostname": "4cc571ab4c1e",
        "name": "4cc571ab4c1e",
        "id": "a0b95f8f-4ef9-4197-abc8-5daa58bb46dd",
        "ephemeral_id": "f418e019-108a-4137-bb16-6a37813d75c0",
        "type": "filebeat",
        "version": "7.11.0"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/login-test.json.log"
        },
        "offset": 0
    },
    "elastic_agent": {
        "id": "e83750e0-3ec9-11eb-89ab-197fa6952ca2",
        "version": "7.11.0",
        "snapshot": true
    },
    "source": {
        "geo": {
            "continent_name": "North America",
            "region_iso_code": "US-PA",
            "city_name": "State College",
            "country_iso_code": "US",
            "country_name": "United States",
            "region_name": "Pennsylvania",
            "location": {
                "lon": -77.8618,
                "lat": 40.7957
            }
        },
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, LLC"
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "name": "foo",
            "id": "1",
            "email": "foo@bar.com"
        }
    },
    "tags": [
        "forwarded"
    ],
    "input": {
        "type": "log"
    },
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "ecs": {
        "version": "1.7.0"
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        },
        "event": {
            "type": "account_warning"
        },
        "login": {
            "affected_email_address": "foo@elastic.co"
        }
    },
    "data_stream": {
        "namespace": "ep",
        "type": "logs",
        "dataset": "google_workspace.login"
    },
    "organization": {
        "id": "1"
    },
    "host": {
        "name": "4cc571ab4c1e"
    },
    "event": {
        "ingested": "2020-12-15T11:45:21.481006689Z",
        "original": "{\"kind\":\"admin#reports#activity\",\"id\":{\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1,\"applicationName\":\"login\",\"customerId\":\"1\"},\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"ownerDomain\":\"elastic.com\",\"ipAddress\":\"98.235.162.24\",\"events\":{\"type\":\"account_warning\",\"name\":\"account_disabled_password_leak\",\"parameters\":[{\"name\":\"affected_email_address\",\"value\":\"foo@elastic.co\"}]}}",
        "provider": "login",
        "action": "account_disabled_password_leak",
        "id": "1",
        "category": [
            "authentication"
        ],
        "type": [
            "user",
            "change"
        ],
        "dataset": "google_workspace.login"
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
| ecs.version | ECS version | keyword |
| event.action | The action captured by the event. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. | keyword |
| event.dataset | Name of the dataset. | keyword |
| event.duration | Duration of the event in nanoseconds. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.original | Raw text message of entire event. Used to demonstrate log integrity. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| event.provider | Source of the event. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   *USER*: Another user in the same domain.   *EXTERNAL_USER*: A user outside the domain.   *KEY*: A non-human actor. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.login.affected_email_address |  | keyword |
| google_workspace.login.challenge_method | Login challenge method. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login. | keyword |
| google_workspace.login.failure_type | Login failure type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login. | keyword |
| google_workspace.login.is_second_factor |  | boolean |
| google_workspace.login.is_suspicious |  | boolean |
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
| log.file.path | Log path | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
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
| user.domain | Name of the directory the user is a member of. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |


### Admin

This is the `admin` dataset.

An example event for `admin` looks as following:

```$json
{
    "agent": {
        "hostname": "3baca80779ab",
        "name": "3baca80779ab",
        "id": "3c8561b2-b476-40cf-9969-90b7613bd543",
        "ephemeral_id": "b57fb8ad-1203-4d99-a9ca-0c785d7023ad",
        "type": "filebeat",
        "version": "7.11.0"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/admin-application-test.json.log"
        },
        "offset": 0
    },
    "elastic_agent": {
        "id": "d56892f0-3ec2-11eb-928b-59bba217f141",
        "version": "7.11.0",
        "snapshot": true
    },
    "source": {
        "geo": {
            "continent_name": "North America",
            "region_iso_code": "US-PA",
            "city_name": "State College",
            "country_iso_code": "US",
            "country_name": "United States",
            "region_name": "Pennsylvania",
            "location": {
                "lon": -77.8618,
                "lat": 40.7957
            }
        },
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, LLC"
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "name": "foo",
            "id": "1",
            "email": "foo@bar.com"
        }
    },
    "tags": [
        "forwarded"
    ],
    "input": {
        "type": "log"
    },
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "ecs": {
        "version": "1.7.0"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        },
        "admin": {
            "org_unit": {
                "name": "org"
            },
            "application": {
                "name": "drive",
                "edition": "basic"
            },
            "old_value": "old",
            "new_value": "new",
            "setting": {
                "name": "setting"
            },
            "group": {
                "email": "group@example.com"
            }
        },
        "event": {
            "type": "APPLICATION_SETTINGS"
        }
    },
    "data_stream": {
        "namespace": "ep",
        "type": "logs",
        "dataset": "google_workspace.admin"
    },
    "organization": {
        "id": "1"
    },
    "host": {
        "name": "3baca80779ab"
    },
    "event": {
        "ingested": "2020-12-15T10:56:36.913768658Z",
        "original": "{\"kind\":\"admin#reports#activity\",\"id\":{\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1,\"applicationName\":\"admin\",\"customerId\":\"1\"},\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"ownerDomain\":\"elastic.com\",\"ipAddress\":\"98.235.162.24\",\"events\":{\"type\":\"APPLICATION_SETTINGS\",\"name\":\"CHANGE_APPLICATION_SETTING\",\"parameters\":[{\"name\":\"APPLICATION_EDITION\",\"value\":\"basic\"},{\"name\":\"APPLICATION_NAME\",\"value\":\"drive\"},{\"name\":\"GROUP_EMAIL\",\"value\":\"group@example.com\"},{\"name\":\"NEW_VALUE\",\"value\":\"new\"},{\"name\":\"OLD_VALUE\",\"value\":\"old\"},{\"name\":\"ORG_UNIT_NAME\",\"value\":\"org\"},{\"name\":\"SETTING_NAME\",\"value\":\"setting\"}]}}",
        "provider": "admin",
        "action": "CHANGE_APPLICATION_SETTING",
        "id": "1",
        "category": [
            "iam",
            "configuration"
        ],
        "type": [
            "change"
        ],
        "dataset": "google_workspace.admin"
    },
    "group": {
        "domain": "example.com",
        "name": "group"
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
| ecs.version | ECS version | keyword |
| event.action | The action captured by the event. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. | keyword |
| event.dataset | Name of the dataset. | keyword |
| event.duration | Duration of the event in nanoseconds. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.original | Raw text message of entire event. Used to demonstrate log integrity. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| event.provider | Source of the event. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   *USER*: Another user in the same domain.   *EXTERNAL_USER*: A user outside the domain.   *KEY*: A non-human actor. | keyword |
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
| log.file.path | Log path | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| network.name | Name given by operators to sections of their network. | keyword |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
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
| url.domain | Domain of the url, such as "www.elastic.co". | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | keyword |
| url.original | Unmodified original url as seen in the event source. | keyword |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | keyword |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. | keyword |
| url.scheme | Scheme of the request, such as "https". | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". | keyword |
| url.username | Username of the request. | keyword |
| user.domain | Name of the directory the user is a member of. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |


### Drive

This is the `drive` dataset.

An example event for `drive` looks as following:

```$json
{
    "agent": {
        "hostname": "87e669265675",
        "name": "87e669265675",
        "id": "b07eaeb9-8ecf-42e8-a496-d4b3a844f73b",
        "type": "filebeat",
        "ephemeral_id": "ee3ad1f1-bda7-4645-b9a3-a306050af7e5",
        "version": "7.11.0"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/drive-test.json.log"
        },
        "offset": 0
    },
    "elastic_agent": {
        "id": "a1b36f30-3ec6-11eb-a3e0-836834823886",
        "version": "7.11.0",
        "snapshot": true
    },
    "source": {
        "geo": {
            "continent_name": "North America",
            "region_iso_code": "US-PA",
            "city_name": "State College",
            "country_iso_code": "US",
            "country_name": "United States",
            "region_name": "Pennsylvania",
            "location": {
                "lon": -77.8618,
                "lat": 40.7957
            }
        },
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, LLC"
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "name": "foo",
            "id": "1",
            "email": "foo@bar.com"
        }
    },
    "tags": [
        "forwarded"
    ],
    "input": {
        "type": "log"
    },
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "file": {
        "owner": "owner",
        "name": "document title",
        "type": "file"
    },
    "ecs": {
        "version": "1.7.0"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo",
            "owner"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        },
        "drive": {
            "file": {
                "owner": {
                    "email": "owner@example.com",
                    "is_shared_drive": false
                },
                "id": "1234",
                "type": "document"
            },
            "primary_event": true,
            "originating_app_id": "1234",
            "visibility": "people_with_link",
            "destination_folder_title": "folder title",
            "billable": false,
            "destination_folder_id": "1234"
        },
        "event": {
            "type": "access"
        }
    },
    "data_stream": {
        "namespace": "ep",
        "type": "logs",
        "dataset": "google_workspace.drive"
    },
    "organization": {
        "id": "1"
    },
    "host": {
        "name": "87e669265675"
    },
    "event": {
        "ingested": "2020-12-15T11:29:11.760838719Z",
        "original": "{\"kind\":\"admin#reports#activity\",\"id\":{\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1,\"applicationName\":\"drive\",\"customerId\":\"1\"},\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"ownerDomain\":\"elastic.com\",\"ipAddress\":\"98.235.162.24\",\"events\":{\"type\":\"access\",\"name\":\"add_to_folder\",\"parameters\":[{\"name\":\"billable\",\"boolValue\":false},{\"name\":\"destination_folder_id\",\"value\":\"1234\"},{\"name\":\"destination_folder_title\",\"value\":\"folder title\"},{\"name\":\"doc_id\",\"value\":\"1234\"},{\"name\":\"doc_title\",\"value\":\"document title\"},{\"name\":\"doc_type\",\"value\":\"document\"},{\"name\":\"originating_app_id\",\"value\":\"1234\"},{\"name\":\"owner\",\"value\":\"owner@example.com\"},{\"name\":\"owner_is_shared_drive\",\"boolValue\":false},{\"name\":\"primary_event\",\"boolValue\":true},{\"name\":\"visibility\",\"value\":\"people_with_link\"}]}}",
        "provider": "drive",
        "action": "add_to_folder",
        "id": "1",
        "category": [
            "file"
        ],
        "type": [
            "change"
        ],
        "dataset": "google_workspace.drive"
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
| ecs.version | ECS version | keyword |
| event.action | The action captured by the event. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. | keyword |
| event.dataset | Name of the dataset. | keyword |
| event.duration | Duration of the event in nanoseconds. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.original | Raw text message of entire event. Used to demonstrate log integrity. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| event.provider | Source of the event. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. | keyword |
| file.extension | File extension, excluding the leading dot. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.owner | File owner's username. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.type | File type (file, dir, or symlink). | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   *USER*: Another user in the same domain.   *EXTERNAL_USER*: A user outside the domain.   *KEY*: A non-human actor. | keyword |
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
| log.file.path | Log path | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
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
| user.domain | Name of the directory the user is a member of. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |


### Groups

This is the `groups` dataset.

An example event for `groups` looks as following:

```$json
{
    "agent": {
        "hostname": "4cc571ab4c1e",
        "name": "4cc571ab4c1e",
        "id": "a0b95f8f-4ef9-4197-abc8-5daa58bb46dd",
        "ephemeral_id": "f418e019-108a-4137-bb16-6a37813d75c0",
        "type": "filebeat",
        "version": "7.11.0"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/groups-test.json.log"
        },
        "offset": 0
    },
    "elastic_agent": {
        "id": "e83750e0-3ec9-11eb-89ab-197fa6952ca2",
        "version": "7.11.0",
        "snapshot": true
    },
    "source": {
        "geo": {
            "continent_name": "North America",
            "region_iso_code": "US-PA",
            "city_name": "State College",
            "country_iso_code": "US",
            "country_name": "United States",
            "region_name": "Pennsylvania",
            "location": {
                "lon": -77.8618,
                "lat": 40.7957
            }
        },
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, LLC"
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "name": "foo",
            "id": "1",
            "email": "foo@bar.com"
        }
    },
    "tags": [
        "forwarded"
    ],
    "input": {
        "type": "log"
    },
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "ecs": {
        "version": "1.7.0"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        },
        "groups": {
            "old_value": [
                "managers"
            ],
            "new_value": [
                "managers",
                "members"
            ],
            "email": "group@example.com",
            "acl_permission": "can_add_members"
        },
        "event": {
            "type": "acl_change"
        }
    },
    "data_stream": {
        "namespace": "ep",
        "type": "logs",
        "dataset": "google_workspace.groups"
    },
    "organization": {
        "id": "1"
    },
    "host": {
        "name": "4cc571ab4c1e"
    },
    "event": {
        "ingested": "2020-12-15T11:43:31.137282906Z",
        "original": "{\"kind\":\"admin#reports#activity\",\"id\":{\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1,\"applicationName\":\"groups\",\"customerId\":\"1\"},\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"ownerDomain\":\"elastic.com\",\"ipAddress\":\"98.235.162.24\",\"events\":{\"type\":\"acl_change\",\"name\":\"change_acl_permission\",\"parameters\":[{\"name\":\"acl_permission\",\"value\":\"can_add_members\"},{\"name\":\"group_email\",\"value\":\"group@example.com\"},{\"name\":\"new_value_repeated\",\"multiValue\":[\"managers\",\"members\"]},{\"name\":\"old_value_repeated\",\"multiValue\":[\"managers\"]}]}}",
        "provider": "groups",
        "action": "change_acl_permission",
        "id": "1",
        "category": [
            "iam"
        ],
        "type": [
            "group",
            "change"
        ],
        "dataset": "google_workspace.groups"
    },
    "group": {
        "domain": "example.com",
        "name": "group"
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
| ecs.version | ECS version | keyword |
| event.action | The action captured by the event. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. | keyword |
| event.dataset | Name of the dataset. | keyword |
| event.duration | Duration of the event in nanoseconds. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.original | Raw text message of entire event. Used to demonstrate log integrity. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| event.provider | Source of the event. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   *USER*: Another user in the same domain.   *EXTERNAL_USER*: A user outside the domain.   *KEY*: A non-human actor. | keyword |
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
| log.file.path | Log path | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| organization.id | Unique identifier for the organization. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
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
| user.domain | Name of the directory the user is a member of. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.domain | Name of the directory the user is a member of. | keyword |
| user.target.email | User email address. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |

