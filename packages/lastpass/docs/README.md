# LastPass

## Overview

The [LastPass](https://www.lastpass.com/) integration allows users to monitor Detailed Shared Folder Data, User Data, and Event Report Logs. LastPass is a cloud-based password manager that stores users' login information online in a secure database and allows users to generate unique passwords for each site they visit. In addition, LastPass stores all users' passwords and enables them to log into their accounts with ease. It’s available on all major platforms, including mobile devices, computers, and browser extensions.

## Data streams

The LastPass integration collects logs for three types of events: Detailed Shared Folder Data, User Data, and Event Report.

**Detailed Shared Folder Data** is used to get a detailed list of all shared folders, the sites within them, and the permissions granted to them. See more details in the doc [here](https://support.lastpass.com/help/get-detailed-shared-folder-data-via-lastpass-api).

**User Data** is used to get account details about the user. See more details in the doc [here](https://support.lastpass.com/help/get-user-data-via-lastpass-api).

**Event Report** is used to gather information about events that have taken place in the user's LastPass Business account. See more details in the doc [here](https://support.lastpass.com/help/event-reporting-via-lastpass-api).

## Requirements

Elasticsearch is needed to store and search data, and Kibana is needed for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

  - **NOTE**
    - A **business account** is required to use the LastPass integration.
    - The LastPass **Provisioning API** does not support **managing groups for pre-configured SSO (Cloud) apps** for LastPass Business accounts.

## Setup

### To collect data from the LastPass REST APIs, follow the below steps:

1. Log in with the user's **email address** and **master password** to access the [Admin Console](https://admin.lastpass.com).
2. If prompted, complete the steps for **multifactor authentication** (if it is enabled for the user account).
3. To get an **Account Number(CID)**, follow the below steps:
  - On the **Dashboard** tab, the **Account Number(CID)** is located at the top of the page. it is preceded by the words **Account number**.
  ![LastPass Account Number](../img/lastpass-account-number-screenshot.png)
4. To create a **Provisioning Hash**, follow the below steps:
  - Go to **Advanced** -> **Enterprise API**.
  - Choose from the following options:
    - If the user has not previously created a provisioning hash, click **Create provisioning hash** -> **OK**, then the provisioning hash is shown at the top of the page.
    - If the user previously created a provisioning hash but has since forgotten it, the user can generate a new one.
    - **NOTE**: If the user has already created a provisioning hash, then generating a new one will invalidate the previous hash, and will require updating all integrations with the newly generated hash.
    - To proceed with creating a new provisioning hash, click **Reset your provisioning hash** -> **OK**, then a new provisioning hash is shown at the top of the page.
    ![LastPass Provisioning Hash](../img/lastpass-provisioning-hash-screenshot.png)

## Logs reference

### detailed_shared_folder

This is the `detailed_shared_folder` dataset.

#### Example

An example event for `detailed_shared_folder` looks as following:

```json
{
    "@timestamp": "2022-09-30T10:43:14.648Z",
    "agent": {
        "ephemeral_id": "9ffd2019-4880-44c2-a638-b3329f681bbf",
        "hostname": "docker-fleet-agent",
        "id": "c8a45af4-c8db-4a9e-bad1-f0fd8ef21467",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "lastpass.detailed_shared_folder",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "c8a45af4-c8db-4a9e-bad1-f0fd8ef21467",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-09-30T10:43:14.648Z",
        "dataset": "lastpass.detailed_shared_folder",
        "ingested": "2022-09-30T10:43:18Z",
        "kind": "state",
        "original": "{\"id\":\"101\",\"score\":99,\"sharedfoldername\":\"ThisSFName\",\"users\":{\"can_administer\":true,\"give\":false,\"readonly\":true,\"sites\":[\"aaa.com\",\"bbb.com\"],\"username\":\"joe.user@lastpass.com\"}}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "lastpass": {
        "detailed_shared_folder": {
            "name": "ThisSFName",
            "score": 99,
            "shared_folder": {
                "id": "101"
            },
            "user": {
                "can_administer": true,
                "give": false,
                "name": "joe.user@lastpass.com",
                "read_only": true,
                "site": [
                    "aaa.com",
                    "bbb.com"
                ]
            }
        }
    },
    "related": {
        "user": [
            "joe.user@lastpass.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "lastpass-detailed_shared_folder"
    ],
    "user": {
        "email": "joe.user@lastpass.com"
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| lastpass.detailed_shared_folder.deleted |  | boolean |
| lastpass.detailed_shared_folder.name |  | keyword |
| lastpass.detailed_shared_folder.score |  | double |
| lastpass.detailed_shared_folder.shared_folder.id |  | keyword |
| lastpass.detailed_shared_folder.user.can_administer |  | boolean |
| lastpass.detailed_shared_folder.user.give |  | boolean |
| lastpass.detailed_shared_folder.user.name |  | keyword |
| lastpass.detailed_shared_folder.user.read_only |  | boolean |
| lastpass.detailed_shared_folder.user.site |  | keyword |
| lastpass.detailed_shared_folder.user.super_admin |  | boolean |
| log.offset | Log offset | long |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |


### event_report

This is the `event_report` dataset.

#### Example

An example event for `event_report` looks as following:

```json
{
    "@timestamp": "2015-07-17T09:51:51.000Z",
    "agent": {
        "ephemeral_id": "13953b06-3145-46e7-a5fd-faa2fa36dff5",
        "hostname": "docker-fleet-agent",
        "id": "c8a45af4-c8db-4a9e-bad1-f0fd8ef21467",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "lastpass.event_report",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "c8a45af4-c8db-4a9e-bad1-f0fd8ef21467",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "action": "Failed Login Attempt",
        "agent_id_status": "verified",
        "created": "2022-09-30T10:43:58.475Z",
        "dataset": "lastpass.event_report",
        "ingested": "2022-09-30T10:44:02Z",
        "kind": "event",
        "original": "{\"Action\":\"Failed Login Attempt\",\"Data\":\"\",\"IP_Address\":\"10.16.21.21\",\"Time\":\"2015-07-17 09:51:51\",\"Username\":\"j.user@example.com\",\"id\":\"Event1\"}",
        "type": [
            "access"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "lastpass": {
        "event_report": {
            "action": "Failed Login Attempt",
            "ip": "10.16.21.21",
            "time": "2015-07-17T09:51:51.000Z",
            "user_name": "j.user@example.com"
        }
    },
    "related": {
        "ip": [
            "10.16.21.21"
        ],
        "user": [
            "j.user@example.com"
        ]
    },
    "source": {
        "ip": "10.16.21.21"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "lastpass-event_report"
    ],
    "user": {
        "email": [
            "j.user@example.com"
        ]
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| lastpass.event_report.action |  | keyword |
| lastpass.event_report.data.added_site |  | keyword |
| lastpass.event_report.data.deleted_site |  | keyword |
| lastpass.event_report.data.failed_login |  | keyword |
| lastpass.event_report.data.group_name |  | keyword |
| lastpass.event_report.data.login_site |  | keyword |
| lastpass.event_report.data.original |  | text |
| lastpass.event_report.data.renamed_shared_folder_name |  | keyword |
| lastpass.event_report.data.saml_login |  | keyword |
| lastpass.event_report.data.secure_note |  | keyword |
| lastpass.event_report.data.shared_folder_name |  | keyword |
| lastpass.event_report.data.shared_folder_user_permissions.admin |  | keyword |
| lastpass.event_report.data.shared_folder_user_permissions.hide_password |  | keyword |
| lastpass.event_report.data.shared_folder_user_permissions.read_only |  | keyword |
| lastpass.event_report.data.site |  | keyword |
| lastpass.event_report.data.user_email |  | keyword |
| lastpass.event_report.ip |  | ip |
| lastpass.event_report.time |  | date |
| lastpass.event_report.user_name |  | keyword |
| log.offset | Log offset | long |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location.lat | Longitude and latitude. | geo_point |
| source.geo.location.lon | Longitude and latitude. | geo_point |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.group.name | Name of the group. | keyword |


### user

This is the `user` dataset.

#### Example

An example event for `user` looks as following:

```json
{
    "@timestamp": "2022-09-30T10:44:43.542Z",
    "agent": {
        "ephemeral_id": "7b68e43e-222f-4be8-a47a-53f48a2ac80d",
        "hostname": "docker-fleet-agent",
        "id": "c8a45af4-c8db-4a9e-bad1-f0fd8ef21467",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "lastpass.user",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "c8a45af4-c8db-4a9e-bad1-f0fd8ef21467",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2022-09-30T10:44:43.542Z",
        "dataset": "lastpass.user",
        "ingested": "2022-09-30T10:44:47Z",
        "kind": "state",
        "original": "{\"admin\":false,\"applications\":0,\"attachments\":1,\"created\":\"2014-03-12 10:02:56\",\"disabled\":false,\"formfills\":2,\"fullname\":\"Ned Flanders\",\"groups\":[\"Domain Admins\",\"Dev Team\",\"Support Team\"],\"id\":\"101\",\"last_login\":\"2015-05-29 11:45:05\",\"last_pw_change\":\"2015-05-19 10:58:33\",\"linked\":\"personal.account@mydomain.com\",\"mpstrength\":\"100\",\"neverloggedin\":false,\"notes\":19,\"password_reset_required\":false,\"sites\":72,\"username\":\"user1@lastpass.com\"}",
        "type": [
            "user"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "lastpass": {
        "user": {
            "application": 0,
            "attachment": 1,
            "created": "2014-03-12T10:02:56.000Z",
            "disabled": false,
            "form_fill": 2,
            "full_name": "Ned Flanders",
            "group": [
                "Domain Admins",
                "Dev Team",
                "Support Team"
            ],
            "id": "101",
            "last_login": "2015-05-29T11:45:05.000Z",
            "last_password_change": "2015-05-19T10:58:33.000Z",
            "linked": "personal.account@mydomain.com",
            "master_password_strength": 100,
            "never_logged_in": false,
            "note": 19,
            "password_reset_required": false,
            "sites": 72,
            "user_name": "user1@lastpass.com"
        }
    },
    "related": {
        "user": [
            "user1@lastpass.com",
            "Ned Flanders"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "lastpass-user"
    ],
    "user": {
        "email": "user1@lastpass.com",
        "full_name": "Ned Flanders",
        "group": {
            "name": [
                "Domain Admins",
                "Dev Team",
                "Support Team"
            ]
        },
        "id": "101"
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| lastpass.user.application |  | long |
| lastpass.user.attachment |  | long |
| lastpass.user.created |  | date |
| lastpass.user.disabled |  | boolean |
| lastpass.user.duo.user_name |  | keyword |
| lastpass.user.form_fill |  | long |
| lastpass.user.full_name |  | keyword |
| lastpass.user.group |  | keyword |
| lastpass.user.id |  | keyword |
| lastpass.user.last_login |  | date |
| lastpass.user.last_password_change |  | date |
| lastpass.user.linked |  | keyword |
| lastpass.user.master_password_strength |  | long |
| lastpass.user.never_logged_in |  | boolean |
| lastpass.user.note |  | long |
| lastpass.user.password_reset_required |  | boolean |
| lastpass.user.sites |  | long |
| lastpass.user.total_score |  | double |
| lastpass.user.user_name |  | keyword |
| log.offset | Log offset | long |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.group.name | Name of the group. | keyword |
| user.id | Unique identifier of the user. | keyword |

