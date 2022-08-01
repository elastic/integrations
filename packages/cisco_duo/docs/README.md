# Cisco Duo

The Cisco Duo integration collects and parses data from the [Cisco Duo Admin APIs](https://duo.com/docs/adminapi).

## Compatibility

This module has been tested against Cisco Duo `Core Authentication Service: D224.13` and `Admin Panel: D224.18`

## Requirements

In order to ingest data from the Cisco Duo Admin API you must:
- Have a the Cisco Duo administrator account with **Owner** role [Sign up](https://signup.duo.com/)
- Sign in to [Duo Admin Panel](https://admin.duosecurity.com/)
- Go through following tabs **Application > Protect an Application > Admin API > Protect**
- Now you will find your **Hostname**, **Integration key** and **Secret key** which will be required while configuring the integration package.
- For this integration you will require **Grant read information** and **Grant read log** permissions.
- Make sure you have whitelisted your IP Address.

## Note

While setting up the interval take care of following.
- `Interval has to be greater than 1m.`
- `Larger values of interval might cause delay in data ingestion.`

## Logs

### Administrator

This is the `admin` dataset.

An example event for `admin` looks as following:

```json
{
    "@timestamp": "2021-07-20T11:41:31.000Z",
    "agent": {
        "ephemeral_id": "7c7523b2-666f-4792-812c-a5697a8929b9",
        "id": "c934978b-c8c9-4484-8fbe-007cc0ace376",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "cisco_duo": {
        "admin": {
            "action": "activation_begin",
            "user": {
                "name": "narroway"
            }
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.admin",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "c934978b-c8c9-4484-8fbe-007cc0ace376",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "action": "activation_begin",
        "agent_id_status": "verified",
        "created": "2022-07-14T12:20:01.540Z",
        "dataset": "cisco_duo.admin",
        "ingested": "2022-07-14T12:20:02Z",
        "kind": "event",
        "original": "{\"action\":\"activation_begin\",\"description\":\"Starting activation process\",\"isotimestamp\":\"2021-07-20T11: 41: 31+00: 00\",\"object\":null,\"timestamp\":1626781291,\"username\":\"narroway\"}",
        "outcome": "success",
        "reason": "Starting activation process"
    },
    "input": {
        "type": "httpjson"
    },
    "message": "Starting activation process",
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-admin"
    ],
    "user": {
        "name": "narroway"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.admin.action | The type of change that was performed | keyword |
| cisco_duo.admin.action_performed_on | The object that was acted on. | keyword |
| cisco_duo.admin.flattened | ES flattened datatype for objects where the subfields aren't known in advance. | flattened |
| cisco_duo.admin.user.name | The full name of the administrator who performed the action in the Duo Admin Panel. | keyword |
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
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
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
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.changes.email | User email address. | keyword |
| user.changes.name | Short name or login of the user. | keyword |
| user.changes.name.text | Multi-field of `user.changes.name`. | match_only_text |
| user.email | User email address. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |


### Authentication

This is the `auth` dataset.

An example event for `auth` looks as following:

```json
{
    "@timestamp": "2020-02-13T18:56:20.000Z",
    "agent": {
        "ephemeral_id": "ba2543c1-a84f-4f56-ae2f-cfecef7ef0e4",
        "id": "c934978b-c8c9-4484-8fbe-007cc0ace376",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "cisco_duo": {
        "auth": {
            "access_device": {
                "flash_version": "uninstalled",
                "ip": "89.160.20.156",
                "is_encryption_enabled": "true",
                "is_firewall_enabled": "true",
                "is_password_set": "true",
                "java_version": "uninstalled",
                "location": {
                    "city": "Ann Arbor",
                    "country": "United States",
                    "state": "Michigan"
                }
            },
            "application": {
                "key": "DIY231J8BR23QK4UKBY8",
                "name": "Microsoft Azure Active Directory"
            },
            "auth_device": {
                "ip": "192.168.225.254",
                "location": {
                    "city": "Ann Arbor",
                    "country": "United States",
                    "state": "Michigan"
                },
                "name": "My iPhone X (734-555-2342)"
            },
            "email": "narroway@example.com",
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "user_approved",
            "result": "success",
            "trusted_endpoint_status": "not trusted",
            "txid": "340a23e3-23f3-23c1-87dc-1491a23dfdbb"
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.auth",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "c934978b-c8c9-4484-8fbe-007cc0ace376",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "authentication",
        "created": "2022-07-14T12:20:57.028Z",
        "dataset": "cisco_duo.auth",
        "ingested": "2022-07-14T12:20:58Z",
        "kind": "event",
        "original": "{\"access_device\":{\"browser\":\"Chrome\",\"browser_version\":\"67.0.3396.99\",\"flash_version\":\"uninstalled\",\"hostname\":null,\"ip\":\"89.160.20.156\",\"is_encryption_enabled\":true,\"is_firewall_enabled\":true,\"is_password_set\":true,\"java_version\":\"uninstalled\",\"location\":{\"city\":\"Ann Arbor\",\"country\":\"United States\",\"state\":\"Michigan\"},\"os\":\"Mac OS X\",\"os_version\":\"10.14.1\",\"security_agents\":null},\"alias\":\"\",\"application\":{\"key\":\"DIY231J8BR23QK4UKBY8\",\"name\":\"Microsoft Azure Active Directory\"},\"auth_device\":{\"ip\":\"192.168.225.254\",\"location\":{\"city\":\"Ann Arbor\",\"country\":\"United States\",\"state\":\"Michigan\"},\"name\":\"My iPhone X (734-555-2342)\"},\"email\":\"narroway@example.com\",\"event_type\":\"authentication\",\"factor\":\"duo_push\",\"isotimestamp\":\"2020-02-13T18:56:20.351346+00:00\",\"ood_software\":null,\"reason\":\"user_approved\",\"result\":\"success\",\"timestamp\":1581620180,\"trusted_endpoint_status\":\"not trusted\",\"txid\":\"340a23e3-23f3-23c1-87dc-1491a23dfdbb\",\"user\":{\"groups\":[\"Duo Users\",\"CorpHQ Users\"],\"key\":\"DU3KC77WJ06Y5HIV7XKQ\",\"name\":\"narroway@example.com\"}}",
        "outcome": "success",
        "reason": "user_approved",
        "type": "info"
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "ip": [
            "89.160.20.156",
            "192.168.225.254"
        ]
    },
    "source": {
        "address": "89.160.20.156",
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.156",
        "user": {
            "email": "narroway@example.com",
            "group": {
                "name": [
                    "Duo Users",
                    "CorpHQ Users"
                ]
            },
            "id": "DU3KC77WJ06Y5HIV7XKQ",
            "name": "narroway@example.com"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-auth"
    ],
    "user": {
        "email": "narroway@example.com",
        "id": "DU3KC77WJ06Y5HIV7XKQ",
        "name": "narroway@example.com"
    },
    "user_agent": {
        "name": "Chrome",
        "os": {
            "name": "Mac OS X",
            "version": "10.14.1"
        },
        "version": "67.0.3396.99"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.auth.access_device.flash_version | The Flash plugin version used, if present. | keyword |
| cisco_duo.auth.access_device.hostname | The hostname, if present. | keyword |
| cisco_duo.auth.access_device.ip | The access device's IP address. | ip |
| cisco_duo.auth.access_device.is_encryption_enabled | Reports the disk encryption state as detected by the Duo Device Health app. | keyword |
| cisco_duo.auth.access_device.is_firewall_enabled | Reports the firewall state as detected by the Duo Device Health app. | keyword |
| cisco_duo.auth.access_device.is_password_set | Reports the system password state as detected by the Duo Device Health app | keyword |
| cisco_duo.auth.access_device.java_version | The Java plugin version used. | keyword |
| cisco_duo.auth.access_device.location.city | The city name of the access device using geoip location. | keyword |
| cisco_duo.auth.access_device.location.country | The country of the access device using geoip location. | keyword |
| cisco_duo.auth.access_device.location.state | The state name of the access device using geoip location. | keyword |
| cisco_duo.auth.access_device.port | The access device's port number. | long |
| cisco_duo.auth.access_device.security_agents | Reports the security agents present on the endpoint as detected by the Duo Device Health app. | flattened |
| cisco_duo.auth.alias | The username alias used to log in. | keyword |
| cisco_duo.auth.application.key | The application's integration_key. | keyword |
| cisco_duo.auth.application.name | The application's name. | keyword |
| cisco_duo.auth.auth_device.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| cisco_duo.auth.auth_device.as.organization.name | Organization name. | keyword |
| cisco_duo.auth.auth_device.geo.city_name | City name. | keyword |
| cisco_duo.auth.auth_device.geo.continent_name | Name of the continent. | keyword |
| cisco_duo.auth.auth_device.geo.country_iso_code | Country ISO code. | keyword |
| cisco_duo.auth.auth_device.geo.country_name | Country name. | keyword |
| cisco_duo.auth.auth_device.geo.location | Longitude and latitude. | geo_point |
| cisco_duo.auth.auth_device.geo.region_iso_code | Region ISO code. | keyword |
| cisco_duo.auth.auth_device.geo.region_name | Region name. | keyword |
| cisco_duo.auth.auth_device.ip | The IP address of the authentication device. | ip |
| cisco_duo.auth.auth_device.location.city | The city name of the authentication device using geoip location. | keyword |
| cisco_duo.auth.auth_device.location.country | The country of the authentication device using geoip location. | keyword |
| cisco_duo.auth.auth_device.location.state | The state name of the authentication device using geoip location. | keyword |
| cisco_duo.auth.auth_device.name | The name of the authentication device. | keyword |
| cisco_duo.auth.auth_device.port | The network port of the authentication device. | long |
| cisco_duo.auth.email | The email address of the user, if known to Duo, otherwise none. | keyword |
| cisco_duo.auth.event_type | The type of activity logged. | keyword |
| cisco_duo.auth.factor | The authentication factor. | keyword |
| cisco_duo.auth.ood_software | If authentication was denied due to out-of-date software, shows the name of the software. | keyword |
| cisco_duo.auth.reason | Provide the reason for the authentication attempt result. | keyword |
| cisco_duo.auth.result | The result of the authentication attempt. | keyword |
| cisco_duo.auth.trusted_endpoint_status | Status of Trusted Endpoint. | keyword |
| cisco_duo.auth.txid | The transaction ID of the event. | keyword |
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
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
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
| log.offset | Log offset | long |
| related.ip | All of the IPs seen on your event. | ip |
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
| source.port | Port of the source. | long |
| source.user.email | User email address. | keyword |
| source.user.group.name | Name of the group. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### Offline Enrollment

This is the `offline_enrollment` dataset.

An example event for `offline_enrollment` looks as following:

```json
{
    "@timestamp": "2019-08-30T16:10:05.000Z",
    "agent": {
        "ephemeral_id": "0d45b27c-6405-44fa-beda-22c49ad27853",
        "id": "c934978b-c8c9-4484-8fbe-007cc0ace376",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "cisco_duo": {
        "offline_enrollment": {
            "action": "o2fa_user_provisioned",
            "description": {
                "factor": "duo_otp",
                "hostname": "WKSW10x64",
                "user_agent": "DuoCredProv/4.0.6.413 (Windows NT 6.3.9600; x64; Server)"
            },
            "object": "Acme Laptop Windows Logon",
            "user": {
                "name": "narroway"
            }
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.offline_enrollment",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "c934978b-c8c9-4484-8fbe-007cc0ace376",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-07-14T12:21:49.801Z",
        "dataset": "cisco_duo.offline_enrollment",
        "ingested": "2022-07-14T12:21:53Z",
        "original": "{\"action\":\"o2fa_user_provisioned\",\"description\":\"{\\\"user_agent\\\": \\\"DuoCredProv/4.0.6.413 (Windows NT 6.3.9600; x64; Server)\\\", \\\"hostname\\\": \\\"WKSW10x64\\\", \\\"factor\\\": \\\"duo_otp\\\"}\",\"isotimestamp\":\"2019-08-30T16:10:05+00:00\",\"object\":\"Acme Laptop Windows Logon\",\"timestamp\":1567181405,\"username\":\"narroway\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-offline_enrollment"
    ],
    "user": {
        "name": "narroway"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.offline_enrollment.action | The offline enrollment operation | keyword |
| cisco_duo.offline_enrollment.description.factor | The type of authenticator used for offline access. | keyword |
| cisco_duo.offline_enrollment.description.hostname | The host name of the system where Duo Windows Logon is installed. | keyword |
| cisco_duo.offline_enrollment.description.user_agent | The Duo Windows Logon application version information and the Windows OS version and platform information. | keyword |
| cisco_duo.offline_enrollment.object | The Duo Windows Logon integration's name. | keyword |
| cisco_duo.offline_enrollment.user.name | The Duo username | keyword |
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| log.offset | Log offset | long |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


### Summary

This is the `summary` dataset.

An example event for `summary` looks as following:

```json
{
    "@timestamp": "2022-07-14T12:22:46.223536172Z",
    "agent": {
        "ephemeral_id": "3cdfc076-fea6-4cfc-af6d-57f48e0517be",
        "id": "c934978b-c8c9-4484-8fbe-007cc0ace376",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "cisco_duo": {
        "summary": {
            "admin_count": 3,
            "integration_count": 9,
            "telephony_credits_remaining": 960,
            "user_count": 8
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.summary",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "c934978b-c8c9-4484-8fbe-007cc0ace376",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-07-14T12:22:42.739Z",
        "dataset": "cisco_duo.summary",
        "ingested": "2022-07-14T12:22:46Z",
        "original": "{\"response\":{\"admin_count\":3,\"integration_count\":9,\"telephony_credits_remaining\":960,\"user_count\":8},\"stat\":\"OK\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-summary"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.summary.admin_count | Current number of admins in the account. | integer |
| cisco_duo.summary.integration_count | Current number of integrations in the account. | integer |
| cisco_duo.summary.telephony_credits_remaining | Current total number of telephony credits available in the account. This is the sum of all types of telephony credits. | integer |
| cisco_duo.summary.user_count | Current number of users in the account. | integer |
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| log.offset | Log offset | long |
| tags | List of keywords used to tag each event. | keyword |


### Telephony

This is the `telephony` dataset.

An example event for `telephony` looks as following:

```json
{
    "@timestamp": "2020-03-20T15:38:12.000Z",
    "agent": {
        "ephemeral_id": "ff6dad5e-0d55-49ac-ad4f-a438160da9af",
        "id": "c934978b-c8c9-4484-8fbe-007cc0ace376",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "cisco_duo": {
        "telephony": {
            "credits": 1,
            "event_type": "authentication",
            "phone_number": "+121234512345",
            "type": "sms"
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.telephony",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "c934978b-c8c9-4484-8fbe-007cc0ace376",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-07-14T12:23:38.029Z",
        "dataset": "cisco_duo.telephony",
        "ingested": "2022-07-14T12:23:39Z",
        "kind": "event",
        "original": "{\"context\":\"authentication\",\"credits\":1,\"isotimestamp\":\"2020-03-20T15:38:12+00:00\",\"phone\":\"+121234512345\",\"timestamp\":1584718692,\"type\":\"sms\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-telephony"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.telephony.credits | How many telephony credits this event cost. | integer |
| cisco_duo.telephony.event_type | How this telephony event was initiated. | keyword |
| cisco_duo.telephony.phone_number | The phone number that initiated this event. | keyword |
| cisco_duo.telephony.type | This type of telephony Event. | keyword |
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| log.offset | Log offset | long |
| tags | List of keywords used to tag each event. | keyword |
