# BeyondInsight and Password Safe Integration

 [BeyondInsight](https://www.beyondtrust.com/beyondinsight) and [Password Safe](https://www.beyondtrust.com/products/password-safe)   enable real-time monitoring of privileged account access, session recordings, and password checkout patterns to help security teams maintain compliance and quickly identify potential privilege abuse.

## Data Streams

- **`useraudit`** Provides audit data for users that includes user actions like login, logout, password change, etc., on a machine.
This data stream utilizes the BeyondInsight and Password Safe API's `/v3/UserAudits` endpoint.

- **`session`** Provides details on active sessions and their status with duration for an asset.
This data stream utilizes the BeyondInsight and Password Safe API's `/v3/Sessions` endpoint.

- **`managedsystem`** Provides a list of managed systems.
This data stream utilizes the BeyondInsight and Password Safe API's `/v3/ManagedSystems` endpoint.

- **`managedaccount`** Provides a list of managed accounts.
This data stream utilizes the BeyondInsight and Password Safe API's `/v3/ManagedAccounts` endpoint.

- **`asset`** Provides a list of assets.
This data stream utilizes the BeyondInsight and Password Safe API's `/v3/assets` endpoint.

## Requirements

### Configure API Registration

Administrators can configure API key-based API registration in BeyondInsight and Password Safe.
To configure the BeyondInsight and Password Safe integration, a BeyondInsight administrator needs to create an API registration and provide an API key, a username and (depending on configuration) the user's password. In order to create the registration, the administrator may need to know the IP address of the Elastic Agent that will run the integration.

#### Add an API Key Policy API Registration

Having an admin account with beyondtrust, [create an API registration](https://docs.beyondtrust.com/bips/docs/configure-api) as mentioned below

##### Create an API key policy API registration:

Login in to application and go to `Configuration > General > API Registrations`.
Click `Create API Registration`.
Add `Authentication Options` and `Rules` on the API Registration Details page.
Select `API Key Policy` from the dropdown list. The Details screen is displayed. Fill out the new API registration details, as detailed below:

If checked User Password Required option - an additional Authorization header value containing the RunAs user password is required with the web request. If not enabled, this header value does not need to be present and is ignored if provided.

Use API key with usernanme and password (if password option is opted while registration) to access the APIs. We donot use oAuth method in this integration.

## Logs

### UserAudit

UserAudit documents can be found by setting the filter `event.dataset :"beyondinsight_password_safe.useraudit"`.

An example event for `useraudit` looks as following:

```json
{
    "@timestamp": "2025-08-22T10:10:00Z",
    "agent": {
        "ephemeral_id": "e2c1b87e-05b5-4bcf-8694-daded90867a3",
        "id": "dedd7833-0617-4781-8067-58768198fc4e",
        "name": "elastic-agent-70915",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "beyondinsight_password_safe": {
        "useraudit": {
            "action_type": "AccessDenied",
            "audit_id": "1",
            "create_date": "2025-08-22T10:10:00Z",
            "ip_address": "203.0.113.100",
            "section": "Authorization",
            "user_id": "105",
            "user_name": "guest.user"
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.useraudit",
        "namespace": "74134",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "dedd7833-0617-4781-8067-58768198fc4e",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "beyondinsight_password_safe.useraudit",
        "ingested": "2025-08-29T02:19:48Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "host": {
        "geo": {
            "city_name": "Madrid",
            "continent_name": "Europe",
            "country_iso_code": "ES",
            "country_name": "Spain",
            "location": {
                "lat": 40.41639,
                "lon": -3.7025
            },
            "region_iso_code": "ES-M",
            "region_name": "Madrid"
        },
        "ip": [
            "203.0.113.100"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hosts": [
            "203.0.113.100"
        ],
        "user": [
            "guest.user"
        ]
    },
    "tags": [
        "forwarded",
        "beyondinsight_password_safe.useraudit"
    ],
    "user": {
        "id": "105",
        "name": "guest.user"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in useraudit documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| beyondinsight_password_safe.useraudit.action_type | Action performed by the user. | keyword |
| beyondinsight_password_safe.useraudit.audit_id | Unique identifier for the audit event. | keyword |
| beyondinsight_password_safe.useraudit.create_date | Timestamp of when the user action was created. | date |
| beyondinsight_password_safe.useraudit.ip_address | IP address from which the user action originated. | ip |
| beyondinsight_password_safe.useraudit.section | Section or feature where the action took place. | keyword |
| beyondinsight_password_safe.useraudit.user_id | Unique identifier for the user. | keyword |
| beyondinsight_password_safe.useraudit.user_name | Username of the user performing the action. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |


### Session

Session documents can be found by setting the filter `event.dataset :"beyondinsight_password_safe.session"`.

An example event for `session` looks as following:

```json
{
    "@timestamp": "2025-01-27T17:12:48.443Z",
    "agent": {
        "ephemeral_id": "916661e9-ed15-4d6f-bfcf-5c5704a5c1ec",
        "id": "650cd1fc-0c46-4ef4-b269-1112fb37690e",
        "name": "elastic-agent-17681",
        "type": "filebeat",
        "version": "8.15.0"
    },
    "beyondinsight_password_safe": {
        "session": {
            "archive_status": "not_archived",
            "asset_name": "localhost",
            "duration": 0,
            "managed_account_name": "example.com\\sdfsfdf",
            "managed_system_id": 13,
            "node_id": "a5c29153-b351-41f1-a12b-0c4da9408d79",
            "protocol": "rdp",
            "record_key": "3958d725d16119a95e64af424a7f8dfsf13f1fgffbe4a6cd34earwr324454bcecce70ee37cbaed",
            "session_id": 1,
            "status": "not_started",
            "user_id": 6
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.session",
        "namespace": "97390",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "650cd1fc-0c46-4ef4-b269-1112fb37690e",
        "snapshot": false,
        "version": "8.15.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "session"
        ],
        "dataset": "beyondinsight_password_safe.session",
        "duration": 0,
        "id": "1",
        "ingested": "2025-01-27T17:12:51Z",
        "kind": "event",
        "module": "beyondinsight_password_safe",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "network": {
        "protocol": [
            "rdp"
        ]
    },
    "related": {
        "user": [
            "6"
        ]
    },
    "tags": [
        "forwarded",
        "beyondinsight_password_safe.session"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in session documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| beyondinsight_password_safe.session.archive_status | Session archive status (applicable only when Session Archiving is enabled and configured) | keyword |
| beyondinsight_password_safe.session.asset_name | Name of the asset | keyword |
| beyondinsight_password_safe.session.duration | Duration of the session in seconds | integer |
| beyondinsight_password_safe.session.end_time | End date/time of the session | date |
| beyondinsight_password_safe.session.managed_account_id | ID of the target managed account | integer |
| beyondinsight_password_safe.session.managed_account_name | Name of the target managed account | keyword |
| beyondinsight_password_safe.session.managed_system_id | ID of the target managed system | integer |
| beyondinsight_password_safe.session.node_id | ID of the session node | keyword |
| beyondinsight_password_safe.session.protocol | Protocol used for the session | keyword |
| beyondinsight_password_safe.session.record_key | Record key use for the session replay | keyword |
| beyondinsight_password_safe.session.session_id | ID of the session | keyword |
| beyondinsight_password_safe.session.start_time | Start date/time of the session | date |
| beyondinsight_password_safe.session.status | Status of the session | keyword |
| beyondinsight_password_safe.session.user_id | ID of the user | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| input.type | Input type | keyword |


### ManagedSystem

ManagedSystem documents can be found by setting the filter `event.dataset :"beyondinsight_password_safe.managedsystem"`.

An example event for `managedsystem` looks as following:

```json
{
    "@timestamp": "2025-08-21T19:51:44.321Z",
    "agent": {
        "ephemeral_id": "65102e1f-0356-43fb-86b7-7194c420165b",
        "id": "5515e62d-ab14-4d0b-a3a9-f0b226d4b586",
        "name": "elastic-agent-42570",
        "type": "filebeat",
        "version": "9.0.4"
    },
    "beyondinsight_password_safe": {
        "managedsystem": {
            "access_url": "http://aardvarkagreement.com/manage",
            "account_name_format": 0,
            "application_host_id": 2,
            "asset_id": 13,
            "auto_management_flag": true,
            "change_frequency_days": 30,
            "change_frequency_type": "first",
            "change_password_after_any_release_flag": false,
            "change_time": "23:30",
            "check_password_flag": false,
            "cloud_id": 1,
            "contact_email": "admin@aardvarkagreement.com",
            "database_id": 5,
            "description": "Primary Managed System for AardvarkAgreement",
            "directory_id": 3,
            "dns_name": "AardvarkAgreement.example.com",
            "dsskey_rule_id": 0,
            "elevation_command": "sudo",
            "entity_type_id": 1,
            "forest_name": "PrimaryForest",
            "functional_account_id": 14,
            "host_name": "AardvarkAgreement",
            "instance_name": "InstanceOne",
            "ip_address": "198.51.100.10",
            "is_application_host": false,
            "is_default_instance": true,
            "isa_release_duration": 120,
            "login_account_id": 20,
            "managed_system_id": 13,
            "max_release_duration": 525600,
            "net_bios_name": "AardvarkNet",
            "oracle_internet_directory_service_name": "OiDService",
            "password_rule_id": 0,
            "platform_id": 4,
            "port": 8080,
            "release_duration": 120,
            "remote_client_type": "None",
            "reset_password_on_mismatch_flag": false,
            "system_name": "AardvarkAgreement",
            "template": "ServerTemplate",
            "timeout": 30,
            "use_ssl": true,
            "workgroup_id": 1
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.managedsystem",
        "namespace": "41053",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5515e62d-ab14-4d0b-a3a9-f0b226d4b586",
        "snapshot": false,
        "version": "9.0.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "beyondinsight_password_safe.managedsystem",
        "ingested": "2025-08-21T19:51:47Z",
        "kind": "asset",
        "module": "beyondinsight_password_safe",
        "type": [
            "info"
        ]
    },
    "host": {
        "domain": "AardvarkAgreement.example.com",
        "geo": {
            "city_name": "Amsterdam",
            "continent_name": "Europe",
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "location": {
                "coordinates": [
                    4.889689916744828,
                    52.37403995823115
                ],
                "type": "Point"
            },
            "region_iso_code": "NL-NH",
            "region_name": "North Holland"
        },
        "ip": [
            "198.51.100.10"
        ],
        "name": "AardvarkAgreement"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hosts": [
            "AardvarkAgreement",
            "AardvarkAgreement.example.com",
            "198.51.100.10"
        ],
        "user": [
            "admin@aardvarkagreement.com"
        ]
    },
    "tags": [
        "forwarded",
        "beyondinsight_password_safe.managedsystem"
    ],
    "url": {
        "full": "http://aardvarkagreement.com/manage"
    },
    "user": {
        "email": "admin@aardvarkagreement.com"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in managedsystem documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| beyondinsight_password_safe.managedsystem.access_url | URL used for cloud access. | keyword |
| beyondinsight_password_safe.managedsystem.account_name_format | Format of the account name. | integer |
| beyondinsight_password_safe.managedsystem.application_host_id | Managed system ID of the target application host. | integer |
| beyondinsight_password_safe.managedsystem.asset_id | Asset ID; set if the managed system is an asset or a database. | integer |
| beyondinsight_password_safe.managedsystem.auto_management_flag | True if password auto-management is enabled, otherwise false. | boolean |
| beyondinsight_password_safe.managedsystem.change_frequency_days | Number of days for scheduled password changes when ChangeFrequencyType is xdays. | integer |
| beyondinsight_password_safe.managedsystem.change_frequency_type | The change frequency for scheduled password changes. | keyword |
| beyondinsight_password_safe.managedsystem.change_password_after_any_release_flag | True to change passwords on release of a request, otherwise false. | boolean |
| beyondinsight_password_safe.managedsystem.change_time | UTC time of day for scheduled password changes in 24hr format. | keyword |
| beyondinsight_password_safe.managedsystem.check_password_flag | True to enable password testing, otherwise false. | boolean |
| beyondinsight_password_safe.managedsystem.cloud_id | Cloud system ID; set if the managed system is a cloud system. | integer |
| beyondinsight_password_safe.managedsystem.contact_email | Contact email for the managed system. | keyword |
| beyondinsight_password_safe.managedsystem.database_id | Database ID; set if the managed system is a database. | integer |
| beyondinsight_password_safe.managedsystem.description | Description of the managed system. | keyword |
| beyondinsight_password_safe.managedsystem.directory_id | Directory ID; set if the managed system is a directory. | integer |
| beyondinsight_password_safe.managedsystem.dns_name | DNS name of the managed system. | keyword |
| beyondinsight_password_safe.managedsystem.dsskey_rule_id | ID of the default DSS key rule assigned to managed accounts. | integer |
| beyondinsight_password_safe.managedsystem.elevation_command | Elevation command to use (sudo, pbrun, pmrun). | keyword |
| beyondinsight_password_safe.managedsystem.entity_type_id | ID of the entity type. | integer |
| beyondinsight_password_safe.managedsystem.forest_name | Forest name of the managed system. | keyword |
| beyondinsight_password_safe.managedsystem.functional_account_id | ID of the functional account used for local managed account password changes. | integer |
| beyondinsight_password_safe.managedsystem.host_name | Host name of the managed system. | keyword |
| beyondinsight_password_safe.managedsystem.instance_name | Instance name of the managed system. | keyword |
| beyondinsight_password_safe.managedsystem.ip_address | IP address of the managed system. | ip |
| beyondinsight_password_safe.managedsystem.is_application_host | True if the managed system can be used as an application host, otherwise false. | boolean |
| beyondinsight_password_safe.managedsystem.is_default_instance | True if this is the default instance, otherwise false. | boolean |
| beyondinsight_password_safe.managedsystem.isa_release_duration | Default Information Systems Administrator (ISA) release duration in minutes. | integer |
| beyondinsight_password_safe.managedsystem.login_account_id | ID of the functional account used for SSH session logins. | integer |
| beyondinsight_password_safe.managedsystem.managed_system_id | ID of the managed system. | integer |
| beyondinsight_password_safe.managedsystem.max_release_duration | Default maximum release duration in minutes. | integer |
| beyondinsight_password_safe.managedsystem.net_bios_name | Domain NetBIOS name for managed domains. | keyword |
| beyondinsight_password_safe.managedsystem.oracle_internet_directory_id | ID of the Oracle Internet Directory. | integer |
| beyondinsight_password_safe.managedsystem.oracle_internet_directory_service_name | Service name of the Oracle Internet Directory. | keyword |
| beyondinsight_password_safe.managedsystem.password_rule_id | ID of the default password rule assigned to managed accounts. | integer |
| beyondinsight_password_safe.managedsystem.platform_id | ID of the managed system platform. | integer |
| beyondinsight_password_safe.managedsystem.port | Port used to connect to the host. | integer |
| beyondinsight_password_safe.managedsystem.release_duration | Default release duration in minutes. | integer |
| beyondinsight_password_safe.managedsystem.remote_client_type | Type of remote client to use. | keyword |
| beyondinsight_password_safe.managedsystem.reset_password_on_mismatch_flag | True to queue a password change when scheduled password test fails, otherwise false. | boolean |
| beyondinsight_password_safe.managedsystem.ssh_key_enforcement_mode | Enforcement mode for SSH host keys. | integer |
| beyondinsight_password_safe.managedsystem.system_name | Name of the related entity (asset, directory, database, or cloud). | keyword |
| beyondinsight_password_safe.managedsystem.template | Template used for the managed system. | keyword |
| beyondinsight_password_safe.managedsystem.timeout | Connection timeout in seconds. | integer |
| beyondinsight_password_safe.managedsystem.use_ssl | True if SSL is used, otherwise false. | boolean |
| beyondinsight_password_safe.managedsystem.workgroup_id | ID of the workgroup. | integer |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type | keyword |


### ManagedAccount

ManagedAccount documents can be found by setting the filter `event.dataset :"beyondinsight_password_safe.managedaccount"`.

An example event for `managedaccount` looks as following:

```json
{
    "@timestamp": "2025-08-21T20:36:43.795Z",
    "agent": {
        "ephemeral_id": "ff445f51-5192-4f3e-a363-87f79be97910",
        "id": "bf400122-2b4e-4f05-b539-cad4ea38233d",
        "name": "elastic-agent-30281",
        "type": "filebeat",
        "version": "9.0.4"
    },
    "beyondinsight_password_safe": {
        "managedaccount": {
            "account_description": "Primary managed account for KittenGrowth system",
            "account_id": "5",
            "account_name": "MacdonaldP.Irene",
            "application_display_name": "AccountingApp",
            "application_id": "123",
            "change_state": "queued",
            "default_release_duration": 120,
            "domain_name": "example.com",
            "instance_name": "Primary",
            "is_changing": false,
            "is_isa_access": true,
            "last_change_date": "2024-12-10T08:57:45.900Z",
            "maximum_release_duration": 525600,
            "next_change_date": "2024-12-12T00:00:00.000Z",
            "platform_id": "4",
            "preferred_node_id": "2ca45774-d4e0-4b8f-9b52-3f52b78ae2ca",
            "system_id": "5",
            "system_name": "KittenGrowth",
            "user_principal_name": "irene@example.com"
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.managedaccount",
        "namespace": "76959",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "bf400122-2b4e-4f05-b539-cad4ea38233d",
        "snapshot": false,
        "version": "9.0.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "beyondinsight_password_safe.managedaccount",
        "ingested": "2025-08-21T20:36:46Z",
        "kind": "event",
        "module": "beyondinsight_password_safe",
        "type": [
            "info"
        ]
    },
    "host": {
        "domain": "example.com",
        "hostname": "KittenGrowth",
        "id": "5"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hosts": [
            "KittenGrowth",
            "5",
            "example.com"
        ],
        "user": [
            "5",
            "MacdonaldP.Irene",
            "irene@example.com"
        ]
    },
    "tags": [
        "forwarded",
        "beyondinsight_password_safe.managedaccount"
    ],
    "user": {
        "email": "irene@example.com",
        "id": "5",
        "name": "MacdonaldP.Irene"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in managedaccount documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| beyondinsight_password_safe.managedaccount.account_description | The Managed Account description. | keyword |
| beyondinsight_password_safe.managedaccount.account_id | ID of the managed account. | keyword |
| beyondinsight_password_safe.managedaccount.account_name | Name of the managed account. | keyword |
| beyondinsight_password_safe.managedaccount.application_display_name | Display name of the application for application-based access. | keyword |
| beyondinsight_password_safe.managedaccount.application_id | ID of the application for application-based access. | keyword |
| beyondinsight_password_safe.managedaccount.change_state | The change state of the account credentials in human-readable format (idle, changing, queued). | keyword |
| beyondinsight_password_safe.managedaccount.default_release_duration | Default release duration (minutes). | integer |
| beyondinsight_password_safe.managedaccount.domain_name | The domain name for a domain-type account. | keyword |
| beyondinsight_password_safe.managedaccount.instance_name | Database instance name of a database-type managed system, or empty for the default instance. | keyword |
| beyondinsight_password_safe.managedaccount.is_changing | True if the account credentials are in the process of changing, otherwise false. | boolean |
| beyondinsight_password_safe.managedaccount.is_isa_access | True if the account is for Information Systems Administrator (ISA) access, otherwise false. | boolean |
| beyondinsight_password_safe.managedaccount.last_change_date | The date and time of the last password change. | date |
| beyondinsight_password_safe.managedaccount.maximum_release_duration | Maximum release duration (minutes). | integer |
| beyondinsight_password_safe.managedaccount.next_change_date | The date and time of the next password change. | date |
| beyondinsight_password_safe.managedaccount.platform_id | ID of the managed system platform. | keyword |
| beyondinsight_password_safe.managedaccount.preferred_node_id | ID of the node that is preferred for establishing sessions. If no node is preferred, returns the local node ID. | keyword |
| beyondinsight_password_safe.managedaccount.system_id | ID of the managed system. | keyword |
| beyondinsight_password_safe.managedaccount.system_name | Name of the managed system. | keyword |
| beyondinsight_password_safe.managedaccount.user_principal_name | User Principal Name of the managed account. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type | keyword |


### Asset

Asset documents can be found by setting the filter `event.dataset :"beyondinsight_password_safe.asset"`.

An example event for `asset` looks as following:

```json
{
    "@timestamp": "2023-06-20T14:45:00Z",
    "agent": {
        "ephemeral_id": "666c4132-794a-41d0-bde8-609ab3a60c33",
        "id": "ebe93be5-e99a-4f02-8679-198df50717de",
        "name": "elastic-agent-21480",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "beyondinsight_password_safe": {
        "asset": {
            "asset_id": "101",
            "asset_name": "TestServer01",
            "asset_type": "Server",
            "create_date": "2023-01-15T10:30:00Z",
            "dns_name": "testserver01.example.com",
            "domain_name": "example.com",
            "ip_address": "192.0.2.10",
            "last_update_date": "2023-06-20T14:45:00Z",
            "mac_address": "00-1B-44-11-3A-B7",
            "operating_system": "Ubuntu 20.04",
            "workgroup_id": "1"
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.asset",
        "namespace": "90442",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ebe93be5-e99a-4f02-8679-198df50717de",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "beyondinsight_password_safe.asset",
        "ingested": "2025-08-29T16:33:00Z",
        "kind": "asset",
        "original": "{\"AssetID\":101,\"AssetName\":\"TestServer01\",\"AssetType\":\"Server\",\"CreateDate\":\"2023-01-15T10:30:00Z\",\"DnsName\":\"testserver01.example.com\",\"DomainName\":\"example.com\",\"IPAddress\":\"192.0.2.10\",\"LastUpdateDate\":\"2023-06-20T14:45:00Z\",\"MacAddress\":\"00:1B:44:11:3A:B7\",\"OperatingSystem\":\"Ubuntu 20.04\",\"WorkgroupID\":1}",
        "type": [
            "info"
        ]
    },
    "host": {
        "domain": "example.com",
        "geo": {
            "city_name": "Las Vegas",
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 36.17497,
                "lon": -115.13722
            },
            "region_iso_code": "US-NV",
            "region_name": "Nevada"
        },
        "ip": [
            "192.0.2.10"
        ],
        "mac": [
            "00-1B-44-11-3A-B7"
        ],
        "name": "TestServer01"
    },
    "input": {
        "type": "cel"
    },
    "os": {
        "name": "Ubuntu 20.04"
    },
    "related": {
        "hosts": [
            "TestServer01",
            "00-1B-44-11-3A-B7",
            "example.com",
            "192.0.2.10"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "beyondinsight_password_safe.asset"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in asset documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| beyondinsight_password_safe.asset.asset_id | Unique identifier for the asset. | keyword |
| beyondinsight_password_safe.asset.asset_name | Name of the asset. | keyword |
| beyondinsight_password_safe.asset.asset_type | Type of the asset. | keyword |
| beyondinsight_password_safe.asset.create_date | Date the asset was created. | date |
| beyondinsight_password_safe.asset.dns_name | DNS name of the asset. | keyword |
| beyondinsight_password_safe.asset.domain_name | Domain name of the asset. | keyword |
| beyondinsight_password_safe.asset.ip_address | IP address of the asset. | ip |
| beyondinsight_password_safe.asset.last_update_date | Date the asset was last updated. | date |
| beyondinsight_password_safe.asset.mac_address | MAC address of the asset. | keyword |
| beyondinsight_password_safe.asset.operating_system | Operating system of the asset. | keyword |
| beyondinsight_password_safe.asset.workgroup_id | Unique identifier for the workgroup. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |

