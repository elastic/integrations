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
    "@timestamp": "2025-08-22T10:10:00.000Z",
    "agent": {
        "ephemeral_id": "3758adeb-3280-49be-b12b-9f6a59e4bbc3",
        "id": "ca8aec7c-bb1b-4a17-bcfb-a435ed4b3aec",
        "name": "elastic-agent-58050",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "beyondinsight_password_safe": {
        "useraudit": {
            "action_type": "AccessDenied",
            "audit_id": "1",
            "create_date": "2025-08-22T10:10:00.000Z",
            "ip_address": "203.0.113.100",
            "section": "Authorization",
            "user_id": "105",
            "user_name": "guest.user"
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.useraudit",
        "namespace": "35398",
        "type": "logs"
    },
    "ecs": {
        "version": "9.1.0"
    },
    "elastic_agent": {
        "id": "ca8aec7c-bb1b-4a17-bcfb-a435ed4b3aec",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "beyondinsight_password_safe.useraudit",
        "ingested": "2025-09-12T15:05:26Z",
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
        "ip": [
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
    "@timestamp": "2025-01-15T10:45:00.000Z",
    "agent": {
        "ephemeral_id": "0ec4e96b-9b86-4f19-a2d2-b07d06efddaf",
        "id": "217cf62f-7384-4be2-a2e1-056839a4d821",
        "name": "elastic-agent-46617",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "beyondinsight_password_safe": {
        "session": {
            "application_id": "101",
            "archive_status": "archived",
            "asset_name": "web-server-01",
            "duration": 8100,
            "end_time": "2025-01-15T10:45:00.000Z",
            "managed_account_id": "789",
            "managed_account_name": "admin_user",
            "managed_system_id": "456",
            "node_id": "node-001",
            "protocol": "rdp",
            "record_key": "rec_key_abc123",
            "request_id": "201",
            "session_id": "1001",
            "session_type": "regular",
            "start_time": "2025-01-15T08:30:00.000Z",
            "status": "in_progress",
            "token": "token_xyz789",
            "user_id": "123"
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.session",
        "namespace": "86539",
        "type": "logs"
    },
    "ecs": {
        "version": "9.1.0"
    },
    "elastic_agent": {
        "id": "217cf62f-7384-4be2-a2e1-056839a4d821",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "session"
        ],
        "dataset": "beyondinsight_password_safe.session",
        "duration": 8100000000000,
        "end": "2025-01-15T10:45:00.000Z",
        "id": "1001",
        "ingested": "2025-09-12T15:04:25Z",
        "kind": "event",
        "original": "{\"ApplicationID\":101,\"ArchiveStatus\":1,\"AssetName\":\"web-server-01\",\"Duration\":8100,\"EndTime\":\"2025-01-15T10:45:00Z\",\"ManagedAccountID\":789,\"ManagedAccountName\":\"admin_user\",\"ManagedSystemID\":456,\"NodeID\":\"node-001\",\"Protocol\":0,\"RecordKey\":\"rec_key_abc123\",\"RequestID\":201,\"SessionID\":1001,\"SessionType\":1,\"StartTime\":\"2025-01-15T08:30:00Z\",\"Status\":1,\"Token\":\"token_xyz789\",\"UserID\":123}",
        "start": "2025-01-15T08:30:00.000Z",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "network": {
        "protocol": "rdp"
    },
    "related": {
        "hosts": [
            "web-server-01"
        ],
        "user": [
            "admin_user",
            "123"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "beyondinsight_password_safe.session"
    ],
    "user": {
        "id": "123",
        "name": "admin_user"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in session documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| beyondinsight_password_safe.session.application_id | The related application ID (if applicable, can be null). | keyword |
| beyondinsight_password_safe.session.archive_status | Session archive status: not_archived, archived, restoring, archiving, session_not_found, repository_offline, unknown | keyword |
| beyondinsight_password_safe.session.asset_name | Name of the target managed system. | keyword |
| beyondinsight_password_safe.session.duration | Session duration (seconds.) | long |
| beyondinsight_password_safe.session.end_time | End date/time of the session. | date |
| beyondinsight_password_safe.session.managed_account_id | ID of the target managed account. | keyword |
| beyondinsight_password_safe.session.managed_account_name | Name of the target managed account. | keyword |
| beyondinsight_password_safe.session.managed_system_id | ID of the target managed system (can be null). | keyword |
| beyondinsight_password_safe.session.node_id | ID of the session node. | keyword |
| beyondinsight_password_safe.session.protocol | Session protocol: rdp, ssh | keyword |
| beyondinsight_password_safe.session.record_key | The record key used for session replay. | keyword |
| beyondinsight_password_safe.session.request_id | The related request ID (if applicable, can be null). | keyword |
| beyondinsight_password_safe.session.session_id | ID of the session. | keyword |
| beyondinsight_password_safe.session.session_type | Session type: regular, isa, admin | keyword |
| beyondinsight_password_safe.session.start_time | Start date/time of the session. | date |
| beyondinsight_password_safe.session.status | Session status: not_started, in_progress, completed, locked, terminated, logged_off, disconnected | keyword |
| beyondinsight_password_safe.session.token | The token used for session replay. | keyword |
| beyondinsight_password_safe.session.user_id | ID of the user. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |


### ManagedSystem

ManagedSystem documents can be found by setting the filter `event.dataset :"beyondinsight_password_safe.managedsystem"`.

An example event for `managedsystem` looks as following:

```json
{
    "@timestamp": "2025-09-12T15:03:32.393Z",
    "agent": {
        "ephemeral_id": "97ef9370-d7bd-4721-be6c-b2ce77a254e9",
        "id": "34f51b07-adf7-49e2-9abd-e0dbc4d6fcd0",
        "name": "elastic-agent-19588",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "beyondinsight_password_safe": {
        "managedsystem": {
            "access_url": "http://aardvarkagreement.com/manage",
            "account_name_format": 0,
            "application_host_id": "2",
            "asset_id": "13",
            "auto_management_flag": true,
            "change_frequency_days": 30,
            "change_frequency_type": "first",
            "change_password_after_any_release_flag": false,
            "change_time": "23:30",
            "check_password_flag": false,
            "cloud_id": "1",
            "contact_email": "admin@aardvarkagreement.com",
            "database_id": "5",
            "description": "Primary Managed System for AardvarkAgreement",
            "directory_id": "3",
            "dns_name": "AardvarkAgreement.example.com",
            "dss_key_rule_id": "0",
            "elevation_command": "sudo",
            "entity_type_id": "1",
            "forest_name": "PrimaryForest",
            "functional_account_id": "14",
            "host_name": "AardvarkAgreement",
            "instance_name": "InstanceOne",
            "ip_address": "198.51.100.10",
            "is_application_host": false,
            "is_default_instance": true,
            "isa_release_duration": 120,
            "login_account_id": "20",
            "managed_system_id": "13",
            "max_release_duration": 525600,
            "net_bios_name": "AardvarkNet",
            "oracle_internet_directory_id": "550e8400-e29b-41d4-a716-446655440000",
            "oracle_internet_directory_service_name": "OiDService",
            "password_rule_id": "0",
            "platform_id": "4",
            "port": 8080,
            "release_duration": 120,
            "remote_client_type": "None",
            "reset_password_on_mismatch_flag": false,
            "ssh_key_enforcement_mode": "Auto",
            "system_name": "AardvarkAgreement",
            "template": "ServerTemplate",
            "timeout": 30,
            "use_ssl": true,
            "workgroup_id": "1"
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.managedsystem",
        "namespace": "51641",
        "type": "logs"
    },
    "ecs": {
        "version": "9.1.0"
    },
    "elastic_agent": {
        "id": "34f51b07-adf7-49e2-9abd-e0dbc4d6fcd0",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "beyondinsight_password_safe.managedsystem",
        "ingested": "2025-09-12T15:03:35Z",
        "kind": "asset",
        "type": [
            "info"
        ]
    },
    "host": {
        "domain": "example.com",
        "geo": {
            "city_name": "Amsterdam",
            "continent_name": "Europe",
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "location": {
                "lat": 52.37404,
                "lon": 4.88969
            },
            "region_iso_code": "NL-NH",
            "region_name": "North Holland"
        },
        "hostname": "AardvarkAgreement",
        "ip": [
            "198.51.100.10"
        ],
        "name": "AardvarkAgreement.example.com"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hosts": [
            "AardvarkAgreement",
            "AardvarkAgreement.example.com"
        ],
        "ip": [
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
| beyondinsight_password_safe.managedsystem.dss_key_rule_id | ID of the default DSS key rule assigned to managed accounts. | integer |
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
| input.type | Input type. | keyword |


### ManagedAccount

ManagedAccount documents can be found by setting the filter `event.dataset :"beyondinsight_password_safe.managedaccount"`.

An example event for `managedaccount` looks as following:

```json
{
    "@timestamp": "2024-12-10T08:57:45.900Z",
    "agent": {
        "ephemeral_id": "13485d3b-415b-474c-a674-2c2f0fd7b247",
        "id": "8429ee5a-d3f6-41ad-87ad-c6a35397b64e",
        "name": "elastic-agent-29194",
        "type": "filebeat",
        "version": "8.18.0"
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
        "namespace": "59569",
        "type": "logs"
    },
    "ecs": {
        "version": "9.1.0"
    },
    "elastic_agent": {
        "id": "8429ee5a-d3f6-41ad-87ad-c6a35397b64e",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "beyondinsight_password_safe.managedaccount",
        "ingested": "2025-09-12T15:02:45Z",
        "kind": "event",
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
            "5",
            "KittenGrowth"
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
| input.type | Input type. | keyword |


### Asset

Asset documents can be found by setting the filter `event.dataset :"beyondinsight_password_safe.asset"`.

An example event for `asset` looks as following:

```json
{
    "@timestamp": "2023-06-20T14:45:00.000Z",
    "agent": {
        "ephemeral_id": "ab8bf717-8595-45da-b4da-abf52b88ec95",
        "id": "88f34c64-f736-496f-b988-3e17eca87055",
        "name": "elastic-agent-94001",
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
        "namespace": "56817",
        "type": "logs"
    },
    "ecs": {
        "version": "9.1.0"
    },
    "elastic_agent": {
        "id": "88f34c64-f736-496f-b988-3e17eca87055",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "beyondinsight_password_safe.asset",
        "ingested": "2025-09-12T15:01:45Z",
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
        "name": "TestServer01",
        "os": {
            "full": "Ubuntu 20.04"
        }
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hosts": [
            "192.0.2.10",
            "TestServer01",
            "testserver01.example.com"
        ],
        "ip": [
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

