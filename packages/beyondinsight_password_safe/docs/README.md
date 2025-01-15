# BeyondInsight and Password Safe Integration

 [BeyondInsight and Password Safe](https://www.beyondtrust.com/products/password-safe)   enable real-time monitoring of privileged account access, session recordings, and password checkout patterns to help security teams maintain compliance and quickly identify potential privilege abuse.

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

API registrations allow you to integrate part of the BeyondInsight and Password Safe functionality into your applications, which allows you to expand your application's overall functionality and provide enhanced security and access management. Administrators can configure API key-based API registration in BeyondInsight and Password Safe.

#### Add an API Key Policy API Registration
Please check the [document](https://www.beyondtrust.com/docs/beyondinsight-password-safe/ps/admin/configure-api-registration.htm) for more details on API key registration.

**User Password Required**: When enabled, an additional Authorization header value containing the RunAs user password is required with the web request. If not enabled, this header value does not need to be present and is ignored if provided.
On successful API key registration, BeyondInsight and Password Safe generate a unique identifier (API key) that the calling application provides in the Authorization header of the web request. 
For example, the Authorization header might look like: 
`Authorization=PS-Auth key=c479a66f…c9484d; runas=doe-main\johndoe; pwd=[un1qu3];`

### API Key-Based Authentication
All the connectors utilize the API key from Beyondtrust and use it with the`/SignAppIn` endpoint passing the key as an authorization header.
Any language with a Representational State Transfer (REST) compliant interface can access the API with the API key and RunAs in the authorization header.

**Authorization Header**
Use the web request authorization header to communicate the API application key, the RunAs username, and the user password:

**key**: The API key configured in BeyondInsight and Password Safe for your application.

**runas**: The username of a BeyondInsight and Password Safe user that has been granted permission to use the API key.

**pwd**: The RunAs user password surrounded by square brackets `(optional; required only if the User Password is required on the application API registration).`

## Logs

### UserAudit

UserAudit documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.useraudit"`.

An example event for `useraudit` looks as following:

```json
{
    "@timestamp": "2024-12-09T10:24:26.323Z",
    "agent": {
        "ephemeral_id": "48de15fd-994c-4e08-8d35-cf635e91ae81",
        "id": "0fb26469-edd2-4f29-8e58-9b534bf1c1ff",
        "name": "elastic-agent-28118",
        "type": "filebeat",
        "version": "8.15.3"
    },
    "beyondinsight_password_safe": {
        "useraudit": {
            "action_type": "Login",
            "audit_id": 1,
            "create_date": "2024-12-09T10:24:26.323Z",
            "ipaddress": "216.160.83.56",
            "section": "PMM API SignAppIn",
            "user_id": 6,
            "user_name": "test.user@example.com"
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.useraudit",
        "namespace": "11225",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0fb26469-edd2-4f29-8e58-9b534bf1c1ff",
        "snapshot": false,
        "version": "8.15.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "beyondinsight_password_safe.useraudit",
        "id": "1",
        "ingested": "2025-01-10T17:34:49Z",
        "kind": "event",
        "module": "beyondinsight_password_safe",
        "type": [
            "info"
        ]
    },
    "event.original": "{\"ActionType\":\"Login\",\"AuditID\":1,\"CreateDate\":\"2024-12-09T10:24:26.323Z\",\"IPAddress\":\"216.160.83.56\",\"Section\":\"PMM API SignAppIn\",\"UserID\":6,\"UserName\":\"test.user@example.com\"}",
    "host": {
        "geo": {
            "city_name": "Milton",
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 47.2513,
                "lon": -122.3149
            },
            "region_iso_code": "US-WA",
            "region_name": "Washington"
        },
        "ip": [
            "216.160.83.56"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hosts": [
            "216.160.83.56"
        ],
        "user": [
            "6",
            "test.user@example.com"
        ]
    },
    "tags": [
        "forwarded"
    ],
    "user": {
        "id": "6",
        "name": "test.user@example.com"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on [ECS](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) fields.

The following non-ECS fields are used in useraudit documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| beyondinsight_password_safe.useraudit.action_type | Action performed by the user (e.g., Login, Logout) | keyword |
| beyondinsight_password_safe.useraudit.audit_id | Unique identifier for the audit event | keyword |
| beyondinsight_password_safe.useraudit.create_date | Timestamp of when the user action was created | date |
| beyondinsight_password_safe.useraudit.ipaddress | IP address from which the user action originated | keyword |
| beyondinsight_password_safe.useraudit.section | Section or feature where the action took place | keyword |
| beyondinsight_password_safe.useraudit.user_id | Unique identifier for the user | keyword |
| beyondinsight_password_safe.useraudit.user_name | Username of the user performing the action | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type. | keyword |


### Session

Session documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.session"`.

An example event for `session` looks as following:

```json
{
    "@timestamp": "2025-01-10T17:33:17.043Z",
    "agent": {
        "ephemeral_id": "f996807b-e519-44cd-96e4-f7cf39f2e3f7",
        "id": "79915fa5-d015-407a-9aec-a46b4aa1176d",
        "name": "elastic-agent-76890",
        "type": "filebeat",
        "version": "8.15.3"
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
            "session_id": "1",
            "status": "not_started",
            "user_id": "6"
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.session",
        "namespace": "32330",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "79915fa5-d015-407a-9aec-a46b4aa1176d",
        "snapshot": false,
        "version": "8.15.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "session"
        ],
        "dataset": "beyondinsight_password_safe.session",
        "duration": 0,
        "id": "1",
        "ingested": "2025-01-10T17:33:20Z",
        "kind": "event",
        "module": "beyondinsight_password_safe",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "forwarded"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on [ECS](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) fields.

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

ManagedSystem documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.managedsystem"`.

An example event for `managedsystem` looks as following:

```json
{
    "@timestamp": "2025-01-10T17:31:54.183Z",
    "agent": {
        "ephemeral_id": "63cb4f19-5ee5-4c5a-85dd-2f67a84a43b3",
        "id": "6334669c-2f0b-4a9b-beda-d7b578d53ac6",
        "name": "elastic-agent-93061",
        "type": "filebeat",
        "version": "8.15.3"
    },
    "beyondinsight_password_safe": {
        "managedsystem": {
            "account_name_format": 0,
            "asset_id": 13,
            "auto_management_flag": true,
            "change_frequency_days": 30,
            "change_frequency_type": "first",
            "change_password_after_any_release_flag": false,
            "change_time": "23:30",
            "check_password_flag": false,
            "dns_name": "AardvarkAgreement.example.com",
            "dsskey_rule_id": 0,
            "entity_type_id": 1,
            "functional_account_id": 14,
            "host_name": "AardvarkAgreement",
            "ipaddress": "172.16.152.110",
            "is_application_host": false,
            "isarelease_duration": 120,
            "managed_system_id": 13,
            "max_release_duration": 525600,
            "password_rule_id": 0,
            "platform_id": 4,
            "release_duration": 120,
            "remote_client_type": "None",
            "reset_password_on_mismatch_flag": false,
            "ssh_key_enforcement_mode": "None",
            "system_name": "AardvarkAgreement",
            "timeout": 30,
            "workgroup_id": 1
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.managedsystem",
        "namespace": "43969",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "6334669c-2f0b-4a9b-beda-d7b578d53ac6",
        "snapshot": false,
        "version": "8.15.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "beyondinsight_password_safe.managedsystem",
        "ingested": "2025-01-10T17:31:56Z",
        "kind": "asset",
        "module": "beyondinsight_password_safe",
        "type": [
            "info"
        ]
    },
    "host": {
        "domain": "AardvarkAgreement.example.com",
        "ip": [
            "172.16.152.110",
            "172.16.152.110"
        ],
        "name": "AardvarkAgreement"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hosts": [
            "AardvarkAgreement",
            "172.16.152.110",
            "AardvarkAgreement.example.com"
        ]
    },
    "tags": [
        "forwarded",
        "managedsystem"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on [ECS](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) fields.

The following non-ECS fields are used in managedsystem documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| beyondinsight_password_safe.managedsystem.ipaddress | IP address of the managed system. | ip |
| beyondinsight_password_safe.managedsystem.is_application_host | True if the managed system can be used as an application host, otherwise false. | boolean |
| beyondinsight_password_safe.managedsystem.is_default_instance | True if this is the default instance, otherwise false. | boolean |
| beyondinsight_password_safe.managedsystem.isarelease_duration | Default Information Systems Administrator (ISA) release duration in minutes. | integer |
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| input.type | Input type | keyword |


### ManagedAccount

ManagedAccount documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.managedaccount"`.

An example event for `managedaccount` looks as following:

```json
{
    "@timestamp": "2025-01-10T17:30:25.266Z",
    "agent": {
        "ephemeral_id": "e7120f70-af54-41cc-812a-eedbcd000c93",
        "id": "130fdc88-8d6e-48ed-ade5-5dfcd2a6d703",
        "name": "elastic-agent-87697",
        "type": "filebeat",
        "version": "8.15.3"
    },
    "beyondinsight_password_safe": {
        "managedaccount": {
            "account_id": "5",
            "account_name": "MacdonaldP.Irene",
            "application_display_name": "AccountingApp",
            "application_id": 123,
            "change_state": 2,
            "default_release_duration": 120,
            "domain_name": "example.com",
            "instance_name": "Primary",
            "is_changing": false,
            "is_isaaccess": true,
            "last_change_date": "2024-12-10T08:57:45.900Z",
            "maximum_release_duration": 525600,
            "next_change_date": "2024-12-12T00:00:00.000Z",
            "platform_id": 4,
            "preferred_node_id": "2ca45774-d4e0-4b8f-9b52-3f52b78ae2ca",
            "system_id": "5",
            "system_name": "KittenGrowth",
            "user_principal_name": "irene@example.com"
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.managedaccount",
        "namespace": "43599",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "130fdc88-8d6e-48ed-ade5-5dfcd2a6d703",
        "snapshot": false,
        "version": "8.15.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "beyondinsight_password_safe.managedaccount",
        "ingested": "2025-01-10T17:30:27Z",
        "kind": "event",
        "module": "beyondinsight_password_safe",
        "type": [
            "info"
        ]
    },
    "host": {
        "domain": "example.com",
        "hostname": [
            "KittenGrowth"
        ],
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
        "managedaccount"
    ],
    "user": {
        "email": "irene@example.com",
        "id": "5",
        "name": "MacdonaldP.Irene"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on [ECS](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) fields.

The following non-ECS fields are used in managedaccount documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| beyondinsight_password_safe.managedaccount.account_id | ID of the managed account. | keyword |
| beyondinsight_password_safe.managedaccount.account_name | Name of the managed account. | keyword |
| beyondinsight_password_safe.managedaccount.application_display_name | Display name of the application for application-based access. | keyword |
| beyondinsight_password_safe.managedaccount.application_id | ID of the application for application-based access. | keyword |
| beyondinsight_password_safe.managedaccount.change_state | The change state of the account credentials. | integer |
| beyondinsight_password_safe.managedaccount.default_release_duration | Default release duration (minutes). | integer |
| beyondinsight_password_safe.managedaccount.domain_name | The domain name for a domain-type account. | keyword |
| beyondinsight_password_safe.managedaccount.instance_name | Database instance name of a database-type managed system, or empty for the default instance. | keyword |
| beyondinsight_password_safe.managedaccount.is_changing | True if the account credentials are in the process of changing, otherwise false. | boolean |
| beyondinsight_password_safe.managedaccount.is_isaaccess | True if the account is for Information Systems Administrator (ISA) access, otherwise false. | boolean |
| beyondinsight_password_safe.managedaccount.last_change_date | The date and time of the last password change. | date |
| beyondinsight_password_safe.managedaccount.maximum_release_duration | Maximum release duration (minutes). | integer |
| beyondinsight_password_safe.managedaccount.next_change_date | The date and time of the next password change. | date |
| beyondinsight_password_safe.managedaccount.platform_id | ID of the managed system platform. | keyword |
| beyondinsight_password_safe.managedaccount.preferred_node_id | ID of the node that is preferred for establishing sessions. If no node is preferred, returns the local node ID. | keyword |
| beyondinsight_password_safe.managedaccount.system_id | ID of the managed system. | keyword |
| beyondinsight_password_safe.managedaccount.system_name | Name of the managed system. | keyword |
| beyondinsight_password_safe.managedaccount.user_principal_name | User Principal Name of the managed account. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| input.type | Input type | keyword |


### Asset

Asset documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.asset"`.

An example event for `asset` looks as following:

```json
{
    "@timestamp": "2025-01-10T17:28:57.168Z",
    "agent": {
        "ephemeral_id": "28da3009-f712-45c6-8cc3-c4ece92152ab",
        "id": "57cf6db5-ad20-496f-ad07-c31f43d068a4",
        "name": "elastic-agent-64679",
        "type": "filebeat",
        "version": "8.15.3"
    },
    "beyondinsight_password_safe": {
        "asset": {
            "asset_id": 2,
            "asset_name": "EPINHYDW002A",
            "asset_type": "WorkStation",
            "create_date": "2024-11-20T06:12:21.047Z",
            "dns_name": "EPINHYDW002A",
            "domain_name": "Unknown",
            "ipaddress": "192.168.29.50",
            "last_update_date": "2024-11-20T06:35:49.927Z",
            "operating_system": "Windows 11 Enterprise",
            "workgroup_id": 1
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.asset",
        "namespace": "94865",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "57cf6db5-ad20-496f-ad07-c31f43d068a4",
        "snapshot": false,
        "version": "8.15.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "beyondinsight_password_safe.asset",
        "ingested": "2025-01-10T17:28:58Z",
        "kind": "asset",
        "module": "beyondinsight_password_safe",
        "type": [
            "info"
        ]
    },
    "host": {
        "domain": "Unknown",
        "ip": [
            "192.168.29.50",
            "192.168.29.50"
        ]
    },
    "input": {
        "type": "cel"
    },
    "os": {
        "name": "Windows 11 Enterprise"
    },
    "related": {
        "hosts": [
            "192.168.29.50",
            "Unknown"
        ]
    },
    "tags": [
        "forwarded",
        "asset"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on [ECS](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) fields.

The following non-ECS fields are used in asset documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| beyondinsight_password_safe.asset.asset_id | Unique identifier for the asset | keyword |
| beyondinsight_password_safe.asset.asset_name | Name of the asset | keyword |
| beyondinsight_password_safe.asset.asset_type | Type of the asset | keyword |
| beyondinsight_password_safe.asset.create_date | Date the asset was created | date |
| beyondinsight_password_safe.asset.dns_name | DNS name of the asset | keyword |
| beyondinsight_password_safe.asset.domain_name | Domain name of the asset | keyword |
| beyondinsight_password_safe.asset.ipaddress | IP address of the asset | ip |
| beyondinsight_password_safe.asset.last_update_date | Date the asset was last updated | boolean |
| beyondinsight_password_safe.asset.mac_address | MAC address of the asset | keyword |
| beyondinsight_password_safe.asset.operating_system | Operating system of the asset | keyword |
| beyondinsight_password_safe.asset.workgroup_id | Unique identifier for the workgroup | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| input.type | Input type | keyword |
