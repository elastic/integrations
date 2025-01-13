### BeyondInsight integration

BeyondInsight enables real-time monitoring of privileged account access, session recordings, and password checkout patterns to help security teams maintain compliance and quickly identify potential privilege abuse.


## Data streams

- **`useraudit`** Provides audit data for users that includes user actions like login, logout, pwd change etc on a machine
This data stream utilizes the BeyondInsight API's `/v3/UserAudits` endpoint.

- **`session`** Provides details on active sessions and its status with duration for an asset. 
This data stream utilizes the BeyondInsight API's `/v3/Sessions` endpoint.

- **`managedsystem`** Provides a list of managed systems.  
This data stream utilizes the BeyondInsight API's `/v3/ManagedSystems` endpoint.

- **`managedaccount`** Provides a list of managed accounts.  
This data stream utilizes the BeyondInsight API's `/v3/ManagedAccounts` endpoint.

- **`asset`** Provides a list of assets.  
This data stream utilizes the BeyondInsight API's `/v3/assets` endpoint.


## Requirements

### Configure API registration ###
API registrations allow you to integrate part of the BeyondInsight and Password Safe functionality into your applications, which allows you to expand your application's overall functionality and provide enhanced security and access management. Administrators can configure API key based API registration in BeyondInsight.

#### Add an API key policy API registration ####
Please check the [document](https://www.beyondtrust.com/docs/beyondinsight-password-safe/ps/admin/configure-api-registration.htm) for more details on API key registration.

**User Password Required**: When enabled, an additional Authorization header value containing the RunAs user password is required with the web request. If not enabled, this header value does not need to be present and is ignored if provided.
On succussfull Api key registration, BeyondInsight generates a unique identifier (API key) that the calling application provides in the Authorization header of the web request. 
For example, the Authorization header might look like: 
Authorization=PS-Auth key=c479a66f…c9484d; runas=doe-main\johndoe; pwd=[un1qu3];

### API Key based authentication
All the connectors utilizes API key from Beyondtrust and use it with /SignAppIn endpoint passing the key as authorization header.
Any language with a Representational State Transfer (REST) compliant interface can access the API with the API key and RunAs in the authorization header.

**Authorization header**
Use the web request authorization header to communicate the API application key, the RunAs username, and the user password:

**key**: The API key configured in BeyondInsight for your application.

**runas**: The username of a BeyondInsight user that has been granted permission to use the API key.

**pwd**: The RunAs user password surrounded by square brackets (optional; required only if the User Password is required on the
application API registration).

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

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in useraudit documents:

**Exported fields**

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

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in session documents:

**Exported fields**

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| beyondinsight_password_safe.session.archive_status |  | keyword |
| beyondinsight_password_safe.session.asset_name |  | keyword |
| beyondinsight_password_safe.session.duration |  | integer |
| beyondinsight_password_safe.session.end_time |  | date |
| beyondinsight_password_safe.session.managed_account_id |  | integer |
| beyondinsight_password_safe.session.managed_account_name |  | keyword |
| beyondinsight_password_safe.session.managed_system_id |  | integer |
| beyondinsight_password_safe.session.node_id |  | keyword |
| beyondinsight_password_safe.session.protocol |  | keyword |
| beyondinsight_password_safe.session.record_key |  | keyword |
| beyondinsight_password_safe.session.session_id |  | keyword |
| beyondinsight_password_safe.session.start_time |  | date |
| beyondinsight_password_safe.session.status |  | keyword |
| beyondinsight_password_safe.session.user_id |  | keyword |
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

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in managedsystem documents:

**Exported fields**

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| beyondinsight_password_safe.managedsystem.access_url |  | keyword |
| beyondinsight_password_safe.managedsystem.account_name_format |  | integer |
| beyondinsight_password_safe.managedsystem.application_host_id |  | integer |
| beyondinsight_password_safe.managedsystem.asset_id |  | integer |
| beyondinsight_password_safe.managedsystem.auto_management_flag |  | boolean |
| beyondinsight_password_safe.managedsystem.change_frequency_days |  | integer |
| beyondinsight_password_safe.managedsystem.change_frequency_type |  | keyword |
| beyondinsight_password_safe.managedsystem.change_password_after_any_release_flag |  | boolean |
| beyondinsight_password_safe.managedsystem.change_time |  | keyword |
| beyondinsight_password_safe.managedsystem.check_password_flag |  | boolean |
| beyondinsight_password_safe.managedsystem.cloud_id |  | integer |
| beyondinsight_password_safe.managedsystem.contact_email |  | keyword |
| beyondinsight_password_safe.managedsystem.database_id |  | integer |
| beyondinsight_password_safe.managedsystem.description |  | keyword |
| beyondinsight_password_safe.managedsystem.directory_id |  | integer |
| beyondinsight_password_safe.managedsystem.dns_name |  | keyword |
| beyondinsight_password_safe.managedsystem.dsskey_rule_id |  | integer |
| beyondinsight_password_safe.managedsystem.elevation_command |  | keyword |
| beyondinsight_password_safe.managedsystem.entity_type_id |  | integer |
| beyondinsight_password_safe.managedsystem.forest_name |  | keyword |
| beyondinsight_password_safe.managedsystem.functional_account_id |  | integer |
| beyondinsight_password_safe.managedsystem.host_name |  | keyword |
| beyondinsight_password_safe.managedsystem.instance_name |  | keyword |
| beyondinsight_password_safe.managedsystem.ipaddress |  | ip |
| beyondinsight_password_safe.managedsystem.is_application_host |  | boolean |
| beyondinsight_password_safe.managedsystem.is_default_instance |  | boolean |
| beyondinsight_password_safe.managedsystem.isarelease_duration |  | integer |
| beyondinsight_password_safe.managedsystem.login_account_id |  | integer |
| beyondinsight_password_safe.managedsystem.managed_system_id |  | integer |
| beyondinsight_password_safe.managedsystem.max_release_duration |  | integer |
| beyondinsight_password_safe.managedsystem.net_bios_name |  | keyword |
| beyondinsight_password_safe.managedsystem.oracle_internet_directory_id |  | integer |
| beyondinsight_password_safe.managedsystem.oracle_internet_directory_service_name |  | keyword |
| beyondinsight_password_safe.managedsystem.password_rule_id |  | integer |
| beyondinsight_password_safe.managedsystem.platform_id |  | integer |
| beyondinsight_password_safe.managedsystem.port |  | integer |
| beyondinsight_password_safe.managedsystem.release_duration |  | integer |
| beyondinsight_password_safe.managedsystem.remote_client_type |  | keyword |
| beyondinsight_password_safe.managedsystem.reset_password_on_mismatch_flag |  | boolean |
| beyondinsight_password_safe.managedsystem.ssh_key_enforcement_mode |  | integer |
| beyondinsight_password_safe.managedsystem.system_name |  | keyword |
| beyondinsight_password_safe.managedsystem.template |  | keyword |
| beyondinsight_password_safe.managedsystem.timeout |  | integer |
| beyondinsight_password_safe.managedsystem.use_ssl |  | boolean |
| beyondinsight_password_safe.managedsystem.workgroup_id |  | integer |
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

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in managedaccount documents:

**Exported fields**

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| beyondinsight_password_safe.managedaccount.account_id |  | keyword |
| beyondinsight_password_safe.managedaccount.account_name |  | keyword |
| beyondinsight_password_safe.managedaccount.application_display_name |  | keyword |
| beyondinsight_password_safe.managedaccount.application_id |  | keyword |
| beyondinsight_password_safe.managedaccount.change_state |  | integer |
| beyondinsight_password_safe.managedaccount.default_release_duration |  | integer |
| beyondinsight_password_safe.managedaccount.domain_name |  | keyword |
| beyondinsight_password_safe.managedaccount.instance_name |  | keyword |
| beyondinsight_password_safe.managedaccount.is_changing |  | boolean |
| beyondinsight_password_safe.managedaccount.is_isaaccess |  | boolean |
| beyondinsight_password_safe.managedaccount.last_change_date |  | date |
| beyondinsight_password_safe.managedaccount.maximum_release_duration |  | integer |
| beyondinsight_password_safe.managedaccount.next_change_date |  | date |
| beyondinsight_password_safe.managedaccount.platform_id |  | keyword |
| beyondinsight_password_safe.managedaccount.preferred_node_id |  | keyword |
| beyondinsight_password_safe.managedaccount.system_id |  | keyword |
| beyondinsight_password_safe.managedaccount.system_name |  | keyword |
| beyondinsight_password_safe.managedaccount.user_principal_name |  | keyword |
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

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in asset documents:

**Exported fields**

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| beyondinsight_password_safe.asset.asset_id |  | keyword |
| beyondinsight_password_safe.asset.asset_name |  | keyword |
| beyondinsight_password_safe.asset.asset_type |  | keyword |
| beyondinsight_password_safe.asset.create_date |  | date |
| beyondinsight_password_safe.asset.dns_name |  | keyword |
| beyondinsight_password_safe.asset.domain_name |  | keyword |
| beyondinsight_password_safe.asset.ipaddress |  | ip |
| beyondinsight_password_safe.asset.last_update_date |  | boolean |
| beyondinsight_password_safe.asset.mac_address |  | keyword |
| beyondinsight_password_safe.asset.operating_system |  | keyword |
| beyondinsight_password_safe.asset.workgroup_id |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| input.type | Input type | keyword |

