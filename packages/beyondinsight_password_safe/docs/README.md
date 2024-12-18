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
        "ephemeral_id": "c76c5039-0b47-4beb-b35d-bc8a61d9a1f7",
        "id": "fe047d4c-ceee-493b-8189-38f07d65c745",
        "name": "elastic-agent-34883",
        "type": "filebeat",
        "version": "8.12.2"
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
        "namespace": "69166",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "fe047d4c-ceee-493b-8189-38f07d65c745",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "beyondinsight_password_safe.useraudit",
        "id": "1",
        "ingested": "2024-12-18T12:00:26Z",
        "kind": "event",
        "module": "beyondinsight_password_safe",
        "type": [
            "info"
        ]
    },
    "event.original": "{\"ActionType\":\"Login\",\"AuditID\":1,\"CreateDate\":\"2024-12-09T10:24:26.323Z\",\"IPAddress\":\"216.160.83.56\",\"Section\":\"PMM API SignAppIn\",\"UserID\":6,\"UserName\":\"test.user@example.com\"}",
    "host": {
        "architecture": "x86_64",
        "containerized": true,
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
        "hostname": "elastic-agent-34883",
        "id": "009f8d5d825944429c9ae8d252b0019a",
        "ip": [
            "172.19.0.2",
            "172.18.0.7",
            "216.160.83.56"
        ],
        "mac": [
            "02-42-AC-12-00-07",
            "02-42-AC-13-00-02"
        ],
        "name": "elastic-agent-34883",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.167.4-microsoft-standard-WSL2",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
    },
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
    "@timestamp": "2024-12-17T11:02:01.560Z",
    "agent": {
        "ephemeral_id": "68a099e7-fbf2-4a83-a6d0-f83510bfe20c",
        "id": "c08ff92b-b893-459d-82cb-4d568c700ce1",
        "name": "elastic-agent-55487",
        "type": "filebeat",
        "version": "8.12.2"
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
            "record_key": "3958d725d16119a95e64af424a7f8dfsf13f1be4a6cd34earwr324454bcecce70ee37cbaed",
            "session_id": "1",
            "status": "not_started",
            "user_id": "6"
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.session",
        "namespace": "69269",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c08ff92b-b893-459d-82cb-4d568c700ce1",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "session"
        ],
        "dataset": "beyondinsight_password_safe.session",
        "duration": 0,
        "id": "1",
        "ingested": "2024-12-17T11:02:04Z",
        "kind": "event",
        "module": "beyondinsight_password_safe",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-55487",
        "id": "29b44b57f32c4ff282841a8a4406ef95",
        "ip": [
            "172.29.0.2",
            "172.24.0.4"
        ],
        "mac": [
            "02-42-AC-18-00-04",
            "02-42-AC-1D-00-02"
        ],
        "name": "elastic-agent-55487",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "6.6.51-0-virt",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
    }
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
    "@timestamp": "2024-12-18T11:57:25.174Z",
    "agent": {
        "ephemeral_id": "790dbd09-2c10-4941-ab6a-885b61e86f97",
        "id": "0259b78e-0295-4890-855b-513b1ef280e1",
        "name": "elastic-agent-74965",
        "type": "filebeat",
        "version": "8.12.2"
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
            "ssh_key_enforcement_mode": 0,
            "system_name": "AardvarkAgreement",
            "timeout": 30,
            "workgroup_id": 1
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.managedsystem",
        "namespace": "75174",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0259b78e-0295-4890-855b-513b1ef280e1",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "beyondinsight_password_safe.managedsystem",
        "ingested": "2024-12-18T11:57:29Z",
        "kind": "asset",
        "module": "beyondinsight_password_safe",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "elastic-agent-74965",
        "id": "009f8d5d825944429c9ae8d252b0019a",
        "ip": [
            "172.19.0.2",
            "172.18.0.7"
        ],
        "mac": [
            "02-42-AC-12-00-07",
            "02-42-AC-13-00-02"
        ],
        "name": "elastic-agent-74965",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.167.4-microsoft-standard-WSL2",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
    }
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
    "@timestamp": "2024-12-17T11:00:02.287Z",
    "agent": {
        "ephemeral_id": "cfd1d10e-cb2a-4ab3-aa61-28db2009ce49",
        "id": "14265df8-8608-4a59-b034-d0bddebe53a1",
        "name": "elastic-agent-32613",
        "type": "filebeat",
        "version": "8.12.2"
    },
    "beyondinsight_password_safe": {
        "managedaccount": {
            "account_id": 5,
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
            "system_id": 5,
            "system_name": "KittenGrowth",
            "user_principal_name": "irene@example.com"
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.managedaccount",
        "namespace": "35062",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "14265df8-8608-4a59-b034-d0bddebe53a1",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "beyondinsight_password_safe.managedaccount",
        "ingested": "2024-12-17T11:00:05Z",
        "kind": "event",
        "module": "beyondinsight_password_safe",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-32613",
        "id": "29b44b57f32c4ff282841a8a4406ef95",
        "ip": [
            "172.25.0.2",
            "172.24.0.4"
        ],
        "mac": [
            "02-42-AC-18-00-04",
            "02-42-AC-19-00-02"
        ],
        "name": "elastic-agent-32613",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "6.6.51-0-virt",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
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
    "@timestamp": "2024-12-17T11:01:02.360Z",
    "agent": {
        "name": "docker-fleet-agent",
        "id": "a447c2bb-3c3f-4aa0-a636-cb93aaeab324",
        "ephemeral_id": "a5cec388-f06a-4cd8-9a13-1b4c1339993c",
        "type": "filebeat",
        "version": "8.12.2"
    },
    "beyondinsight_password_safe": {
        "asset": {
            "ipaddress": "172.16.201.219",
            "domain_name": "example.com",
            "asset_name": "InteractionMynahBird",
            "workgroup_id": 1,
            "asset_type": "UNKNOWN",
            "operating_system": "ExampleOS",
            "asset_id": 23,
            "create_date": "2024-12-10T09:14:28.653Z",
            "dns_name": "InteractionMynahBird.example.com",
            "last_update_date": "2024-12-10T09:14:28.653Z"
        }
    },
    "data_stream": {
        "dataset": "beyondinsight_password_safe.assets",
        "namespace": "70520",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "24d8f479-9397-47ca-9fae-5f1fe550b1ff",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-12-17T07:40:24Z",
        "kind": "asset",
        "module": "beyondinsight_password_safe",
        "category": [
            "host"
        ],
        "type": [
            "info"
        ],
        "dataset": "beyondinsight_password_safe.assets"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-76157",
        "id": "29b44b57f32c4ff282841a8a4406ef95",
        "ip": [
            "172.27.0.2",
            "172.24.0.4"
        ],
        "mac": [
            "02-42-AC-18-00-04",
            "02-42-AC-1B-00-02"
        ],
        "name": "elastic-agent-76157",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "6.6.51-0-virt",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
    }
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

