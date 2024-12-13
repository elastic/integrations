# BeyondInsight integration

BeyondInsight enables real-time monitoring of privileged account access, session recordings, and password checkout patterns to help security teams maintain compliance and quickly identify potential privilege abuse.


## Data streams

- **`useraudit`** Provides audit data for users that includes user actions like login, logout, pwd change etc on a machine
This data stream utilizes the BeyondInsight API's `/v3/UserAudits` endpoint.

- **`session`** Provides details on active sessions and its status with duration for an asset. 
This data stream utilizes the BeyondInsight API's `/v3/Sessions` endpoint.

- **`managedsystem`** Provides a list of managed systems.  
This data stream utilizes the BeyondInsight API's `/v3//ManagedSystems` endpoint.

- **`managedaccount`** Provides a list of managed accounts.  
This data stream utilizes the BeyondInsight API's `/v3//ManagedAccounts` endpoint.

- **`asset`** Provides a list of assets.  
This data stream utilizes the BeyondInsight API's `/v3//assets` endpoint.

- **`request`** Provides a list of managed accounts.  
This data stream utilizes the BeyondInsight API's `/v3//requests` endpoint.

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

Here is an example useraudit document:

An example event for `useraudit` looks as following:

```json
{
  "_index": ".ds-logs-beyondinsight_password_safe.useraudit-default-2024.12.11-000001",
  "_id": "Z6i+/IqzAb9roIH6zU8rsBDyUdg=",
  "_score": 1,
  "_source": {
    "input": {
      "type": "cel"
    },
    "agent": {
      "name": "docker-fleet-agent",
      "id": "98cd62df-49de-41c8-93ce-8b94d4bf06c8",
      "ephemeral_id": "7e08184f-b554-45d0-974e-7319b4155b5d",
      "type": "filebeat",
      "version": "8.12.2"
    },
    "beyondinsight_password_safe": {
      "useraudit": {
        "ipaddress": "223.233.80.172",
        "audit_id": 22239,
        "action_type": "Login",
        "user_id": 6,
        "user_name": "balaji_dongare@epam.com",
        "section": "PMM API SignAppIn",
        "create_date": "2024-12-11T21:03:20.503Z"
      }
    },
    "@timestamp": "2024-12-11T21:03:20.503Z",
    "ecs": {
      "version": "8.11.0"
    },
    "data_stream": {
      "namespace": "default",
      "type": "logs",
      "dataset": "beyondinsight_password_safe.useraudit"
    },
    "elastic_agent": {
      "id": "98cd62df-49de-41c8-93ce-8b94d4bf06c8",
      "version": "8.12.2",
      "snapshot": false
    },
    "host": {
      "ip": [
        "223.233.80.172"
      ]
    },
    "event": {
      "agent_id_status": "verified",
      "ingested": "2024-12-11T21:08:18Z",
      "kind": "event",
      "module": "beyondinsight_password_safe",
      "id": "22239",
      "category": [
        "iam"
      ],
      "type": [
        "info"
      ],
      "dataset": "beyondinsight_password_safe.useraudit"
    },
    "user": {
      "name": "balaji_dongare@epam.com",
      "id": "6"
    },
    "tags": [
      "preserve_original_event",
      "forwarded"
    ]
  }
}
 
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in useraudit documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Dataset | constant_keyword |
| event.module | Module | constant_keyword |
| input.type | Input type | keyword |
| beyondinsight_password_safe.useraudit.audit_id | Unique identifier for the audit event | long |
| beyondinsight_password_safe.useraudit.action_type | Action performed by the user (e.g., Login, Logout) | keyword |
| beyondinsight_password_safe.useraudit.section | Section or feature where the action took place | boolean |
| user.id | Unique identifier for the user | keyword |
| user.name | Username of the user performing the action | keyword |
| host.ip | IP address from which the user action originated | ip |
| beyondinsight_password_safe.useraudit.create_date | Timestamp of when the user action was created | date |



### Session

Session documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.session"`.

Here is an example session document:

An example event for `session` looks as following:

```json
{
        "_index": ".ds-logs-beyondinsight_password_safe.session-default-2024.12.11-000004",
        "_id": "RfP2MMIFCS+8Zi9m137F6dJpO9k=",
        "_score": null,
        "_source": {
          "input": {
            "type": "cel"
          },
          "agent": {
            "name": "docker-fleet-agent",
            "id": "a7001b31-5e06-4cd3-98a6-150537020817",
            "ephemeral_id": "4394976e-aa96-433d-9872-979278c1dfcf",
            "type": "filebeat",
            "version": "8.12.2"
          },
          "beyondinsight_password_safe": {
            "session": {
              "duration": 0,
              "protocol": "rdp",
              "record_key": "892067f27037140e5d009db50031b15d4ca224376504c13b1695f19c4d01991a",
              "archive_status": "not_archived",
              "asset_name": "123.6.7.8.8",
              "user_id": "2",
              "session_id": "3",
              "managed_account_name": """sdfsf\sdfsdfs""",
              "status": "not_started",
              "node_id": "a5c29153-b351-41f1-a12b-0c4da9408d79"
            }
          },
          "@timestamp": "2024-12-11T12:24:24.757Z",
          "ecs": {
            "version": "8.11.0"
          },
          "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "beyondinsight_password_safe.session"
          },
          "host": {
            "hostname": "docker-fleet-agent",
            "os": {
              "kernel": "5.15.167.4-microsoft-standard-WSL2",
              "codename": "focal",
              "name": "Ubuntu",
              "family": "debian",
              "type": "linux",
              "version": "20.04.6 LTS (Focal Fossa)",
              "platform": "ubuntu"
            },
            "containerized": true,
            "ip": [
              "172.18.0.7"
            ],
            "name": "docker-fleet-agent",
            "id": "009f8d5d825944429c9ae8d252b0019a",
            "mac": [
              "02-42-AC-12-00-07"
            ],
            "architecture": "x86_64"
          },
          "elastic_agent": {
            "id": "a7001b31-5e06-4cd3-98a6-150537020817",
            "version": "8.12.2",
            "snapshot": false
          },
          "event": {
            "duration": 0,
            "agent_id_status": "verified",
            "ingested": "2024-12-11T12:24:25Z",
            "kind": "event",
            "module": "beyondinsight_password_safe",
            "id": "3",
            "category": [
              "session"
            ],
            "type": [
              "info"
            ],
            "dataset": "beyondinsight_password_safe.session"
          }
        },
        "sort": [
          1733919864757
        ]
      }
 
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in session documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| input.type | Input type | keyword |
| beyondinsight_password_safe.session.sessionid | Session id | keyword |
| beyondinsight_password_safe.session.user_id | User id | keyword |
| event.start | Session state time | date |
| event.end | Session end date | date |
| beyondinsight_password_safe.session.duration | Session duration | integer |
| beyondinsight_password_safe.session.asset_name | Asset name | keyword |
| beyondinsight_password_safe.session.record_key | Record key | keyword |
| beyondinsight_password_safe.session.protocol | Protocol | keyword |

### ManagedSystem

ManagedSystem documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.managedsystem"`.

Here is an example managedsystem document:

An example event for `managedsystem` looks as following:

```json
{
        "_index": ".ds-logs-beyondinsight_password_safe.managedsystem-default-2024.12.11-000003",
        "_id": "W+7DCDPfDZqFu+hJXnXjPOvAhfg=",
        "_score": null,
        "_source": {
          "input": {
            "type": "cel"
          },
          "agent": {
            "name": "docker-fleet-agent",
            "id": "a7001b31-5e06-4cd3-98a6-150537020817",
            "type": "filebeat",
            "ephemeral_id": "4394976e-aa96-433d-9872-979278c1dfcf",
            "version": "8.12.2"
          },
          "beyondinsight_password_safe": {
            "managedsystem": {
              "ipaddress": "85.206.176.106",
              "remote_client_type": "None",
              "description": "test",
              "dsskey_rule_id": 0,
              "entity_type_id": 1,
              "timeout": 30,
              "change_frequency_type": "first",
              "managed_system_id": 2,
              "is_application_host": false,
              "workgroup_id": 1,
              "max_release_duration": 10079,
              "change_time": "23:30",
              "check_password_flag": false,
              "system_name": "windows",
              "password_rule_id": 0,
              "change_password_after_any_release_flag": false,
              "dns_name": "test",
              "functional_account_id": 4,
              "reset_password_on_mismatch_flag": false,
              "account_name_format": 0,
              "port": 22,
              "platform_id": 46,
              "release_duration": 120,
              "isarelease_duration": 120,
              "change_frequency_days": 30,
              "host_name": "windows",
              "auto_management_flag": true
            }
          },
          "@timestamp": "2024-12-11T12:24:54.103Z",
          "ecs": {
            "version": "8.11.0"
          },
          "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "beyondinsight_password_safe.managedsystem"
          },
          "elastic_agent": {
            "id": "a7001b31-5e06-4cd3-98a6-150537020817",
            "version": "8.12.2",
            "snapshot": false
          },
          "host": {
            "hostname": "docker-fleet-agent",
            "os": {
              "kernel": "5.15.167.4-microsoft-standard-WSL2",
              "codename": "focal",
              "name": "Ubuntu",
              "type": "linux",
              "family": "debian",
              "version": "20.04.6 LTS (Focal Fossa)",
              "platform": "ubuntu"
            },
            "containerized": true,
            "ip": [
              "172.18.0.7"
            ],
            "name": "docker-fleet-agent",
            "id": "009f8d5d825944429c9ae8d252b0019a",
            "mac": [
              "02-42-AC-12-00-07"
            ],
            "architecture": "x86_64"
          },
          "event": {
            "agent_id_status": "verified",
            "ingested": "2024-12-11T12:24:55Z",
            "kind": "asset",
            "module": "beyondinsight_password_safe",
            "category": [
              "iam"
            ],
            "type": [
              "info"
            ],
            "dataset": "beyondinsight_password_safe.managedsystem"
          }
        },
        "sort": [
          1733919894103
        ]
      }
 
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in managedsystem documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| input.type | Input type | keyword |
|beyondinsight_password_safe.managedsystem.total_count | Total count | integer |
|beyondinsight_password_safe.managedsystem.data | Array of managed systems | nested |
|beyondinsight_password_safe.managedsystem.data.workgroup_id | Work group id | integer |
|beyondinsight_password_safe.managedsystem.data.host_name | Host name | keyword |
|beyondinsight_password_safe.managedsystem.data.ipaddress | IP address | ip |
|beyondinsight_password_safe.managedsystem.data.dns_name | DNS Name | keyword |
|beyondinsight_password_safe.managedsystem.data.instance_name | Instance name | keyword |
|beyondinsight_password_safe.managedsystem.data.is_default_instance | Is default instance | bool |
|beyondinsight_password_safe.managedsystem.data.template | Template | keyword |
|beyondinsight_password_safe.managedsystem.data.forest_name | Forest name | keyword |
|beyondinsight_password_safe.managedsystem.data.use_ssl | Use SSL | bool |
|beyondinsight_password_safe.managedsystem.data.managed_system_id | Managed system id | integer |
|beyondinsight_password_safe.managedsystem.data.entity_type_id | Entity type id | integer |
|beyondinsight_password_safe.managedsystem.data.asset_id | Asset id | integer |
|beyondinsight_password_safe.managedsystem.data.database_id | Database id | integer |
|beyondinsight_password_safe.managedsystem.data.directory_id | Directory id | integer |
|beyondinsight_password_safe.managedsystem.data.cloud_id | Cloud id | integer |
|beyondinsight_password_safe.managedsystem.data.system_name | System name | keyword |
|beyondinsight_password_safe.managedsystem.data.timeout | Timeout | integer |
|beyondinsight_password_safe.managedsystem.data.platform_id | Platform id | integer |
|beyondinsight_password_safe.managedsystem.data.net_bios_name | Net BIOS name | keyword |
|beyondinsight_password_safe.managedsystem.data.contact_email | Contact email | keyword |
|beyondinsight_password_safe.managedsystem.data.description | Description | keyword |
|beyondinsight_password_safe.managedsystem.data.port | Port | integer |
|beyondinsight_password_safe.managedsystem.data.timeout | Timeout |integer |
|beyondinsight_password_safe.managedsystem.data. sshKey_enforcement_mode | SSH key enforcement mode | integer |
|beyondinsight_password_safe.managedsystem.data.password_rule_id | Password rule id |integer |
|beyondinsight_password_safe.managedsystem.data.dss_key_rule_id | Dss key rule id | integer |
|beyondinsight_password_safe.managedsystem.data.login_account_id | Login account id | integer |
|beyondinsight_password_safe.managedsystem.data.account_name_format | Account name format | integer |
|beyondinsight_password_safe.managedsystem.data.Oracle_Internet_Directory_id | Oracle internet directory id | keyword |
|beyondinsight_password_safe.managedsystem.data.oracle_internet_directory_service_name | Oracle internet directory service name | keyword |
|beyondinsight_password_safe.managedsystem.data.release_duration | Release duration | integer |
|beyondinsight_password_safe.managedsystem.data.max_release_duration | Max release duration | integer |
|beyondinsight_password_safe.managedsystem.data.is_a_release_duration | Is a release duration | integer |
|beyondinsight_password_safe.managedsystem.data.auto_management_flag | Auto management flag | bool |
|beyondinsight_password_safe.managedsystem.data.functional_account_id | Functional account id | integer |
|beyondinsight_password_safe.managedsystem.data.elevation_command | Elevation command | keyword |
|beyondinsight_password_safe.managedsystem.data.check_password_flag | Check password flag | bool |
|beyondinsight_password_safe.managedsystem.data.change_password_after_any_release_flag | Change password after any release flag | bool |
|beyondinsight_password_safe.managedsystem.data.reset_password_on_mismatch_flag | Reset password on mismatch flag | bool |
|beyondinsight_password_safe.managedsystem.data.change_frequency_type | Change frequency type |keyword |
|beyondinsight_password_safe.managedsystem.data.change_frequency_days | Frequency days | integer |
|beyondinsight_password_safe.managedsystem.data.change_time | Change time | keyword |
|beyondinsight_password_safe.managedsystem.data.remote_client_type | Remote client type | keyword |
|beyondinsight_password_safe.managedsystem.data.application_host_id | Data application host id | integer |
|beyondinsight_password_safe.managedsystem.data.is_application_host | Is application host | bool |
|beyondinsight_password_safe.managedsystem.data.access_url | Access url | keyword |



### ManagedAccount

ManagedAccount documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.managedaccount"`.

Here is an example managedaccount document:

An example event for `managedaccount` looks as following:

```json
{
        "_index": ".ds-logs-beyondinsight_password_safe.managedaccount-default-2024.12.11-000001",
        "_id": "4J23rqov7peRAEhvv6gvy7hzsUA=",
        "_score": null,
        "_source": {
          "input": {
            "type": "cel"
          },
          "agent": {
            "name": "docker-fleet-agent",
            "id": "a7001b31-5e06-4cd3-98a6-150537020817",
            "ephemeral_id": "4394976e-aa96-433d-9872-979278c1dfcf",
            "type": "filebeat",
            "version": "8.12.2"
          },
          "beyondinsight_password_safe": {
            "managedaccount": {
              "is_isaaccess": true,
              "last_change_date": "2024-12-10T08:58:19.163Z",
              "account_id": "7",
              "is_changing": false,
              "default_release_duration": 120,
              "system_id": "7",
              "system_name": "BasketMuskOx",
              "account_name": "AsaZ.Suarez",
              "platform_id": "4",
              "preferred_node_id": "2ca45774-d4e0-4b8f-9b52-3f52b78ae2ca",
              "maximum_release_duration": 525600,
              "change_state": 0
            }
          },
          "@timestamp": "2024-12-11T12:24:27.579Z",
          "ecs": {
            "version": "8.11.0"
          },
          "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "beyondinsight_password_safe.managedaccount"
          },
          "host": {
            "hostname": "docker-fleet-agent",
            "os": {
              "kernel": "5.15.167.4-microsoft-standard-WSL2",
              "codename": "focal",
              "name": "Ubuntu",
              "type": "linux",
              "family": "debian",
              "version": "20.04.6 LTS (Focal Fossa)",
              "platform": "ubuntu"
            },
            "containerized": true,
            "ip": [
              "172.18.0.7"
            ],
            "name": "docker-fleet-agent",
            "id": "009f8d5d825944429c9ae8d252b0019a",
            "mac": [
              "02-42-AC-12-00-07"
            ],
            "architecture": "x86_64"
          },
          "elastic_agent": {
            "id": "a7001b31-5e06-4cd3-98a6-150537020817",
            "version": "8.12.2",
            "snapshot": false
          },
          "event": {
            "agent_id_status": "verified",
            "ingested": "2024-12-11T12:24:28Z",
            "kind": "event",
            "module": "beyondinsight_password_safe",
            "category": [
              "iam"
            ],
            "type": [
              "info"
            ],
            "dataset": "beyondinsight_password_safe.managedaccount"
          }
        },
        "sort": [
          1733919867579
        ]
      }
 
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in managedaccount documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| input.type | Input type | keyword |
|beyondinsight_password_safe.managedaccount.platform_id | Platform id | keyword |
|beyondinsight_password_safe.managedaccount.system_id | System id | keyword |
|beyondinsight_password_safe.managedaccount.system_name | System name | keyword |
|beyondinsight_password_safe.managedaccount.domain_name | Domain name | keyword |
|beyondinsight_password_safe.managedaccount.account_id | Account id | keyword |
|beyondinsight_password_safe.managedaccount.account_name | Account name | keyword |
|beyondinsight_password_safe.managedaccount.instance_name | Instance name | keyword |
|beyondtrust.asset. user_principal_name| User principal name | keyword |
|beyondinsight_password_safe.managedaccount.application_id | Applicaiton id | keyword |
|beyondinsight_password_safe.managedaccount.application_display_name | Application display name | keyword |
|beyondinsight_password_safe.managedaccount.default_release_duration | Defalut release duration | integer |
|beyondinsight_password_safe.managedaccount.maximum_release_duration | Maximum release duration | integer |
|beyondinsight_password_safe.managedaccount.last_change_date | Last change date | date |
|beyondinsight_password_safe.managedaccount. Next_change_date | Next change date | date |
|beyondinsight_password_safe.managedaccount.is_changing | Is changing | bool |
|beyondinsight_password_safe.managedaccount.change_state | Change state | integer |
|beyondinsight_password_safe.managedaccount.is_is_access | Is is access | bool |
|beyondinsight_password_safe.managedaccount.preferred_node_id | Preferred node id | keyword |

### Asset

Asset documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.asset"`.

Here is an example asset document:

An example event for `asset` looks as following:

```json
{
       
      }
 
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in asset documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| input.type | Input type | keyword |
|beyondinsight_password_safe.asset.workgroup_id | Workgroup id | keyword |
|beyondinsight_password_safe.asset.asset_id | Asset id | keyword |
|beyondinsight_password_safe.asset.asset_name | Asset name | keyword |
|beyondinsight_password_safe.asset.dns_name | DNS name | keyword |
|beyondinsight_password_safe.asset.domain_name | Domain name | keyword |
|beyondinsight_password_safe.asset. host.ip | Next change date | ip |
|beyondinsight_password_safe.asset.host.mac | Is changing | keyword |
|beyondinsight_password_safe.asset.asset_type | Change state | keyword |
|beyondinsight_password_safe.asset.os.name | Is is access | keyword |
|beyondinsight_password_safe.asset.create_date | Create date | date |
