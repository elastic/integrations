# BeyondInsight integration

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
| beyondinsight_password_safe.useraudit.section | Section or feature where the action took place | keyword |
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
| beyondinsight_password_safe.session.sessionid |  ID of the Session. | keyword |
| beyondinsight_password_safe.session.user_id | ID of the user that requested the session | keyword |
| event.start | Session state time | date |
| event.end | Session end date | date |
| beyondinsight_password_safe.session.status | Session status 0: Not Started 1: In Progress 2: Completed 5: Locked 7: Terminated (deprecated) 8: Logged Off 9: Disconnected (RDP only) | integer |
 beyondinsight_password_safe.session.ArchiveStatus | Session archive status (applicable only when Session Archiving is enabled and configured) 0: Not Archived 1: Archived 2: Restoring (from Archive Repository) 3: Archiving (from Node) 4: Session Not Found (in Archive Repository) 5: Archive Repository Offline/Inaccessible 6: Unknown | integer |
| beyondinsight_password_safe.session.duration | Session duration | integer |
| beyondinsight_password_safe.session.asset_name | Name of the target Managed System. | keyword |
| beyondinsight_password_safe.session.record_key | The Record Key used for Session replay. | keyword |
| beyondinsight_password_safe.session.protocol | Session protocol 0: RDP 1: SSH | keyword |
| beyondinsight_password_safe.session.ManagedSystemID | ID of the target Managed System. | integer |
| beyondinsight_password_safe.session.ManagedAccountID | ID of the target Managed Account. | integer |
| beyondinsight_password_safe.session.ManagedAccountName | Name of the target Managed Account. | keyword |


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
|beyondinsight_password_safe.managedsystem.data.managed_system_id | ID of the managed system | integer |
|beyondinsight_password_safe.managedsystem.data.entity_type_id | Entity type id | integer |
|beyondinsight_password_safe.managedsystem.data.asset_id | Asset ID; set if the managed system is an asset or a database | integer |
|beyondinsight_password_safe.managedsystem.data.database_id | Database ID; set if the managed system is a database | integer |
|beyondinsight_password_safe.managedsystem.data.directory_id | Directory ID; set if the managed system is a directory | integer |
|beyondinsight_password_safe.managedsystem.data.cloud_id | Cloud system ID; set if the managed system is a cloud system | integer |
|beyondinsight_password_safe.managedsystem.data.system_name | Name of the related entity (asset, directory, database, or cloud). | keyword |
|beyondinsight_password_safe.managedsystem.data.timeout | Timeout | integer |
|beyondinsight_password_safe.managedsystem.data.platform_id | ID of the managed system platform. | integer |
|beyondinsight_password_safe.managedsystem.data.net_bios_name | (Managed domains only) Domain NetBIOS name. Setting this value will allow Password Safe to fall back to the NetBIOS name if needed | keyword |
|beyondinsight_password_safe.managedsystem.data.contact_email | Contact email | keyword |
|beyondinsight_password_safe.managedsystem.data.description | Description | keyword |
|beyondinsight_password_safe.managedsystem.data.port | The port used to connect to the host. If null and the related Platform.PortFlag is true, Password Safe uses Platform.DefaultPort for communication | integer |
|beyondinsight_password_safe.managedsystem.data.timeout | (seconds) Connection timeout. Length of time in seconds before a slow or unresponsive connection to the system fails. |integer |
|beyondinsight_password_safe.managedsystem.data. sshKey_enforcement_mode | Enforcement mode for SSH host keys. 0: None.1: Auto. Auto accept initial key.2: Strict. Manually accept keys. | integer |
|beyondinsight_password_safe.managedsystem.data.password_rule_id | ID of the default password rule assigned to managed accounts created under this managed system|integer |
|beyondinsight_password_safe.managedsystem.data.dss_key_rule_id | ID of the default DSS key rule assigned to managed accounts created under this managed system | integer |
|beyondinsight_password_safe.managedsystem.data.login_account_id | ID of the functional account used for SSH session logins | integer |
|beyondinsight_password_safe.managedsystem.data.account_name_format | Account name format | integer |
|beyondinsight_password_safe.managedsystem.data.Oracle_Internet_Directory_id | Oracle internet directory id | keyword |
|beyondinsight_password_safe.managedsystem.data.oracle_internet_directory_service_name | Oracle internet directory service name | keyword |
|beyondinsight_password_safe.managedsystem.data.release_duration | (minutes: 1-525600) Default release duration. | integer |
|beyondinsight_password_safe.managedsystem.data.max_release_duration | (minutes: 1-525600) Default maximum release duration | integer |
|beyondinsight_password_safe.managedsystem.data.is_a_release_duration | (minutes: 1-525600) Default Information Systems Administrator (ISA) release duration | integer |
|beyondinsight_password_safe.managedsystem.data.auto_management_flag | True if password auto-management is enabled, otherwise false. | bool |
|beyondinsight_password_safe.managedsystem.data.functional_account_id | ID of the functional account used for local managed account password changes. | integer |
|beyondinsight_password_safe.managedsystem.data.elevation_command | Elevation command to use (sudo, pbrun, pmrun). | keyword |
|beyondinsight_password_safe.managedsystem.data.check_password_flag | True to enable password testing, otherwise false. | bool |
|beyondinsight_password_safe.managedsystem.data.change_password_after_any_release_flag |True to change passwords on release of a request, otherwise false. | bool |
|beyondinsight_password_safe.managedsystem.data.reset_password_on_mismatch_flag | True to queue a password change when scheduled password test fails, otherwise false.
 | bool |
|beyondinsight_password_safe.managedsystem.data.change_frequency_type | The change frequency for scheduled password changes |keyword |
|beyondinsight_password_safe.managedsystem.data.change_frequency_days | (days: 1-90) When ChangeFrequencyType is xdays, password changes take place this configured number of days. | integer |
|beyondinsight_password_safe.managedsystem.data.change_time | (24hr format: 00:00-23:59) UTC time of day scheduled password changes take place. | keyword |
|beyondinsight_password_safe.managedsystem.data.remote_client_type | The type of remote client to use. None: No remote client.EPM: Endpoint Privilege Management. | keyword |
|beyondinsight_password_safe.managedsystem.data.application_host_id | Managed system ID of the target application host. Must be an ID of a managed system whose IsApplicationHost = true. | integer |
|beyondinsight_password_safe.managedsystem.data.is_application_host | True if the managed system can be used as an application host, otherwise false. Can be set when the Platform.ApplicationHostFlag = true, and cannot be set when ApplicationHostID has a value. | bool |
|beyondinsight_password_safe.managedsystem.data.access_url | The URL used for cloud access (applies to cloud systems only). | keyword |



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
|beyondinsight_password_safe.managedaccount.platform_id | ID of the managed system platform | keyword |
|host.id | ID of the managed system | keyword |
|host.hostname | Name of the managed system | keyword |
|host.domain | The domain name for a domain-type account | keyword |
|user.id | ID of the managed account | keyword |
|user.name | Name of the managed account | keyword |
|beyondinsight_password_safe.managedaccount.instance_name | Database instance name of a database-type managed system, or empty for the default instance | keyword |
|beyondtrust.asset. user_principal_name| User Principal Name of the managed account | keyword |
|beyondinsight_password_safe.managedaccount.application_id | ID of the application for application-based access | keyword |
|beyondinsight_password_safe.managedaccount.application_display_name | Display name of the application for application-based access | keyword |
|beyondinsight_password_safe.managedaccount.default_release_duration | Default release duration | integer |
|beyondinsight_password_safe.managedaccount.maximum_release_duration | Maximum release duration | integer |
|beyondinsight_password_safe.managedaccount.last_change_date | The date and time of the last password change | date |
|beyondinsight_password_safe.managedaccount. Next_change_date | The date and time of the next password change | date |
|beyondinsight_password_safe.managedaccount.is_changing | True if the account credentials are in the process of changing, otherwise false | bool |
|beyondinsight_password_safe.managedaccount.change_state | ChangeState: The change state of the account credentials: 0: Idle / no change taking place or scheduled within  minutes. 1: Changing / managed account credential currently changing. 2: Queued / managed account credential is queued to change or scheduled to change within 5 minutes. | integer |
|beyondinsight_password_safe.managedaccount.is_is_access | True if the account is for Information Systems Administrator (ISA) access, otherwise false. | bool |
|beyondinsight_password_safe.managedaccount.preferred_node_id | ID of the node that is preferred for establishing sessions. If no node is preferred, returns the local node ID | keyword |

### Asset

Asset documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.asset"`.

Here is an example asset document:

An example event for `asset` looks as following:

```json
{
        "_index": ".ds-logs-beyondinsight_password_safe.assets-default-2024.12.17-000003",
        "_id": "rODK63iwttrLrnvuyG8+/D7xxMw=",
        "_score": null,
        "_ignored": [
          "beyondinsight_password_safe.assets.last_update_date"
        ],
        "_source": {
          "input": {
            "type": "cel"
          },
          "agent": {
            "name": "docker-fleet-agent",
            "id": "a447c2bb-3c3f-4aa0-a636-cb93aaeab324",
            "ephemeral_id": "a5cec388-f06a-4cd8-9a13-1b4c1339993c",
            "type": "filebeat",
            "version": "8.12.2"
          },
          "beyondinsight_password_safe": {
            "assets": {
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
          "@timestamp": "2024-12-17T07:40:23.678Z",
          "ecs": {
            "version": "8.11.0"
          },
          "os": {
            "name": "ExampleOS"
          },
          "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "beyondinsight_password_safe.assets"
          },
          "elastic_agent": {
            "id": "a447c2bb-3c3f-4aa0-a636-cb93aaeab324",
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
              "172.18.0.4",
              "172.16.201.219",
              "172.16.201.219"
            ],
            "name": "docker-fleet-agent",
            "id": "009f8d5d825944429c9ae8d252b0019a",
            "mac": [
              "02-42-AC-12-00-04",
              ""
            ],
            "architecture": "x86_64"
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
          }
        },
        "sort": [
          1734421223678
        ]
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
|host.domain | Domain name | keyword |
|host.ip | Host IP address | ip |
|beyondinsight_password_safe.asset.asset_type | Asset type | keyword |
|os.name | Operating System | keyword |
|beyondinsight_password_safe.asset.create_date | Create date | date |
|beyondinsight_password_safe.asset.last_update_date | Last update date | date |
