### BeyondInsight integration

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

{{event "useraudit"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in useraudit documents:

**Exported fields**

{{fields "useraudit"}}



### Session

Session documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.session"`.

Here is an example session document:

{{event "session"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in session documents:

**Exported fields**

{{fields "session"}}

### ManagedSystem

ManagedSystem documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.managedsystem"`.

Here is an example managedsystem document:

{{event "managedsystem"}}



**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in managedsystem documents:

**Exported fields**

{{fields "managedsystem"}}



### ManagedAccount

ManagedAccount documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.managedaccount"`.

Here is an example managedaccount document:

{{event "managedaccount"}}



**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in managedaccount documents:

**Exported fields**

{{fields "managedaccount"}}

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
