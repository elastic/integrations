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

{{event "useraudit"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in useraudit documents:

{{fields "useraudit"}}

### Session

Session documents can be found by setting the filter `event.dataset :"beyondinsight_password_safe.session"`.

{{event "session"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in session documents:

{{fields "session"}}

### ManagedSystem

ManagedSystem documents can be found by setting the filter `event.dataset :"beyondinsight_password_safe.managedsystem"`.

{{event "managedsystem"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in managedsystem documents:

{{fields "managedsystem"}}

### ManagedAccount

ManagedAccount documents can be found by setting the filter `event.dataset :"beyondinsight_password_safe.managedaccount"`.

{{event "managedaccount"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in managedaccount documents:

{{fields "managedaccount"}}

### Asset

Asset documents can be found by setting the filter `event.dataset :"beyondinsight_password_safe.asset"`.

{{event "asset"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in asset documents:

{{fields "asset"}}
