# Workday

## Overview

[Workday](https://www.workday.com/en-in/homepage.html) is a cloud-based ERP system that manages business processes and allows organizations to use an integrated application. Workday is a coherent cloud ERP system for financial analysis, analytical solutions, HCM suites, and better business processes.

The Workday integration for Elastic collects `Activity` logs via the **Workday API** and `Sign-on` logs via the **Workday Custom Report API**, and visualizes them in Kibana.

### Compatibility

- The **Activity** data stream is compatible with Workday API version **v1**.
- The **Sign-on** data stream is compatible with Workday Custom Reports exposed via the **Reports as a Service (RaaS)** JSON endpoint (`/ccx/service/customreport2/...?format=json`).

### How it works

- **Activity**: This integration periodically queries the Workday API to retrieve Activity logs.
- **Sign-on**: This integration periodically downloads a Workday Custom Report (for example, a Sign-on report that lists sign-on records along with their key attributes) and ingests each report row as a single event.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Activity`: Collects [Activity Logs](https://community.workday.com/sites/default/files/file-hosting/restapi/#privacy/v1/get-/activityLogging) via the Workday API (endpoint: `/activityLogging`).
- `Sign-on`: Collects sign-on information from a Workday Custom Report via the Workday Reports as a Service (RaaS) JSON endpoint.

### Supported use cases

Integrating Workday with Elastic gives security and IT teams centralized visibility into **Workday activity logging** and **Workday sign-on data**, so you can monitor configuration and usage changes, track sign-on activity and access patterns, support audits, and investigate suspicious or unusual authentication behavior from Kibana.

The **Activity** dashboard summarizes key patterns such as **activity volume over time** and **top actors**, helping you spot unusual spikes and focus on the users and operations that matter. Built-in filters make it easier to narrow events by attributes such as **task**, **system account**, and **IP address**, which supports faster triage and a more consistent investigation workflow across your Workday telemetry.

## What do I need to use this integration?

### From Workday

#### For the Activity data stream

##### Enable User Activity Logging

1. Sign in to your Workday tenant as a Security Administrator.
2. In the Workday search bar, search for and open the Edit Tenant Setup - System task.
3. In the Security section, select the Enable User Activity Logging checkbox.
4. Click OK to save the changes.

**Note:** Once enabled, Workday records all user activity in a secure tenant database. Activity logging must be enabled before any logs are available for export.

##### Create Integration System User (ISU)

1. In the Workday search bar, search for Create Integration System User.
2. Enter a User Name (for example, ISU_SIEM_Export) and a strong Password.
3. Clear the Require New Password at Next Sign In checkbox.
4. Click OK.
5. Search for Create Security Group and create an Integration System Security Group (Unconstrained).
6. Add the ISU (ISU_SIEM_Export) to this security group.
7. Search for View Domain and locate the User Activity Logging domain. Grant Get access to the ISU security group for this domain.
8. Search for Activate Pending Security Policy Changes and activate the changes.

##### Register API client for OAuth

1. In the Workday search bar, search for Register API Client for Integrations.
2. Enter a Client Name (for example, SIEM_OAuth_Client).
3. Select the Non-Expiring Refresh Tokens option.
4. Add the scope: System (or the scope required for User Activity Logging API).
5. Click OK.
6. Copy and save the following details in a secure location:
   - Client ID: The API client identifier.
   - Client Secret: The API client secret.
7. Search for Manage Refresh Tokens for Integrations.
8. Select the ISU account (ISU_SIEM_Export).
9. Generate a new refresh token for the API client.
10. Copy and save the Refresh Token.

##### Determine tenant URL

The API endpoint is based on your Workday tenant. The format is:

Component   | Value

Token endpoint | https://HOST/ccx/oauth2/TENANT/token

Activity Logging API |	https://HOST/ccx/api/privacy/v1/TENANT/activityLogging

**Note:** Replace HOST with your Workday hostname and TENANT with your tenant name.

**Note:** For additional Workday API security context, see [Generating API Keys for the Workday API](https://workday.my.site.com/customercenter/article?no=000013105&redirect=false).

#### For the Sign-on data stream

##### Build the Sign-on custom report

1. Sign in to your Workday tenant as a user with report-authoring privileges.
2. In the Workday search bar, search for **Create Custom Report**.
3. Create an Advanced report on a data source that exposes sign-on activity (for example, `Signons and Attempted Signons`).
4. Add the columns required for sign-on analytics (for example, `System Account`, `Session Start`, `Session End`, `Authentication Type for Signon`, `Failed Signon`, `Invalid Credentials`, `Account Locked, Disabled or Expired`, `Browser Type`, `Operating System`, `Device Type`, `Request Originator`, `SAML Identity Provider`).
5. On the **Advanced** tab, select **Enable As Web Service** so the report is exposed as Reports as a Service (RaaS).
6. Save the report and note the **Report Name** and the **Report Owner** (the Workday account that owns the report).

##### Create the Integration System User (ISU)

1. In the Workday search bar, search for **Create Integration System User**.
2. Enter a User Name (for example, `ISU_SIEM_Export`) and a strong Password.
3. Clear the **Require New Password at Next Sign In** checkbox.
4. Click **OK**.
5. Search for **Create Security Group** and create an Integration System Security Group (Unconstrained).
6. Add the ISU (`ISU_SIEM_Export`) to this security group.
7. Grant the ISU security group access to the domain protecting the custom report's data source (for example, the `System Auditing` domain).
8. Search for **Activate Pending Security Policy Changes** and activate the changes.

##### Determine the report URL

The Custom Report endpoint URL has the following format:

```
https://HOST/ccx/service/customreport2/TENANT/REPORT_OWNER/REPORT_NAME?format=json
```

Where:

- `HOST` is your Workday hostname.
- `TENANT` is your Workday tenant name.
- `REPORT_OWNER` is the Workday account that owns the custom report.
- `REPORT_NAME` is the name of the custom report you created above.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Configure the integration

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Workday**.
3. Select the **Workday** integration from the search results.
4. Select **Add Workday** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect Workday Activity logs via API**, you'll need to:

        - Configure **Hostname**.
        - Configure **Tenant**.
        - Configure **Client ID**.
        - Configure **Client Secret**.
        - Configure **Refresh Token**.
        - Adjust the integration configuration parameters if required, including the **Interval**, **Initial Interval**, **Preserve original event** etc. to enable data collection.

    * To **Collect Workday Sign-on logs via Custom Report API**, you'll need to:

        - Configure **Report URL** with the full Workday Custom Report (RaaS) URL noted above.
        - Configure **Username** and **Password** for basic authentication against the Workday Custom Report API.
        - Adjust the integration configuration parameters if required, including the **Interval** and **Preserve original event** etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Workday**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Activity

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| workday.activity.activity_action | The type of action that was executed. | keyword |
| workday.activity.session_id | The system ID for tracking signons from the user signon used to make the request. | keyword |
| workday.activity.target.descriptor | The display name of the instance. | keyword |
| workday.activity.target.href | A link to the instance. | keyword |
| workday.activity.target.id | Workday Id or Reference Id of the instance. | keyword |
| workday.activity.task_display_name | The action executed in the transaction. | keyword |
| workday.activity.task_id | The Workday ID of the task executed in the transaction. | keyword |
| workday.activity.user_activity_entry_count | Returns the User Activity Count for the inputted filter parameters. | long |


#### Sign-on

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| workday.sign_on.Account | The Workday account associated with the sign-on (for example, the account user name and worker display name). | keyword |
| workday.sign_on.Account_Locked__Disabled_or_Expired | Whether the account was locked, disabled, or expired at the time of the sign-on. | boolean |
| workday.sign_on.Active_Session | Whether the session was still active at the time the report was generated. | boolean |
| workday.sign_on.Authentication_Channel | The channel through which the sign-on was performed (for example, Web, Mobile, API). | keyword |
| workday.sign_on.Authentication_Type | The authentication method used for the sign-on (for example, SAML, OAuth 2.0, Trusted, User Name Password, ID Token). | keyword |
| workday.sign_on.Authentication_Type_for_Signon | The authentication method used for the sign-on (for example, SAML, OAuth 2.0, Biometric, User Name Password). | keyword |
| workday.sign_on.Browser_Type | The browser or client application used for the sign-on (for example, Chrome, Workday Phone App). | keyword |
| workday.sign_on.Device_is_Trusted | Whether the device used for the sign-on is trusted. | boolean |
| workday.sign_on.Failed_Signon | Whether the sign-on attempt failed. | boolean |
| workday.sign_on.Forgotten_Password_Reset_Request | Whether the sign-on was associated with a forgotten password reset request. | boolean |
| workday.sign_on.Invalid_Credentials | Whether the sign-on attempt was made with invalid credentials. | boolean |
| workday.sign_on.Invalid_Password | Whether the sign-on attempt was made with an invalid password. | boolean |
| workday.sign_on.Is_Device_Managed | Whether the device used for the sign-on is managed. | boolean |
| workday.sign_on.Multi_Factor_Type | The type of multi-factor authentication used for the sign-on. | keyword |
| workday.sign_on.Password_Changed | Whether the password was changed during the sign-on. | boolean |
| workday.sign_on.Prompt___Positive_Integer | The sign-on prompt value as reported by Workday, typically the account name and worker display name. | keyword |
| workday.sign_on.Request_Originator | The originator of the sign-on request (for example, UI, Internal, Web Services). | keyword |
| workday.sign_on.Required_Multi_Factor | The type of multi-factor authentication required for the sign-on (for example, SMS, Email, Phone, Security Key). | keyword |
| workday.sign_on.SAML_Identity_Provider | The SAML identity provider used for the sign-on. | keyword |
| workday.sign_on.Session_ID | The Workday session identifier associated with the sign-on. | keyword |
| workday.sign_on.Signon | Whether the sign-on attempt was successful. | boolean |
| workday.sign_on.Successful | Whether the sign-on attempt was successful. | boolean |
| workday.sign_on.System_Account | The Workday system account associated with the sign-on (for example, the account user name and worker display name). | keyword |
| workday.sign_on.UI_Client_Type | The type of UI client used for the sign-on (for example, iPhone Native, Android Native). | keyword |
| workday.sign_on.Workday_Account | The Workday account associated with the sign-on (alternate report column name for System_Account). | keyword |
| workday.sign_on.session_ip_address_string | The originating IP address of the session (alternate report column name for Session_IP_Address). | keyword |
| workday.sign_on.signon_ip_address_string | The originating IP address of the sign-on (alternate report column name for Signon_IP_Address). | keyword |


### Example event

#### Activity

An example event for `activity` looks as following:

```json
{
    "@timestamp": "2026-04-02T12:46:18.012Z",
    "agent": {
        "ephemeral_id": "56b15ab2-aac3-4167-a87e-300667f9c510",
        "id": "49c06832-6dd8-4eea-8c9d-702a4bcee941",
        "name": "elastic-agent-15161",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "workday.activity",
        "namespace": "58781",
        "type": "logs"
    },
    "device": {
        "type": "desktop"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "49c06832-6dd8-4eea-8c9d-702a4bcee941",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "action": "read",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "workday.activity",
        "ingested": "2026-06-05T11:40:39Z",
        "kind": "event",
        "original": "{\"activityAction\":\"READ\",\"deviceType\":\"Desktop\",\"ipAddress\":\"127.0.0.1\",\"requestTime\":\"2026-04-02T12:46:18.012Z\",\"sessionId\":\"c7c6ff\",\"systemAccount\":\"wd-implementer\",\"taskDisplayName\":\"privacy/activityLogging/userActivity (GET) (v1 -  )\",\"taskId\":\"e67b812850dc100047be196f396d745f\",\"userAgent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ],
        "user": [
            "wd-implementer"
        ]
    },
    "source": {
        "ip": "127.0.0.1"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "workday-activity"
    ],
    "user": {
        "name": "wd-implementer"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "os": {
            "full": "Windows 10",
            "name": "Windows",
            "version": "10"
        },
        "version": "146.0.0.0"
    },
    "workday": {
        "activity": {
            "activity_action": "READ",
            "session_id": "c7c6ff",
            "task_display_name": "privacy/activityLogging/userActivity (GET) (v1 -  )",
            "task_id": "e67b812850dc100047be196f396d745f"
        }
    }
}
```

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following Workday APIs:

- **Activity**: [Workday Activity API documentation](https://community.workday.com/sites/default/files/file-hosting/restapi/#privacy/v1/get-/activityLogging).
- **Sign-on**: The Workday **Reports as a Service (RaaS)** JSON endpoint is used to fetch a user-defined Sign-on custom report:

```
GET https://HOST/ccx/service/customreport2/TENANT/REPORT_OWNER/REPORT_NAME?format=json
```
