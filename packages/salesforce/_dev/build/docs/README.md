# Salesforce Integration

## Overview

The Salesforce integration enables you to monitor your [Salesforce](https://www.salesforce.com/) instance. Salesforce is a customer relationship management (CRM) platform that supports businesses in managing marketing, sales, commerce, service, and IT teams from a unified platform accessible from anywhere.

You can use the Salesforce integration for:

- **Operational insights**: Gain valuable insights into your organization's login and logout activities and other operational events.

- **Data visualization**: Create detailed visualizations to monitor, measure, and analyze usage trends and key data, helping you derive actionable business insights.

- **Proactive alerts**: Set up alerts to minimize Mean Time to Detection (MTTD) and Mean Time to Resolution (MTTR) by referencing relevant logs during troubleshooting.

### How it works

Elastic Agent uses the Salesforce input to query the EventLogFile API and Real-Time Event Monitoring objects via SOQL over the REST API. `Login` and `Logout` data streams can collect from either EventLogFile or the `LoginEvent`/`LogoutEvent` platform events. The `Apex` data stream reads EventLogFile records; `SetupAuditTrail` data stream queries the `SetupAuditTrail` object. OAuth 2.0 authentication is provided through a Salesforce Connected App using either the JWT bearer flow or the Username-Password flow. Collection is interval-based, uses cursors to avoid duplicates, and supports backfilling with an initial time window.

- `login`: Collects information related to users who log in to Salesforce.
- `logout`: Collects information related to users who log out from Salesforce.
- `apex`: Collects information about various Apex events such as Callout, Execution, REST API, SOAP API, Trigger, and so on.
- `setupaudittrail`: Collects information related to changes users made in the organization's setup area for the last 180 days.

The Salesforce integration collects the following events using the Salesforce REST API:

- [Login EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.object\_reference.meta/object\_reference/sforce\_api\_objects\_eventlogfile\_login.htm)
- [Login Platform Events](https://developer.salesforce.com/docs/atlas.en-us.platform\_events.meta/platform\_events/sforce\_api\_objects\_logineventstream.htm)
- [Logout EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.object\_reference.meta/object\_reference/sforce\_api\_objects\_eventlogfile\_logout.htm)
- [Logout Platform Events](https://developer.salesforce.com/docs/atlas.en-us.platform\_events.meta/platform\_events/sforce\_api\_objects\_logouteventstream.htm)
- [Apex EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.object\_reference.meta/object\_reference/sforce\_api\_objects\_eventlogfile.htm)
- [SetupAuditTrail Object](https://developer.salesforce.com/docs/atlas.en-us.object\_reference.meta/object\_reference/sforce\_api\_objects\_setupaudittrail.htm)

## Compatibility

This integration has been tested against the Salesforce Winter '26 (v65.0). The minimum supported version is v46.0.

To determine your Salesforce instance version, use one of the following methods:

- Salesforce Classic

  On the `Home` tab in Salesforce Classic, you can find a link in the top right corner that indicates the current release version of your Salesforce instance, for example `Summer '24 for Developers`.

- Use the Salesforce instance URL

  Use your Salesforce instance URL in the following format: `<instance URL>/services/data` (for example, `https://na9.salesforce.com/services/data`). In this example, `https://na9.salesforce.com` is the instance URL.

  Requesting the URL returns an XML response listing all available versions:

```xml
<Version>
    <label>Spring '25</label>
    <url>/services/data/v63.0</url>
    <version>63.0</version>
</Version>
<Version>
    <label>Summer '25</label>
    <url>/services/data/v64.0</url>
    <version>64.0</version>
</Version>
<Version>
    <label>Winter '26</label>
    <url>/services/data/v65.0</url>
    <version>65.0</version>
</Version>
```

The last entry in the list indicates the current version of your Salesforce instance. In this example, the current version is `Winter '26 (v65.0)`.

## What data does this integration collect?

The Salesforce integration collects the following data streams:

- `login`: Collects information related to users who log in to Salesforce.
- `logout`: Collects information related to users who log out from Salesforce.
- `apex`: Collects information about various Apex events such as `ApexCallout`, `ApexExecution`, `ApexRestApi`, `ApexSoap`, `ApexTrigger`, and `ExternalCustomApexCallout`.
- `setupaudittrail`: Collects information related to changes users made in the organization's setup area for the last 180 days.

The Salesforce integration collects the following events using the Salesforce REST API:

- For `login` — [Login EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_login.htm) and [Login Platform Events](https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/sforce_api_objects_logineventstream.htm)
- For `logout` — [Logout EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile_logout.htm) and [Logout Platform Events](https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/sforce_api_objects_logouteventstream.htm)
- For `apex` — [Apex EventLogFile](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_eventlogfile.htm)
- For `setupaudittrail` — [SetupAuditTrail Object](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_setupaudittrail.htm)

## What do I need to use this integration?

- You need Elasticsearch to store and search your data and Kibana to visualize and manage it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

- Make sure API Enabled permission is selected for the user profile in your Salesforce instance:

  1. Go to `Setup` > `Quick Find` and type `Users`.
  2. Select `Users` from the left navigation tree.
  3. In the `Full Name` column, select the name associated with the user account used for data collection.
  4. Search for the `API Enabled` permission on the profile page. If it’s not present, search under `System Permissions` and check if the `API Enabled` privilege is selected. If not, enable it for data collection.

- Make sure that collecting data using [Real-Time Event Monitoring API](https://help.salesforce.com/s/articleView?id=sf.real_time_event_monitoring_enable.htm&type=5) is enabled:

  1. Go to `Setup` > `Quick Find` and type `Event Manager`.
  2. Select `Event Manager` from the left navigation tree.
  3. To monitor an event, for example, Login Event, or Logout Event, click the dropdown arrow and select `Enable Storage`.
  4. Check if you have the required permissions: `View Real-Time Event Monitoring Data`.

NOTE: Real-Time Event Monitoring may require additional licensing. Check your subscription level with your Salesforce account representative.

## How do I deploy this integration?

For step-by-step instructions on how to set up an integration, see {{ url "getting-started-observability" "Getting started" }}.

### Onboard and configure

1. Install Elastic Agent and enroll it in Fleet.
2. In Fleet, add the Salesforce integration and enable the `apex`, `login`, `logout`, and/or `setupaudittrail` data streams as needed.
3. Enter your Salesforce instance URL and API version.
4. Choose an authentication method:
   - JWT bearer flow: set Client ID, Username, Private key path (PEM), and JWT audience URL.
   - Username‑Password flow: set Client ID, Client Secret, Username, Password (+ security token if required), and Token URL (base domain).
5. For `login` and `logout`, choose which sources to collect:
   - EventLogFile (batch logs)
   - Platform Events (`LoginEvent`, `LogoutEvent`)
6. Optional tuning:
   - Set an initial interval to backfill historical data.
   - Adjust the collection interval per source.
   - Optionally filter EventLogFile by log file interval (for example, hourly).
   - In Advanced options, adjust the request timeout if Salesforce responses are slow.

### Configuration

To configure the Salesforce integration, you need the following information:

- [Salesforce instance URL](#salesforce-instance-url)
- [Authentication methods](#authentication-methods): choose one of the following and gather the required values:
  - JWT bearer flow: Client ID, Username, JWT audience URL, Private key path (PEM)
  - Username-Password flow: Client ID, Client Secret, Username, Password (+ security token if required), Token URL (base domain)
- [API version](#api-version)

#### Authentication methods

Choose one of the following OAuth 2.0 flows when configuring authentication:

##### JWT bearer flow

- Use a Salesforce Connected App with a certificate/private key.
- Required settings include: Client ID, Username, JWT audience URL, and the path to the private key file.
- In the integration settings, enable `Enable JWT Authentication`.

##### Username-Password flow

- Uses a Connected App with client secret and a named integration user.
- Required settings include: Client ID, Client Secret, Username, Password (append security token if required), and the Token URL (or your custom domain).
- Suitable for quick setup.
  
NOTE: Leave `Enable JWT Authentication` disabled to use the Username-Password flow.

#### Salesforce instance URL

This is the URL of your Salesforce organization.

- **Salesforce Classic**: Given the example URL https://na9.salesforce.com/home/home.jsp, the Salesforce Instance URL is extracted as https://na9.salesforce.com.

- **Salesforce Lightning**: The instance URL is available under your user name in the `View Profile` tab. Use the correct instance URL in case of Salesforce Lightning because it uses *.lightning.force.com but the instance URL is *.salesforce.com.

#### Create a Connected App

Create a Salesforce Connected App (supports both JWT Bearer and Username-Password flows):

1. Log in to Salesforce (Lightning UI).
2. From `Setup`, in `Quick Find` enter `External Client Apps` and select `Settings`. Turn on `Allow creation of connected apps`. To create a connected app, select `New Connected App`.
3. Fill `Basic Information`: `Connected App Name`, `API Name`, `Contact Email`.
4. In `API (Enable OAuth Settings)`, check `Enable OAuth Settings`.
5. `Callback URL`:
   - Web apps: your app callback (for example, `https://yourapp.example.com/callback`).
   - Not used by the JWT or Username-Password flows, but Salesforce requires a value; you can enter your instance URL.
6. Select OAuth scopes:
   - `Manage user data via APIs (api)`
   - `Perform requests at any time (refresh_token, offline_access)`
   - (Optional) `Full access (full)`
7. Click `Save`. It can take up to 10 minutes for the Connected App to propagate.
8. After saving, open `Manage Consumer Details` to obtain `Consumer Key` and `Consumer Secret`.

JWT Bearer flow (optional, recommended method):

1. Generate an RSA key pair and a certificate (PEM) for signing.
2. In the Connected App, upload the certificate in `Use digital signatures` (under `API (Enable OAuth Settings)`) for JWT.
3. Note the audience URL to use (typically `https://login.salesforce.com` or `https://test.salesforce.com` for sandbox).
4. In Elastic, set `Client ID`, `Username`, `Private key path (PEM)`, and `JWT audience URL`.

Username-Password flow (alternative):

1. Use the `Connected App`'s `Consumer Key` and `Consumer Secret`.
2. In Elastic, set `Username`, `Password` (append security token if required), `Client ID`, `Client Secret`, and `Token URL` (instance base domain; `/services/oauth2/token` is appended internally).

IMPORTANT: For security reasons, Salesforce blocks the OAuth 2.0 Username-Password flow by default in recent releases. Prefer the JWT bearer flow. If you must use the Username-Password flow, in `OAuth and OpenID Connect Settings`, select `Allow OAuth Username-Password Flows`. For more information, see the Salesforce release note: [Username-Password OAuth flow blocked by default](https://help.salesforce.com/s/articleView?id=release-notes.rn_security_username-password_flow_blocked_by_default.htm&language=en_US&release=244&type=5).

For official steps, see Salesforce docs: [Create a Connected App (Basics)](https://help.salesforce.com/s/articleView?id=xcloud.connected_app_create_basics.htm&type=5), [OAuth 2.0 JWT Bearer Flow](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_jwt_flow.htm&type=5), and [OAuth 2.0 Username-Password Flow](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_username_password_flow.htm&type=5)

#### Username

The email address or username associated with your Salesforce account used for authentication.

#### Password

The password used to authenticate the user with your Salesforce instance.

When using a Salesforce instance with a security token, append the token directly to your password without spaces or special characters. For example, if your password is `password` and your security token is `12345`, enter: `password12345`.

#### Token URL

The Salesforce integration uses the token URL to obtain authentication tokens for API access. **Important:** The integration internally appends `/services/oauth2/token` to the URL you provide, so you should enter only the base URL.

1. For most Salesforce instances, enter: `https://login.salesforce.com`
2. For Salesforce sandbox environments, enter: `https://test.salesforce.com`
3. For custom Salesforce domains, enter your custom domain base URL. For example, if your custom domain is `mycompany.my.salesforce.com`, enter: `https://mycompany.my.salesforce.com`

In most cases, the Token URL is the same as the Salesforce instance URL.

NOTE: Salesforce Lightning users must use a URL with the `*.salesforce.com` domain (the same as the instance URL) instead of `*.lightning.force.com` because the Salesforce API does not work with `*.lightning.force.com`.

#### API version

To find the API version:

1. Go to `Setup` > `Quick Find` > `Apex Classes`.
2. Click `New`.
3. Click the `Version Settings` tab.
4. Refer to the `Version` dropdown for the API Version number.

Alternatively, you can use the Salesforce instance API version as described in the "Compatibility" section.

### Validation

Once the Salesforce integration is successfully configured, follow these steps to validate the setup:

1. Navigate to the `Assets` tab in the Salesforce Integration. You will find a list of available dashboards related to your configured data streams.
2. Select the dashboard relevant to your data stream (for example, login, logout, apex, setupaudittrail).
3. Verify that the dashboard is populated with the expected data.

If the dashboard displays the data correctly, your integration is successfully validated.

## Dashboards

This integration ships curated Kibana dashboards for each data stream. After data starts flowing, open the Salesforce integration and go to the Assets tab to launch:

- Apex dashboard
- Login dashboard
- Logout dashboard
- SetupAuditTrail dashboard

## Migration (v0.15.0+)

With version 0.15.0, we've significantly enhanced the Salesforce integration, introducing major changes in data collection mechanisms, authentication, and data streams. Due to these changes, we recommend using Salesforce integration v0.15.0 or above and uninstalling previous versions.

### Key enhancements

1. Unified data collection: The integration now uses a single Filebeat input ([Salesforce input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-salesforce.html)) for data collection from EventLogFile and Real-time Event Monitoring APIs.
2. JWT authentication: Introduced JWT authentication mechanism.
3. Expanded configuration options: Added `initial_interval` and other options to fine-tune data collection, including historical data retrieval.
4. Change in data-collection mechanism: Replaced Streaming API (cometd) with Real-time Event Monitoring APIs.
5. Performance optimization: Significantly reduced CPU and memory usage during data collection.
6. Enhanced dashboards: Improved visualizations.

### Breaking changes

1. Data stream consolidation: Reduced from 6 to 4 data streams — `apex`, `login`, `logout`, and `setupaudittrail`.
2. Field mapping updates: Modified mappings for multiple fields.
3. Additional changes: Several other adjustments have been made to improve the overall performance and functionality of the integration.

## Troubleshooting

This section provides solutions to common issues you might encounter while using the Salesforce integration.

### Request timeout

If you experience delays in the response from the Salesforce server in the `apex`, `login`, `logout`, or `setupaudittrail` data streams, you might encounter a similar error:

```
Error while processing http request: failed to execute rf.collectResponse: failed to execute http client.Do: failed to execute http client.Do: failed to read http.response.body
```

**Solution:** Consider increasing the `Request timeout` setting in the `Advanced options` section for the affected data stream.

### Data ingestion error

If you encounter data ingestion errors, you might get the following error message:

> 400 Bad Request

**Solution:** Make sure that the `API Enabled` permission is granted to the `profile` associated with the `username` used for the integration. For more information, check the [What do I need to use this integration?](#what-do-i-need-to-use-this-integration) section.

If the error persists, follow these steps:

1. Navigate to `Setup` > `Quick Find` > `App Manager`.
2. Locate the app and click the corresponding arrow to view available actions.
3. Click `View`.
4. Obtain the client key and secret by clicking on `Manage Consumer Details` in the API section.
5. Click `Manage` to edit the policies.
6. Click `Edit Policies` and choose `Relax IP restrictions` from the dropdown menu for IP Relaxation.

### Validate OAuth 2.0 authentication with Salesforce Connected App

```sh
CLIENT_ID="" # Replace with your client ID
CLIENT_SECRET="" # Replace with your client secret
USERNAME="" # Replace with your Salesforce username
PASSWORD="" # Replace with your Salesforce password
SECURITY_TOKEN=""  # Replace with your Salesforce security token (if applicable). Else, leave it blank.
TOKEN_URL="https://<your-instance>.my.salesforce.com/services/oauth2/token" # Replace with your Salesforce instance URL

curl -v -X POST "${TOKEN_URL}" \
     -d "grant_type=password" \
     -d "client_id=${CLIENT_ID}" \
     -d "client_secret=${CLIENT_SECRET}" \
     -d "username=${USERNAME}" \
     -d "password=${PASSWORD}${SECURITY_TOKEN}"
```

NOTE: The script has been tested on Unix-based systems (macOS, Linux). If you use a different operating system, you might need to adjust the command accordingly.

This command is useful for debugging and troubleshooting OAuth 2.0 authentication with Salesforce Connected Apps. It is recommended to use a tool like `curl` for testing OAuth 2.0 authentication before setting up the full Salesforce integration. This approach allows you to verify the authentication process and identify any potential issues early when setting up the full Salesforce integration. If the request is successful, the response will contain an access token that can be used to authenticate subsequent requests to the Salesforce API. If the request fails, the response will contain an error message indicating the reason for the failure.

## Performance and scaling

- Collection intervals: Longer intervals reduce API usage and agent load; shorter intervals increase freshness at the cost of API calls and resource usage.
- Backfill: Use the initial interval to safely ingest historical data. Large backfills may consume significant Salesforce API quotas; consider staging by data stream.
- Login/Logout sources: EventLogFile is efficient for batched reporting; Platform Events provide lower‑latency signals but may have throughput and retention limits in your org.
- Timeouts: Increase the request timeout in Advanced options if Salesforce responses are slow or large result sets are expected.

## Reference

### Inputs used in this integration

- Salesforce input: https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-salesforce.html

### Logs reference

#### Apex

The `apex` data stream captures events related to Apex operations, enabling developers to access the Salesforce platform back-end database and client-server interfaces to create third-party SaaS applications.

{{event "apex"}}

{{fields "apex"}}

#### Login

The `login` data stream captures events that detail the login history of users within your Salesforce organization. This data stream provides insights into user authentication activities, helping you monitor and analyze login patterns, detect anomalies, and ensure security compliance.

{{event "login"}}

{{fields "login"}}

#### Logout

The `logout` data stream captures events that detail the logout history of users within your Salesforce organization. This data stream provides insights into user authentication activities, helping you monitor and analyze logout patterns, detect anomalies, and ensure security compliance.

{{event "logout"}}

{{fields "logout"}}

#### SetupAuditTrail

The `setupaudittrail` data stream captures and records changes made by users in the organization's Setup area. By default, it collects data from the last week, but users can configure it to collect data from up to the last 180 days by adjusting the initial interval in the configuration.

{{event "setupaudittrail"}}

{{fields "setupaudittrail"}}
