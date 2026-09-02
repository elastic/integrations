# Box Events Integration

The Box Events integration allows you to monitor [Box](https://app.box.com/). Box is a secure cloud storage and collaboration service that allows businesses and individuals to easily share files. 

Use the Box Events integration to ingest the activity logs which are generated each time files are uploaded, accessed, or modified in Box, enabling you to monitor data movement to the cloud. If you have [opted-in to receive additional events](https://developer.box.com/guides/events/event-triggers/shield-alert-events/), the Box Events integration will ingest context-rich alerts on potential threats, such as compromised accounts and data theft, based on anomalous user behavior. Combining this data with other events can lead to the detection of data exfiltration attacks.

Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference `box_events.events` when troubleshooting an issue.

## Elastic Managed enabled integration

Elastic Managed integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Elastic Managed integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

For example, if you wanted to set up notifications for incoming Box Shield alerts you could verify that this data is being ingested from the `Box Shield Alerts` Dashboard. Then, go to `Alerts and Insights / Rules and Connectors` in the sidebar and set up a Rule using an Elasticsearch Query against index `*box*alert*` with time field `@timestamp` and DSL 

```
{
  "query":{
    "match" : {
      "event.kind": "alert"
    }
  }
}
```

to match incoming box alerts during your desired timeframe and notify you using your preferred connector.

## Compatibility

The Box Web Application does not feature version numbers, see this [Community Post](https://support.box.com/hc/en-us/community/posts/1500000033881/comments/1500000038001). This integration was configured and tested against Box in the second quarter of 2022.

## Upgrading to version 4.x

Version 4.0.0 changes the code used to collect events from Box. This update fixes a bug that could occasionally cause small gaps in your data.

### Before you upgrade

- **Check your `stream_type` setting**  
  This determines how far back events may temporarily reappear after upgrading - see the table below. If you're not sure what yours is set to, check your integration policies before upgrading.
- **No other action is required**  
  The upgrade is safe to run as-is once you know what to expect for your setup. It's most noticeable if you're on `admin_logs`, where events from up to a year back may be collected again.

### What happens after you upgrade

- **You'll need to re-enter your Box credentials**  
  Go to your integration policy and re-enter your Client ID, Client Secret, and Box Subject ID. This is a one-time step.
- **You'll see some old events collected again**  
  The integration will briefly restart collection from further back in your Box history, so events you've already ingested may be requested a second time. This is expected and temporary - it won't create duplicate records in your data (see below).
- **How far back it goes depends on your stream type**  
  If you're using `admin_logs`, the type with the longest history available, expect the collection to take longer to finish processing. If you don't need to fill a data gap older than 14 days, it's recommended you switch from `admin_logs` to `admin_logs_streaming`.

  | Stream Type            | Maximum Data |
  |------------------------|-------------:|
  | `all` (default)        |      21 days |
  | `admin_logs_streaming` |      14 days |
  | `admin_logs`           |     365 days |
  | `changes`              |      21 days |
  | `sync`                 |      31 days |

- **You won't end up with duplicate events**  
  As long as you keep using the same setup you have today and don't manually roll over the data stream to a new backing index.

## Box Events

The Box events API enables subscribing to live events across the enterprise or for a particular user, or querying historical events across the enterprise.

The API Returns up to a year of past events for configurable to the `admin` user (default) or for the entire enterprise.

### Elastic Integration for Box Events Settings

The Elastic Integration for Box Events requires the following Authentication Settings in order to connect to the Target service:
  - Client ID
  - Client Secret
  - Box Subject ID
  - Box Subject Type
  - Grant Type

The Elastic Integration for Box Events requires the following Data Stream Settings to configure the request to the Target API:
  - Interval
  - Stream Type
  - Preserve Original Event

Here is a brief guide to help you generate these settings

### Target Repository Authentication Settings Prerequisites
The Elastic Integration for Box Events connects using OAuth 2.0 to interact with a Box Custom App. As prerequisites you will need to:
  - Enable `MFA/2FA` on your admin account by following the instructions in [MFA Setup on Box Support](https://support.box.com/hc/en-us/articles/360043697154-Multi-Factor-Authentication-Set-Up-for-Your-Account)
  - Configure a `Box Custom Application using Server Authentication `    
  `(with Client Credentials Grant)`. A suggested workflow is provided below, see [Setup with OAuth 2.0](https://developer.box.com/guides/authentication/oauth2/oauth2-setup/) for additional information.

### Authorized User
It is important to login to the [Box Developer Console](https://app.box.com/developers/console) as an `admin` and not `co-admin`.

## A suggested workflow is as follows:

### Create a `Custom Application using Server Authentication (with Client Credentials Grant) authentication`
  1. Open the [Box Developer Console](https://app.box.com/developers/console)
  2. Click on `Create new App`
  3. Click on `Custom App`
  4. Select `Server Authentication (Client Credentials Grant)`
  5. Provide an App name, for example `elastic-box-integration`
  6. Click on `Create App` 
  7. When your App has been created, scroll down and under `App Access Level` select `App + Enterprise Access`
  8. Scroll down to `Application Scopes` and under `Administrative Actions` select 
    - `Manage users`
    - `Manage enterprise properties`
  9. Scroll down to `Advanced Features` and select 
    - `Generate user access tokens`
  10. Click on `Save Changes`

### Submit the application for Authorization from the [Box Developer Console](https://app.box.com/developers/console)
  1. In the left side bar, at the bottom, click on `</> Dev Console`
  2. Click on your application, which should now have an extra `Authorization` tab, so click on this
  3. Click on `Review and Submit`, add a comment to explain your changes then click on `Submit`.

### Authorize the Application from the [Box Admin Console](https://app.box.com/master)
If you are the `admin` user you can do this yourself, otherwise reach out to the admin to confirm your motives and request that they authorize your request, since there may be some delay before they are aware of your request.

To authorize the App ensure you are logged in to the [Admin Console](https://app.box.com/master) and follow these steps:

  1. In the left side bar click on [Apps](https://app.box.com/master/settings/apps)
  2. Click on the [Custom Apps Manager](https://app.box.com/master/custom-apps) tab, you should see your App under `Server Authentication Apps` and the `Authorisation Status` should be `Pending Reauth`
  3. Click on your App, it should have the following `App Details`:
    - Last Activity
      - `<date>`
    - Developer Email
      - `<your email>`
    - Authorization Status
      - `Pending Reauthorization`
    - Enablement Status
      - `Enabled`
    - Client ID
      - `<alphanumeric id>`
    - App Access
      - `All Users`
    - App Scopes
      - `Read and write all files and folders stored in Box`
      - `Manage enterprise properties`
      - `Manage users`
      - `Manage app users`
      - `Generate user access tokens`
    - Authentication Type
      - `OAuth 2.0 with Client Credentials Grant`
  4. Click on `Authorize` - a pop up will reconfirm these details
  5. Click on `Authorize` - the Authorization Status should update to 
    - Authorized

### Locate the Elastic Integration for Box Events Settings

#### Client ID
Click on your App in the [Box Developer Console](https://app.box.com/developers/console), under the `Configuration` tab, scroll down to `OAuth 2.0 Credentials` and copy the `Client ID`

####  Client Secret
Have your 2FA device prepared and to hand. Click on your App in the [Box Developer Console](https://app.box.com/developers/console), under the `Configuration` tab, scroll down to `OAuth 2.0 Credentials` and click on `Fetch Client Secret`. Complete the 2FA challenge to copy the `Client Secret`

####  Box Subject ID
Click on your App in the [Box Developer Console](https://app.box.com/developers/console), under the `General Settings` tab, scroll down to `App Info`. If you intend to harvest events solely for the `admin` user copy the `User ID` otherwise copy the `Enterprise ID`

####  Box Subject Type
If you intend to harvest events solely for the `admin` user set this to `user` otherwise set to `enterprise`

####  Grant Type
Use the provided default `client_credentials`

####  Interval
This sets the interval between requests to the Target Service, for example `300s` will send a request every 300 seconds. Events will be returned in batches of up to 100, with successive calls on expiry of the configured `interval` so you may wish to specify a lower interval when a substantial number of events are expected, however, we suggest to consider bandwidth when using lower settings

####  Stream Type
To retrieve events for a single user, set stream type to `all` (default). To select only events that may cause file tree changes such as file updates or collaborations, use `changes`. To select a subset of `changes` for synced folders, use `sync`. To retrieve events for the entire enterprise, set the stream_type to `admin_logs_streaming` for live monitoring of new events, or `admin_logs` for querying across historical events.

####  Preserve Original Event
Preserves a raw copy of the original event, added to the field `event.original`.

{{fields "events"}}
