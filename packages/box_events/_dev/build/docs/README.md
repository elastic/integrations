# Box Events Integration

The Box Events integration allows you to monitor [Box](https://app.box.com/). Box is a secure cloud storage and collaboration service that allows businesses and individuals to easily share files. 

Use the Box Events integration to ingest the activity logs which are generated each time files are uploaded, accessed, or modified in Box, enabling you to monitor data movement to the cloud. If you have [opted-in to receive additional events](https://developer.box.com/guides/events/event-triggers/shield-alert-events/), the Box Events integration will ingest context-rich alerts on potential threats, such as compromised accounts and data theft, based on anomalous user behavior. Combining this data with other events can lead to the detection of data exfiltration attacks.

Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference `box_events.events` when troubleshooting an issue.

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

### Box Events

The Box events API enables subscribing to live events across the enterprise or for a particular user, or querying historical events across the enterprise.

The API Returns up to a year of past events for a given user or for the entire enterprise.

By default this returns events for the authenticated user. 

#### Elastic Integration for Box Events Settings

To retrieve events for the entire enterprise, set the `stream_type` in the Elastic Integration Settings page to `admin_logs_streaming` for live monitoring of new events, or `admin_logs` for querying across historical events. 

Events will be returned in batches of up to 100, with successive calls on expiry of the configured `interval` so you may wish to specify a lower interval when a substantial number of events are expected.

#### Target Repository Authentication Settings

The Elastic Integration for Box Events connects using OAuth 2.0 to interact with a Box Custom App. To configure a Box Custom App see [Setup with OAuth 2.0](https://developer.box.com/guides/authentication/oauth2/oauth2-setup/).

Your app will need:

- A Custom Application using Server Authentication (with Client Credentials Grant) authentication in the Box Developer Console
- [2FA](https://support.box.com/hc/en-us/articles/360043697154-Two-Factor-Authentication-Set-Up-for-Your-Account) enabled on your Box account for viewing and copying the application's client secret from the configuration tab
- The application is [authorized](https://developer.box.com/guides/authorization/custom-app-approval/) in the Box Admin Console

#### Target Repository User Privileges

To access the `events` endpoint, the user making the API call will need to have `admin` privileges, and the application will need to have the scope `manage enterprise properties` checked. Changes to these settings may require you to repeat the `Custom App Approval` authorisation.

{{fields "events"}}
