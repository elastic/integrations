# Check Point Harmony Email & Collaboration

Check Point's [Harmony Email & Collaboration](https://www.checkpoint.com/harmony/email-security/) monitors traffic across email platforms (Office 365, Gmail), file sharing services (OneDrive, SharePoint, Google Drive, Dropbox, Box, and Citrix ShareFile), and messaging applications (Teams and Slack). It scans emails, files, and messages for malware, DLP, and phishing indicators, and intercepts & quarantines potentially malicious emails before they are delivered.

The Check Point Harmony Email & Collaboration integration collects security event logs using REST API.

## Data streams

This integration collects the following logs:

- **[Event](https://app.swaggerhub.com/apis-docs/Check-Point/harmony-email-collaboration-smart-api/1.50#/APIs/query_event_v1_0_event_query_post)** - Get security event logs.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Collect data from the Harmony Email and Collaboration Smart API

- In the Infinity Portal, go to Account Settings and click **API Keys**.
- Click **New** > **New Account API key**.
- In the **Create a New API Key** window, select **Email & Collaboration** as the service.
- (Optional) In the **Expiration** field, select an expiration date and time for the API key. By default, the expiration date is three months after the creation date.
- (Optional) In the **Description** field, enter a description for the API key.
- Click **Create**.
- Copy the **Client ID** and **Secret Key**.
    - **Note**: You can always obtain the **Client ID** from the **API Keys** table, but you cannot retrieve the **Secret Key** after the **Create a New API Key** window is closed.
- Click **Close**.

For more details, see [Documentation](https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/Infinity-Portal-Admin-Guide/Content/Topics-Infinity-Portal/API-Keys.htm?tocpath=Account%20Settings%7C_____7#API_Keys).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Check Point Harmony Email & Collaboration**.
3. Select the **Check Point Harmony Email & Collaboration** integration and add it.
4. Add all the required configuration parameters, including the URL, Client ID, Client Secret, Interval, and Initial Interval, to enable data collection.
5. Save the integration.

**Note**: The default URL is `https://cloudinfra-gw.portal.checkpoint.com`, but this may vary depending on your region. Please refer to the [Documentation](https://sc1.checkpoint.com/documents/Harmony_Email_and_Collaboration_API_Reference/Topics-HEC-Avanan-API-Reference-Guide/Overview/URLs-and-URL-Base.htm?tocpath=Executing%20API%20Calls%7C_____3) to find the correct URL for your region.

## Logs reference

### Event

This is the `event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}
