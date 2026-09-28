# Zoom Integration for Elastic

## Overview

[Zoom](https://www.zoom.com/) is a unified communications platform that provides meetings, webinars, phone, team chat, and Zoom Rooms. The Zoom integration for Elastic enables you to collect Zoom event and audit data so you can monitor user activity, investigate security incidents, and analyze platform usage in Elastic.

This integration collects data using two complementary methods:

- **Webhook**: a real-time HTTP listener that receives event notifications pushed by Zoom (meeting, webinar, recording, user, account, phone, team chat, and Zoom Room events).
- **REST API**: a periodic poll of the Zoom REST API to collect the sign in / sign out **activity** report, the **operation** logs report, and the **meeting_activity** logs report for an account.

## Elastic Managed Enabled Integration

Elastic Managed integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Elastic Managed integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Compatibility

- The **activity** data stream uses the Zoom REST API [`GET /report/activities`](https://developers.zoom.us/docs/api/meetings/#tag/reports/get/report/activities) endpoint and requires a Zoom Pro (or higher) plan.
- The **operation** data stream uses the Zoom REST API [`GET /report/operationlogs`](https://developers.zoom.us/docs/api/meetings/#tag/reports/get/report/operationlogs) endpoint and requires a Zoom Pro plan or above.
- The **meeting_activity** data stream uses the Zoom REST API [`GET /report/meeting_activities`](https://developers.zoom.us/docs/api/meetings/#tag/reports/get/report/meeting_activities) endpoint. The meeting audit trail log feature must be enabled for the account by Zoom Support.

### How it works

The **webhook** data stream creates an HTTP listener that accepts incoming webhook callbacks from Zoom. The Elastic Agent running this integration must be reachable from the internet so that Zoom can connect to it. Zoom requires that webhooks are delivered over HTTPS, so you must either configure the integration with a valid TLS certificate or place a reverse proxy that terminates TLS in front of the integration. Incoming events are then routed to the appropriate ingest pipeline based on the Zoom event type.

The **activity**, **operation** and **meeting_activity** data streams poll the Zoom REST API using Server-to-Server OAuth. On each interval, they request records within a date window (a maximum of one month per request) and paginate through the results.

## What data does this integration collect?

The Zoom integration collects the following data:

- `webhook`: real-time Zoom event notifications, including account, team chat (channel and message), meeting, phone, recording, user, webinar, and Zoom Room events.
- `activity`: account-wide sign in and sign out activity logs from the Zoom REST API reports endpoint. Note that the API does not provide data for failed sign-in or authentication attempts, so those logs will not be available here.
- `operation`: account-wide admin and user operation logs from the Zoom REST API reports endpoint, such as adding a user, changing account settings, or deleting a recording.
- `meeting_activity`: meeting activity logs from the Zoom REST API reports endpoint, such as a meeting being created or started, a user joining or leaving, in-meeting chat, remote control, and a meeting ending.

### Supported use cases

Integrating Zoom with Elastic SIEM provides centralized visibility into collaboration and administrative activity:

- **Webhook** events enable real-time monitoring across meetings, recordings, users, and account changes.
- The **activity** report provides an account-wide sign in / sign out audit trail for investigating user access and anomalous logins.
- The **operation** logs report tracks admin and user operations for auditing configuration changes and detecting unauthorized actions.
- The **meeting_activity** logs report provides a meeting-level audit trail of meeting lifecycle and participant activity — meetings being created, started, and ended, participants joining and leaving, in-meeting chat, and remote control — helping you reconstruct what happened in a specific meeting, monitor meeting usage, and support compliance investigations.

## What do I need to use this integration?

### From Zoom

#### Collecting data via Webhook

1. Create a Webhook-only app in the [Zoom App Marketplace](https://marketplace.zoom.us/) by following the [Zoom webhook documentation](https://developers.zoom.us/docs/api/webhooks/).
2. Add the event types you want to receive and set the event notification endpoint URL to the public HTTPS address where this integration is reachable.
3. Note the **Secret Token** generated by Zoom. It is used for CRC endpoint validation and to verify the authenticity of incoming events.

#### Collecting data from the Zoom REST API

1. Create a **Server-to-Server OAuth** app in the [Zoom App Marketplace](https://marketplace.zoom.us/) by following the [Server-to-Server OAuth documentation](https://developers.zoom.us/docs/internal-apps/s2s-oauth/).
2. Record the app's **Account ID**, **Client ID**, and **Client Secret**.
3. Add the `report:read:admin` scope (or the granular `report:read:user_activities:admin`, `report:read:operation_logs:admin` & `report:read:meeting_activity_log:admin` scopes) to the app and activate it. A Zoom Pro plan or above is required.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to receive the Zoom webhook callbacks or to poll the Zoom REST API, and to ship the data to Elastic, where the events are then processed via the integration's ingest pipelines.

### Onboard / configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Zoom**.
3. Select the **Zoom** integration from the search results.
4. Select **Add Zoom** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect Zoom logs via Webhook**, you'll need to:

        - Configure the **Listen Address**, **Listen Port**, and **Webhook path** where the integration accepts requests.
        - Optionally enable **CRC validation** and provide the **Zoom Secret Token**, and/or configure a custom header to verify incoming requests.
        - Provide a valid **TLS** certificate (or front the integration with a TLS-terminating reverse proxy), since Zoom requires HTTPS.

    * To **Collect Zoom logs via REST API**, you'll need to:

        - Configure the **Account ID**, **Client ID**, and **Client Secret** of your Server-to-Server OAuth app.
        - Adjust the integration configuration parameters if required, including the **Interval** and **Initial Interval** (lookback), to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Zoom**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Zoom REST API rate limits

The REST API data streams (`activity`, `operation`, and `meeting_activity`) query Zoom's Report endpoints, which are classified as **Heavy** APIs. Zoom enforces both a per-second (QPS) limit and a daily request quota, and **both are shared across every app and user on the account, as well as across all of the Report data streams in this integration**:

| Plan | Per second | Per day (shared by Heavy and Resource-intensive APIs) |
|---|---|---|
| Pro | 10 requests/second | 30,000 requests/day |
| Business+ (Business, Education, Enterprise, and Partner) | 40 requests/second | 60,000 requests/day |

To keep the Report data streams within this shared budget, each REST API data stream has client-side rate limiting enabled by default (**Rate Limit** and **Rate Limit Burst** in the data stream settings). The default values are conservative so that the streams can run together without exhausting the account quota, which matters most during the initial backfill when many requests are made.

If you hit an `HTTP 429 Too Many Requests` response, or you want to tune throughput, adjust these settings per data stream:

- **Reduce the rate** (lower the **Rate Limit**, for example to `0.05`) if you are seeing `429` errors, if other applications share the same Zoom account quota, or if the daily quota is being consumed too quickly. A daily-limit `429` is only cleared at `00:00 UTC`, so it is better to run slower than to be locked out.
- **Increase the rate** (raise the **Rate Limit**) if you are on a Business+ plan, run fewer Report data streams, or need the initial backfill to complete faster. Keep the combined rate of all enabled Report data streams below your plan's per-second limit.

You can also reduce the total number of requests by increasing the **Page Size** (up to Zoom's maximum of `300`), since fewer, larger pages consume less of the shared quota.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### webhook

This is the `webhook` data stream. It collects real-time event notifications pushed by Zoom over an HTTP endpoint.

{{event "webhook"}}

{{fields "webhook"}}

### activity

This is the `activity` data stream. It collects sign in / sign out activity logs from the Zoom REST API.

{{event "activity"}}

{{fields "activity"}}

### operation

This is the `operation` data stream. It collects admin and user operation logs from the Zoom REST API.

{{event "operation"}}

{{fields "operation"}}

### meeting_activity

This is the `meeting_activity` data stream. It collects meeting activity logs from the Zoom REST API.

{{event "meeting_activity"}}

{{fields "meeting_activity"}}

### Inputs used

These inputs are used in this integration:

- [http_endpoint](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-http_endpoint)
- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following APIs:

- `activity`: [Get sign in / sign out activity report](https://developers.zoom.us/docs/api/meetings/#tag/reports/get/report/activities).
- `operation`: [Get operation logs report](https://developers.zoom.us/docs/api/meetings/#tag/reports/get/report/operationlogs).
- `meeting_activity`: [Get a meeting activities report](https://developers.zoom.us/docs/api/meetings/#tag/reports/get/report/meeting_activities).
