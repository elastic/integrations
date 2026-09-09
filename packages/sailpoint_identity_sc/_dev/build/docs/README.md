# Sailpoint Identity Security Cloud

The Elastic integration for [Sailpoint Identity Security Cloud](https://www.sailpoint.com/products/identity-security-cloud) enables real-time monitoring and analysis of identity security events within the SailPoint platform. This integration collects, processes, and visualizes audit logs, access activities, and identity lifecycle events to enhance security posture, compliance, and operational efficiency.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data Streams

- **`events`**: Provides audit data that includes actions such as `USER_MANAGEMENT`, `PASSWORD_ACTIVITY`, `PROVISIONING`, `ACCESS_ITEM`, `SOURCE_MANAGEMENT`, `CERTIFICATION`, `AUTH`, `SYSTEM_CONFIG`, `ACCESS_REQUEST`, `SSO`, `WORKFLOW`, `SEGMENT` and more. [Audit Events](https://community.sailpoint.com/t5/IdentityNow-Wiki/Audit-Events-in-Cloud-Audit/ta-p/218727) are records that a user took action in an [IdentityNow](https://www.sailpoint.com/products/identitynow) tenant, or other service like [IdentityAI](https://www.sailpoint.com/products/ai-driven-identity-security). This data stream leverages the [/v2026/search](https://developer.sailpoint.com/docs/api/v2026/search-post) endpoint.

## Requirements

### Create an OAuth2 API Client

This integration uses OAuth2 `client_credentials` to authenticate against the SailPoint ISC API.

1. Log in to the SailPoint ISC admin console.
2. Navigate to **Admin → Security Settings → API Management**.
3. Click **Create API Client**, select **Client Credentials** as grant type, and grant the following scopes:
   - `sp:search:read` — required for the `events`data stream
4. Note the generated **Client ID** and **Client Secret** for use in the integration configuration.

For further details see the official [Authentication documentation](https://developer.sailpoint.com/docs/api/authentication).

## Logs

### Events

Event documents can be found by setting the following filter:
`event.dataset : "sailpoint_identity_sc.events"`

{{event "events"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in events documents:

{{fields "events"}}
