# Sailpoint Identity Security Cloud

The Elastic integration for [Sailpoint Identity Security Cloud](https://www.sailpoint.com/products/identity-security-cloud) enables real-time monitoring and analysis of identity security events within the SailPoint platform. This integration collects, processes, and visualizes audit logs, access activities, and identity lifecycle events to enhance security posture, compliance, and operational efficiency.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data Streams

- **`events`**: Provides audit data that includes actions such as `USER_MANAGEMENT`, `PASSWORD_ACTIVITY`, `PROVISIONING`, `ACCESS_ITEM`, `SOURCE_MANAGEMENT`, `CERTIFICATION`, `AUTH`, `SYSTEM_CONFIG`, `ACCESS_REQUEST`, `SSO`, `WORKFLOW`, `SEGMENT` and more.
- [Audit Events](https://community.sailpoint.com/t5/IdentityNow-Wiki/Audit-Events-in-Cloud-Audit/ta-p/218727) are records that a user took action in an [IdentityNow](https://www.sailpoint.com/products/identitynow) tenant, or other service like [IdentityAI](https://www.sailpoint.com/products/ai-driven-identity-security). Audit Events are structurally and conceptually very similar to [IdentityIQ's](https://www.sailpoint.com/products/identity-security-software/identity-iq)Audit Events, but have evolved in several ways.
- This data stream leverages the Sailpoint identity security cloud API's [/v2025/search](https://developer.sailpoint.com/docs/api/v2025/search-post) endpoint to retrieve event logs.

## Requirements

### Generate a Personal Access Token (PAT)

Log in to the application with an administrator account and generate a **Personal Access Token (PAT)**. Personal access tokens are associated with a user in **Sailpoint identity security cloud** and inherit the user's permission level (e.g., Admin, Helpdesk, etc.) to determine access.

To create a **Personal Access Token (PAT)** using an **admin account**, follow the instructions provided in the official documentation:  
[Generate a Personal Access Token](https://developer.sailpoint.com/docs/api/v2024/authentication#generate-a-personal-access-token).

## Logs

### Events

Event documents can be found by setting the following filter: 
`event.dataset : "sailpoint_identity_sc.events"`

{{event "events"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in events documents:

{{fields "events"}}

