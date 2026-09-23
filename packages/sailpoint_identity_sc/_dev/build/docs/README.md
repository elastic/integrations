# Sailpoint Identity Security Cloud

The Elastic integration for [Sailpoint Identity Security Cloud](https://www.sailpoint.com/products/identity-security-cloud) enables real-time monitoring and analysis of identity security events within the SailPoint platform. This integration collects, processes, and visualizes audit logs, access activities, and identity lifecycle events to enhance security posture, compliance, and operational efficiency.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

## Data Streams

- **`events`**: Provides audit data that includes actions such as `USER_MANAGEMENT`, `PASSWORD_ACTIVITY`, `PROVISIONING`, `ACCESS_ITEM`, `SOURCE_MANAGEMENT`, `CERTIFICATION`, `AUTH`, `SYSTEM_CONFIG`, `ACCESS_REQUEST`, `SSO`, `WORKFLOW`, `SEGMENT` and more. [Audit Events](https://community.sailpoint.com/t5/IdentityNow-Wiki/Audit-Events-in-Cloud-Audit/ta-p/218727) are records that a user took action in an [IdentityNow](https://www.sailpoint.com/products/identitynow) tenant, or other service like [IdentityAI](https://www.sailpoint.com/products/ai-driven-identity-security). This data stream leverages the [/v2026/search](https://developer.sailpoint.com/docs/api/v2026/search-post) endpoint.

- **`identities`**: Collects human identity records (employees, contractors, and external users) governed by SailPoint ISC. Each document represents the current governance state of an identity including their access entitlements, owned governance objects, manager relationships, and segment memberships. Designed for entity analytics, user risk scoring, and identity-correlated security detections. Uses incremental collection via the [Search API](https://developer.sailpoint.com/docs/api/v2026/search-post) with a `searchAfter` cursor so only identities modified since the last run are fetched.

- **`machine_identities`**: Collects machine/non-human identity records (service accounts, application accounts, bots, and AI agents) governed by SailPoint ISC. Each document represents a machine identity with its owner relationships and held entitlements. Uses the experimental [Machine Identities API](https://developer.sailpoint.com/docs/api/v2026/list-machine-identities/) with a full offset-based scan each collection cycle. **Note:** This data stream depends on an experimental SailPoint API (`X-SailPoint-Experimental: true`). The API may change without notice in future SailPoint releases. HTTP 404 and 501 responses are treated as "feature not enabled" rather than errors.

## Requirements

### Create an OAuth2 API Client

This integration uses OAuth2 `client_credentials` to authenticate against the SailPoint ISC API.

1. Log in to the SailPoint ISC admin console.
2. Navigate to **Admin → Security Settings → API Management**.
3. Click **Create API Client**, select **Client Credentials** as grant type, and grant the following scopes:
   - `sp:search:read` — required for the `events` and `identities` data streams
   - `idn:mis-identity:read` and `idn:mis-identity:manage` — required for the `machine_identities` data stream (experimental API)
4. Note the generated **Client ID** and **Client Secret** for use in the integration configuration.

For further details see the official [Authentication documentation](https://developer.sailpoint.com/docs/api/authentication).

## Logs

### Events

Event documents can be found by setting the following filter:
`event.dataset : "sailpoint_identity_sc.events"`

{{event "events"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in events documents:

{{fields "events"}}

### Identities

Identity documents can be found by setting the following filter:
`event.dataset : "sailpoint_identity_sc.identities"`

Identity documents carry ECS entity fields (`user.entity.*`) that enable Entity Analytics, user risk scoring, and identity-correlated detections.

{{event "identities"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in identities documents:

{{fields "identities"}}

### Machine Identities

Machine identity documents can be found by setting the following filter:
`event.dataset : "sailpoint_identity_sc.machine_identities"`

Machine identity documents carry ECS entity fields (`service.entity.*`) that enable entity analytics for non-human identities such as service accounts, application accounts, bots, and AI agents.

{{event "machine_identities"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in identities documents:

{{fields "machine_identities"}}
