# Greenhouse Integration

The Greenhouse integration allows you to collect audit logs from [Greenhouse](https://www.greenhouse.io/), a popular Applicant Tracking System (ATS). Audit logs provide a record of important events from the previous 30 days, tracking who accessed or edited information in Greenhouse Recruiting.

## Data Streams

This integration collects the following data:

- **Audit Logs**: Records of events including data changes, user actions, and API access.

## Requirements

- Greenhouse Expert subscription tier with the Audit Log add-on
- Harvest V3 (OAuth) API credentials with audit log permissions
- A Site Admin user ID for API authorization

### Compatibility

This integration uses the Greenhouse Harvest API V3 with OAuth 2.0 Client Credentials authentication.

## Setup

### Creating Harvest V3 OAuth Credentials

1. Log in to Greenhouse as a user with Developer permissions
2. Navigate to **Configure > Dev Center > API Credentials**
3. Click **Create new API credentials**
4. Select **Harvest V3 (OAuth)** as the credential type
5. Save the credential and configure the scopes your integration needs (ensure Audit Log access is enabled)
6. Copy the **Client ID** and **Client Secret** - you will need these for the integration

### Finding the Authorizing User ID

The OAuth 2.0 Client Credentials flow requires a `user_id` to identify the authorizing user. This user must be a **Site Admin** to access audit log endpoints.

To find a user's ID:
1. In Greenhouse, navigate to **Configure > Users**
2. Click on the Site Admin user you want to use for authorization
3. Look at the URL in your browser - it will contain the numeric user ID (for example, `https://app.greenhouse.io/configure/users/12345`)
4. Use this numeric ID in the integration configuration

### Configuration

1. In Kibana, navigate to **Integrations** and search for "Greenhouse"
2. Click **Add Greenhouse**
3. Enter your OAuth credentials:
   - **OAuth Client ID**: The Client ID from your Harvest V3 credentials
   - **OAuth Client Secret**: The Client Secret from your Harvest V3 credentials
   - **Authorizing User ID**: The numeric user ID of a Site Admin
4. Configure optional settings:
   - **Initial Interval**: How far back to collect logs on first run (default: 24h, maximum: 30d)
   - **Interval**: How often to poll for new events (default: 5m)
   - **Batch Size**: Number of events per API request (100-500, default: 500)
   - **Performer IDs Filter**: Filter by specific user IDs
   - **Event Types Filter**: Filter by event type (data_change_update, data_change_create, data_change_destroy, harvest_access, action)

## Logs

### Audit Logs

Audit logs capture the following types of events:

| Event Type | Description |
|------------|-------------|
| `action` | General actions taken in Greenhouse Recruiting |
| `data_change_create` | New data created |
| `data_change_update` | Existing data modified |
| `data_change_destroy` | Data deleted |
| `harvest_access` | Data accessed using Harvest API |

## Rate Limiting

The Greenhouse Audit Log API has the following rate limits:

- General requests: 50 per 10 seconds
- Paginated requests: 3 per 30 seconds

This integration handles rate limiting automatically by respecting the default polling interval and pagination settings.

## Data Retention

Greenhouse retains audit log data for 30 days only. To maintain a longer history, ensure this integration is collecting data continuously.

## Troubleshooting

### Authentication Errors

If you receive "Failed to obtain OAuth access token" errors:
1. Verify your Client ID and Client Secret are correct
2. Ensure the OAuth credentials have audit log permissions enabled
3. Check that the authorizing user ID is a valid Site Admin user

### 403 Forbidden Errors

If you receive 403 errors:
1. Verify the authorizing user (specified by user_id) is a Site Admin
2. Check that your OAuth credentials have the necessary scopes for audit log access

### No Data Collected

If no events are being collected:
1. Verify your Greenhouse subscription includes the Audit Log add-on
2. Check that there have been events in the last 30 days
3. Review any filter settings that might be excluding events

## Logs reference

### audit

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| greenhouse.audit.event.meta | The before and after values from data change events, or other relevant data for the event. | flattened |
| greenhouse.audit.event.target_id | The ID of the element that was edited or accessed. | keyword |
| greenhouse.audit.event.target_type | The resource name for data changes, Harvest access, or the event action type for other actions. | keyword |
| greenhouse.audit.event.type | The type of event: data_change_update, data_change_create, data_change_destroy, harvest_access, or action. | keyword |
| greenhouse.audit.performer.id | The Greenhouse Recruiting user ID of the person who performed the change or the API key if performed via Greenhouse API. | keyword |
| greenhouse.audit.performer.ip_address | The IP address of the person or integration that performed the change. | ip |
| greenhouse.audit.performer.meta.api_key_type | The type of API key used when performer is an API key. | keyword |
| greenhouse.audit.performer.meta.name | The name of the performer. | keyword |
| greenhouse.audit.performer.meta.username | The email address of the performer or the API key type. | keyword |
| greenhouse.audit.performer.type | The type of performer: user, api_key, or greenhouse_internal. | keyword |
| greenhouse.audit.request.id | The ID of the request. | keyword |
| greenhouse.audit.request.type | The name of the action taken in Greenhouse Recruiting, or the request URL if from Harvest API. | keyword |
| input.type | Type of Filebeat input. | keyword |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2023-06-02T16:06:19.217Z",
    "agent": {
        "ephemeral_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "name": "elastic-agent",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "greenhouse.audit",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "action": "action",
        "category": [
            "configuration",
            "iam"
        ],
        "dataset": "greenhouse.audit",
        "id": "1234zID",
        "kind": "event",
        "module": "greenhouse",
        "original": "{\"request\":{\"id\":\"1234zID\",\"type\":\"email_settings#create_organization_email\"},\"performer\":{\"meta\":{\"name\":\"Allison Jamie\",\"username\":\"allison.j@omniva-corp.com\"},\"id\":12345,\"ip_address\":\"192.168.0.1\",\"type\":\"user\"},\"organization_id\":123,\"event\":{\"meta\":null,\"target_type\":\"Global Email Added\",\"type\":\"action\"},\"event_time\":\"2023-06-02T16:06:19.217Z\"}",
        "type": [
            "info"
        ]
    },
    "greenhouse": {
        "audit": {
            "event": {
                "target_type": "Global Email Added",
                "type": "action"
            },
            "performer": {
                "type": "user"
            },
            "request": {
                "id": "1234zID",
                "type": "email_settings#create_organization_email"
            }
        }
    },
    "organization": {
        "id": "123"
    },
    "related": {
        "ip": [
            "192.168.0.1"
        ],
        "user": [
            "12345",
            "allison.j@omniva-corp.com"
        ]
    },
    "source": {
        "ip": "192.168.0.1"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "greenhouse-audit"
    ],
    "user": {
        "email": "allison.j@omniva-corp.com",
        "full_name": "Allison Jamie",
        "id": "12345"
    }
}
```
