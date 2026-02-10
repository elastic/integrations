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

#### Exported Fields

| Field | Description | Type |
|-------|-------------|------|
| `@timestamp` | Event timestamp | date |
| `event.id` | Request ID | keyword |
| `event.action` | Event type | keyword |
| `event.category` | Event category | keyword |
| `event.type` | Event type classification | keyword |
| `user.id` | Performer ID | keyword |
| `user.email` | Performer email | keyword |
| `user.full_name` | Performer name | keyword |
| `source.ip` | Performer IP address | ip |
| `organization.id` | Greenhouse organization ID | keyword |
| `greenhouse.audit.request.type` | Action name or API endpoint | keyword |
| `greenhouse.audit.event.target_type` | Resource type affected | keyword |
| `greenhouse.audit.event.target_id` | Resource ID affected | keyword |
| `greenhouse.audit.event.meta` | Before/after values for changes | flattened |
| `greenhouse.audit.performer.type` | Performer type (user, api_key, greenhouse_internal) | keyword |

#### Sample Event

An example event for `greenhouse.audit` looks as follows:

```json
{
    "@timestamp": "2023-06-02T16:06:19.217Z",
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "action",
        "category": ["configuration", "iam"],
        "id": "1234zID",
        "kind": "event",
        "type": ["info"]
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
    "source": {
        "ip": "192.168.0.1"
    },
    "user": {
        "email": "allison.j@omniva-corp.com",
        "full_name": "Allison Jamie",
        "id": "12345"
    }
}
```

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
