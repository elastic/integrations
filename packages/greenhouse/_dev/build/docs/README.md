# Greenhouse Integration

The Greenhouse integration allows you to collect audit logs from [Greenhouse](https://www.greenhouse.io/), a popular Applicant Tracking System (ATS). Audit logs provide a record of important events from the previous 30 days, tracking who accessed or edited information in Greenhouse Recruiting.

## Data Streams

This integration collects the following data:

- **Audit Logs**: Records of events including data changes, user actions, and API access.

## Requirements

- Greenhouse Expert subscription tier with the Audit Log add-on
- Harvest V3 (OAuth) API credentials with audit log permissions
- Optionally, a Site Admin user ID for API authorization (if not configured as a default in your OAuth credentials)

### Compatibility

This integration uses the [Greenhouse Audit Log API](https://developers.greenhouse.io/audit-log.html#introduction) with Harvest V3 OAuth 2.0 Client Credentials authentication.

- **Data retention**: Greenhouse retains audit log data for **30 days** only. Events older than 30 days are no longer available from the API. To maintain a longer history, ensure this integration is collecting data continuously.
- **Rate limits**: The Greenhouse Audit Log API allows 50 general requests per 10 seconds and 3 paginated requests per 30 seconds. The integration handles rate limiting automatically by respecting `HTTP 429` responses and backing off before retrying.

## Setup

### Creating Harvest V3 OAuth Credentials

1. Log in to Greenhouse as a user with Developer permissions
2. Navigate to **Configure > Dev Center > API Credentials**
3. Click **Create new API credentials**
4. Select **Harvest V3 (OAuth)** as the credential type
5. Save the credential and configure the scopes your integration needs (ensure Audit Log access is enabled)
6. Copy the **Client ID** and **Client Secret** - you will need these for the integration

### Finding the Authorizing User ID (Optional)

The OAuth 2.0 Client Credentials flow can use a `user_id` to identify the authorizing user. This user must be a **Site Admin** to access audit log endpoints. If your OAuth credentials are configured with a default authorizing user, this field can be left empty.

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
4. Configure optional settings:
   - **Authorizing User ID**: The numeric user ID of a Site Admin (optional if your OAuth credentials have a default user configured)
   - **Initial Interval**: How far back to collect logs on first run (default: 24h, maximum: 30d)
   - **Interval**: How often to poll for new events (default: 5m)
   - **Batch Size**: Number of events per API request (100-500, default: 500)
   - **Performer IDs Filter**: Filter by specific user IDs
   - **Event Types Filter**: Filter by event type (data_change_update, data_change_create, data_change_destroy, harvest_access, action)
   - **Enrich rejected application events**: When enabled, look up the rejection reason and rejection notes/comments from the Harvest API and add them to the event (default: disabled)

### Enabling rejection enrichment (optional)

When a candidate or prospect is rejected, Greenhouse audits it as an `action` event with `event.target_type` set to the literal string `Candidate or Prospect rejected` — this event does **not** include an application or candidate ID, and does not include the rejection reason or notes/comments entered at rejection time. Enabling **Enrich rejected application events** looks these up from the Harvest API and correlates them back to the audit event.

1. On the same Harvest V3 (OAuth) API credential used for audit log access, grant the following read permissions (under **Configure > Dev Center > API Credentials** on the credential):
   - **Rejection details** → *List rejection details*, needed for `GET /v3/rejection_details?ids={id}` to look up the rejection detail record
   - **Rejection reasons** → *Show rejection reason*, needed for `GET /v3/rejection_reasons/{id}` to resolve the reason name and category (only called when a reason was selected)
   - **Notes** → *List notes*, needed for `GET /v3/notes?ids={id}` to retrieve the free-text rejection note (only called when notes were entered)
2. Enable the **Enrich rejected application events** setting on the integration.

Because the "Candidate or Prospect rejected" audit event has no application ID, the integration correlates it to a second audit event that Greenhouse records for the same rejection — one with `event.target_type` of `RejectionDetails` — by matching the `request.id` shared by both events. That event's `event.meta.application_id` is then used to look up the rejection reason and notes:

- **Exactly one matching `RejectionDetails` event**: the rejection reason and notes are fetched via up to two additional API calls and added to the event under `greenhouse.audit.event.rejection` (`application_id`, `candidate_id`, `reason.id`/`reason.name`/`reason.type`, `notes`, `rejected_at`). The notes are also copied to `event.reason`.
- **No matching event found**: the audit event is still indexed, with `greenhouse.audit.event.rejection.error` explaining that no matching `RejectionDetails` event was found for that request. This can happen if the two events land on different pages of a poll; increasing **Batch Size** reduces how often this occurs.
- **More than one matching event** (for example, a bulk rejection of several candidates in one action, which shares a single `request.id` across all of them): the integration does not guess which pairs with which. The audit event is indexed with `greenhouse.audit.event.rejection.error` and `greenhouse.audit.event.rejection.ambiguous_application_ids` listing the candidates, for manual follow-up.

Any of the error cases above also adds the tag `greenhouse-rejection-enrichment-failed`, and the underlying rejection audit event is never dropped.

Because this issues up to three extra API requests per rejection on top of the audit log polling, be mindful of Greenhouse's rate limits (50 general requests per 10 seconds) if your organization rejects applications in bulk.

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

## Troubleshooting

### Authentication Errors

If you receive "Failed to obtain OAuth access token" errors:
1. Verify your Client ID and Client Secret are correct
2. Ensure the OAuth credentials have audit log permissions enabled
3. If using a user ID, check that it is a valid Site Admin user

### 403 Forbidden Errors

If you receive 403 errors:
1. Verify the authorizing user (specified by user_id) is a Site Admin
2. Check that your OAuth credentials have the necessary scopes for audit log access

### No Data Collected

If no events are being collected:
1. Verify your Greenhouse subscription includes the Audit Log add-on
2. Check that there have been events in the last 30 days
3. Review any filter settings that might be excluding events

### Rejection Enrichment Errors

If rejection events are tagged with `greenhouse-rejection-enrichment-failed` and `greenhouse.audit.event.rejection.error` is populated:
1. Verify the OAuth credential has been granted all three required read permissions: **Rejection details** (*List rejection details*), **Rejection reasons** (*Show rejection reason*), and **Notes** (*List notes*)
2. Check that the authorizing user has permission to view the affected application
3. If the error mentions no matching `RejectionDetails` event was found, try increasing **Batch Size** so the two related audit events are less likely to land on different pages
4. If the error mentions an ambiguous match, the rejection was likely part of a bulk-reject action; `greenhouse.audit.event.rejection.ambiguous_application_ids` lists the candidates involved for manual follow-up

## Logs reference

### audit

{{fields "audit"}}

{{event "audit"}}
