{{- generatedHeader }}
# CyberArk Identity Security (Idira) Integration for Elastic

## Overview
The CyberArk Identity Security (Idira) integration for Elastic collects audit events from the [CyberArk Identity Security Platform](https://www.cyberark.com/products/) Audit Service. The Audit Service records activity from all services on the platform in one audit trail, including CyberArk Identity, Privilege Cloud, Secure Infrastructure Access and Identity Threat Detection and Response.

Use this integration if your CyberArk services run on the CyberArk Identity Security Platform (also called Idira or ISPSS). For other CyberArk products, use these integrations instead:

- **Endpoint Privilege Manager (EPM)**: the [CyberArk EPM](https://www.elastic.co/docs/reference/integrations/cyberark_epm) integration.
- **Self-hosted Privileged Access Security (PAS) Vault**: the [CyberArk Privileged Access Security](https://www.elastic.co/docs/reference/integrations/cyberarkpas) integration.
- **Self-hosted Privileged Threat Analytics (PTA)**: the [CyberArk PTA](https://www.elastic.co/docs/reference/integrations/cyberark_pta) integration.

### Compatibility
This integration uses the CyberArk Identity Security Platform SIEM integration API (`/api/audits/stream`). It has been tested against a CyberArk Identity Security Platform tenant with the CyberArk Identity service.

### How it works
Elastic Agent gets an OAuth2 access token from your CyberArk Identity tenant with the client credentials flow. It then creates a stream query on the Audit Service and reads the results page by page. The Audit Service returns a cursor with each page. Elastic Agent stores the cursor and uses it on the next poll to read only the new events.

The Audit Service keeps events for 7 days. On the first run, the integration collects events from the period set in **Initial Interval** (at most 7 days).

## What data does this integration collect?
The CyberArk Identity Security (Idira) integration collects log messages of the following types:
* `audit`: audit events from all services that send to the CyberArk Audit Service, for example:
  * CyberArk Identity: sign-ins, sign-outs, failed sign-ins, MFA challenges, OAuth token creation, user, role and application changes, and provisioning.
  * Privilege Cloud: vault sign-ins, password retrieval and changes, safe and owner changes, and privileged sessions.
  * Secure Infrastructure Access: privileged session start, end and failure.
  * Identity Threat Detection and Response: security alerts.

### Supported use cases
Use this integration to monitor identity and privileged access activity across the CyberArk Identity Security Platform in one place. For example, detect sign-in failures and MFA abuse, track changes to administrative rights and roles, audit access to privileged credentials, and investigate CyberArk threat detection alerts together with your other security data.

## What do I need to use this integration?
- A CyberArk Identity Security Platform tenant.
- An administrator who can create web apps, users and roles in Identity Administration, and create a SIEM integration in the administration portal.
- A free SIEM integration slot. A tenant can have at most two third-party SIEM integrations.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to collect data from the CyberArk API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

### Set up steps in CyberArk Identity Security Platform
Menu names can be different in your portal version. Newer portals group the menus under **Access**, **Manage** and **Setup**.

1. Create an OAuth2 Server web app:
   1. In Identity Administration, go to **Apps & Widgets** > **Web Apps** and click **Add Web Apps**.
   2. On the **Custom** tab, add **OAuth2 Server**.
   3. On the **Settings** tab, set the **Application ID**, for example `elastic_siem`. This is the **Application ID** in the integration settings.
   4. On the **Tokens** tab, set **Token Type** to `jwtRS256` and select only the **Client Creds** authentication method. Set the token lifetime, for example 5 hours.
   5. On the **Scope** tab, add a scope named `isp.audit.events:read`.
   6. On the **Advanced** tab, add this script. The Audit Service does not accept the token without these claims.
      ```
      setClaim('tenant_id', TenantData.Get("CybrTenantID"));
      setClaim('aud', 'cyberark.isp.audit');
      ```
   7. Save the web app.
2. Create a service user:
   1. Go to **Core Services** > **Users** and click **Add User**.
   2. Enable **Is service user** and **Is OAuth confidential client**.
   3. Note the full login name, including the tenant suffix, for example `svc_elastic@cyberark.cloud.1234`, and the password. These are the **Client ID** and **Client Secret** in the integration settings. Service users do not get an invitation, so the status **Not invited** is normal.
3. On the **Permissions** tab of the web app, add the service user with the **Grant**, **View**, **Run** and **Automatically Deploy** permissions.
4. Give the service user the **Read Only System Administration** administrative right. CyberArk documents that without this right, queries return no events. Go to **Core Services** > **Roles**, add a role, add the **Read Only System Administration** right on the **Administrative Rights** tab, and add the service user on the **Members** tab.
5. Create a SIEM integration:
   1. In the administration portal, go to **Integrations** > **Export to SIEM**, then click **Create** > **Create SIEM integration**.
   2. Enter a name and click **Apply**.
   3. Copy the **API key** and the **API base URL**. The API key is shown only once. These are the **SIEM API Key** and **Audit API URL** in the integration settings.
6. Note your Identity ID: in Identity Administration, click your user name, select **About**, and copy the **ID** shown under **Identity**, for example `ACF4874`.

#### Vendor resources
- [SIEM integration API](https://docs.cyberark.com/audit-and-reports/latest/en/audit/isp_siem-integration-api/)
- [Idira SIEM integration development guide](https://github.com/cyberark/Idira-Partner-Integration-Docs/blob/main/docs/audit-service/siem-integration/development-guide.md)

### Set up steps in Kibana
1. In Kibana, go to **Management** > **Integrations**.
2. Search for **CyberArk Identity Security** and select the integration.
3. Click **Add CyberArk Identity Security (Idira)**.
4. Enter the **Audit API URL**, **SIEM API Key**, **Identity ID**, **Application ID**, **Client ID** and **Client Secret** from the CyberArk setup.
5. Optionally change **Interval** and **Initial Interval**. The Audit Service keeps events for 7 days, so an **Initial Interval** larger than `168h` is reduced to `168h`.
6. Save the integration.

### Validation
1. Sign in to the CyberArk portal to create a new audit event.
2. In Kibana, go to **Discover** and select the `logs-*` data view.
3. Filter on `data_stream.dataset : "cyberark_identity_security.audit"`. Events appear after the next poll.

## Troubleshooting
- Token request fails with `400` and `access_denied`: make sure **Client ID** is the full login name of the service user, including the tenant suffix (for example `svc_elastic@cyberark.cloud.1234`).
- Token request fails with an empty or wrong secret: check that **Client Secret** is the current password of the service user.
- Audit API requests fail with `401`, or `createQuery` fails with `403`: check that the web app has the `isp.audit.events:read` scope and the advanced script with the `tenant_id` and `aud` claims, and that the service user has the web app permissions.
- A document with the `error.message` "cursor rejected, a new query starts on the next poll": the Audit Service did not accept the stored cursor (`400` or `403` on `results`). On the next poll, the integration creates a new query from the time of the last collected event. Events that are collected again at that time are not duplicated, because the document ID comes from the event ID. If the message repeats and the next poll logs a `createQuery` error, the cause is the credentials or permissions, not the cursor.
- No events are collected and there are no errors: give the service user the **Read Only System Administration** right.
- Events older than 7 days are missing: the Audit Service keeps events for 7 days only. If Elastic Agent stops for longer than that, the older events cannot be collected.

## Performance and scaling
CyberArk documents that the stream APIs can be called once a minute. The integration polls every **Interval** (default `5m`) and limits its request rate with **Resource Rate Limit** (default one request a second) and **Resource Rate Limit Burst**. If CyberArk returns a rate limit error (`429`), Elastic Agent retries the request with exponential backoff: up to **Resource Retry Max Attempts** retries (default `5`), waiting from **Resource Retry Wait Min** (default `1s`) up to **Resource Retry Wait Max** (default `60s`), and following the `Retry-After` header when CyberArk sends one. If the retries also fail, the integration logs an error and tries again on the next poll, from the same position. If rate limit errors continue, set **Resource Rate Limit** to `0.0167` to make no more than one request a minute.

Each page has at most the number of events set in **Page Size** (default `100`, maximum 500). Large page sizes can fail with `NonTimeBasedRetrieval: Response size too big on first page`, so keep the default unless you need more throughput.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used
{{ inputDocs }}

### API usage
These APIs are used with this integration:
* `POST https://<identity_id>.id.cyberark.cloud/oauth2/token/<application_id>`: gets an OAuth2 access token.
* `POST <audit_url>/api/audits/stream/createQuery`: creates a stream query and returns a cursor.
* `POST <audit_url>/api/audits/stream/results`: returns a page of audit events and the next cursor.

For details, refer to the [SIEM integration API](https://docs.cyberark.com/audit-and-reports/latest/en/audit/isp_siem-integration-api/) documentation.

### Vendor documentation links
- [CyberArk Identity Security Platform documentation](https://docs.cyberark.com/)
- [SIEM integration API](https://docs.cyberark.com/audit-and-reports/latest/en/audit/isp_siem-integration-api/)

### Data streams

#### audit

The `audit` data stream provides audit events from the CyberArk Identity Security Platform Audit Service, for all services that send audit events to it.

##### audit fields

{{ fields "audit" }}

##### audit sample event
{{ event "audit" }}

{{ ilm }}

{{ transform }}
