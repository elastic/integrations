# Snowflake Integration for Elastic

## Overview

The Snowflake integration for Elastic enables you to collect security telemetry from [Snowflake](https://www.snowflake.com/) `ACCOUNT_USAGE` views and event tables through the [SQL API](https://docs.snowflake.com/en/developer-guide/sql-api/intro). By ingesting this data, you can monitor database access, query executions, configuration changes, and potential exfiltration paths.

This integration supports collecting data from the following data streams:
- `access_history`: Object and column access events from `SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY`.
- `data_transfer_history`: Hourly aggregated cross-cloud and cross-region data transfer volumes from `SNOWFLAKE.ACCOUNT_USAGE.DATA_TRANSFER_HISTORY`.
- `events`: Handler log messages from the Snowflake event table.
- `external_access_history`: Outbound network access events from `SNOWFLAKE.ACCOUNT_USAGE.EXTERNAL_ACCESS_HISTORY` joined with query details.
- `grants_to_users`: Role grants and revocations from `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`.
- `login_history`: User authentication and login attempts from `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY`.
- `query_history`: Completed SQL statements from `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY`.
- `sessions`: Session lifecycle events from `SNOWFLAKE.ACCOUNT_USAGE.SESSIONS`.
- `stages`: Stage inventory changes from `SNOWFLAKE.ACCOUNT_USAGE.STAGES`.

### Compatibility

This integration queries Snowflake `ACCOUNT_USAGE` historical views and the account event table through SQL API v2 (`/api/v2/statements`). Those views retain about one year of data and have latency ranging from 45 minutes to 3 hours depending on the view. The `access_history` data stream requires Snowflake Enterprise Edition or later.

This integration is compatible with Snowflake accounts hosted on the following cloud providers:
- Amazon Web Services (AWS)
- Google Cloud Platform (GCP)
- Microsoft Azure

PrivateLink hosts and China region hosts (`.snowflakecomputing.cn`) are supported when you set the account URL accordingly.

This integration requires Elastic Stack version 8.11.0 or later.

### How it works

Elastic Agent submits SQL statements to the Snowflake SQL API v2 endpoint (`POST /api/v2/statements`) and reads result partitions. If Snowflake returns an HTTP status code `202`, Elastic Agent polls the statement handle until results are ready.

Each data stream queries a single `ACCOUNT_USAGE` view or event table and advances a timestamp watermark with lookback to cover view latency. When a statement returns a full `batch_size` page, the next request continues from the last returned `ORDER BY` key without lag overlap until the backlog drains. Role grants maintain separate watermarks for creation and deletion timestamps.

## What data does this integration collect?

The Snowflake integration collects logs and security telemetry from the following data streams:
- `query_history`: Completed SQL statements from `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY` collected through the SQL API, including SQL text, user, role, warehouse, execution status, byte counts, and timing information.
- `events`: Handler log messages with a `RECORD_TYPE` of `LOG` from the account event table (default `SNOWFLAKE.TELEMETRY.EVENTS_VIEW`) through the SQL API. Rows with `SPAN`, `SPAN_EVENT`, `METRIC`, or `EVENT` record types are dropped during ingest.
- `external_access_history`: Outbound network calls from user-defined function (UDF) and procedure handlers in `SNOWFLAKE.ACCOUNT_USAGE.EXTERNAL_ACCESS_HISTORY`, joined to `QUERY_HISTORY` for event timing using the SQL API.
- `access_history`: Objects and columns read or written by queries from `SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY`, including direct and base objects accessed, objects modified, DDL operations, and policies referenced. This stream requires Snowflake Enterprise Edition or later.
- `data_transfer_history`: Hourly byte-count windows of data moved between cloud providers and regions from `SNOWFLAKE.ACCOUNT_USAGE.DATA_TRANSFER_HISTORY`, organized by transfer type. This stream requires the `USAGE_VIEWER` database role or equivalent on the `SNOWFLAKE` database.
- `stages`: Stage inventory changes (creation, alteration, and deletion) from `SNOWFLAKE.ACCOUNT_USAGE.STAGES`, including external stage locations such as `s3://`, `azure://`, or `gcs://` and configured storage integrations. This stream requires the `OBJECT_VIEWER` database role or equivalent on the `SNOWFLAKE` database.
- `login_history`: Authentication attempts from `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY`, including user names, client IP addresses, authentication factors used, success or failure results, and malicious IP protection details.
- `sessions`: Session lifecycle activity from `SNOWFLAKE.ACCOUNT_USAGE.SESSIONS`, including open or closed session states, last access timestamps, and session closure reasons.
- `grants_to_users`: Privilege assignments and role revoke events from `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`.

### Supported use cases

You can use this integration for the following security and operational use cases:
- Track user authentication attempts, session lifecycles, and privilege changes to maintain a secure environment and meet regulatory requirements.
- Detect unusual data transfer volumes across cloud providers or regions, and monitor outbound network access from user-defined function or procedure handlers to identify potential data exfiltration paths.
- Analyze completed SQL statements to monitor performance, identify long-running queries, and audit raw SQL text for sensitive operations or configuration changes.
- Inspect direct and base object access to ensure sensitive tables and columns are accessed only by authorized users and roles.

## What do I need to use this integration?

Before you install and configure this integration, ensure you have:

- Elastic Stack version 8.11.0 or later.
- An Elastic Agent installed and enrolled in Fleet.
- Outbound HTTPS network connectivity (port 443) from the Elastic Agent host to your Snowflake account URL.
- Snowflake administrative access (for example, `ACCOUNTADMIN` or `SECURITYADMIN` role) to create users, roles, and grant privileges.
- A Snowflake virtual warehouse configured with `AUTO_RESUME = TRUE`.
- A Snowflake `TYPE=SERVICE` user with a role authorized to query the `SNOWFLAKE.ACCOUNT_USAGE` views and use the virtual warehouse.
- A Programmatic Access Token (PAT) generated for the service user (standard password, OAuth access tokens, and key-pair JWT authentication aren't supported).
- Snowflake Enterprise Edition or later if you plan to collect data using the `access_history` data stream.
- The `USAGE_VIEWER` and `OBJECT_VIEWER` database roles (or equivalent) on the `SNOWFLAKE` database to collect data for streams such as `data_transfer_history` and `stages`.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data using the Snowflake SQL API and ship the data to Elastic, where the events will then be processed using the integration's ingest pipelines.

### Set up steps in Snowflake

To set up Snowflake for data collection, run the following steps in a Snowflake worksheet:

1. Create a dedicated role for the agent:
   ```sql
   CREATE ROLE ELASTIC_AGENT_ROLE;
   ```
2. Grant monitoring database roles to the new agent role:
   - `SNOWFLAKE.GOVERNANCE_VIEWER` for `access_history`, `external_access_history`, and `query_history`
   - `SNOWFLAKE.USAGE_VIEWER` for `data_transfer_history` and `external_access_history`
   - `SNOWFLAKE.OBJECT_VIEWER` for `stages`
   - `SNOWFLAKE.SECURITY_VIEWER` for `grants_to_users`, `login_history`, and `sessions`
   - `SNOWFLAKE.EVENTS_VIEWER` for `events`

   Run the following SQL commands:
   ```sql
   GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
   GRANT DATABASE ROLE SNOWFLAKE.USAGE_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
   GRANT DATABASE ROLE SNOWFLAKE.OBJECT_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
   GRANT DATABASE ROLE SNOWFLAKE.SECURITY_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
   GRANT DATABASE ROLE SNOWFLAKE.EVENTS_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
   ```
3. Create a virtual warehouse for queries and grant usage to the role:
   ```sql
   CREATE WAREHOUSE ELASTIC_AGENT_WH WITH WAREHOUSE_SIZE = 'XSMALL' AUTO_SUSPEND = 60 AUTO_RESUME = TRUE;
   GRANT USAGE ON WAREHOUSE ELASTIC_AGENT_WH TO ROLE ELASTIC_AGENT_ROLE;
   ```
4. Create a service user and assign the role:
   ```sql
   CREATE USER ELASTIC_AGENT_USER TYPE = SERVICE DEFAULT_ROLE = ELASTIC_AGENT_ROLE;
   GRANT ROLE ELASTIC_AGENT_ROLE TO USER ELASTIC_AGENT_USER;
   ```
5. If a network policy is enabled, set the policy to allow the Elastic Agent IP address (replace `<your-agent-ip>` with your actual Elastic Agent egress IP address):
   ```sql
   CREATE NETWORK POLICY ELASTIC_AGENT_POLICY ALLOWED_IP_LIST = ('<your-agent-ip>');
   ALTER USER ELASTIC_AGENT_USER SET NETWORK_POLICY = ELASTIC_AGENT_POLICY;
   ```
6. Generate a Programmatic Access Token (PAT) for the service user and record the token secret:
   ```sql
   ALTER USER ELASTIC_AGENT_USER ADD PROGRAMMATIC ACCESS TOKEN elastic_agent_token ROLE_RESTRICTION = 'ELASTIC_AGENT_ROLE' DAYS_TO_EXPIRY = 90;
   ```

#### Vendor resources

For more information on setting up Snowflake, refer to the following documentation:
- [Using programmatic access tokens for authentication](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens)
- [ALTER USER … ADD PROGRAMMATIC ACCESS TOKEN (PAT)](https://docs.snowflake.com/en/sql-reference/sql/alter-user-add-programmatic-access-token)
- [SQL API introduction](https://docs.snowflake.com/en/developer-guide/sql-api/intro)
- [Authenticating to the SQL API](https://docs.snowflake.com/en/developer-guide/sql-api/authenticating)
- [Account Usage](https://docs.snowflake.com/en/sql-reference/account-usage)
- [SNOWFLAKE database roles](https://docs.snowflake.com/en/sql-reference/snowflake-db-roles)
- [Event table setup](https://docs.snowflake.com/en/developer-guide/logging-tracing/event-table-setting-up)

### Set up steps in Kibana

To configure the integration in Kibana, follow these steps:

1. In Kibana, navigate to **Management** > **Integrations**.
2. Search for **Snowflake** and select the integration.
3. Select **Add Snowflake**.
4. Configure the global settings:
   - Account URL: Enter your Snowflake account URL including scheme (for example, `https://myorg-myaccount.snowflakecomputing.com` or PrivateLink host `https://myorg-myaccount.privatelink.snowflakecomputing.com`).
   - Role: Enter the Snowflake role granted to the service user (for example, `ELASTIC_AGENT_ROLE`).
   - Warehouse: Enter the virtual warehouse name (for example, `ELASTIC_AGENT_WH`).
   - Token: Enter the programmatic access token secret for the service user. Key-pair JWT and OAuth access tokens are not supported.
5. Under **Advanced Options**, configure optional parameters if needed:
   - Proxy URL: Enter the proxy server URL in the format `http://<user>:<password>@<server>:<port>` (replace with your actual proxy details).
   - SSL: Configure SSL options if custom certificates or verification settings are needed.
6. Enable and configure the specific data streams you want to collect:
   - Access History (`snowflake.access_history`): Collects object and column access events from `SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY`. Requires Snowflake Enterprise Edition or later.
   - Data Transfer History (`snowflake.data_transfer_history`): Collects hourly aggregated cross-cloud and cross-region data transfer volumes from `SNOWFLAKE.ACCOUNT_USAGE.DATA_TRANSFER_HISTORY`.
   - Events (`snowflake.events`): Collects handler log messages (`RECORD_TYPE LOG`) from the Snowflake event table (default `SNOWFLAKE.TELEMETRY.EVENTS_VIEW`).
   - External Access History (`snowflake.external_access_history`): Collects outbound network access from `SNOWFLAKE.ACCOUNT_USAGE.EXTERNAL_ACCESS_HISTORY`, joined to `QUERY_HISTORY`.
   - Grants to Users (`snowflake.grants_to_users`): Collects role grants and revokes from `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`.
   - Login History (`snowflake.login_history`): Collects login attempts from `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY`.
   - Query History (`snowflake.query_history`): Collects completed SQL statements from `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY`.
   - Sessions (`snowflake.sessions`): Collects session lifecycle events from `SNOWFLAKE.ACCOUNT_USAGE.SESSIONS`.
   - Stages (`snowflake.stages`): Collects stage inventory changes from `SNOWFLAKE.ACCOUNT_USAGE.STAGES`.
7. For each data stream, configure optional parameters if needed:
   - Interval: How often to query the specific view (for example, `1h`, `2h`, or `3h`).
   - Initial interval: How far back to query on the first run (defaults to `24h`).
   - Lag time: Duration subtracted from the watermark to include late-arriving rows.
   - Batch size: SQL limit applied to statements (defaults to `10000`).
   - HTTP Client Timeout: Timeout for API requests (defaults to `90s`).
   - Resource Retry Max Attempts: Maximum HTTP retries (defaults to `5`).
   - Preserve original event: Store raw copy of event in `event.original` (defaults to `false`).
   - Enable request tracing: Debugging tool for logging HTTP requests (defaults to `false`). Enabling request tracing writes raw HTTP request payloads to agent logs, which may contain sensitive data; use this option for troubleshooting only.
   - Processors: Add Elastic Agent processors to filter or enhance data before ingest.
   - Tags: Add custom tags to apply to events.
8. Assign the integration policy to an agent policy and select **Save and continue**.

### Validation

To validate that the integration is working properly and ingesting data into Elasticsearch, perform the following steps:

1. Verify Fleet status:
   In Kibana, navigate to **Management** > **Fleet** > **Agents** and verify that the Elastic Agent status is online and healthy.
2. Trigger telemetry activity in Snowflake:
   To generate data for validation, run the following actions in Snowflake:
   - Authentication event: Log out and log back into the Snowflake web interface to generate a login record.
   - Query event: Run a simple query in a worksheet (for example, `SELECT 1;`) to generate a query record.
   - Configuration change: Create a temporary test stage to trigger a stage event:
     ```sql
     CREATE OR REPLACE STAGE elastic_validation_test;
     ```
   - Access event: Query a table with sensitive data (if using Snowflake Enterprise Edition or later) to generate an access history entry.
3. Check data in Discover:
   - In Kibana, navigate to **Analytics** > **Discover**.
   - Select the `logs-*` data view.
   - In the search bar, filter by `data_stream.dataset` to verify incoming documents for enabled streams (for example, `data_stream.dataset: "snowflake.query_history"` or `data_stream.dataset: "snowflake.login_history"`).
   - Expand a document and verify that timestamps are recent and expected fields are populated, including `event.dataset`, `source.ip`, `event.action`, and `message`.
4. Check dashboards:
   In Kibana, navigate to **Analytics** > **Dashboards** and search for Snowflake dashboards (for example, "Snowflake Authentication and Access Overview" or "Snowflake Query Analysis and Security") to verify visualizations are populated with data.

## Troubleshooting

For help with Elastic ingest tools, see [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

If you encounter issues while using this integration, check the following common problems:
- No data is being collected: Confirm the Snowflake warehouse can auto-resume (`AUTO_RESUME = TRUE`), the assigned role has the required `SNOWFLAKE` database roles, and the account URL is reachable on HTTPS port `443`. In addition, `ACCOUNT_USAGE` view latency means new rows can take between 45 minutes and 3 hours to appear.
- `access_history` data stream returns an error: The `ACCESS_HISTORY` view exists only on Snowflake Enterprise Edition or later. Disable the `access_history` data stream if you're using an earlier edition.
- Authentication failures occur: Service users can't use passwords or OAuth tokens. Provide a Programmatic Access Token (PAT). Ensure you applied the correct role restriction during token generation. The integration sends `X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN`.
- Network policy blocks the SQL API: Add the Elastic Agent egress IP address to your network policy, or use a PrivateLink hostname retrieved through `SYSTEM$GET_PRIVATELINK_CONFIG()`.
- HTTP 429 (`390505`) rate limit errors: Reduce the polling frequency in the integration settings to decrease API request volume. Snowflake doesn't specify a `Retry-After` contract on the SQL API.
- Missing data in specific data streams: Verify that the assigned role has the required database role for that view. For example, `stages` requires `SNOWFLAKE.OBJECT_VIEWER` and `data_transfer_history` requires `SNOWFLAKE.USAGE_VIEWER`.
- Sensitive information in `QUERY_TEXT`: Collecting `query_history` stores SQL statement text, which can include literals or tokens. Use Elastic Agent processors to mask or drop sensitive query patterns.
- External access rows lack a native timestamp: The `external_access_history` data stream joins `QUERY_HISTORY` on `QUERY_ID` and watermarks on `END_TIME`.
- Duplicate rows appear in indices: Each poll overlaps the previous watermark by the configured lag time to capture late-arriving rows. Documents use a fingerprint `_id`, so re-delivered rows are dropped as duplicates rather than overwritten. A few duplicate documents can appear across index rollovers.

### Vendor resources

Refer to the following Snowflake documentation for additional troubleshooting information:
- [Snowflake SQL API reference](https://docs.snowflake.com/en/developer-guide/sql-api/index)
- [Snowflake Account Usage documentation](https://docs.snowflake.com/en/sql-reference/account-usage)
- [Using programmatic access tokens for authentication](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens)

## Performance and scaling

Each poll runs queries on your configured warehouse and consumes Snowflake credits. Because latency for `ACCOUNT_USAGE` views ranges between 45 minutes and 3 hours, polling faster than the view latency doesn't make your data fresher.

To balance performance and credit usage, use these suggested starting intervals:
- Set `1h` for `query_history`.
- Set `2h` for `data_transfer_history`, `events`, `grants_to_users`, `login_history`, and `stages`.
- Set `3h` for `access_history`, `external_access_history`, and `sessions`.

To optimize resource usage and prevent bottlenecks, follow these scaling guidelines:
- Overlap the watermark by at least the view latency to ensure you include late-arriving rows.
- Keep the batch size at the default setting of `10000` to balance memory usage on Elastic Agent and the number of API calls to Snowflake.
- If your virtual warehouse times out under load, consider increasing the HTTP client timeout or using a larger warehouse size, though an `XSMALL` warehouse is typically sufficient for metadata polling.
- For high-volume environments or organizations with many data streams, deploy multiple Elastic Agents and distribute data streams across separate policies so a single agent isn't overwhelmed by large result sets from views like `query_history` or `access_history`.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### API usage

This integration uses the following APIs to collect data from Snowflake:
- [Submit SQL](https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests) - `POST /api/v2/statements`
- [Poll status and fetch partitions](https://docs.snowflake.com/en/developer-guide/sql-api/handling-responses) - `GET /api/v2/statements/{statementHandle}`

### Vendor documentation links

The following vendor documentation links provide reference information about Snowflake account usage views, event tables, and APIs:
- [Snowflake SQL API reference](https://docs.snowflake.com/en/developer-guide/sql-api/index)
- [Snowflake Account Usage documentation](https://docs.snowflake.com/en/sql-reference/account-usage)
- [QUERY_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/query_history)
- [EXTERNAL_ACCESS_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/external_access_history)
- [Event table columns](https://docs.snowflake.com/en/developer-guide/logging-tracing/event-table-columns)
- [ACCESS_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/access_history)
- [DATA_TRANSFER_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/data_transfer_history)
- [STAGES view](https://docs.snowflake.com/en/sql-reference/account-usage/stages)
- [LOGIN_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/login_history)
- [SESSIONS view](https://docs.snowflake.com/en/sql-reference/account-usage/sessions)
- [GRANTS_TO_USERS view](https://docs.snowflake.com/en/sql-reference/account-usage/grants_to_users)

### Data streams

#### access_history

The `access_history` data stream provides object and column access events from `SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY`. Nested object lists are decoded from the view's JSON columns and kept as flattened fields. Object names and column names (which vary for each query) are also extracted into keyword arrays for aggregation.

##### access_history fields

{{ fields "access_history" }}

##### access_history sample event

{{ event "access_history" }}

#### data_transfer_history

The `data_transfer_history` data stream provides hourly data transfer windows from `SNOWFLAKE.ACCOUNT_USAGE.DATA_TRANSFER_HISTORY`. Bytes transferred are mapped to `network.bytes` and the transfer type to `event.action`.

##### data_transfer_history fields

{{ fields "data_transfer_history" }}

##### data_transfer_history sample event

{{ event "data_transfer_history" }}

#### events

The `events` data stream collects handler log messages from the account event table (default `SNOWFLAKE.TELEMETRY.EVENTS_VIEW`). The collector filters `RECORD_TYPE = 'LOG'`; remaining `SPAN`, `SPAN_EVENT`, `METRIC`, or `EVENT` rows are dropped by the ingest pipeline. You can confirm a custom table name using `SHOW PARAMETERS LIKE 'EVENT_TABLE' IN ACCOUNT`.

##### events fields

{{ fields "events" }}

##### events sample event

{{ event "events" }}

#### external_access_history

The `external_access_history` data stream provides outbound network access events from `SNOWFLAKE.ACCOUNT_USAGE.EXTERNAL_ACCESS_HISTORY`, joined to `QUERY_HISTORY` for `END_TIME`.

##### external_access_history fields

{{ fields "external_access_history" }}

##### external_access_history sample event

{{ event "external_access_history" }}

#### grants_to_users

The `grants_to_users` data stream provides role grant and revoke events from `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`. Creates and revokes are collected with separate statements so a revoke timestamp cannot skip unread grants.

##### grants_to_users fields

{{ fields "grants_to_users" }}

##### grants_to_users sample event

{{ event "grants_to_users" }}

#### login_history

The `login_history` data stream provides login attempt events from `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY`.

##### login_history fields

{{ fields "login_history" }}

##### login_history sample event

{{ event "login_history" }}

#### query_history

The `query_history` data stream provides completed SQL statement events from `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY`. The collector watermarks on `END_TIME`.

##### query_history fields

{{ fields "query_history" }}

##### query_history sample event

{{ event "query_history" }}

#### sessions

The `sessions` data stream provides session lifecycle events from `SNOWFLAKE.ACCOUNT_USAGE.SESSIONS`. Rows update until the session closes. The collector watermarks on `ACCESS_TIME`.

##### sessions fields

{{ fields "sessions" }}

##### sessions sample event

{{ event "sessions" }}

#### stages

The `stages` data stream provides stage lifecycle events from `SNOWFLAKE.ACCOUNT_USAGE.STAGES`. Rows update in place, so the collector watermarks on `LAST_ALTERED` and `DELETED`, and the pipeline derives `create`, `alter`, or `drop` from the timestamps.

##### stages fields

{{ fields "stages" }}

##### stages sample event

{{ event "stages" }}
