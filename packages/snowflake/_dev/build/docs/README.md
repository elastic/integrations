{{- generatedHeader }}
# Snowflake Integration for Elastic

## Overview

The Snowflake integration for Elastic collects security telemetry from [Snowflake](https://www.snowflake.com/) `ACCOUNT_USAGE` views and event tables using the [SQL API](https://docs.snowflake.com/en/developer-guide/sql-api/intro). It covers completed SQL statements, handler log messages, outbound network access from user-defined functions and procedures, object and column access, cross-cloud and cross-region data transfer, stage lifecycle changes, authentication, sessions, and privilege changes so you can monitor data access and possible exfiltration paths in Elasticsearch.

### Compatibility

This integration queries Snowflake `ACCOUNT_USAGE` historical views and the account event table through SQL API v2 (`/api/v2/statements`). Those views retain about one year of data and are delayed (about 45 minutes to 3 hours depending on the view). It is compatible with Snowflake accounts on AWS, Azure, and Google Cloud, including PrivateLink hosts. China region hosts (`.snowflakecomputing.cn`) are supported when the account URL is set accordingly. The `access_history` data stream requires Snowflake Enterprise Edition or later.

### How it works

Elastic Agent submits SQL statements to `POST /api/v2/statements` and pages result partitions. If Snowflake returns HTTP 202, the agent polls the statement handle until results are ready. Each data stream queries one `ACCOUNT_USAGE` view or event table and advances a timestamp watermark with lookback to cover view latency. When a statement returns a full `batch_size` page, the next request continues from the last returned `ORDER BY` key without the lag overlap until the backlog is drained.
Grants keep separate watermarks for `CREATED_ON` and `DELETED_ON`.

## What data does this integration collect?

The Snowflake integration collects the following logs:

* **query_history**: Completed statements from `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY` (SQL text, user, role, warehouse, status, bytes, and timing).
* **events**: Handler **log messages** (`RECORD_TYPE` `LOG`) from the account event table (default `SNOWFLAKE.TELEMETRY.EVENTS`). Rows with `SPAN`, `SPAN_EVENT`, `METRIC`, or `EVENT` are dropped during ingest and are not stored in Elasticsearch.
* **external_access_history**: Outbound network calls from UDF and procedure handlers in `SNOWFLAKE.ACCOUNT_USAGE.EXTERNAL_ACCESS_HISTORY`, joined to `QUERY_HISTORY` for event time.
* **access_history**: Objects and columns read or written by each query from `SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY` (direct and base objects accessed, objects modified, DDL operations, policies referenced). Enterprise Edition or later.
* **data_transfer_history**: Hourly byte-count windows of data moved between clouds and regions from `SNOWFLAKE.ACCOUNT_USAGE.DATA_TRANSFER_HISTORY`, by transfer type.
* **stages**: Stage create, alter, and drop activity from `SNOWFLAKE.ACCOUNT_USAGE.STAGES`, including external stage locations (`s3://`, `azure://`, `gcs://`) and storage integrations. Watermarks are `LAST_ALTERED` and `DELETED` because rows update in place.
* **login_history**: Login attempts from `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY` (user, client IP, authentication factors, success or failure, malicious-IP protection details).
* **sessions**: Session lifecycle from `SNOWFLAKE.ACCOUNT_USAGE.SESSIONS` (open or closed sessions, last access time, closed reason). Watermark is `ACCESS_TIME` because session rows update until they close.
* **grants_to_users**: Role grants and revokes from `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`. Creates and revokes are queried separately so each watermark advances only along `CREATED_ON` or `DELETED_ON`.

### Supported use cases

Use this integration to audit SQL activity and handler log messages, detect unexpected outbound network access from Snowflake handlers, detect failed or suspicious logins, track session activity, audit privilege grants and revokes, monitor access to sensitive tables and columns, detect unusual outbound data transfers, and track the creation or alteration of external stages that could facilitate data exfiltration from Snowflake.

## What do I need to use this integration?

* An Elastic Stack deployment (self-managed or Elastic Cloud) that meets the package Kibana version condition.
* A Snowflake account and a virtual warehouse that can auto-resume.
* A Snowflake `TYPE=SERVICE` user with a role that can query the views and use the warehouse.
* A programmatic access token for the service user. Username/password, OAuth access tokens, and key-pair JWT are not supported by this integration.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the SQL API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Snowflake

1. Create a role and a `TYPE=SERVICE` user, and grant the role to the user.
2. Grant `USAGE` on a warehouse that can auto-resume.
3. Grant the SNOWFLAKE database roles and application roles the data streams need (or `IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE`):
   * `SNOWFLAKE.GOVERNANCE_VIEWER` for `query_history` and `access_history`
   * `SNOWFLAKE.USAGE_VIEWER` for `external_access_history` and `data_transfer_history`
   * `SNOWFLAKE.OBJECT_VIEWER` for `stages`
   * `SNOWFLAKE.SECURITY_VIEWER` (or imported privileges) for `login_history`, `sessions`, and `grants_to_users`
   * Application role `SNOWFLAKE.EVENTS_VIEWER` (or `SELECT` on a custom event table) for `events`
4. Create a programmatic access token for the service user.
5. If a network policy is enabled, allow the Elastic Agent egress IP (or PrivateLink endpoint).

#### Vendor resources

- [SQL API introduction](https://docs.snowflake.com/en/developer-guide/sql-api/intro)
- [Authenticating to the SQL API](https://docs.snowflake.com/en/developer-guide/sql-api/authenticating)
- [Programmatic access tokens](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens)
- [Account Usage](https://docs.snowflake.com/en/sql-reference/account-usage)
- [SNOWFLAKE database roles](https://docs.snowflake.com/en/sql-reference/snowflake-db-roles)
- [Event table setup](https://docs.snowflake.com/en/developer-guide/logging-tracing/event-table-setting-up)

### Set up steps in Kibana

1. In Kibana go to **Management → Integrations**.
2. Search for **Snowflake** and add the integration.
3. Set the account URL, role, and warehouse.
4. Provide the programmatic access token for the service user. OAuth access tokens and key-pair JWT are not supported.
5. Enable the data streams you want and save the policy.

### Validation

In Discover, filter on `event.dataset: snowflake.query_history`, `event.dataset: snowflake.events`, `event.dataset: snowflake.external_access_history`, `event.dataset: snowflake.access_history`, `event.dataset: snowflake.data_transfer_history`, `event.dataset: snowflake.stages`, `event.dataset: snowflake.login_history`, `event.dataset: snowflake.sessions`, or `event.dataset: snowflake.grants_to_users`. Query history and access history should contain `event.category: database` events. External access and data transfer should contain `event.category: network` events (data transfer includes `network.bytes`). Stages should contain `event.category: configuration` events with `event.action` of `create`, `alter`, or `drop`. Login history should contain `event.category: authentication` events. Grants should contain IAM change events.

## Troubleshooting

- No data is being collected: Confirm the warehouse can auto-resume, the role has the required SNOWFLAKE database or application roles (or imported privileges), and the account URL is reachable on HTTPS 443. ACCOUNT_USAGE latency means new rows can take up to 45 minutes to 3 hours to appear.
- `access_history` returns an error: The `ACCESS_HISTORY` view exists only on Enterprise Edition or later. Turn off the data stream on lower editions.
- Authentication failures: Service users cannot use passwords. Provide a programmatic access token. The integration always sends `X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN`.
- Network policy blocks the SQL API: Add the agent egress IP, or use a PrivateLink hostname from `SYSTEM$GET_PRIVATELINK_CONFIG()`.
- HTTP 429 (`390505`): Reduce poll frequency. There is no documented `Retry-After` contract on the SQL API.
- QUERY_TEXT can contain secrets: Collecting `query_history` stores statement text, which can include literals or tokens.
- External access rows have no native timestamp: The stream joins `QUERY_HISTORY` on `QUERY_ID` and watermarks on `END_TIME`.
- Duplicate rows: Each poll overlaps the previous watermark by the configured lag time so late-arriving rows are included. Documents use a fingerprint `_id`, so re-delivered rows are usually dropped as duplicates, never overwritten, and a few duplicates can appear across index rollovers.

## Performance and scaling

Each poll runs SQL on the configured warehouse and consumes Snowflake credits. `ACCOUNT_USAGE` latency is 45 minutes to 3 hours, so polling faster than the view latency does not make data fresher. Suggested starting intervals are `1h` for query history, `2h` for events, login history, grants, data transfer history, and stages, and `3h` for external access history, sessions, and access history. Overlap the watermark by at least the view latency so late-arriving rows are included. `ACCESS_HISTORY` can be high volume on busy accounts. Keep `batch_size` at the default unless statements time out.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:

* [Submit SQL](https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests) — `POST /api/v2/statements`
* [Poll status and fetch partitions](https://docs.snowflake.com/en/developer-guide/sql-api/handling-responses) — `GET /api/v2/statements/{statementHandle}`

### Vendor documentation links

- [SQL API reference](https://docs.snowflake.com/en/developer-guide/sql-api/reference)
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

#### query_history

The `query_history` data stream provides completed SQL statement events from
`SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY`. The collector watermarks on `END_TIME`.

##### query_history fields

{{ fields "query_history" }}

##### query_history sample event

{{ event "query_history" }}

#### events

The `events` data stream collects handler **log messages** from the account event table (default `SNOWFLAKE.TELEMETRY.EVENTS`). Only rows with `RECORD_TYPE` `LOG` are ingested; `SPAN`, `SPAN_EVENT`, `METRIC`, and `EVENT` rows are dropped by the ingest pipeline. Confirm the table name with `SHOW PARAMETERS LIKE 'EVENT_TABLE' IN ACCOUNT`.

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

#### access_history

The `access_history` data stream provides object and column access events from `SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY`. Nested object lists are decoded from the view's JSON columns and kept as flattened fields. Object names and column names (which vary per query) are also extracted into keyword arrays for aggregation.

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

#### stages

The `stages` data stream provides stage lifecycle events from `SNOWFLAKE.ACCOUNT_USAGE.STAGES`. Rows update in place, so the collector watermarks on `LAST_ALTERED` and `DELETED`, and the pipeline derives `create`, `alter`, or `drop` from the timestamps.

##### stages fields

{{ fields "stages" }}

##### stages sample event

{{ event "stages" }}


#### login_history

The `login_history` data stream provides login attempt events from
`SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY`.

##### login_history fields

{{ fields "login_history" }}

##### login_history sample event

{{ event "login_history" }}

#### sessions

The `sessions` data stream provides session lifecycle events from
`SNOWFLAKE.ACCOUNT_USAGE.SESSIONS`. Rows update until the session closes.
The collector watermarks on `ACCESS_TIME`.

##### sessions fields

{{ fields "sessions" }}

##### sessions sample event

{{ event "sessions" }}

#### grants_to_users

The `grants_to_users` data stream provides role grant and revoke events from
`SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`. Creates and revokes are collected
with separate statements so a revoke timestamp cannot skip unread grants.

##### grants_to_users fields

{{ fields "grants_to_users" }}

##### grants_to_users sample event

{{ event "grants_to_users" }}
