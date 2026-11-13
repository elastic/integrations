{{- generatedHeader }}
# Snowflake Integration for Elastic

## Overview

The Snowflake integration for Elastic collects security telemetry from [Snowflake](https://www.snowflake.com/) `ACCOUNT_USAGE` views and event tables using the [SQL API](https://docs.snowflake.com/en/developer-guide/sql-api/intro). It covers completed SQL statements, handler log messages, outbound network access from user-defined functions and procedures, object and column access, cross-cloud and cross-region data transfer, stage lifecycle changes, authentication, sessions, and privilege changes so you can monitor data access and possible exfiltration paths in Elasticsearch.

### Compatibility

This integration queries Snowflake `ACCOUNT_USAGE` historical views and the account event table through SQL API v2 (`/api/v2/statements`). Those views retain about one year of data and are delayed (about 45 minutes to 3 hours depending on the view). It is compatible with Snowflake accounts on AWS, Azure, and Google Cloud, including PrivateLink hosts. China region hosts (`.snowflakecomputing.cn`) are supported when the account URL is set accordingly. The `access_history` data stream requires Snowflake Enterprise Edition or later.

## What data does this integration collect?

The Snowflake integration collects the following logs:

* **query_history**: Completed statements from `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY` (SQL text, user, role, warehouse, status, bytes, and timing).
* **events**: Handler **log messages** (`RECORD_TYPE` `LOG`) from the account event table (default `SNOWFLAKE.TELEMETRY.EVENTS_VIEW`). The collector filters `RECORD_TYPE = 'LOG'`; remaining `SPAN`, `SPAN_EVENT`, `METRIC`, or `EVENT` rows are dropped during ingest.
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

This integration supports both Elastic Managed and Agent-based installations.

### Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Set up steps in Snowflake

Run the statements in a Snowflake worksheet as `ACCOUNTADMIN`. Replace `ELASTIC_AGENT_ROLE` and `ELASTIC_WH` with an existing role and a warehouse. Use those same names for **Role** and **Warehouse** in Kibana.

#### 1. Grant the privileges

The integration role needs `USAGE` on a warehouse, plus the SNOWFLAKE database roles for the data streams you enable. Only `ACCOUNTADMIN` can grant those database roles.

| Privilege | Data streams |
| --- | --- |
| `USAGE` on the warehouse | All |
| `SNOWFLAKE.GOVERNANCE_VIEWER` | `query_history`, `access_history`, and `external_access_history` (the external access collector joins `QUERY_HISTORY`) |
| `SNOWFLAKE.USAGE_VIEWER` | `external_access_history` and `data_transfer_history` |
| `SNOWFLAKE.OBJECT_VIEWER` | `stages` |
| `SNOWFLAKE.SECURITY_VIEWER` | `login_history`, `sessions`, and `grants_to_users` |
| `SNOWFLAKE.EVENTS_VIEWER` | `events`, for the default `SNOWFLAKE.TELEMETRY.EVENTS_VIEW` |

```sql
USE ROLE ACCOUNTADMIN;

GRANT USAGE ON WAREHOUSE ELASTIC_WH TO ROLE ELASTIC_AGENT_ROLE;

GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
GRANT DATABASE ROLE SNOWFLAKE.USAGE_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
GRANT DATABASE ROLE SNOWFLAKE.OBJECT_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
GRANT DATABASE ROLE SNOWFLAKE.SECURITY_VIEWER TO ROLE ELASTIC_AGENT_ROLE;

GRANT APPLICATION ROLE SNOWFLAKE.EVENTS_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
```

Each poll consumes credits on that warehouse. Skip `EVENTS_VIEWER` when you will not collect `events`. For a custom event table, grant `USAGE` on its database and schema and `SELECT` on the table instead of `EVENTS_VIEWER`.

#### 2. Create the token

The role must be granted to the user before `ROLE_RESTRICTION` is set. Copy `token_secret` from the result. Snowflake shows it only once. Paste that value into the Kibana **Token** field, without a `Bearer ` prefix.

Snowflake rejects the token statement when the service user has no network policy that contains a network rule. That is a programmatic access token requirement, not a general Snowflake login requirement. The statements are in Troubleshooting.

```sql
CREATE USER IF NOT EXISTS ELASTIC_AGENT_USER
  TYPE = SERVICE
  DEFAULT_ROLE = ELASTIC_AGENT_ROLE
  DEFAULT_WAREHOUSE = ELASTIC_WH
  COMMENT = 'Service user for the Elastic Snowflake integration';

GRANT ROLE ELASTIC_AGENT_ROLE TO USER ELASTIC_AGENT_USER;

ALTER USER IF EXISTS ELASTIC_AGENT_USER
  ADD PROGRAMMATIC ACCESS TOKEN elastic_agent_token
  ROLE_RESTRICTION = 'ELASTIC_AGENT_ROLE'
  DAYS_TO_EXPIRY = 90
  COMMENT = 'Elastic Agent SQL API token';
```

The result looks like this. The Kibana **Token** is the `token_secret` cell.

```text
+----------------------+-------------------------------+
| token_name           | token_secret                  |
+----------------------+-------------------------------+
| ELASTIC_AGENT_TOKEN  | <copy this entire cell>       |
+----------------------+-------------------------------+
```

`DAYS_TO_EXPIRY` cannot exceed the account maximum. If you closed the result before copying the secret, run the following statement and copy the new `token_secret`. The previous secret stops working immediately.

```sql
ALTER USER IF EXISTS ELASTIC_AGENT_USER
  ROTATE PROGRAMMATIC ACCESS TOKEN elastic_agent_token
  EXPIRE_ROTATED_TOKEN_AFTER_HOURS = 0;
```

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
3. Set the account URL (for example `https://myorg-myaccount.snowflakecomputing.com`), the role, and the warehouse from the grant statements.
4. Paste the `token_secret` value into **Token**. Username/password, OAuth access tokens, and key-pair JWT are not accepted.
5. Enable the data streams you want and save the policy.

### Validation

In Discover, filter on `event.dataset: snowflake.query_history`, `event.dataset: snowflake.events`, `event.dataset: snowflake.external_access_history`, `event.dataset: snowflake.access_history`, `event.dataset: snowflake.data_transfer_history`, `event.dataset: snowflake.stages`, `event.dataset: snowflake.login_history`, `event.dataset: snowflake.sessions`, or `event.dataset: snowflake.grants_to_users`. Query history and access history should contain `event.category: database` events. External access and data transfer should contain `event.category: network` events (data transfer includes `network.bytes`). Stages should contain `event.category: configuration` events with `event.action` of `create`, `alter`, or `drop`. Login history should contain `event.category: authentication` events. Grants should contain IAM change events.

## Troubleshooting

- No data is being collected: Confirm the warehouse can auto-resume, the role has the required SNOWFLAKE database or application roles (or imported privileges), and the account URL is reachable on HTTPS 443. ACCOUNT_USAGE latency means new rows can take up to 45 minutes to 3 hours to appear.
- `access_history` returns an error: The `ACCESS_HISTORY` view exists only on Enterprise Edition or later. Turn off the data stream on lower editions.
- Authentication failures: Service users cannot use passwords. Provide a programmatic access token. The integration always sends `X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN`.
- Token creation fails, or the SQL API is blocked by a network policy: A service user must be subject to a network policy that contains at least one network rule before Snowflake will create or accept a programmatic access token. Allow the Elastic Agent egress address on the existing policy, or create one and attach it, then run the token statement again. For an Elastic Managed deployment, use the static egress addresses for your Elastic Cloud region from [Elastic Cloud traffic filtering](https://www.elastic.co/guide/en/cloud/current/ec-traffic-filtering-ip.html). For PrivateLink, allow the endpoint from `SYSTEM$GET_PRIVATELINK_CONFIG()` instead of a public CIDR.

  ```sql
  CREATE DATABASE IF NOT EXISTS ELASTIC_AGENT_DB;
  CREATE SCHEMA IF NOT EXISTS ELASTIC_AGENT_DB.SECURITY;

  CREATE NETWORK RULE IF NOT EXISTS ELASTIC_AGENT_DB.SECURITY.ELASTIC_AGENT_INGRESS
    MODE = INGRESS
    TYPE = IPV4
    VALUE_LIST = ('<elastic_agent_egress_cidr>');

  CREATE NETWORK POLICY IF NOT EXISTS ELASTIC_AGENT_POLICY
    ALLOWED_NETWORK_RULE_LIST = ('ELASTIC_AGENT_DB.SECURITY.ELASTIC_AGENT_INGRESS');

  ALTER USER IF EXISTS ELASTIC_AGENT_USER SET NETWORK_POLICY = ELASTIC_AGENT_POLICY;
  ```
- HTTP 429 (`390505`): Reduce poll frequency. There is no documented `Retry-After` contract on the SQL API.
- QUERY_TEXT can contain secrets: Collecting `query_history` stores statement text, which can include literals or tokens.
- External access rows have no native timestamp: The stream joins `QUERY_HISTORY` on `QUERY_ID` and watermarks on `END_TIME`.
- Duplicate rows: Each poll overlaps the previous watermark by the configured lag time so late-arriving rows are included. Documents use a fingerprint `_id`, so re-delivered rows are usually dropped as duplicates, never overwritten, and a few duplicates can appear across index rollovers.

## Performance and scaling

Each poll runs SQL on the configured warehouse and consumes Snowflake credits. `ACCOUNT_USAGE` latency is 45 minutes to 3 hours, so polling faster than the view latency does not make data fresher. Suggested starting intervals are `1h` for query history, `2h` for events, login history, grants, data transfer history, and stages, and `3h` for external access history, sessions, and access history. Overlap the watermark by at least the view latency so late-arriving rows are included. `ACCESS_HISTORY` can be high volume on busy accounts. Keep `batch_size` at the default unless statements time out.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### How it works

Elastic Agent submits SQL statements to `POST /api/v2/statements` and pages result partitions. If Snowflake returns HTTP 202, the agent polls the statement handle until results are ready. Each data stream queries one `ACCOUNT_USAGE` view or event table and advances a timestamp watermark with lookback to cover view latency. When a statement returns a full `batch_size` page, the next request continues from the last returned `ORDER BY` key without the lag overlap until the backlog is drained.
Grants keep separate watermarks for `CREATED_ON` and `DELETED_ON`.

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

The `events` data stream collects handler **log messages** from the account event table (default `SNOWFLAKE.TELEMETRY.EVENTS_VIEW`). The collector filters `RECORD_TYPE = 'LOG'`; remaining `SPAN`, `SPAN_EVENT`, `METRIC`, or `EVENT` rows are dropped by the ingest pipeline. Confirm a custom table name with `SHOW PARAMETERS LIKE 'EVENT_TABLE' IN ACCOUNT`.

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
