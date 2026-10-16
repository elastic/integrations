{{- generatedHeader }}
# Snowflake Integration for Elastic

## Overview

The Snowflake integration for Elastic collects security telemetry from
[Snowflake](https://www.snowflake.com/) `ACCOUNT_USAGE` views using the
[SQL API](https://docs.snowflake.com/en/developer-guide/sql-api/intro). It
covers authentication attempts, session lifecycle, and role grants or revokes
so you can monitor access and privilege changes in Elasticsearch.

### Compatibility

This integration queries Snowflake `ACCOUNT_USAGE` historical views through
SQL API v2 (`/api/v2/statements`). Those views retain about one year of data
and are delayed (about 45 minutes to 3 hours depending on the view). It is
compatible with Snowflake accounts on AWS, Azure, and Google Cloud, including
PrivateLink hosts. China region hosts (`.snowflakecomputing.cn`) are supported
when the account URL is set accordingly.

### How it works

Elastic Agent submits SQL statements to `POST /api/v2/statements`, polls
asynchronous statement handles, and pages result partitions. Each data stream
queries one `ACCOUNT_USAGE` view and advances a timestamp watermark with
lookback to cover view latency. Grants keep separate watermarks for
`CREATED_ON` and `DELETED_ON`.

## What data does this integration collect?

The Snowflake integration collects the following logs:

* **login_history**: Login attempts from `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY` (user, client IP, authentication factors, success or failure, malicious-IP protection details).
* **sessions**: Session lifecycle from `SNOWFLAKE.ACCOUNT_USAGE.SESSIONS` (open or closed sessions, last access time, closed reason). Watermark is `ACCESS_TIME` because session rows update until they close.
* **grants_to_users**: Role grants and revokes from `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`. Creates and revokes are queried separately so each watermark advances only along `CREATED_ON` or `DELETED_ON`.

### Supported use cases

Use this integration to detect failed or suspicious logins, track session
activity, and audit privilege grants and revokes for Snowflake accounts.

## What do I need to use this integration?

* An Elastic Stack deployment (self-managed or Elastic Cloud) that meets the package Kibana version condition.
* A Snowflake account and a virtual warehouse that can auto-resume.
* A Snowflake `TYPE=SERVICE` user with a role that can query the views and use the warehouse.
* Authentication via a programmatic access token for a `TYPE=SERVICE` user. Username/password, OAuth access tokens, and key-pair JWT are not supported.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the SQL API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Snowflake

1. Create a role and a `TYPE=SERVICE` user, and grant the role to the user.
2. Grant `USAGE` on a warehouse that can auto-resume.
3. Grant the `SNOWFLAKE.SECURITY_VIEWER` database role (or `IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE`) so the user can read login history, sessions, and grants to users.
4. Create a programmatic access token for the service user.
5. If a network policy is enabled, allow the Elastic Agent egress IP (or PrivateLink endpoint).

#### Vendor resources

- [SQL API introduction](https://docs.snowflake.com/en/developer-guide/sql-api/intro)
- [Authenticating to the SQL API](https://docs.snowflake.com/en/developer-guide/sql-api/authenticating)
- [Programmatic access tokens](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens)
- [Account Usage](https://docs.snowflake.com/en/sql-reference/account-usage)
- [SNOWFLAKE database roles](https://docs.snowflake.com/en/sql-reference/snowflake-db-roles)

### Set up steps in Kibana

1. In Kibana go to **Management > Integrations**.
2. Search for **Snowflake** and add the integration.
3. Set the account URL, role, and warehouse.
4. Provide the programmatic access token.
5. Enable the data streams you want and save the policy.

### Validation

In Discover, filter on `event.dataset: snowflake.login_history`,
`event.dataset: snowflake.sessions`, or
`event.dataset: snowflake.grants_to_users`. Login history should contain
`event.category: authentication` events; grants should contain IAM change
events.

## Troubleshooting

- No data is being collected: Confirm the warehouse can auto-resume, the role has `SECURITY_VIEWER` (or imported privileges), and the account URL is reachable on HTTPS 443. ACCOUNT_USAGE latency means new rows may take up to 2–3 hours to appear.
- Authentication failures: Service users cannot use passwords. Provide a programmatic access token. The integration sends `X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN`.
- Network policy blocks the SQL API: Add the agent egress IP, or use a PrivateLink hostname from `SYSTEM$GET_PRIVATELINK_CONFIG()`.
- HTTP 429 (`390505`): Reduce poll frequency. There is no documented `Retry-After` contract on the SQL API.
- Session closes are missing: The sessions stream watermarks on `ACCESS_TIME`. SQL API transient sessions are not recorded in `ACCOUNT_USAGE.SESSIONS`.

## Performance and scaling

Each poll runs SQL on the configured warehouse and consumes Snowflake credits.
`ACCOUNT_USAGE` latency is 45 minutes to 3 hours, so polling faster than the
view latency does not make data fresher. Suggested starting intervals are `2h`
for login history and grants, and `3h` for sessions. Overlap the watermark by
at least the view latency so late-arriving rows are included.

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
- [LOGIN_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/login_history)
- [SESSIONS view](https://docs.snowflake.com/en/sql-reference/account-usage/sessions)
- [GRANTS_TO_USERS view](https://docs.snowflake.com/en/sql-reference/account-usage/grants_to_users)

### Data streams

#### login_history

The `login_history` data stream provides login attempt events from
`SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY`.

##### login_history fields

{{ fields "login_history" }}

##### login_history sample event

{{ event "login_history" }}

#### sessions

The `sessions` data stream provides session lifecycle events from
`SNOWFLAKE.ACCOUNT_USAGE.SESSIONS`. Rows update until the session closes;
the collector watermarks on `ACCESS_TIME`.

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
