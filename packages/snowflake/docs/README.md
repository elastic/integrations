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

These inputs can be used with this integration:
<details>
<summary>cel</summary>

## Setup

For more details about the CEL input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html).

Before configuring the CEL input, make sure you have:
- Network connectivity to the target API endpoint
- Valid authentication credentials (API keys, tokens, or certificates as required)
- Appropriate permissions to read from the target data source

### Collecting logs from CEL

To configure the CEL input, you must specify the `request.url` value pointing to the API endpoint. The interval parameter controls how frequently requests are made and is the primary way to balance data freshness with API rate limits and costs. Authentication is often configured through the `request.headers` section using the appropriate method for the service.

NOTE: To access the API service, make sure you have the necessary API credentials and that the Filebeat instance can reach the endpoint URL. Some services may require IP whitelisting or VPN access.

To collect logs via API endpoint, configure the following parameters:

- API Endpoint URL
- API credentials (tokens, keys, or username/password)
- Request interval (how often to fetch data)
</details>


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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| snowflake.access_history.additional_properties | Operational metadata for the source of the event. Decoded from the ADDITIONAL_PROPERTIES VARIANT. | flattened |
| snowflake.access_history.agents_info | Ordered list of invoking agents, from the nearest agent to the top-level agent (agentType, agentId, agentName). Decoded from the AGENTS_INFO JSON array. | flattened |
| snowflake.access_history.base_objects_accessed | All base data objects required to run the query. Decoded from the BASE_OBJECTS_ACCESSED JSON array. | flattened |
| snowflake.access_history.base_objects_accessed_columns | Distinct columnName values extracted from base_objects_accessed. Column names vary per query. | keyword |
| snowflake.access_history.base_objects_accessed_names | Fully qualified objectName values extracted from base_objects_accessed. | keyword |
| snowflake.access_history.direct_objects_accessed | Data objects (tables, views, columns, stages, UDFs, stored procedures) directly named in the query. Decoded from the DIRECT_OBJECTS_ACCESSED JSON array. | flattened |
| snowflake.access_history.direct_objects_accessed_columns | Distinct columnName values extracted from direct_objects_accessed. Column names vary per query. | keyword |
| snowflake.access_history.direct_objects_accessed_names | Fully qualified objectName values extracted from direct_objects_accessed. | keyword |
| snowflake.access_history.invoker_identity | Snowflake service that directly accessed the object. Deprecated by Snowflake (removed in the 2026_07 bundle). Decoded from the INVOKER_IDENTITY VARIANT. | flattened |
| snowflake.access_history.object_modified_by_ddl.object_domain | Type of the object defined or modified by the DDL operation. | keyword |
| snowflake.access_history.object_modified_by_ddl.object_id | Identifier of the object defined or modified by the DDL operation, unique within an account and domain. | keyword |
| snowflake.access_history.object_modified_by_ddl.object_name | Fully qualified name of the object defined or modified by the DDL operation. | keyword |
| snowflake.access_history.object_modified_by_ddl.operation_type | SQL keyword for the DDL operation, for example ALTER, CREATE, DROP, GRANT, or REVOKE. | keyword |
| snowflake.access_history.object_modified_by_ddl.properties | Object or column properties set by the DDL operation (atomic and compound properties). | flattened |
| snowflake.access_history.objects_modified | Objects associated with a write operation in the query, including column lineage (directSources/baseSources). Decoded from the OBJECTS_MODIFIED JSON array. | flattened |
| snowflake.access_history.objects_modified_columns | Distinct columnName values extracted from objects_modified. Column names vary per query. | keyword |
| snowflake.access_history.objects_modified_names | Fully qualified objectName values extracted from objects_modified. | keyword |
| snowflake.access_history.parent_query_id | Query ID of the parent job, or absent if the job has no parent. | keyword |
| snowflake.access_history.policies_referenced | Masking and row access policies enforced on the accessed objects and columns. Decoded from the POLICIES_REFERENCED JSON array. | flattened |
| snowflake.access_history.root_query_id | Query ID of the topmost job in the chain, or absent if the job has no parent. | keyword |


##### access_history sample event

An example event for `access_history` looks as following:

```json
{
    "@timestamp": "2020-06-15T08:00:00.123Z",
    "agent": {
        "ephemeral_id": "cf02fdc4-df7a-4f1b-a6ff-7d763d19695e",
        "id": "cb2cd5d9-c75e-4d1d-ac01-946cfd5aa107",
        "name": "elastic-agent-79554",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "snowflake.access_history",
        "namespace": "75267",
        "type": "logs"
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "cb2cd5d9-c75e-4d1d-ac01-946cfd5aa107",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "snowflake.access_history",
        "id": "01b5a1c2-0000-1a2b-0000-000100000001",
        "ingested": "2026-10-08T05:56:42Z",
        "kind": "event",
        "original": "{\"ADDITIONAL_PROPERTIES\":null,\"AGENTS_INFO\":null,\"BASE_OBJECTS_ACCESSED\":\"[\\n  {\\n    \\\"columns\\\": [\\n      {\\n        \\\"columnId\\\": 68610,\\n        \\\"columnName\\\": \\\"CONTENT\\\"\\n      },\\n      {\\n        \\\"columnId\\\": 68611,\\n        \\\"columnName\\\": \\\"CREATED_AT\\\"\\n      }\\n    ],\\n    \\\"objectDomain\\\": \\\"Table\\\",\\n    \\\"objectId\\\": 66564,\\n    \\\"objectName\\\": \\\"EXAMPLE_DB.PUBLIC.ORDERS\\\"\\n  }\\n]\",\"DIRECT_OBJECTS_ACCESSED\":\"[\\n  {\\n    \\\"argumentSignature\\\": \\\"(NUM1 NUMBER, NUM2 NUMBER)\\\",\\n    \\\"dataType\\\": \\\"NUMBER(38,0)\\\",\\n    \\\"objectDomain\\\": \\\"Function\\\",\\n    \\\"objectId\\\": 2,\\n    \\\"objectName\\\": \\\"EXAMPLE_DB.FUNCTIONS.RETURN_SUM\\\"\\n  },\\n  {\\n    \\\"columns\\\": [\\n      {\\n        \\\"columnId\\\": 68610,\\n        \\\"columnName\\\": \\\"CONTENT\\\"\\n      },\\n      {\\n        \\\"columnId\\\": 68611,\\n        \\\"columnName\\\": \\\"CREATED_AT\\\"\\n      }\\n    ],\\n    \\\"objectDomain\\\": \\\"Table\\\",\\n    \\\"objectId\\\": 66564,\\n    \\\"objectName\\\": \\\"EXAMPLE_DB.PUBLIC.ORDERS\\\"\\n  }\\n]\",\"EVENT_SOURCE\":\"snowflake_sql\",\"INVOKER_IDENTITY\":null,\"OBJECTS_MODIFIED\":\"[]\",\"OBJECT_MODIFIED_BY_DDL\":null,\"PARENT_QUERY_ID\":null,\"POLICIES_REFERENCED\":\"[]\",\"QUERY_ID\":\"01b5a1c2-0000-1a2b-0000-000100000001\",\"QUERY_START_TIME\":\"2020-06-15 08:00:00.123 +0000\",\"ROOT_QUERY_ID\":null,\"USER_NAME\":\"alice.johnson\"}",
        "provider": "snowflake_sql",
        "start": "2020-06-15T08:00:00.123Z",
        "type": [
            "access"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Snowflake",
        "vendor": "Snowflake"
    },
    "related": {
        "user": [
            "alice.johnson"
        ]
    },
    "snowflake": {
        "access_history": {
            "base_objects_accessed": [
                {
                    "columns": [
                        {
                            "columnId": 68610,
                            "columnName": "CONTENT"
                        },
                        {
                            "columnId": 68611,
                            "columnName": "CREATED_AT"
                        }
                    ],
                    "objectDomain": "Table",
                    "objectId": 66564,
                    "objectName": "EXAMPLE_DB.PUBLIC.ORDERS"
                }
            ],
            "base_objects_accessed_columns": [
                "CONTENT",
                "CREATED_AT"
            ],
            "base_objects_accessed_names": [
                "EXAMPLE_DB.PUBLIC.ORDERS"
            ],
            "direct_objects_accessed": [
                {
                    "argumentSignature": "(NUM1 NUMBER, NUM2 NUMBER)",
                    "dataType": "NUMBER(38,0)",
                    "objectDomain": "Function",
                    "objectId": 2,
                    "objectName": "EXAMPLE_DB.FUNCTIONS.RETURN_SUM"
                },
                {
                    "columns": [
                        {
                            "columnId": 68610,
                            "columnName": "CONTENT"
                        },
                        {
                            "columnId": 68611,
                            "columnName": "CREATED_AT"
                        }
                    ],
                    "objectDomain": "Table",
                    "objectId": 66564,
                    "objectName": "EXAMPLE_DB.PUBLIC.ORDERS"
                }
            ],
            "direct_objects_accessed_columns": [
                "CONTENT",
                "CREATED_AT"
            ],
            "direct_objects_accessed_names": [
                "EXAMPLE_DB.FUNCTIONS.RETURN_SUM",
                "EXAMPLE_DB.PUBLIC.ORDERS"
            ]
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snowflake-access_history"
    ],
    "user": {
        "name": "alice.johnson"
    }
}
```

#### data_transfer_history

The `data_transfer_history` data stream provides hourly data transfer windows from `SNOWFLAKE.ACCOUNT_USAGE.DATA_TRANSFER_HISTORY`. Bytes transferred are mapped to `network.bytes` and the transfer type to `event.action`.

##### data_transfer_history fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.origin.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.origin.region | Region in which this host, resource, or service is located. | keyword |
| cloud.target.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.target.region | Region in which this host, resource, or service is located. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| snowflake.data_transfer_history.source_cloud | Name of the cloud provider the data was transferred from, for example aws, azure, or gcp. | keyword |
| snowflake.data_transfer_history.source_region | Name of the cloud provider region the data was transferred from. | keyword |
| snowflake.data_transfer_history.target_cloud | Name of the cloud provider the data was transferred to, for example aws, azure, or gcp. | keyword |
| snowflake.data_transfer_history.target_region | Name of the cloud provider region the data was transferred to. | keyword |
| snowflake.data_transfer_history.transfer_type | Type of data transfer as reported by Snowflake, for example COPY, COPY_FILES, DATA_LAKE, EXTERNAL_ACCESS, EXTERNAL_FUNCTION, INTERNAL, POSTGRES, REPLICATION, or SNOWPARK_CONTAINER_SERVICES. | keyword |


##### data_transfer_history sample event

An example event for `data_transfer_history` looks as following:

```json
{
    "@timestamp": "2020-06-15T08:00:00.000Z",
    "agent": {
        "ephemeral_id": "2ad5e7e1-0f12-4b84-bac8-6f6674be71fd",
        "id": "b522240b-9d02-4649-9b4f-69f97f1e8603",
        "name": "elastic-agent-35610",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "snowflake.data_transfer_history",
        "namespace": "67685",
        "type": "logs"
    },
    "cloud": {
        "origin": {
            "provider": "aws",
            "region": "us-west-2"
        },
        "target": {
            "provider": "azure",
            "region": "eastus2"
        }
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "b522240b-9d02-4649-9b4f-69f97f1e8603",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "copy",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "snowflake.data_transfer_history",
        "duration": 3600000000000,
        "end": "2020-06-15T09:00:00.000Z",
        "ingested": "2026-10-08T06:45:51Z",
        "kind": "event",
        "original": "{\"BYTES_TRANSFERRED\":\"104857600.0\",\"END_TIME\":\"2020-06-15 09:00:00.000 +0000\",\"SOURCE_CLOUD\":\"aws\",\"SOURCE_REGION\":\"us-west-2\",\"START_TIME\":\"2020-06-15 08:00:00.000 +0000\",\"TARGET_CLOUD\":\"azure\",\"TARGET_REGION\":\"eastus2\",\"TRANSFER_TYPE\":\"COPY\"}",
        "start": "2020-06-15T08:00:00.000Z",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "network": {
        "bytes": 104857600
    },
    "observer": {
        "product": "Snowflake",
        "vendor": "Snowflake"
    },
    "snowflake": {
        "data_transfer_history": {
            "source_cloud": "aws",
            "source_region": "us-west-2",
            "target_cloud": "azure",
            "target_region": "eastus2",
            "transfer_type": "COPY"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snowflake-data_transfer_history"
    ]
}
```

#### events

The `events` data stream collects handler log messages from the account event table (default `SNOWFLAKE.TELEMETRY.EVENTS_VIEW`). The collector filters `RECORD_TYPE = 'LOG'`; remaining `SPAN`, `SPAN_EVENT`, `METRIC`, or `EVENT` rows are dropped by the ingest pipeline. You can confirm a custom table name using `SHOW PARAMETERS LIKE 'EVENT_TABLE' IN ACCOUNT`.

##### events fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| container.name | Container name. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| snowflake.events.custom_attributes | Handler-defined RECORD_ATTRIBUTES keys that are not part of the documented Snowflake or Openflow attribute set. | flattened |
| snowflake.events.query_id | Query identifier copied from RESOURCE_ATTRIBUTES snow.query.id. | keyword |
| snowflake.events.record_attributes.architecture | Operating system architecture from Openflow CPU metrics. | keyword |
| snowflake.events.record_attributes.authorization.issue | Authorization used to access an Openflow remote process group (authorization.issue). | keyword |
| snowflake.events.record_attributes.code.namespace | Namespace of the code that generated a log message (code.namespace). | keyword |
| snowflake.events.record_attributes.component | Immutable class name of an Openflow processor. | keyword |
| snowflake.events.record_attributes.counter | User- or system-generated name of an Openflow processor counter. | keyword |
| snowflake.events.record_attributes.db.query.executable.names | Executables run under the traced query (db.query.executable.names). | keyword |
| snowflake.events.record_attributes.db.query.table.names | Tables read or modified by the traced query (db.query.table.names). | keyword |
| snowflake.events.record_attributes.db.query.text | SQL text of the traced statement (db.query.text). Present only when SQL statement tracing is enabled. | wildcard |
| snowflake.events.record_attributes.db.query.view.names | Views accessed by the traced query (db.query.view.names). | keyword |
| snowflake.events.record_attributes.destination.id | Openflow component receiving FlowFiles from a connection (destination.id). | keyword |
| snowflake.events.record_attributes.destination.name | Name of the Openflow component receiving FlowFiles (destination.name). | keyword |
| snowflake.events.record_attributes.exception.escaped | True when the log entry is an unhandled exception (exception.escaped). | boolean |
| snowflake.events.record_attributes.exception.message | Unhandled exception message (exception.message). | wildcard |
| snowflake.events.record_attributes.exception.stacktrace | Unhandled exception stack trace (exception.stacktrace). | wildcard |
| snowflake.events.record_attributes.exception.type | Exception class name (exception.type). | keyword |
| snowflake.events.record_attributes.execution.node | Openflow processor execution node, ALL or PRIMARY (execution.node). | keyword |
| snowflake.events.record_attributes.group.id | Openflow process group that contains the component (group.id). | keyword |
| snowflake.events.record_attributes.id | Openflow component identifier. | keyword |
| snowflake.events.record_attributes.log.file.path | Openflow log file path (log.file.path). | keyword |
| snowflake.events.record_attributes.log.iostream | Openflow log stream, such as stdout (log.iostream). | keyword |
| snowflake.events.record_attributes.logtag | Openflow log tag, such as F. | keyword |
| snowflake.events.record_attributes.name | User-visible Openflow component name. | keyword |
| snowflake.events.record_attributes.snow.input.rows | Input rows processed by a UDF span (snow.input.rows). | long |
| snowflake.events.record_attributes.snow.output.rows | Output rows emitted by a UDF span (snow.output.rows). | long |
| snowflake.events.record_attributes.snow.snapshot.id | Iceberg snapshot id being refreshed (snow.snapshot.id). Null when automated refresh fails. | long |
| snowflake.events.record_attributes.source.id | Openflow component sending FlowFiles to a connection (source.id). | keyword |
| snowflake.events.record_attributes.source.name | Name of the Openflow component sending FlowFiles (source.name). | keyword |
| snowflake.events.record_attributes.storage.type | Openflow storage repository type (storage.type). One of flowfile, content, or provenance. | keyword |
| snowflake.events.record_attributes.target.uri | URI of an Openflow remote process group (target.uri). | keyword |
| snowflake.events.record_attributes.thread.id | Thread id that created the log event (thread.id). | long |
| snowflake.events.record_attributes.thread.name | Thread name that created the log event (thread.name). | keyword |
| snowflake.events.record_attributes.tree.level | Openflow process group depth relative to the flow root (tree.level). | long |
| snowflake.events.record_attributes.type | Openflow component type, such as connection, port-input, port-output, process-group, processor, counter, or remote-process-group. | keyword |
| snowflake.events.record_attributes.version | Operating system version from Openflow CPU metrics. | keyword |
| snowflake.events.record_type | RECORD_TYPE from the event table. Only LOG rows are ingested; other types are dropped in the pipeline. | keyword |
| snowflake.events.resource_attributes.application | Openflow application name. Fixed value openflow. | keyword |
| snowflake.events.resource_attributes.deployment.version | Openflow deployment version (deployment.version). | keyword |
| snowflake.events.resource_attributes.k8s.container.restart_count | Container restart count, stored by Openflow as a numeric string (k8s.container.restart_count). | keyword |
| snowflake.events.resource_attributes.k8s.pod.name | Kubernetes pod name (k8s.pod.name). | keyword |
| snowflake.events.resource_attributes.k8s.pod.start_time | Pod start time (k8s.pod.start_time). | date |
| snowflake.events.resource_attributes.k8s.pod.uid | Pod UID (k8s.pod.uid). | keyword |
| snowflake.events.resource_attributes.openflow.dataplane.id | Openflow deployment identifier (openflow.dataplane.id). | keyword |
| snowflake.events.resource_attributes.snow.application.consumer.account_locator | Consumer account locator (snow.application.consumer.account_locator). | keyword |
| snowflake.events.resource_attributes.snow.application.consumer.account_name | Consumer account name (snow.application.consumer.account_name). | keyword |
| snowflake.events.resource_attributes.snow.application.consumer.name | Deprecated consumer account locator (snow.application.consumer.name). | keyword |
| snowflake.events.resource_attributes.snow.application.consumer.organization | Consumer organization (snow.application.consumer.organization). | keyword |
| snowflake.events.resource_attributes.snow.application.consumer.snowflake_region | Consumer Snowflake region (snow.application.consumer.snowflake_region). | keyword |
| snowflake.events.resource_attributes.snow.application.id | Native App identifier (snow.application.id). | keyword |
| snowflake.events.resource_attributes.snow.application.name | Installed Native App name (snow.application.name). | keyword |
| snowflake.events.resource_attributes.snow.application.package.name | Application package name (snow.application.package.name). | keyword |
| snowflake.events.resource_attributes.snow.catalog.integration.name | Catalog integration for Iceberg automated refresh (snow.catalog.integration.name). | keyword |
| snowflake.events.resource_attributes.snow.catalog.table.name | Iceberg catalog table name (snow.catalog.table.name). | keyword |
| snowflake.events.resource_attributes.snow.database.id | Internal database identifier (snow.database.id). | long |
| snowflake.events.resource_attributes.snow.database.name | Database containing the executable (snow.database.name). | keyword |
| snowflake.events.resource_attributes.snow.executable.id | Internal executable identifier (snow.executable.id). | long |
| snowflake.events.resource_attributes.snow.executable.name | Executable name, such as a procedure, function, or Streamlit app (snow.executable.name). | keyword |
| snowflake.events.resource_attributes.snow.executable.runtime.version | Language runtime version (snow.executable.runtime.version). | keyword |
| snowflake.events.resource_attributes.snow.executable.type | Executable type (snow.executable.type). Documented values include procedure, function, query, sql, spcs, streamlit, DBT_PROJECT, and TASK. | keyword |
| snowflake.events.resource_attributes.snow.listing.global_name | Native App listing identifier (snow.listing.global_name). | keyword |
| snowflake.events.resource_attributes.snow.listing.name | Native App listing name (snow.listing.name). | keyword |
| snowflake.events.resource_attributes.snow.owner.id | Internal identifier of the role with OWNERSHIP on the executable (snow.owner.id). | long |
| snowflake.events.resource_attributes.snow.owner.name | Role with OWNERSHIP on the executable (snow.owner.name). | keyword |
| snowflake.events.resource_attributes.snow.patch | Executable patch level (snow.patch). | keyword |
| snowflake.events.resource_attributes.snow.release.version | Snowflake release that generated the event (snow.release.version). | keyword |
| snowflake.events.resource_attributes.snow.schema.id | Internal schema identifier (snow.schema.id). | long |
| snowflake.events.resource_attributes.snow.schema.name | Schema containing the executable (snow.schema.name). | keyword |
| snowflake.events.resource_attributes.snow.session.role.primary.id | Internal identifier of the session primary role (snow.session.role.primary.id). | long |
| snowflake.events.resource_attributes.snow.table.name | Table associated with the executable (snow.table.name). | keyword |
| snowflake.events.resource_attributes.snow.version | Executable version (snow.version). | keyword |
| snowflake.events.resource_attributes.snow.warehouse.id | Internal warehouse identifier (snow.warehouse.id). | long |
| snowflake.events.resource_attributes.snow.warehouse.name | Warehouse that ran the query (snow.warehouse.name). | keyword |
| snowflake.events.resource_attributes.telemetry.sdk.language | Handler or SDK language (telemetry.sdk.language). Snowflake uses java, scala, python, javascript, and sql. | keyword |
| snowflake.events.runtime_log.logger_name | Fully qualified Openflow logger class name. | keyword |
| snowflake.events.runtime_log.mdc.process_group_id | Process group identifier. | keyword |
| snowflake.events.runtime_log.mdc.process_group_id_path | Hierarchical path of process group identifiers. | keyword |
| snowflake.events.runtime_log.mdc.process_group_name | Process group name. | keyword |
| snowflake.events.runtime_log.mdc.process_group_name_path | Hierarchical path of process group names. | keyword |
| snowflake.events.runtime_log.mdc.registered_flow_identifier | Registered flow identifier. | keyword |
| snowflake.events.runtime_log.mdc.registered_flow_version | Registered flow version. | keyword |
| snowflake.events.runtime_log.nanoseconds | Nanosecond component of the Openflow log timestamp. | long |
| snowflake.events.runtime_log.thread_name | Thread that emitted the Openflow log. | keyword |
| snowflake.events.runtime_log.throwable.class_name | Exception class name. | keyword |
| snowflake.events.runtime_log.throwable.message | Exception message. | wildcard |
| snowflake.events.runtime_log.timestamp | Openflow log time as epoch milliseconds. | long |
| snowflake.events.session_id | Session identifier copied from RESOURCE_ATTRIBUTES snow.session.id. ECS has no session.id. | keyword |


##### events sample event

An example event for `events` looks as following:

```json
{
    "@timestamp": "2020-07-01T08:00:00.000Z",
    "agent": {
        "ephemeral_id": "c1763dfd-125c-4858-8976-7ebb87156425",
        "id": "e8858486-268f-4c65-929c-90fb70a79da1",
        "name": "elastic-agent-40334",
        "type": "filebeat",
        "version": "9.4.0"
    },
    "data_stream": {
        "dataset": "snowflake.events",
        "namespace": "28806",
        "type": "logs"
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "e8858486-268f-4c65-929c-90fb70a79da1",
        "snapshot": false,
        "version": "9.4.0"
    },
    "event": {
        "action": "LOG",
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "created": "2020-07-01T08:00:00.000Z",
        "dataset": "snowflake.events",
        "ingested": "2026-10-28T05:57:55Z",
        "kind": "event",
        "module": "snowflake",
        "original": "{\"OBSERVED_TIMESTAMP\":\"2020-07-01 08:00:00.000 +0000\",\"RECORD\":\"{\\\"severity_text\\\":\\\"INFO\\\"}\",\"RECORD_ATTRIBUTES\":\"{\\\"code.filepath\\\":\\\"main.py\\\",\\\"code.function\\\":\\\"handler\\\",\\\"code.lineno\\\":42,\\\"code.namespace\\\":\\\"example.module\\\",\\\"thread.id\\\":1,\\\"thread.name\\\":\\\"main\\\"}\",\"RECORD_TYPE\":\"LOG\",\"RESOURCE_ATTRIBUTES\":\"{\\\"db.user\\\":\\\"alice.johnson\\\",\\\"snow.database.id\\\":13,\\\"snow.database.name\\\":\\\"EXAMPLE_DB\\\",\\\"snow.executable.id\\\":197,\\\"snow.executable.name\\\":\\\"EXAMPLE_HANDLER\\\",\\\"snow.executable.type\\\":\\\"FUNCTION\\\",\\\"snow.owner.id\\\":2,\\\"snow.owner.name\\\":\\\"EXAMPLE_ROLE\\\",\\\"snow.query.id\\\":\\\"01ab0f07-0000-15c8-0000-0129000592c2\\\",\\\"snow.schema.id\\\":16,\\\"snow.schema.name\\\":\\\"PUBLIC\\\",\\\"snow.session.id\\\":1275605667850,\\\"snow.session.role.primary.id\\\":2,\\\"snow.session.role.primary.name\\\":\\\"EXAMPLE_ROLE\\\",\\\"snow.user.id\\\":25,\\\"snow.warehouse.id\\\":5,\\\"snow.warehouse.name\\\":\\\"EXAMPLE_WH\\\",\\\"telemetry.sdk.language\\\":\\\"python\\\"}\",\"SCOPE\":\"{\\\"name\\\":\\\"com.sample.MyClass\\\"}\",\"START_TIMESTAMP\":null,\"TIMESTAMP\":\"2020-07-01 08:00:00.000 +0000\",\"TRACE\":null,\"VALUE\":\"Example handler log message\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "log": {
        "level": "info",
        "logger": "com.sample.MyClass",
        "origin": {
            "file": {
                "line": 42,
                "name": "main.py"
            },
            "function": "handler"
        }
    },
    "message": "Example handler log message",
    "observer": {
        "product": "Snowflake",
        "vendor": "Snowflake"
    },
    "related": {
        "user": [
            "alice.johnson",
            "25"
        ]
    },
    "snowflake": {
        "events": {
            "query_id": "01ab0f07-0000-15c8-0000-0129000592c2",
            "record_attributes": {
                "code": {
                    "namespace": "example.module"
                },
                "thread": {
                    "id": 1,
                    "name": "main"
                }
            },
            "record_type": "LOG",
            "resource_attributes": {
                "snow": {
                    "database": {
                        "id": 13,
                        "name": "EXAMPLE_DB"
                    },
                    "executable": {
                        "id": 197,
                        "name": "EXAMPLE_HANDLER",
                        "type": "FUNCTION"
                    },
                    "owner": {
                        "id": 2,
                        "name": "EXAMPLE_ROLE"
                    },
                    "schema": {
                        "id": 16,
                        "name": "PUBLIC"
                    },
                    "session": {
                        "role": {
                            "primary": {
                                "id": 2
                            }
                        }
                    },
                    "warehouse": {
                        "id": 5,
                        "name": "EXAMPLE_WH"
                    }
                },
                "telemetry": {
                    "sdk": {
                        "language": "python"
                    }
                }
            },
            "session_id": "1275605667850"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snowflake-events"
    ],
    "user": {
        "id": "25",
        "name": "alice.johnson",
        "roles": [
            "EXAMPLE_ROLE"
        ]
    }
}
```

#### external_access_history

The `external_access_history` data stream provides outbound network access events from `SNOWFLAKE.ACCOUNT_USAGE.EXTERNAL_ACCESS_HISTORY`, joined to `QUERY_HISTORY` for `END_TIME`.

##### external_access_history fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.origin.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.origin.region | Region in which this host, resource, or service is located. | keyword |
| cloud.target.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.target.region | Region in which this host, resource, or service is located. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| snowflake.external_access_history.hostnames | Raw HOSTNAMES value when it lists multiple hosts and cannot be mapped to a single destination.domain. | keyword |
| snowflake.external_access_history.ip | Remote endpoint address when the value is not a valid IP. Valid addresses are stored in destination.ip. | keyword |
| snowflake.external_access_history.status | Raw access outcome from the view (Success or Deny). The ingest pipeline normalizes this for event.outcome. | keyword |


##### external_access_history sample event

An example event for `external_access_history` looks as following:

```json
{
    "@timestamp": "2020-08-01T08:00:00.000Z",
    "agent": {
        "ephemeral_id": "82fa2a6e-f0ef-4d40-b699-70a2ce5c44b0",
        "id": "9ada382d-811c-4a4f-84e0-ef6280e269e9",
        "name": "elastic-agent-39109",
        "type": "filebeat",
        "version": "9.4.0"
    },
    "cloud": {
        "origin": {
            "provider": "aws",
            "region": "us-west-2"
        }
    },
    "data_stream": {
        "dataset": "snowflake.external_access_history",
        "namespace": "20784",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 64501,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "bytes": 8192,
        "domain": "api.example.com",
        "geo": {
            "city_name": "Amsterdam",
            "continent_name": "Europe",
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "location": {
                "lat": 52.37404,
                "lon": 4.88969
            },
            "region_iso_code": "NL-NH",
            "region_name": "North Holland"
        },
        "ip": "198.51.100.42"
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "9ada382d-811c-4a4f-84e0-ef6280e269e9",
        "snapshot": false,
        "version": "9.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "snowflake.external_access_history",
        "end": "2020-08-01T08:00:00.000Z",
        "id": "01b2c3d4-e5f6-7890-abcd-ef1234567ea0",
        "ingested": "2026-10-23T11:51:17Z",
        "kind": "event",
        "module": "snowflake",
        "original": "{\"END_TIME\":\"2020-08-01 08:00:00.000 +0000\",\"HOSTNAMES\":\"api.example.com\",\"IP\":\"198.51.100.42\",\"QUERY_ID\":\"01b2c3d4-e5f6-7890-abcd-ef1234567ea0\",\"RECEIVED_BYTES\":\"8192\",\"SENT_BYTES\":\"2048\",\"SOURCE_CLOUD\":\"aws\",\"SOURCE_REGION\":\"us-west-2\",\"START_TIME\":\"2020-08-01 07:59:58.000 +0000\",\"STATUS\":\"Success\",\"TARGET_CLOUD\":\"internet\",\"TARGET_REGION\":\"internet\",\"USER_NAME\":\"alice.johnson\"}",
        "outcome": "success",
        "start": "2020-08-01T07:59:58.000Z",
        "type": [
            "connection",
            "allowed"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Snowflake",
        "vendor": "Snowflake"
    },
    "related": {
        "hosts": [
            "api.example.com"
        ],
        "ip": [
            "198.51.100.42"
        ],
        "user": [
            "alice.johnson"
        ]
    },
    "snowflake": {
        "external_access_history": {
            "status": "Success"
        }
    },
    "source": {
        "bytes": 2048
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snowflake-external_access_history"
    ],
    "user": {
        "name": "alice.johnson"
    }
}
```

#### grants_to_users

The `grants_to_users` data stream provides role grant and revoke events from `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`. Creates and revokes are collected with separate statements so a revoke timestamp cannot skip unread grants.

##### grants_to_users fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| snowflake.grants_to_users.granted_by | Role that performed the grant. | keyword |
| snowflake.grants_to_users.granted_to | Object type that received the grant. Always USER for this view. | keyword |


##### grants_to_users sample event

An example event for `grants_to_users` looks as following:

```json
{
    "@timestamp": "2020-06-15T08:00:00.123Z",
    "agent": {
        "ephemeral_id": "65f483fb-e78a-4d8e-8dc7-35c6479b7ad6",
        "id": "823fb7a6-0e9e-472a-af29-6457a68454a4",
        "name": "elastic-agent-67476",
        "type": "filebeat",
        "version": "8.19.3"
    },
    "data_stream": {
        "dataset": "snowflake.grants_to_users",
        "namespace": "66625",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "823fb7a6-0e9e-472a-af29-6457a68454a4",
        "snapshot": false,
        "version": "8.19.3"
    },
    "event": {
        "action": "role_granted",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "snowflake.grants_to_users",
        "id": "yEvZ1XzOTI5L8fEHIqJnGZ7jaRI=",
        "ingested": "2026-09-30T08:50:12Z",
        "kind": "event",
        "original": "{\"CREATED_ON\":\"2020-06-15 08:00:00.123 +0000\",\"DELETED_ON\":null,\"GRANTED_BY\":\"ACCOUNTADMIN\",\"GRANTED_TO\":\"USER\",\"GRANTEE_NAME\":\"alice.johnson\",\"ROLE\":\"SYSADMIN\"}",
        "start": "2020-06-15T08:00:00.123Z",
        "type": [
            "change",
            "user"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Snowflake",
        "vendor": "Snowflake"
    },
    "related": {
        "user": [
            "alice.johnson"
        ]
    },
    "snowflake": {
        "grants_to_users": {
            "granted_by": "ACCOUNTADMIN",
            "granted_to": "USER"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snowflake-grants_to_users"
    ],
    "user": {
        "target": {
            "name": "alice.johnson",
            "roles": [
                "SYSADMIN"
            ]
        }
    }
}
```

#### login_history

The `login_history` data stream provides login attempt events from `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY`.

##### login_history fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| snowflake.login_history.authorizing_integration_name | Security integration that authorized the login, when present. | keyword |
| snowflake.login_history.client_ip | Client IP address reported for the login attempt when the value is not a valid IP (for example INTERNAL_SNOWFLAKE_IP/0.0.0.0). | keyword |
| snowflake.login_history.client_private_link_id | Private connectivity endpoint identifier. | keyword |
| snowflake.login_history.connection | Client Redirect connection name, when present. | keyword |
| snowflake.login_history.first_authentication_factor | First authentication factor (for example PASSWORD or OAUTH_ACCESS_TOKEN). | keyword |
| snowflake.login_history.first_authentication_factor_id | Identifier of the first authentication factor credential. | keyword |
| snowflake.login_history.login_details.authn_validation_error | Validation errors from authn_validation_error when present (array of strings in Snowflake). | keyword |
| snowflake.login_history.login_details.malicious_ip_protection_info.categories | Threat categories (for example ANONYMOUS_VPN, TOR_EXITS). | keyword |
| snowflake.login_history.login_details.malicious_ip_protection_info.result | Malicious IP protection action, for example BLOCKED or OPTED_OUT. | keyword |
| snowflake.login_history.login_details.malicious_ip_protection_info.risk_classification | Risk level from riskClassification, for example HIGH or LOW. | keyword |
| snowflake.login_history.related_event_id | Reserved related event identifier from LOGIN_HISTORY.RELATED_EVENT_ID. | keyword |
| snowflake.login_history.reported_client_type | Client family reported by the caller (not authenticated). | keyword |
| snowflake.login_history.reported_client_version | Client version reported by the caller. | keyword |
| snowflake.login_history.second_authentication_factor | Second authentication factor when MFA was used (for example MFA_TOKEN). | keyword |
| snowflake.login_history.second_authentication_factor_id | Identifier of the second authentication factor credential. | keyword |


##### login_history sample event

An example event for `login_history` looks as following:

```json
{
    "@timestamp": "2020-06-15T08:00:00.123Z",
    "agent": {
        "ephemeral_id": "5516fff1-8ecf-4e14-b756-516f327c5883",
        "id": "2d0e0768-6742-4799-9f4d-ed051ff65975",
        "name": "elastic-agent-56427",
        "type": "filebeat",
        "version": "8.19.3"
    },
    "data_stream": {
        "dataset": "snowflake.login_history",
        "namespace": "44418",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "2d0e0768-6742-4799-9f4d-ed051ff65975",
        "snapshot": false,
        "version": "8.19.3"
    },
    "event": {
        "action": "LOGIN",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "dataset": "snowflake.login_history",
        "id": "1001",
        "ingested": "2026-09-29T09:48:15Z",
        "kind": "event",
        "original": "{\"AUTHORIZING_INTEGRATION_NAME\":null,\"CLIENT_IP\":\"198.51.100.10\",\"CLIENT_PRIVATE_LINK_ID\":null,\"CONNECTION\":null,\"ERROR_CODE\":null,\"ERROR_MESSAGE\":null,\"EVENT_ID\":\"1001\",\"EVENT_TIMESTAMP\":\"2020-06-15 08:00:00.123 +0000\",\"EVENT_TYPE\":\"LOGIN\",\"FIRST_AUTHENTICATION_FACTOR\":\"PASSWORD\",\"IS_SUCCESS\":\"YES\",\"LOGIN_DETAILS\":null,\"REPORTED_CLIENT_TYPE\":\"JDBC_DRIVER\",\"REPORTED_CLIENT_VERSION\":\"3.14.4\",\"SECOND_AUTHENTICATION_FACTOR\":\"MFA_TOKEN\",\"USER_NAME\":\"alice.johnson\"}",
        "outcome": "success",
        "type": [
            "start"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Snowflake",
        "vendor": "Snowflake"
    },
    "related": {
        "ip": [
            "198.51.100.10"
        ],
        "user": [
            "alice.johnson"
        ]
    },
    "snowflake": {
        "login_history": {
            "first_authentication_factor": "PASSWORD",
            "reported_client_type": "JDBC_DRIVER",
            "reported_client_version": "3.14.4",
            "second_authentication_factor": "MFA_TOKEN"
        }
    },
    "source": {
        "as": {
            "number": 64501,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Amsterdam",
            "continent_name": "Europe",
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "location": {
                "lat": 52.37404,
                "lon": 4.88969
            },
            "region_iso_code": "NL-NH",
            "region_name": "North Holland"
        },
        "ip": "198.51.100.10"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snowflake-login_history"
    ],
    "user": {
        "name": "alice.johnson"
    }
}
```

#### query_history

The `query_history` data stream provides completed SQL statement events from `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY`. The collector watermarks on `END_TIME`.

##### query_history fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| snowflake.query_history.agent_type | Agent that issued the statement when present (for example CORTEX_AGENT, EXTERNAL_AGENT). | keyword |
| snowflake.query_history.authn_event_id | LOGIN_HISTORY event identifier associated with the session that issued the query. | keyword |
| snowflake.query_history.bytes_scanned | Number of bytes scanned by the statement. | long |
| snowflake.query_history.database_name | Database in which the query ran, when present. | keyword |
| snowflake.query_history.execution_status | Raw Account Usage execution status (for example success, fail, incident, or SUCCESS). The ingest pipeline normalizes this for event.outcome. | keyword |
| snowflake.query_history.query_hash | Snowflake statement fingerprint hash. This is not a file content hash. | keyword |
| snowflake.query_history.query_text | SQL text of the statement (capped by Snowflake at 100,000 characters). The text can contain secrets such as literals or tokens. | wildcard |
| snowflake.query_history.rows_unloaded | Number of rows unloaded by the statement. | long |
| snowflake.query_history.schema_name | Schema in which the query ran, when present. | keyword |
| snowflake.query_history.session_id | Snowflake session identifier for the statement. | keyword |
| snowflake.query_history.user_type | Type of user that issued the statement (for example PERSON). | keyword |
| snowflake.query_history.warehouse_name | Warehouse that ran the statement, when present. | keyword |


##### query_history sample event

An example event for `query_history` looks as following:

```json
{
    "@timestamp": "2020-06-15T08:00:00.123Z",
    "agent": {
        "ephemeral_id": "9e998031-a3dd-425c-a268-c5b42feeb66b",
        "id": "24f2bc86-42bb-4e3d-93d4-08b82799e884",
        "name": "elastic-agent-96428",
        "type": "filebeat",
        "version": "9.4.0"
    },
    "data_stream": {
        "dataset": "snowflake.query_history",
        "namespace": "14118",
        "type": "logs"
    },
    "destination": {
        "bytes": 0
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "24f2bc86-42bb-4e3d-93d4-08b82799e884",
        "snapshot": false,
        "version": "9.4.0"
    },
    "event": {
        "action": "SELECT",
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "snowflake.query_history",
        "duration": 1250000000,
        "end": "2020-06-15T08:00:00.123Z",
        "id": "01b2c3d4-e5f6-7890-abcd-ef1234567890",
        "ingested": "2026-10-23T11:49:18Z",
        "kind": "event",
        "module": "snowflake",
        "original": "{\"AGENT_TYPE\":null,\"AUTHN_EVENT_ID\":\"1234567890001\",\"BYTES_SCANNED\":\"65536\",\"DATABASE_NAME\":\"EXAMPLE_DB\",\"END_TIME\":\"2020-06-15 08:00:00.123 +0000\",\"ERROR_CODE\":null,\"ERROR_MESSAGE\":null,\"EXECUTION_STATUS\":\"success\",\"INBOUND_DATA_TRANSFER_BYTES\":\"0\",\"OUTBOUND_DATA_TRANSFER_BYTES\":\"0\",\"QUERY_HASH\":\"abcdef0123456789abcdef0123456789\",\"QUERY_ID\":\"01b2c3d4-e5f6-7890-abcd-ef1234567890\",\"QUERY_TEXT\":\"SELECT id, email FROM example_db.public.customers WHERE created_on \\u003e '2026-01-01' LIMIT 100\",\"QUERY_TYPE\":\"SELECT\",\"ROLE_NAME\":\"ANALYST\",\"ROWS_UNLOADED\":\"0\",\"SCHEMA_NAME\":\"PUBLIC\",\"SESSION_ID\":\"9876543210001\",\"START_TIME\":\"2020-06-15 07:59:58.873 +0000\",\"TOTAL_ELAPSED_TIME\":\"1250\",\"USER_NAME\":\"alice.johnson\",\"USER_TYPE\":\"PERSON\",\"WAREHOUSE_NAME\":\"EXAMPLE_WH\"}",
        "outcome": "success",
        "start": "2020-06-15T07:59:58.873Z",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Snowflake",
        "vendor": "Snowflake"
    },
    "related": {
        "user": [
            "alice.johnson"
        ]
    },
    "snowflake": {
        "query_history": {
            "authn_event_id": "1234567890001",
            "bytes_scanned": 65536,
            "database_name": "EXAMPLE_DB",
            "execution_status": "success",
            "query_hash": "abcdef0123456789abcdef0123456789",
            "query_text": "SELECT id, email FROM example_db.public.customers WHERE created_on > '2026-01-01' LIMIT 100",
            "rows_unloaded": 0,
            "schema_name": "PUBLIC",
            "session_id": "9876543210001",
            "user_type": "PERSON",
            "warehouse_name": "EXAMPLE_WH"
        }
    },
    "source": {
        "bytes": 0
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snowflake-query_history"
    ],
    "user": {
        "name": "alice.johnson",
        "roles": [
            "ANALYST"
        ]
    }
}
```

#### sessions

The `sessions` data stream provides session lifecycle events from `SNOWFLAKE.ACCOUNT_USAGE.SESSIONS`. Rows update until the session closes. The collector watermarks on `ACCESS_TIME`.

##### sessions fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| snowflake.sessions.authentication_method | Authentication method used to create the session (for example PASSWORD or OAUTH_ACCESS_TOKEN). | keyword |
| snowflake.sessions.client_application_id | Client application identifier (for example JDBC 3.8.7). | keyword |
| snowflake.sessions.client_application_version | Client application version. | keyword |
| snowflake.sessions.client_build_id | Client build identifier from SESSIONS.CLIENT_BUILD_ID when present. | keyword |
| snowflake.sessions.client_environment | Parsed JSON from SESSIONS.CLIENT_ENVIRONMENT (operating system, OCSP mode, and similar client details). | flattened |
| snowflake.sessions.client_version | Client version from SESSIONS.CLIENT_VERSION when present. | keyword |
| snowflake.sessions.is_open | Whether the session is still open. | boolean |
| snowflake.sessions.login_event_id | LOGIN_HISTORY.EVENT_ID that opened this session. | keyword |
| snowflake.sessions.session_id | Snowflake session identifier from SESSIONS.SESSION_ID. | keyword |


##### sessions sample event

An example event for `sessions` looks as following:

```json
{
    "@timestamp": "2020-06-15T08:00:00.123Z",
    "agent": {
        "ephemeral_id": "be7fda63-20db-4c59-a13d-ccdb5d4b5087",
        "id": "9cfb7833-58bc-4efe-b8d2-c0d48761f01d",
        "name": "elastic-agent-94334",
        "type": "filebeat",
        "version": "8.19.3"
    },
    "data_stream": {
        "dataset": "snowflake.sessions",
        "namespace": "53326",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "9cfb7833-58bc-4efe-b8d2-c0d48761f01d",
        "snapshot": false,
        "version": "8.19.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "session",
            "authentication"
        ],
        "dataset": "snowflake.sessions",
        "ingested": "2026-09-30T05:44:24Z",
        "kind": "event",
        "original": "{\"ACCESS_TIME\":\"2020-06-15 08:00:00.123 +0000\",\"AUTHENTICATION_METHOD\":\"PASSWORD\",\"CLIENT_APPLICATION_ID\":\"JDBC 3.14.4\",\"CLIENT_APPLICATION_VERSION\":\"3.14.4\",\"CLIENT_ENVIRONMENT\":\"{\\\"OS\\\":\\\"Linux\\\",\\\"OCSP_MODE\\\":\\\"FAIL_OPEN\\\"}\",\"CLOSED_REASON\":\"LOGOUT\",\"CREATED_ON\":\"2020-06-15 07:50:00.000 +0000\",\"IS_OPEN\":\"false\",\"LOGIN_EVENT_ID\":\"1001\",\"SESSION_ID\":\"3001\",\"USER_NAME\":\"alice.johnson\"}",
        "reason": "LOGOUT",
        "start": "2020-06-15T07:50:00.000Z",
        "type": [
            "end"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Snowflake",
        "vendor": "Snowflake"
    },
    "related": {
        "user": [
            "alice.johnson"
        ]
    },
    "snowflake": {
        "sessions": {
            "authentication_method": "PASSWORD",
            "client_application_id": "JDBC 3.14.4",
            "client_application_version": "3.14.4",
            "client_environment": {
                "OCSP_MODE": "FAIL_OPEN",
                "OS": "Linux"
            },
            "is_open": false,
            "login_event_id": "1001",
            "session_id": "3001"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snowflake-sessions"
    ],
    "user": {
        "name": "alice.johnson"
    }
}
```

#### stages

The `stages` data stream provides stage lifecycle events from `SNOWFLAKE.ACCOUNT_USAGE.STAGES`. Rows update in place, so the collector watermarks on `LAST_ALTERED` and `DELETED`, and the pipeline derives `create`, `alter`, or `drop` from the timestamps.

##### stages fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| snowflake.stages.created | Date and time when the stage was created. | date |
| snowflake.stages.deleted | Date and time when the stage was dropped. | date |
| snowflake.stages.instance_id | Internal, Snowflake-generated identifier of the application instance that owns the stage, when the owner is an application. | keyword |
| snowflake.stages.last_altered | Date and time when the stage was last altered by a DDL statement. | date |
| snowflake.stages.owner_role_type | Type of the role that owns the stage, for example ROLE or APPLICATION. | keyword |
| snowflake.stages.stage_catalog | Database that the stage belongs to. | keyword |
| snowflake.stages.stage_catalog_id | Internal, Snowflake-generated identifier of the database that the stage belongs to. | keyword |
| snowflake.stages.stage_id | Internal, Snowflake-generated identifier for the stage. | keyword |
| snowflake.stages.stage_name | Name of the stage. | keyword |
| snowflake.stages.stage_owner | Name of the role that owns the stage. Null if the stage has been dropped. | keyword |
| snowflake.stages.stage_region | Region where the stage is located. | keyword |
| snowflake.stages.stage_schema | Schema that the stage belongs to. | keyword |
| snowflake.stages.stage_schema_id | Internal, Snowflake-generated identifier of the schema that the stage belongs to. | keyword |
| snowflake.stages.stage_type | Type of the stage, for example Internal Named or External Named. Null for stages owned by Snowflake applications. | keyword |
| snowflake.stages.storage_integration | Name of the storage integration associated with an external stage. | keyword |


##### stages sample event

An example event for `stages` looks as following:

```json
{
    "@timestamp": "2020-06-15T08:00:00.000Z",
    "agent": {
        "ephemeral_id": "e012d790-6839-46d0-a271-6eccbd6e63c7",
        "id": "6e17e3e6-08d3-40e6-a8a5-9f0095ebeef8",
        "name": "elastic-agent-19781",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "snowflake.stages",
        "namespace": "50435",
        "type": "logs"
    },
    "cloud": {
        "provider": "aws",
        "region": "us-west-2"
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "6e17e3e6-08d3-40e6-a8a5-9f0095ebeef8",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "create",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "snowflake.stages",
        "ingested": "2026-10-08T08:42:23Z",
        "kind": "event",
        "original": "{\"COMMENT\":null,\"CREATED\":\"2020-06-15 08:00:00.000 +0000\",\"DELETED\":null,\"INSTANCE_ID\":null,\"LAST_ALTERED\":\"2020-06-15 08:00:00.000 +0000\",\"OWNER_ROLE_TYPE\":\"ROLE\",\"STAGE_CATALOG\":\"EXAMPLE_DB\",\"STAGE_CATALOG_ID\":\"2002\",\"STAGE_ID\":\"501234\",\"STAGE_NAME\":\"EXAMPLE_EXT_STAGE\",\"STAGE_OWNER\":\"SYSADMIN\",\"STAGE_REGION\":\"us-west-2\",\"STAGE_SCHEMA\":\"PUBLIC\",\"STAGE_SCHEMA_ID\":\"1001\",\"STAGE_TYPE\":\"External Named\",\"STAGE_URL\":\"s3://example-bucket/exports/\",\"STORAGE_INTEGRATION\":\"EXAMPLE_S3_INTEGRATION\"}",
        "start": "2020-06-15T08:00:00.000Z",
        "type": [
            "creation"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Snowflake",
        "vendor": "Snowflake"
    },
    "snowflake": {
        "stages": {
            "created": "2020-06-15T08:00:00.000Z",
            "last_altered": "2020-06-15T08:00:00.000Z",
            "owner_role_type": "ROLE",
            "stage_catalog": "EXAMPLE_DB",
            "stage_catalog_id": "2002",
            "stage_id": "501234",
            "stage_name": "EXAMPLE_EXT_STAGE",
            "stage_owner": "SYSADMIN",
            "stage_region": "us-west-2",
            "stage_schema": "PUBLIC",
            "stage_schema_id": "1001",
            "stage_type": "External Named",
            "storage_integration": "EXAMPLE_S3_INTEGRATION"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snowflake-stages"
    ],
    "url": {
        "domain": "example-bucket",
        "original": "s3://example-bucket/exports/",
        "path": "/exports/",
        "scheme": "s3"
    }
}
```
