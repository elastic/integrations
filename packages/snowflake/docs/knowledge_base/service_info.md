# Service Info

The Snowflake integration for Elastic is designed to provide comprehensive visibility into your Snowflake cloud data warehouse by ingesting telemetry from historical views and event tables.

## Common use cases

- **Security Auditing and Compliance:** Track all user authentication attempts, session lifecycles, and privilege changes (grants/revokes) to maintain a secure environment and meet regulatory requirements.
- **Threat Detection and Exfiltration Monitoring:** Detect unusual data transfer volumes across cloud providers/regions and monitor outbound network access from UDFs or procedures to identify potential data exfiltration paths.
- **Operational Query Analysis:** Analyze completed SQL statements to monitor performance, identify long-running queries, and audit raw SQL text for sensitive operations or configuration changes.
- **Data Governance and Lineage:** Utilize access history to inspect direct and base object access, ensuring sensitive tables and columns are accessed only by authorized users and roles.

## Data types collected

This integration collects the following data types using the `cel` input:

- **Access History:** Collect object and column access events from `SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY` via the SQL API. Requires Snowflake Enterprise Edition or later.
- **Data Transfer History:** Collect hourly aggregated cross-cloud and cross-region data transfer volumes from `SNOWFLAKE.ACCOUNT_USAGE.DATA_TRANSFER_HISTORY` via the SQL API. Requires the `USAGE_VIEWER` database role (or equivalent) on the `SNOWFLAKE` database.
- **Event Table Telemetry:** Collect handler log messages (`RECORD_TYPE LOG`) from the Snowflake event table via the SQL API. `SPAN`, `SPAN_EVENT`, `METRIC`, and `EVENT` rows are dropped during ingest.
- **External Access History:** Collect outbound network access from `SNOWFLAKE.ACCOUNT_USAGE.EXTERNAL_ACCESS_HISTORY`, joined to `QUERY_HISTORY` for event time, via the SQL API.
- **Grants to Users:** Collect role grants and revokes from `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS` via the SQL API.
- **Login History:** Collect login attempts from `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY` via the SQL API.
- **Query History:** Collect completed SQL statements from `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY` via the SQL API.
- **Sessions:** Collect session lifecycle from `SNOWFLAKE.ACCOUNT_USAGE.SESSIONS` via the SQL API.
- **Stages:** Collect stage inventory changes (created, altered, and dropped stages) from `SNOWFLAKE.ACCOUNT_USAGE.STAGES` via the SQL API. Requires the `OBJECT_VIEWER` database role (or equivalent) on the `SNOWFLAKE` database.

## Compatibility

The Snowflake integration is compatible with the following Snowflake configurations:
- **Supported Cloud Providers:** Accounts hosted on **Amazon Web Services (AWS)**, **Google Cloud Platform (GCP)**, and **Microsoft Azure**.
- **Snowflake Editions:** **Standard Edition** or higher for most streams; **Enterprise Edition** or later is strictly required for the `access_history` data stream.
- **Regional Support:** Supports standard regions, PrivateLink endpoints, and **China region hosts** (`.snowflakecomputing.cn`).
- **Protocol Support:** Interacts exclusively with the **Snowflake SQL API v2** via HTTPS.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:
- **Transport/Collection Considerations:** This integration uses the Snowflake SQL API v2 (REST) to poll data via HTTPS. Most `ACCOUNT_USAGE` views have an inherent latency (lag) between 45 minutes and 3 hours. Polling at a frequency higher than the view's data freshness (e.g., every 1 minute) will consume unnecessary Snowflake credits and API overhead without providing fresher data.
- **Data Volume Management:** For high-volume environments, tune the **Batch size** (default `10000`) to balance memory usage on the Elastic Agent and the number of API calls to Snowflake. If the virtual warehouse is timing out under load, consider increasing the **HTTP Client Timeout** or using a larger warehouse size, though an **XSMALL** warehouse is typically sufficient for metadata polling.
- **Elastic Agent Scaling:** For organizations with extremely high query volumes or dozens of data streams, deploy multiple Elastic Agents and distribute the data streams across separate policies. This prevents a single Agent from being overwhelmed by large result sets from high-volume views like `query_history` or `access_history`.

# Set Up Instructions

## Vendor prerequisites

- **Account Access:** Administrative access (e.g., `ACCOUNTADMIN` or `SECURITYADMIN` role) to create roles, users, and grant privileges.
- **Network Connectivity:** The Elastic Agent must have outbound HTTPS access (port 443) to the Snowflake Account URL.
- **Snowflake Features:** A virtual warehouse must be available and configured with `AUTO_RESUME = TRUE`.
- **Licensing:** Use of the `access_history` stream requires Snowflake Enterprise Edition or higher.
- **Authentication:** Ability to generate and store a Programmatic Access Token (PAT). Standard password-based or OAuth authentication is not supported.

## Elastic prerequisites

- **Elastic Stack Version:** Elastic Stack version **8.11.0 or above** is required.
- **Elastic Agent:** An Elastic Agent must be installed and enrolled in Fleet.
- **Connectivity:** Secure network connectivity between the Elastic Agent and the Snowflake SQL API endpoint.

## Vendor set up steps

1.  **Create a Dedicated Role:**
    Open a Snowflake worksheet and execute:
    ```sql
    CREATE ROLE ELASTIC_AGENT_ROLE;
    ```
2.  **Grant Monitoring Privileges:**
    Assign the necessary database roles to the new agent role:
    ```sql
    GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
    GRANT DATABASE ROLE SNOWFLAKE.USAGE_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
    GRANT DATABASE ROLE SNOWFLAKE.OBJECT_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
    GRANT DATABASE ROLE SNOWFLAKE.SECURITY_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
    GRANT DATABASE ROLE SNOWFLAKE.EVENTS_VIEWER TO ROLE ELASTIC_AGENT_ROLE;
    ```
3.  **Configure a Virtual Warehouse:**
    Create or assign a warehouse for the agent's SQL queries:
    ```sql
    CREATE WAREHOUSE ELASTIC_AGENT_WH WITH WAREHOUSE_SIZE = 'XSMALL' AUTO_SUSPEND = 60 AUTO_RESUME = TRUE;
    GRANT USAGE ON WAREHOUSE ELASTIC_AGENT_WH TO ROLE ELASTIC_AGENT_ROLE;
    ```
4.  **Create a Service User:**
    Define a user of type `SERVICE` and assign the role:
    ```sql
    CREATE USER ELASTIC_AGENT_USER TYPE = SERVICE DEFAULT_ROLE = ELASTIC_AGENT_ROLE;
    GRANT ROLE ELASTIC_AGENT_ROLE TO USER ELASTIC_AGENT_USER;
    ```
5.  **Set Network Policy:**
    Ensure the service user can connect from the Elastic Agent's IP:
    ```sql
    CREATE NETWORK POLICY ELASTIC_AGENT_POLICY ALLOWED_IP_LIST = ('<Your_Agent_IP>');
    ALTER USER ELASTIC_AGENT_USER SET NETWORK_POLICY = ELASTIC_AGENT_POLICY;
    ```
6.  **Generate Programmatic Access Token (PAT):**
    Generate the token and record the `token_secret` immediately:
    ```sql
    ALTER USER ELASTIC_AGENT_USER ADD PROGRAMMATIC ACCESS TOKEN elastic_agent_token ROLE_RESTRICTION = 'ELASTIC_AGENT_ROLE' DAYS_TO_EXPIRY = 90;
    ```

### Vendor Set up Resources

- [Using programmatic access tokens for authentication | Snowflake Documentation](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens)
- [ALTER USER … ADD PROGRAMMATIC ACCESS TOKEN (PAT) | Snowflake Documentation](https://docs.snowflake.com/en/sql-reference/sql/alter-user-add-programmatic-access-token)

## Kibana set up steps

1. In Kibana, navigate to **Integrations** and search for **Snowflake**.
2. Click **Add Snowflake**.
3. Configure the **Global Settings** used for the connection:
    - **Account URL** (`url`): Snowflake account URL including scheme (e.g., `https://myorg-myaccount.snowflakecomputing.com`).
    - **Role** (`role`): Role passed in the SQL API request body (e.g., `ELASTIC_AGENT_ROLE`).
    - **Warehouse** (`warehouse`): Virtual warehouse to execute queries (e.g., `ELASTIC_AGENT_WH`).
    - **Token** (`token`): Programmatic access token secret for the service user.

### Collect Snowflake access history, data transfer history, stages, login history, sessions, grants, query history, event table handler logs, and external access history using the SQL API.

Each data stream listed below can be enabled and configured independently within the integration policy.

**Common Configuration Variables (Available for most streams):**
- **Interval** (`interval`): How often to query the specific view (varies by stream, e.g., `1h`, `2h`, `3h`).
- **Initial interval** (`initial_interval`): How far back to query on the first run (default `24h`).
- **Lag time** (`lag_time`): Duration subtracted from the watermark to include late-arriving rows (varies by stream).
- **Batch size** (`batch_size`): SQL `LIMIT` applied to statements (default `10000`).
- **HTTP Client Timeout** (`http_client_timeout`): Timeout for API requests (default `90s`).
- **Resource Retry Max Attempts** (`resource_retry_max_attempts`): Max HTTP retries (default `5`).
- **Preserve original event** (`preserve_original_event`): Store raw copy in `event.original` (default `false`).
- **Enable request tracing** (`enable_request_tracer`): Debugging tool for logging HTTP requests (default `false`).

**Stream-Specific Variables:**
- **Event table** (`event_table`): (For **Events** stream) Fully qualified event table or view (default `SNOWFLAKE.TELEMETRY.EVENTS_VIEW`).

**Advanced Settings:**
- **Processors** (`processors`): Add Elastic Agent processors to filter or enhance data before ingest.
- **Tags** (`tags`): Custom tags to apply to the events.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on Snowflake:
- **Authentication event:** Log out and log back into the Snowflake web interface to generate a login record.
- **Query event:** Execute a simple query in a worksheet: `SELECT 1;`
- **Configuration change:** Create a temporary test stage to trigger a stage event: `CREATE OR REPLACE STAGE elastic_validation_test;`
- **Access event:** Query a table with sensitive data (if Enterprise Edition) to generate an `ACCESS_HISTORY` entry.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "snowflake.log"`
4. Verify logs appear. Expand a log entry and confirm these fields:
   - `event.dataset` (should match the Snowflake datastream name, e.g., `snowflake.query_history`)
   - `source.ip` (the IP address of the user or agent)
   - `event.action` or `event.outcome` (describing the Snowflake event)
   - `message` (the raw log payload or SQL text)
5. Navigate to **Analytics > Dashboards** and search for "Snowflake" to verify visual data population.

# Troubleshooting

## Common Configuration Issues

- **View Latency Lag**: Data may not appear immediately due to Snowflake `ACCOUNT_USAGE` latency (45m–3h). Check the `lag_time` setting in the integration to ensure it covers the expected latency.
- **Warehouse Not Auto-Resuming**: If the assigned warehouse is suspended and `AUTO_RESUME` is disabled, the Agent's SQL queries will fail. Ensure the warehouse is configured to resume automatically.
- **Privilege Mismatch**: If a specific data stream (e.g., `stages`) is empty, verify the `ELASTIC_AGENT_ROLE` has the specific database role (e.g., `SNOWFLAKE.OBJECT_VIEWER`).
- **Network Policy Block**: If the service user cannot connect, verify the Elastic Agent's egress IP is added to the Snowflake Network Policy.

## Ingestion Errors

- **Enterprise Edition Requirement**: The `access_history` data stream will produce errors if the Snowflake account is not Enterprise Edition or higher. Disable this stream for lower editions.
- **Fingerprint Deduplication**: The integration uses fingerprinting for `_id`. If duplicate rows appear, it may be due to index rollovers during high-volume periods.
- **Sensitive Data Ingestion**: `query_history` collects raw SQL text. If sensitive tokens are appearing, use Elastic Agent processors to mask or drop specific query patterns.

## API Authentication Errors

- **PAT Authentication Failure**: Standard passwords or OAuth tokens will fail. Ensure only a Programmatic Access Token (PAT) is used and the `ROLE_RESTRICTION` was correctly applied during token generation.
- **HTTP 429 Rate Limiting**: If Snowflake returns error `390505`, the SQL API is being rate-limited. Increase the `interval` in the Kibana settings to reduce polling frequency.

## Vendor Resources

- [Snowflake SQL API reference](https://docs.snowflake.com/en/developer-guide/sql-api/index) - General documentation for the API used by the integration.
- [Snowflake Account Usage documentation](https://docs.snowflake.com/en/sql-reference/account-usage) - Details on the views being queried.

# Documentation sites

- [QUERY_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/query_history)
- [ACCESS_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/access_history)
- [LOGIN_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/login_history)
- [Snowflake Integration Reference](https://docs.snowflake.com/en/developer-guide/sql-api/intro)