# SQL input

The SQL input package allows you to run custom queries against an SQL database and store the results in Elasticsearch.

This input package supports the following databases

- MySQL
- Oracle
- Microsoft SQL
- PostgreSQL

## Configuration options


### Hosts

The host configuration should be specified from where the metrics are to be fetched. It varies depending upon the driver you are running.

#### MySQL

The supported configuration takes this form
- `<user>:<password>@tcp(<host>:<port>)/`

Here is an example of the supported configuration:
- `root:root@tcp(localhost:3306)/`

#### Oracle 

Two types of host configurations are supported:

- Old style host configuration

    a. `hosts: ["user/pass@0.0.0.0:1521/ORCLPDB1.localdomain"]`
    b. `hosts: ["user/password@0.0.0.0:1521/ORCLPDB1.localdomain as sysdba"]`

- DSN host configuration

    a. `hosts: ['user="user" password="pass" connectString="0.0.0.0:1521/ORCLPDB1.localdomain"']`
    b. `hosts: ['user="user" password="password" connectString="host:port/service_name" sysdba=true']`
  
#### MSSQL

The supported configuration takes this form
- `sqlserver://<user>:<password>@<host>`

Here is an example of the supported configuration:
- `sqlserver://root:test@localhost`

#### PostgreSQL

The supported configuration takes this form
- `postgres://<user>:<password>@<connection_string>`

Here is an example of the supported configuration 
- `postgres://postgres:postgres@localhost:5432/stuff?sslmode=disable`

NOTE: If the password includes a backslash (\), you need to escape it by adding another backslash. For example, my\_password should be written as my\\_password.

### Driver

Specifies the driver for which you want to run the queries. These are the supported drivers:

- mysql
- oracle
- mssql
- postgres

### SQL_Queries

Receives the list of queries to run. `query` and `response_format` is repeated to get multiple query inputs.

For example:
```
sql_queries: 
  - query: SHOW GLOBAL STATUS LIKE 'Innodb_system%'
    response_format: variables
```

`response_format`: This can be either `variables` or `table`

- `variables`: Expects a two-column table that looks like a key/value result. The left column is considered a key and the right column the value. This mode generates a single event on each fetch operation.

- `table`: Expects any number of columns. This mode generates a single event for each row.

For more examples of response format please refer [here](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-module-sql.html)

### SQL Query (Cursor Mode)

A single SQL query used for cursor-based incremental data fetching. When this field is set, it is used instead of **SQL Queries**. The query must include a `:cursor` placeholder in the WHERE clause. Set **SQL Response Format** to `table`. See the Cursor-based incremental data fetching section below for details.

### Merge Results
Merge multiple queries into a single event.

Multiple queries will create multiple events, one for each query.  It may be preferable to create a single event by combining the metrics together in a single event.

This feature can be enabled using the `merge_results` config.

`merge_results` can merge queries having response format as "variable". 
However, for queries with a response format as "table", a merge is possible only if each table query produces a single row.

For example, if we have the following queries for PostgreSQL:
```
sql_queries:
  - query: "SELECT blks_hit,blks_read FROM pg_stat_database LIMIT 1;"
    response_format: table
  - query: "SELECT checkpoints_timed,checkpoints_req FROM pg_stat_bgwriter;"
    response_format: table
```

The `merge_results` feature will create a combined event, where `blks_hit`, `blks_read`, `checkpoints_timed` and `checkpoints_req` are part of the same event.

### Cursor-based incremental data fetching

Cursor support enables incremental fetching by tracking the last fetched row value and using it to fetch only new data on subsequent collection cycles. This is useful for continuously appended data like audit logs, event tables, or time-series data where you want to avoid re-fetching already-seen rows.

When cursor is enabled, you must use the **SQL Query (Cursor Mode)** field instead of the **SQL Queries** field. Cursor mode requires a single query; it does not support multiple queries. Set **SQL Response Format** to `table`.

#### Required fields

- **SQL Query (Cursor Mode):** Enter a single SQL query string. Include exactly one `:cursor` placeholder in the WHERE clause and an `ORDER BY` clause on the cursor column.
- **Cursor Configuration:** Enter YAML in the form shown below.
- **SQL Response Format:** Must be set to `table`.

#### Cursor Configuration field value

Enter the following in the **Cursor Configuration** field (the values are merged under the `cursor:` key in the generated config):

```yaml
enabled: true
column: id
type: integer
default: "0"
```

#### SQL Query (Cursor Mode) field examples

**Integer cursor (auto-increment ID):**

```
SELECT id, event_type, payload FROM audit_log WHERE id > :cursor ORDER BY id ASC LIMIT 500
```

**Timestamp cursor:**

```
SELECT id, message, created_at FROM logs WHERE created_at > :cursor ORDER BY created_at ASC LIMIT 500
```

**Date cursor:**

```
SELECT report_date, metrics FROM daily_reports WHERE report_date > :cursor ORDER BY report_date ASC
```

**Decimal cursor:**

```
SELECT id, amount, description FROM transactions WHERE amount > :cursor ORDER BY amount ASC LIMIT 500
```

**MSSQL (uses TOP instead of LIMIT):**

```
SELECT TOP 500 id, event_type, payload FROM audit_log WHERE id > :cursor ORDER BY id ASC
```

**Descending cursor:**

```
SELECT id, event_data FROM events WHERE id < :cursor ORDER BY id DESC LIMIT 500
```

With `direction: desc` in the Cursor Configuration field:

```yaml
enabled: true
column: id
type: integer
default: "999999999"
direction: desc
```

#### Cursor configuration options

| Option | Required | Description |
|--------|----------|-------------|
| `enabled` | No | Set to `true` to enable cursor-based fetching. Default: `false`. |
| `column` | Yes (when enabled) | Name of the column to track. Must appear in the query results. |
| `type` | Yes (when enabled) | Data type of the cursor column. One of: `integer`, `timestamp`, `date`, `float`, `decimal`. |
| `default` | Yes (when enabled) | Initial cursor value used before any state is persisted. |
| `direction` | No | `asc` (default) tracks the maximum value; `desc` tracks the minimum value. |

#### Supported cursor types

| Type | Description | Default format example |
|------|-------------|------------------------|
| `integer` | Integer values such as auto-increment IDs or sequences. | `"0"` |
| `timestamp` | TIMESTAMP or DATETIME columns. Accepts RFC 3339, `YYYY-MM-DD HH:MM:SS[.nnnnnnnnn]`, or date-only formats. Stored internally as nanoseconds in UTC. | `"2024-01-01T00:00:00Z"` |
| `date` | Date-only columns (`YYYY-MM-DD`). | `"2024-01-01"` |
| `float` | FLOAT, DOUBLE, or REAL columns. IEEE 754 precision limits apply. | `"0.0"` |
| `decimal` | DECIMAL or NUMERIC columns. Supports arbitrary precision. | `"0.00"` |

#### Scan direction

| Direction | WHERE clause operator | ORDER BY | Cursor tracks |
|-----------|----------------------|----------|---------------|
| `asc` (default) | `>` or `>=` | `ASC` | Maximum value in results |
| `desc` | `<` or `<=` | `DESC` | Minimum value in results |

#### Query requirements

When cursor is enabled:

1. Use the **SQL Query (Cursor Mode)** field (not SQL Queries).
2. Set **SQL Response Format** to `table`.
3. Include an `ORDER BY` clause on the cursor column matching the configured direction.
4. Include exactly one `:cursor` placeholder in the WHERE clause.
5. Cursor is not compatible with `fetch_from_all_databases`. Use separate module blocks per database if needed.

#### State persistence

Cursor state is persisted to disk under `{data.path}/sql-cursor/` and survives Elastic Agent restarts. The state key is a hash derived from the cursor direction, column name, query string, and full database URI/DSN. Changing any of these values resets the cursor to the configured `default`.

#### Choosing `>` vs `>=`

- Use `>` when the cursor column has unique, monotonically increasing values (for example, auto-increment IDs). This avoids re-fetching the last row.
- Use `>=` when multiple rows can share the same cursor value (for example, timestamps with second-level precision). This might re-fetch the last row but avoids data loss. Use Elasticsearch document IDs or an ingest pipeline to deduplicate.

#### Error handling

The cursor uses at-least-once delivery: events are emitted before cursor state is updated. If a failure occurs after emitting events but before saving the cursor, previously emitted rows are re-fetched on the next cycle. This guarantees no data loss, but duplicates are possible.

#### Driver-specific notes

- **MySQL:** Add `parseTime=true` to the DSN for timestamp cursors (for example, `root:pass@tcp(localhost:3306)/mydb?parseTime=true`).
- **Oracle:** Set the session timezone to UTC for timestamp cursors (for example, using the `alterSession` DSN parameter).
- **MSSQL:** Use `TOP` instead of `LIMIT`. The driver translates the `:cursor` placeholder to `@p1` internally.
- **Decimal:** Values are passed as strings. Use `CAST(:cursor AS DECIMAL(10,2))` in the query if the database requires explicit typing.

#### Limitations

- Each fetch cycle loads all matching rows into memory. Use `LIMIT` (or `TOP` for MSSQL) to bound the result set (500–5000 rows recommended).
- Long-running fetch cycles can cause subsequent cycles to be skipped until the current one finishes.
- Each fetch is limited by the module `timeout` (defaults to `period`).
- Float cursors have IEEE 754 precision limits. Use `decimal` for exact values.
- String, UUID, and ULID types are not supported as cursor columns.
- NULL cursor values in result rows are skipped.
- The cursor column must appear in the SELECT clause.
- Only one `:cursor` placeholder per query is supported.

### SSL configuration

The drivers `mysql`, `mssql`, and `postgres` are supported.

The SSL configuration is driver-specific. Different drivers have slightly different parameter interpretations. Subset of the [params](https://www.elastic.co/docs/reference/beats/metricbeat/configuration-ssl#ssl-client-config) is supported.

When "SSL Configuration" parameters are set, only URL-formatted connection strings are accepted.
Use this format: `postgres://myuser:mypassword@localhost:5432/mydb`.
Don't use this format: `user=myuser password=mypassword dbname=mydb`.

Example of SSL configuration:
```
verification_mode: full
certificate_authorities:
  - /path/to/ca.pem
```

#### `mysql` driver

Parameters supported: `verification_mode`, `certificate`, `key`, `certificate_authorities`.

The certificates can be passed both as file paths and certificate content.

Example with the certificate content "embedded":
```
verification_mode: full
certificate_authorities:
  - |
    -----BEGIN CERTIFICATE-----
    MIIDCjCCAfKgAwIBAgITJ706Mu2wJlKckpIvkWxEHvEyijANBgkqhkiG9w0BAQsF
    ADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwIBcNMTkwNzIyMTkyOTA0WhgPMjExOTA2
    MjgxOTI5MDRaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEB
    BQADggEPADCCAQoCggEBANce58Y/JykI58iyOXpxGfw0/gMvF0hUQAcUrSMxEO6n
    fZRA49b4OV4SwWmA3395uL2eB2NB8y8qdQ9muXUdPBWE4l9rMZ6gmfu90N5B5uEl
    94NcfBfYOKi1fJQ9i7WKhTjlRkMCgBkWPkUokvBZFRt8RtF7zI77BSEorHGQCk9t
    /D7BS0GJyfVEhftbWcFEAG3VRcoMhF7kUzYwp+qESoriFRYLeDWv68ZOvG7eoWnP
    PsvZStEVEimjvK5NSESEQa9xWyJOmlOKXhkdymtcUd/nXnx6UTCFgnkgzSdTWV41
    CI6B6aJ9svCTI2QuoIq2HxX/ix7OvW1huVmcyHVxyUECAwEAAaNTMFEwHQYDVR0O
    BBYEFPwN1OceFGm9v6ux8G+DZ3TUDYxqMB8GA1UdIwQYMBaAFPwN1OceFGm9v6ux
    8G+DZ3TUDYxqMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAG5D
    874A4YI7YUwOVsVAdbWtgp1d0zKcPRR+r2OdSbTAV5/gcS3jgBJ3i1BN34JuDVFw
    3DeJSYT3nxy2Y56lLnxDeF8CUTUtVQx3CuGkRg1ouGAHpO/6OqOhwLLorEmxi7tA
    H2O8mtT0poX5AnOAhzVy7QW0D/k4WaoLyckM5hUa6RtvgvLxOwA0U+VGurCDoctu
    8F4QOgTAWyh8EZIwaKCliFRSynDpv3JTUwtfZkxo6K6nce1RhCWFAsMvDZL8Dgc0
    yvgJ38BRsFOtkRuAGSf6ZUwTO8JJRRIFnpUzXflAnGivK9M13D5GEQMmIl6U9Pvk
    sxSmbIUfc2SGJGCJD4I=
    -----END CERTIFICATE-----
```

#### `postgres` driver

Parameters supported: `verification_mode`, `certificate`, `key`, `certificate_authorities`.

Only one certificate can be passed to the `certificate_authorities` parameter.
The certificates can be passed only as file paths. The files have to be present in the environment where the metricbeat is running.

The `verification_mode` is translated as follows:

- `full` -> `verify-full`

- `strict` -> `verify-full`

- `certificate` -> `verify-ca`

- `none` -> `require`

#### `mssql` driver

Params supported: `verification_mode`, `certificate_authorities`.

Only one certificate can be passed to the `certificate_authorities` parameter.
The certificates can be passed only as file paths. The files have to be present in the environment where the metricbeat is running.

If `verification_mode` is set to `none`, `TrustServerCertificate` will be set to `true`, otherwise it is `false`.


## Metrics reference

### Example

```json
{
    "@timestamp": "2025-06-25T07:34:08.850Z",
    "agent": {
        "ephemeral_id": "062e1a2d-efcc-495c-9cef-2f4d1ea6bdaa",
        "id": "81f6c307-e62b-45cd-aa0d-be554deb83b2",
        "name": "elastic-agent-33528",
        "type": "metricbeat",
        "version": "9.1.0"
    },
    "data_stream": {
        "dataset": "sql.sql",
        "namespace": "72095",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "81f6c307-e62b-45cd-aa0d-be554deb83b2",
        "snapshot": true,
        "version": "9.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "sql.sql",
        "duration": 1311560,
        "ingested": "2025-06-25T07:34:11Z",
        "module": "sql"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-33528",
        "ip": [
            "192.168.160.2",
            "172.28.0.4"
        ],
        "mac": [
            "02-42-AC-1C-00-04",
            "02-42-C0-A8-A0-02"
        ],
        "name": "elastic-agent-33528",
        "os": {
            "family": "",
            "kernel": "6.8.0-50-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "metricset": {
        "name": "query",
        "period": 10000
    },
    "service": {
        "address": "svc-sql_input_mysql:3306",
        "type": "sql"
    },
    "sql": {
        "driver": "mysql",
        "metrics": {
            "delayed_insert_threads": "0",
            "mysqlx_worker_threads": "2",
            "mysqlx_worker_threads_active": "0",
            "slow_launch_threads": "0",
            "threads_cached": "0",
            "threads_connected": "1",
            "threads_created": "1",
            "threads_running": "2"
        },
        "query": [
            "SHOW STATUS LIKE '%Threads%'"
        ]
    }
}
```
