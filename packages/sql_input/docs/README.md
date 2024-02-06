# SQL input

The SQL input package allows you to execute custom queries against an SQL database and store the results in Elasticsearch.

This input package supports the below listed databases:

- MySQL
- Oracle
- Microsoft SQL
- PostgreSQL

## Configuration Options for the User:


### Hosts: 
The host configuration should be specified from where the metrics are to be fetched. It varies depending upon the driver you are running

#### MySQL: 
The supported configuration takes this form
- `<user>:<password>@tcp(<host>:<port>)/`

Example of supported configuration is as below:
- `root:root@tcp(localhost:3306)/`

#### Oracle: 

The following two types of host configurations are supported:

1. Old style host configuration :

    a. `hosts: ["user/pass@0.0.0.0:1521/ORCLPDB1.localdomain"]`
    
    b. `hosts: ["user/password@0.0.0.0:1521/ORCLPDB1.localdomain as sysdba"]`

2. DSN host configuration:

    a. `hosts: ['user="user" password="pass" connectString="0.0.0.0:1521/ORCLPDB1.localdomain"']`
    
    b. `hosts: ['user="user" password="password" connectString="host:port/service_name" sysdba=true']`
  
#### MSSQL: 
The supported configuration takes this form
- `sqlserver://<user>:<password>@<host>`

Example of supported configurations is as below:
- `sqlserver://root:test@localhost`

#### PostgreSQL: 
The supported configuration takes this form
- `postgres://<user>:<password>@<connection_string>`

Example of supported configuration is as below:
- `postgres://postgres:postgres@localhost:5432/stuff?sslmode=disable`

Note: If the password contains the backslash (`\`) character, it must be escaped with a backslash. For example, if the password is `my\_password`, it should be written as `my\\_password`.

### Driver
Specify the driver for which you want to run the queries. Below are the supported drivers:

- mysql
- oracle
- mssql
- postgres

### SQL_Queries
Receives the list of queries to execute. query and response_format is repeated to get multiple query inputs.

Eg:   
sql_queries: 
  - query: SHOW GLOBAL STATUS LIKE 'Innodb_system%'
    
    response_format: variables

response_format: This can be either variables or table

variables:
Expects a two-column table that looks like a key/value result. The left column is considered a key and the right column the value. This mode generates a single event on each fetch operation.

table:
Expects any number of columns. This mode generates a single event for each row.

For more examples of response format pelase refer [here](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-module-sql.html)


### Merge Results
Merge multiple queries into a single event.

Multiple queries will create multiple events, one for each query.  It may be preferable to create a single event by combining the metrics together in a single event.

This feature can be enabled using the `merge_results` config.

`merge_results` can merge queries having response format as "variable". 
However, for queries with a response format as "table", a merge is possible only if each table query produces a single row.

For example, if we have 2 queries as below for PostgreSQL:

sql_queries:
  - query: "SELECT blks_hit,blks_read FROM pg_stat_database LIMIT 1;"
    response_format: table

  - query: "SELECT checkpoints_timed,checkpoints_req FROM pg_stat_bgwriter;"
    response_format: table

The `merge_results` feature will create a combined event, where `blks_hit`, `blks_read`, `checkpoints_timed` and `checkpoints_req` are part of the same event.

