# SQL input

The SQL input package allows you to execute custom queries against an SQL database and store the results in Elasticsearch.

This module supports the below listed databases:

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
The supported configuration takes one of the forms
- `oracle://<user>:<password>@<connection_string>`
- `<user>:<password>@<connection_string>`

Examples of supported configurations are as below:
- `oracle://sys:Oradoc_db1@0.0.0.0:1521/ORCLCDB.localdomain?sysdba=1`
- `sys:Oradoc_db1@0.0.0.0:1521/ORCLCDB.localdomain?sysdba=1`

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

