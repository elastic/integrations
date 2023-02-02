# SQL input

The SQL input package allows you to execute custom queries against an SQL database and store the results in Elasticsearch.

This module supports the below listed databases:

- MySQL
- Oracle
- Microsoft SQL
- PostgreSQL
- CockroachDB

## Configuration Options for the User:


### Hosts: 
The host configuration should be specified from where the metrics are to be fetched. It varies depending upon the driver you are running

Eg: 
- Mssqlserver: sqlserver://root:test @localhost
- Oracle: oracle://sys:Oradoc_db1@172.17.0.3:1521/ORCLPDB1.localdomain?sysdba=1
- Mysql: root:root@tcp(localhost:3306)/
- Postgresql: postgres://postgres:postgres@localhost:5432/stuff?sslmode=disable


### Driver
Specify the driver for which you want to run the queries. Eg: mysql, oracle


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


## Compatibility

This input package has been tested with SQL verion 8.0.32
