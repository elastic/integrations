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

For more examples of response format please refer [here](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-module-sql.html)


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

### SSL configuration

#### Option 1. Using "SSL Configuration" section (`ssl.*` parameters)

The drivers `mysql`, `mssql`, and `postgres` are supported.

The SSL configuration is driver-specific. Different drivers interpret parameters not in the same way. Subset of the [params](https://www.elastic.co/docs/reference/beats/metricbeat/configuration-ssl#ssl-client-config) is supported.

When any `ssl.*` parameters are set, only URL-formatted connection strings are accepted, like `"postgres://myuser:mypassword@localhost:5432/mydb"`, not like `"user=myuser password=mypassword dbname=mydb"`.

##### `mysql` driver

Params supported: `ssl.verification_mode`, `ssl.certificate`, `ssl.key`, `ssl.certificate_authorities`.

The certificates can be passed both as file paths and as certificate content.

Example 1:
```
ssl.certificate_authorities: |
  -----BEGIN CERTIFICATE-----
  MIID+jCCAuKgAwIBAgIGAJJMzlxLMA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNVBAYT
  AlVTMQwwCgYDVQQKEwNJQk0xFjAUBgNVBAsTDURlZmF1bHROb2RlMDExFjAUBgNV
  BAsTDURlZmF1bHRDZWxsMDExGTAXBgNVBAsTEFJvb3QgQ2VydGlmaWNhdGUxEjAQ
  BgNVBAMTCWxvY2FsaG9zdDAeFw0yMTEyMTQyMjA3MTZaFw0yMjEyMTQyMjA3MTZa
  MF8xCzAJBgNVBAYTAlVTMQwwCgYDVQQKEwNJQk0xFjAUBgNVBAsTDURlZmF1bHRO
  b2RlMDExFjAUBgNVBAsTDURlZmF1bHRDZWxsMDExEjAQBgNVBAMTCWxvY2FsaG9z
  dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMv5HCsJZIpI5zCy+jXV
  z6lmzNc9UcVSEEHn86h6zT6pxuY90TYeAhlZ9hZ+SCKn4OQ4GoDRZhLPTkYDt+wW
  CV3NTIy9uCGUSJ6xjCKoxClJmgSQdg5m4HzwfY4ofoEZ5iZQ0Zmt62jGRWc0zuxj
  hegnM+eO2reBJYu6Ypa9RPJdYJsmn1RNnC74IDY8Y95qn+WZj//UALCpYfX41hko
  i7TWD9GKQO8SBmAxhjCDifOxVBokoxYrNdzESl0LXvnzEadeZTd9BfUtTaBHhx6t
  njqqCPrbTY+3jAbZFd4RiERPnhLVKMytw5ot506BhPrUtpr2lusbN5svNXjuLeea
  MMUCAwEAAaOBoDCBnTATBgNVHSMEDDAKgAhOatpLwvJFqjAdBgNVHSUEFjAUBggr
  BgEFBQcDAQYIKwYBBQUHAwIwVAYDVR0RBE0wS4E+UHJvZmlsZVVVSUQ6QXBwU3J2
  MDEtQkFTRS05MDkzMzJjMC1iNmFiLTQ2OTMtYWI5NC01Mjc1ZDI1MmFmNDiCCWxv
  Y2FsaG9zdDARBgNVHQ4ECgQITzqhA5sO8O4wDQYJKoZIhvcNAQELBQADggEBAKR0
  gY/BM69S6BDyWp5dxcpmZ9FS783FBbdUXjVtTkQno+oYURDrhCdsfTLYtqUlP4J4
  CHoskP+MwJjRIoKhPVQMv14Q4VC2J9coYXnePhFjE+6MaZbTjq9WaekGrpKkMaQA
  iQt5b67jo7y63CZKIo9yBvs7sxODQzDn3wZwyux2vPegXSaTHR/rop/s/mPk3YTS
  hQprs/IVtPoWU4/TsDN3gIlrAYGbcs29CAt5q9MfzkMmKsuDkTZD0ry42VjxjAmk
  xw23l/k8RoD1wRWaDVbgpjwSzt+kl+vJE/ip2w3h69eEZ9wbo6scRO5lCO2JM4Pr
  7RhLQyWn2u00L7/9Omw=
  -----END CERTIFICATE-----
```

Example 2:
```
ssl.certificate_authorities: /path/to/ca.pem
```

##### `postgres` driver

Params supported: `ssl.verification_mode`, `ssl.certificate`, `ssl.key`, `ssl.certificate_authorities`.

Only one certificate can be passed to `ssl.certificate_authorities` parameter.
The certificates can be passed only as file paths. The files have to be present in the environment where the metricbeat is running.

The `ssl.verification_mode` is translated as following:

- `full` -> `verify-full`

- `strict` -> `verify-full`

- `certificate` -> `verify-ca`

- `none` -> `require`

##### `mssql` driver

Params supported: `ssl.verification_mode`, `ssl.certificate_authorities`.

Only one certificate can be passed to `ssl.certificate_authorities` parameter.
The certificates can be passed only as file paths. The files have to be present in the environment where the metricbeat is running.

If `ssl.verification_mode` is set to `none`, `TrustServerCertificate` will be set to `true`, otherwise it is `false`


#### Option 2. Passing SSL configuration in the connection string

It is possible to configure SSL connections using the `hosts` parameter by passing the parameters in the connection string. For example, for `postgres`: `postgres://myuser:mypassword@localhost:5432/mydb?sslcert=.%2Fcert.pem&sslkey=.%2Fkey.pem&sslmode=verify-full&sslrootcert=.%2Fca.pem`. (The parameters needs to be URL encoded). Refer to the documentation of your database for parameters specification.

When you use this option, don't set any parameters in the "SSL Configuration" sections, otherwise parameters you supply in the connection string may be overwritten.
