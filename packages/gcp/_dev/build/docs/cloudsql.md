# CloudSQL

The `cloudsql` dataset fetches metrics from [CloudSQL](https://cloud.google.com/sql) in Google Cloud Platform. It contains all metrics exported from the [GCP CloudSQL Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-cloudsql).

`gcp.labels.cloudsql.name` label is utilized to identify the type of Google Cloud SQL database that generated the metrics. In the pipelines, this label is crucial for distinguishing between various Cloud SQL database types and directing the metrics to their respective destinations. Current valid values are `mysql`, `postgres` and `sqlserver`. Other values will be dropped.

## MySQL Metrics

CloudSQL MySQL metrics.

{{event "cloudsql_mysql"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "cloudsql_mysql"}}

## PostgreSQL Metrics

CloudSQL PostgreSQL metrics.

{{event "cloudsql_postgresql"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "cloudsql_postgresql"}}


## SQL Server Metrics

CloudSQL SQL Server metrics.

{{event "cloudsql_sqlserver"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "cloudsql_sqlserver"}}
