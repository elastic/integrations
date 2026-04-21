# Input Types for Integrations Owned by `obs-infraobs-integrations`

This report lists each integration and data stream owned by the GitHub team
`@elastic/obs-infraobs-integrations`, together with the Elastic Agent input
type(s) each data stream uses.

> **Generated automatically** by `scripts/generate_obs_infraobs_report.py`.
> Re-run the script to refresh this file.

| Package | Data Stream | Input Type | Evidence (file path) |
| ------- | ----------- | ---------- | -------------------- |
| activemq | audit | logfile | `packages/activemq/data_stream/audit/manifest.yml` |
| activemq | broker | activemq/metrics | `packages/activemq/data_stream/broker/manifest.yml` |
| activemq | log | logfile | `packages/activemq/data_stream/log/manifest.yml` |
| activemq | queue | activemq/metrics | `packages/activemq/data_stream/queue/manifest.yml` |
| activemq | topic | activemq/metrics | `packages/activemq/data_stream/topic/manifest.yml` |
| airflow | statsd | statsd/metrics | `packages/airflow/data_stream/statsd/manifest.yml` |
| apache | access | logfile | `packages/apache/data_stream/access/manifest.yml` |
| apache | error | logfile | `packages/apache/data_stream/error/manifest.yml` |
| apache | status | apache/metrics | `packages/apache/data_stream/status/manifest.yml` |
| apache_spark | application | jolokia/metrics | `packages/apache_spark/data_stream/application/manifest.yml` |
| apache_spark | driver | jolokia/metrics | `packages/apache_spark/data_stream/driver/manifest.yml` |
| apache_spark | executor | jolokia/metrics | `packages/apache_spark/data_stream/executor/manifest.yml` |
| apache_spark | node | jolokia/metrics | `packages/apache_spark/data_stream/node/manifest.yml` |
| apache_tomcat | access | filestream | `packages/apache_tomcat/data_stream/access/manifest.yml, packages/apache_tomcat/data_stream/access/agent/stream/filestream.yml.hbs` |
| apache_tomcat | cache | prometheus/metrics | `packages/apache_tomcat/data_stream/cache/manifest.yml` |
| apache_tomcat | catalina | filestream | `packages/apache_tomcat/data_stream/catalina/manifest.yml, packages/apache_tomcat/data_stream/catalina/agent/stream/filestream.yml.hbs` |
| apache_tomcat | connection_pool | prometheus/metrics | `packages/apache_tomcat/data_stream/connection_pool/manifest.yml` |
| apache_tomcat | localhost | filestream | `packages/apache_tomcat/data_stream/localhost/manifest.yml, packages/apache_tomcat/data_stream/localhost/agent/stream/filestream.yml.hbs` |
| apache_tomcat | memory | prometheus/metrics | `packages/apache_tomcat/data_stream/memory/manifest.yml` |
| apache_tomcat | request | prometheus/metrics | `packages/apache_tomcat/data_stream/request/manifest.yml` |
| apache_tomcat | session | prometheus/metrics | `packages/apache_tomcat/data_stream/session/manifest.yml` |
| apache_tomcat | thread_pool | prometheus/metrics | `packages/apache_tomcat/data_stream/thread_pool/manifest.yml` |
| aws | apigateway_logs | aws-s3 | `packages/aws/data_stream/apigateway_logs/manifest.yml, packages/aws/data_stream/apigateway_logs/agent/stream/aws-s3.yml.hbs` |
| aws | apigateway_logs | aws-cloudwatch | `packages/aws/data_stream/apigateway_logs/manifest.yml, packages/aws/data_stream/apigateway_logs/agent/stream/aws-cloudwatch.yml.hbs` |
| aws | apigateway_metrics | aws/metrics | `packages/aws/data_stream/apigateway_metrics/manifest.yml` |
| aws | awshealth | aws/metrics | `packages/aws/data_stream/awshealth/manifest.yml` |
| aws | billing | aws/metrics | `packages/aws/data_stream/billing/manifest.yml` |
| aws | cloudfront_logs | aws-s3 | `packages/aws/data_stream/cloudfront_logs/manifest.yml, packages/aws/data_stream/cloudfront_logs/agent/stream/aws-s3.yml.hbs` |
| aws | dynamodb | aws/metrics | `packages/aws/data_stream/dynamodb/manifest.yml` |
| aws | elb_logs | aws-s3 | `packages/aws/data_stream/elb_logs/manifest.yml, packages/aws/data_stream/elb_logs/agent/stream/aws-s3.yml.hbs` |
| aws | elb_logs | aws-cloudwatch | `packages/aws/data_stream/elb_logs/manifest.yml, packages/aws/data_stream/elb_logs/agent/stream/aws-cloudwatch.yml.hbs` |
| aws | elb_metrics | aws/metrics | `packages/aws/data_stream/elb_metrics/manifest.yml` |
| aws | emr_logs | aws-s3 | `packages/aws/data_stream/emr_logs/manifest.yml, packages/aws/data_stream/emr_logs/agent/stream/aws-s3.yml.hbs` |
| aws | emr_logs | aws-cloudwatch | `packages/aws/data_stream/emr_logs/manifest.yml, packages/aws/data_stream/emr_logs/agent/stream/aws-cloudwatch.yml.hbs` |
| aws | emr_metrics | aws/metrics | `packages/aws/data_stream/emr_metrics/manifest.yml` |
| aws | kafka_metrics | aws/metrics | `packages/aws/data_stream/kafka_metrics/manifest.yml` |
| aws | kinesis | aws/metrics | `packages/aws/data_stream/kinesis/manifest.yml` |
| aws | lambda | aws/metrics | `packages/aws/data_stream/lambda/manifest.yml` |
| aws | lambda_logs | aws-cloudwatch | `packages/aws/data_stream/lambda_logs/manifest.yml, packages/aws/data_stream/lambda_logs/agent/stream/aws-cloudwatch.yml.hbs` |
| aws | natgateway | aws/metrics | `packages/aws/data_stream/natgateway/manifest.yml` |
| aws | rds | aws/metrics | `packages/aws/data_stream/rds/manifest.yml` |
| aws | redshift | aws/metrics | `packages/aws/data_stream/redshift/manifest.yml` |
| aws | s3_storage_lens | aws/metrics | `packages/aws/data_stream/s3_storage_lens/manifest.yml` |
| aws | sns | aws/metrics | `packages/aws/data_stream/sns/manifest.yml` |
| aws | sqs | aws/metrics | `packages/aws/data_stream/sqs/manifest.yml` |
| aws | transitgateway | aws/metrics | `packages/aws/data_stream/transitgateway/manifest.yml` |
| aws | usage | aws/metrics | `packages/aws/data_stream/usage/manifest.yml` |
| aws | vpn | aws/metrics | `packages/aws/data_stream/vpn/manifest.yml` |
| aws_bedrock | guardrails | aws/metrics | `packages/aws_bedrock/data_stream/guardrails/manifest.yml` |
| aws_bedrock | runtime | aws/metrics | `packages/aws_bedrock/data_stream/runtime/manifest.yml` |
| aws_bedrock_agentcore | gateway_application_logs | aws-cloudwatch | `packages/aws_bedrock_agentcore/data_stream/gateway_application_logs/manifest.yml, packages/aws_bedrock_agentcore/data_stream/gateway_application_logs/agent/stream/aws-cloudwatch.yml.hbs` |
| aws_bedrock_agentcore | gateway_application_logs | aws-s3 | `packages/aws_bedrock_agentcore/data_stream/gateway_application_logs/manifest.yml, packages/aws_bedrock_agentcore/data_stream/gateway_application_logs/agent/stream/aws-s3.yml.hbs` |
| aws_bedrock_agentcore | memory_application_logs | aws-cloudwatch | `packages/aws_bedrock_agentcore/data_stream/memory_application_logs/manifest.yml, packages/aws_bedrock_agentcore/data_stream/memory_application_logs/agent/stream/aws-cloudwatch.yml.hbs` |
| aws_bedrock_agentcore | memory_application_logs | aws-s3 | `packages/aws_bedrock_agentcore/data_stream/memory_application_logs/manifest.yml, packages/aws_bedrock_agentcore/data_stream/memory_application_logs/agent/stream/aws-s3.yml.hbs` |
| aws_bedrock_agentcore | metrics | aws/metrics | `packages/aws_bedrock_agentcore/data_stream/metrics/manifest.yml` |
| aws_bedrock_agentcore | runtime_application_logs | aws-cloudwatch | `packages/aws_bedrock_agentcore/data_stream/runtime_application_logs/manifest.yml, packages/aws_bedrock_agentcore/data_stream/runtime_application_logs/agent/stream/aws-cloudwatch.yml.hbs` |
| aws_bedrock_agentcore | runtime_application_logs | aws-s3 | `packages/aws_bedrock_agentcore/data_stream/runtime_application_logs/manifest.yml, packages/aws_bedrock_agentcore/data_stream/runtime_application_logs/agent/stream/aws-s3.yml.hbs` |
| aws_billing | cur | aws-s3 | `packages/aws_billing/data_stream/cur/manifest.yml, packages/aws_billing/data_stream/cur/agent/stream/aws-s3.yml.hbs` |
| aws_mq | activemq_audit_logs | aws-cloudwatch | `packages/aws_mq/data_stream/activemq_audit_logs/manifest.yml, packages/aws_mq/data_stream/activemq_audit_logs/agent/stream/aws-cloudwatch.yml.hbs` |
| aws_mq | activemq_general_logs | aws-cloudwatch | `packages/aws_mq/data_stream/activemq_general_logs/manifest.yml, packages/aws_mq/data_stream/activemq_general_logs/agent/stream/aws-cloudwatch.yml.hbs` |
| aws_mq | activemq_metrics | aws/metrics | `packages/aws_mq/data_stream/activemq_metrics/manifest.yml` |
| aws_mq | rabbitmq_general_logs | aws-cloudwatch | `packages/aws_mq/data_stream/rabbitmq_general_logs/manifest.yml, packages/aws_mq/data_stream/rabbitmq_general_logs/agent/stream/aws-cloudwatch.yml.hbs` |
| aws_mq | rabbitmq_metrics | aws/metrics | `packages/aws_mq/data_stream/rabbitmq_metrics/manifest.yml` |
| awsfargate | task_stats | awsfargate/metrics | `packages/awsfargate/data_stream/task_stats/manifest.yml` |
| azure | activitylogs | azure-eventhub | `packages/azure/data_stream/activitylogs/manifest.yml, packages/azure/data_stream/activitylogs/agent/stream/azure-eventhub.yml.hbs` |
| azure | auditlogs | azure-eventhub | `packages/azure/data_stream/auditlogs/manifest.yml, packages/azure/data_stream/auditlogs/agent/stream/azure-eventhub.yml.hbs` |
| azure | identity_protection | azure-eventhub | `packages/azure/data_stream/identity_protection/manifest.yml, packages/azure/data_stream/identity_protection/agent/stream/azure-eventhub.yml.hbs` |
| azure | platformlogs | azure-eventhub | `packages/azure/data_stream/platformlogs/manifest.yml, packages/azure/data_stream/platformlogs/agent/stream/azure-eventhub.yml.hbs` |
| azure | provisioning | azure-eventhub | `packages/azure/data_stream/provisioning/manifest.yml, packages/azure/data_stream/provisioning/agent/stream/azure-eventhub.yml.hbs` |
| azure | signinlogs | azure-eventhub | `packages/azure/data_stream/signinlogs/manifest.yml, packages/azure/data_stream/signinlogs/agent/stream/azure-eventhub.yml.hbs` |
| azure | springcloudlogs | azure-eventhub | `packages/azure/data_stream/springcloudlogs/manifest.yml, packages/azure/data_stream/springcloudlogs/agent/stream/azure-eventhub.yml.hbs` |
| azure_ai_foundry | logs | azure-eventhub | `packages/azure_ai_foundry/data_stream/logs/manifest.yml, packages/azure_ai_foundry/data_stream/logs/agent/stream/azure-eventhub.yml.hbs` |
| azure_ai_foundry | metrics | azure/metrics | `packages/azure_ai_foundry/data_stream/metrics/manifest.yml` |
| azure_app_service | app_service_logs | azure-eventhub | `packages/azure_app_service/data_stream/app_service_logs/manifest.yml, packages/azure_app_service/data_stream/app_service_logs/agent/stream/azure-eventhub.yml.hbs` |
| azure_application_insights | app_insights | azure/metrics | `packages/azure_application_insights/data_stream/app_insights/manifest.yml` |
| azure_application_insights | app_state | azure/metrics | `packages/azure_application_insights/data_stream/app_state/manifest.yml` |
| azure_billing | billing | azure/metrics | `packages/azure_billing/data_stream/billing/manifest.yml` |
| azure_functions | functionapplogs | azure-eventhub | `packages/azure_functions/data_stream/functionapplogs/manifest.yml, packages/azure_functions/data_stream/functionapplogs/agent/stream/azure-eventhub.yml.hbs` |
| azure_functions | metrics | azure/metrics | `packages/azure_functions/data_stream/metrics/manifest.yml` |
| azure_openai | logs | azure-eventhub | `packages/azure_openai/data_stream/logs/manifest.yml, packages/azure_openai/data_stream/logs/agent/stream/azure-eventhub.yml.hbs` |
| azure_openai | metrics | azure/metrics | `packages/azure_openai/data_stream/metrics/manifest.yml` |
| cassandra | log | logfile | `packages/cassandra/data_stream/log/manifest.yml` |
| cassandra | metrics | jolokia/metrics | `packages/cassandra/data_stream/metrics/manifest.yml` |
| ceph | cluster_disk | httpjson | `packages/ceph/data_stream/cluster_disk/manifest.yml, packages/ceph/data_stream/cluster_disk/agent/stream/httpjson.yml.hbs` |
| ceph | cluster_health | httpjson | `packages/ceph/data_stream/cluster_health/manifest.yml, packages/ceph/data_stream/cluster_health/agent/stream/httpjson.yml.hbs` |
| ceph | cluster_status | httpjson | `packages/ceph/data_stream/cluster_status/manifest.yml, packages/ceph/data_stream/cluster_status/agent/stream/httpjson.yml.hbs` |
| ceph | osd_performance | httpjson | `packages/ceph/data_stream/osd_performance/manifest.yml, packages/ceph/data_stream/osd_performance/agent/stream/httpjson.yml.hbs` |
| ceph | osd_pool_stats | httpjson | `packages/ceph/data_stream/osd_pool_stats/manifest.yml, packages/ceph/data_stream/osd_pool_stats/agent/stream/httpjson.yml.hbs` |
| ceph | osd_tree | httpjson | `packages/ceph/data_stream/osd_tree/manifest.yml, packages/ceph/data_stream/osd_tree/agent/stream/httpjson.yml.hbs` |
| ceph | pool_disk | httpjson | `packages/ceph/data_stream/pool_disk/manifest.yml, packages/ceph/data_stream/pool_disk/agent/stream/httpjson.yml.hbs` |
| cisco_meraki_metrics | device_health | meraki/metrics | `packages/cisco_meraki_metrics/data_stream/device_health/manifest.yml` |
| citrix_adc | interface | httpjson | `packages/citrix_adc/data_stream/interface/manifest.yml, packages/citrix_adc/data_stream/interface/agent/stream/httpjson.yml.hbs` |
| citrix_adc | lbvserver | httpjson | `packages/citrix_adc/data_stream/lbvserver/manifest.yml, packages/citrix_adc/data_stream/lbvserver/agent/stream/httpjson.yml.hbs` |
| citrix_adc | service | httpjson | `packages/citrix_adc/data_stream/service/manifest.yml` |
| citrix_adc | system | httpjson | `packages/citrix_adc/data_stream/system/manifest.yml` |
| citrix_adc | vpn | httpjson | `packages/citrix_adc/data_stream/vpn/manifest.yml, packages/citrix_adc/data_stream/vpn/agent/stream/httpjson.yml.hbs` |
| cockroachdb | status | prometheus/metrics | `packages/cockroachdb/data_stream/status/manifest.yml` |
| coredns | log | filestream | `packages/coredns/data_stream/log/manifest.yml, packages/coredns/data_stream/log/agent/stream/filestream.yml.hbs` |
| coredns | log | journald | `packages/coredns/data_stream/log/manifest.yml, packages/coredns/data_stream/log/agent/stream/journald.yml.hbs` |
| couchbase | bucket | http/metrics | `packages/couchbase/data_stream/bucket/manifest.yml` |
| couchbase | cache | prometheus/metrics | `packages/couchbase/data_stream/cache/manifest.yml` |
| couchbase | cbl_replication | prometheus/metrics | `packages/couchbase/data_stream/cbl_replication/manifest.yml` |
| couchbase | cluster | http/metrics | `packages/couchbase/data_stream/cluster/manifest.yml` |
| couchbase | database_stats | prometheus/metrics | `packages/couchbase/data_stream/database_stats/manifest.yml` |
| couchbase | miscellaneous | prometheus/metrics | `packages/couchbase/data_stream/miscellaneous/manifest.yml` |
| couchbase | node | httpjson | `packages/couchbase/data_stream/node/manifest.yml` |
| couchbase | query_index | http/metrics | `packages/couchbase/data_stream/query_index/manifest.yml` |
| couchbase | resource | prometheus/metrics | `packages/couchbase/data_stream/resource/manifest.yml` |
| couchbase | xdcr | http/metrics | `packages/couchbase/data_stream/xdcr/manifest.yml` |
| couchdb | server | http/metrics | `packages/couchdb/data_stream/server/manifest.yml` |
| envoyproxy | log | filestream | `packages/envoyproxy/data_stream/log/manifest.yml, packages/envoyproxy/data_stream/log/agent/stream/filestream.yml.hbs` |
| envoyproxy | stats | statsd/metrics | `packages/envoyproxy/data_stream/stats/manifest.yml` |
| ess_billing | billing | cel | `packages/ess_billing/data_stream/billing/manifest.yml, packages/ess_billing/data_stream/billing/agent/stream/cel.yml.hbs` |
| ess_billing | credits | cel | `packages/ess_billing/data_stream/credits/manifest.yml, packages/ess_billing/data_stream/credits/agent/stream/cel.yml.hbs` |
| etcd | leader | etcd/metrics | `packages/etcd/data_stream/leader/manifest.yml` |
| etcd | metrics | prometheus/metrics | `packages/etcd/data_stream/metrics/manifest.yml` |
| etcd | self | etcd/metrics | `packages/etcd/data_stream/self/manifest.yml` |
| etcd | store | etcd/metrics | `packages/etcd/data_stream/store/manifest.yml` |
| gcp | billing | gcp/metrics | `packages/gcp/data_stream/billing/manifest.yml` |
| gcp | cloudrun_metrics | gcp/metrics | `packages/gcp/data_stream/cloudrun_metrics/manifest.yml` |
| gcp | cloudsql_mysql | gcp/metrics | `packages/gcp/data_stream/cloudsql_mysql/manifest.yml` |
| gcp | cloudsql_postgresql | gcp/metrics | `packages/gcp/data_stream/cloudsql_postgresql/manifest.yml` |
| gcp | cloudsql_sqlserver | gcp/metrics | `packages/gcp/data_stream/cloudsql_sqlserver/manifest.yml` |
| gcp | dataproc | gcp/metrics | `packages/gcp/data_stream/dataproc/manifest.yml` |
| gcp | firestore | gcp/metrics | `packages/gcp/data_stream/firestore/manifest.yml` |
| gcp | loadbalancing_logs | gcp-pubsub | `packages/gcp/data_stream/loadbalancing_logs/manifest.yml, packages/gcp/data_stream/loadbalancing_logs/agent/stream/gcp-pubsub.yml.hbs` |
| gcp | loadbalancing_metrics | gcp/metrics | `packages/gcp/data_stream/loadbalancing_metrics/manifest.yml` |
| gcp | redis | gcp/metrics | `packages/gcp/data_stream/redis/manifest.yml` |
| gcp_vertexai | auditlogs | gcp-pubsub | `packages/gcp_vertexai/data_stream/auditlogs/manifest.yml` |
| gcp_vertexai | metrics | gcp/metrics | `packages/gcp_vertexai/data_stream/metrics/manifest.yml` |
| gcp_vertexai | prompt_response_logs | gcp/metrics | `packages/gcp_vertexai/data_stream/prompt_response_logs/manifest.yml` |
| golang | expvar | httpjson | `packages/golang/data_stream/expvar/manifest.yml, packages/golang/data_stream/expvar/agent/stream/httpjson.yml.hbs` |
| golang | heap | httpjson | `packages/golang/data_stream/heap/manifest.yml, packages/golang/data_stream/heap/agent/stream/httpjson.yml.hbs` |
| grafana | logs | logfile | `packages/grafana/data_stream/logs/manifest.yml` |
| grafana | metrics | prometheus/metrics | `packages/grafana/data_stream/metrics/manifest.yml` |
| hadoop | application | httpjson | `packages/hadoop/data_stream/application/manifest.yml` |
| hadoop | cluster | http/metrics | `packages/hadoop/data_stream/cluster/manifest.yml` |
| hadoop | datanode | http/metrics | `packages/hadoop/data_stream/datanode/manifest.yml` |
| hadoop | namenode | http/metrics | `packages/hadoop/data_stream/namenode/manifest.yml` |
| hadoop | node_manager | http/metrics | `packages/hadoop/data_stream/node_manager/manifest.yml` |
| haproxy | info | haproxy/metrics | `packages/haproxy/data_stream/info/manifest.yml` |
| haproxy | log | logfile | `packages/haproxy/data_stream/log/manifest.yml` |
| haproxy | log | syslog | `packages/haproxy/data_stream/log/manifest.yml, packages/haproxy/data_stream/log/agent/stream/syslog.yml.hbs` |
| haproxy | stat | haproxy/metrics | `packages/haproxy/data_stream/stat/manifest.yml` |
| ibmmq | errorlog | logfile | `packages/ibmmq/data_stream/errorlog/manifest.yml` |
| ibmmq | qmgr | prometheus/metrics | `packages/ibmmq/data_stream/qmgr/manifest.yml` |
| iis | access | logfile | `packages/iis/data_stream/access/manifest.yml` |
| iis | application_pool | iis/metrics | `packages/iis/data_stream/application_pool/manifest.yml` |
| iis | error | logfile | `packages/iis/data_stream/error/manifest.yml` |
| iis | webserver | iis/metrics | `packages/iis/data_stream/webserver/manifest.yml` |
| iis | website | iis/metrics | `packages/iis/data_stream/website/manifest.yml` |
| influxdb | advstatus | prometheus/metrics | `packages/influxdb/data_stream/advstatus/manifest.yml` |
| influxdb | status | prometheus/metrics | `packages/influxdb/data_stream/status/manifest.yml` |
| kafka | broker | kafka/metrics | `packages/kafka/data_stream/broker/manifest.yml` |
| kafka | consumer | jolokia/metrics | `packages/kafka/data_stream/consumer/manifest.yml` |
| kafka | consumergroup | kafka/metrics | `packages/kafka/data_stream/consumergroup/manifest.yml` |
| kafka | controller | jolokia/metrics | `packages/kafka/data_stream/controller/manifest.yml` |
| kafka | jvm | jolokia/metrics | `packages/kafka/data_stream/jvm/manifest.yml` |
| kafka | log | logfile | `packages/kafka/data_stream/log/manifest.yml` |
| kafka | log_manager | jolokia/metrics | `packages/kafka/data_stream/log_manager/manifest.yml` |
| kafka | network | jolokia/metrics | `packages/kafka/data_stream/network/manifest.yml` |
| kafka | partition | kafka/metrics | `packages/kafka/data_stream/partition/manifest.yml` |
| kafka | producer | jolokia/metrics | `packages/kafka/data_stream/producer/manifest.yml` |
| kafka | raft | jolokia/metrics | `packages/kafka/data_stream/raft/manifest.yml` |
| kafka | replica_manager | jolokia/metrics | `packages/kafka/data_stream/replica_manager/manifest.yml` |
| kafka | topic | jolokia/metrics | `packages/kafka/data_stream/topic/manifest.yml` |
| kafka_connect | client | jolokia/metrics | `packages/kafka_connect/data_stream/client/manifest.yml` |
| kafka_connect | connector | jolokia/metrics | `packages/kafka_connect/data_stream/connector/manifest.yml` |
| kafka_connect | task | jolokia/metrics | `packages/kafka_connect/data_stream/task/manifest.yml` |
| kafka_connect | worker | jolokia/metrics | `packages/kafka_connect/data_stream/worker/manifest.yml` |
| kafka_log | generic | kafka | `packages/kafka_log/data_stream/generic/manifest.yml, packages/kafka_log/data_stream/generic/agent/stream/kafka.yml.hbs` |
| memcached | stats | memcached/metrics | `packages/memcached/data_stream/stats/manifest.yml` |
| microsoft_sqlserver | audit | winlog | `packages/microsoft_sqlserver/data_stream/audit/manifest.yml, packages/microsoft_sqlserver/data_stream/audit/agent/stream/winlog.yml.hbs` |
| microsoft_sqlserver | availability_groups | sql/metrics | `packages/microsoft_sqlserver/data_stream/availability_groups/manifest.yml` |
| microsoft_sqlserver | log | logfile | `packages/microsoft_sqlserver/data_stream/log/manifest.yml` |
| microsoft_sqlserver | performance | sql/metrics | `packages/microsoft_sqlserver/data_stream/performance/manifest.yml` |
| microsoft_sqlserver | transaction_log | sql/metrics | `packages/microsoft_sqlserver/data_stream/transaction_log/manifest.yml` |
| mongodb | collstats | mongodb/metrics | `packages/mongodb/data_stream/collstats/manifest.yml` |
| mongodb | dbstats | mongodb/metrics | `packages/mongodb/data_stream/dbstats/manifest.yml` |
| mongodb | log | logfile | `packages/mongodb/data_stream/log/manifest.yml` |
| mongodb | metrics | mongodb/metrics | `packages/mongodb/data_stream/metrics/manifest.yml` |
| mongodb | replstatus | mongodb/metrics | `packages/mongodb/data_stream/replstatus/manifest.yml` |
| mongodb | status | mongodb/metrics | `packages/mongodb/data_stream/status/manifest.yml` |
| mongodb_atlas | alert | cel | `packages/mongodb_atlas/data_stream/alert/manifest.yml` |
| mongodb_atlas | disk | cel | `packages/mongodb_atlas/data_stream/disk/manifest.yml` |
| mongodb_atlas | hardware | cel | `packages/mongodb_atlas/data_stream/hardware/manifest.yml` |
| mongodb_atlas | mongod_audit | cel | `packages/mongodb_atlas/data_stream/mongod_audit/manifest.yml` |
| mongodb_atlas | mongod_database | cel | `packages/mongodb_atlas/data_stream/mongod_database/manifest.yml` |
| mongodb_atlas | organization | cel | `packages/mongodb_atlas/data_stream/organization/manifest.yml` |
| mongodb_atlas | process | cel | `packages/mongodb_atlas/data_stream/process/manifest.yml` |
| mongodb_atlas | project | cel | `packages/mongodb_atlas/data_stream/project/manifest.yml` |
| mysql | error | logfile | `packages/mysql/data_stream/error/manifest.yml` |
| mysql | galera_status | mysql/metrics | `packages/mysql/data_stream/galera_status/manifest.yml` |
| mysql | performance | mysql/metrics | `packages/mysql/data_stream/performance/manifest.yml` |
| mysql | replica_status | sql/metrics | `packages/mysql/data_stream/replica_status/manifest.yml` |
| mysql | slowlog | logfile | `packages/mysql/data_stream/slowlog/manifest.yml` |
| mysql | status | mysql/metrics | `packages/mysql/data_stream/status/manifest.yml` |
| nagios_xi | events | httpjson | `packages/nagios_xi/data_stream/events/manifest.yml` |
| nagios_xi | host | httpjson | `packages/nagios_xi/data_stream/host/manifest.yml` |
| nagios_xi | service | httpjson | `packages/nagios_xi/data_stream/service/manifest.yml` |
| nats | connection | nats/metrics | `packages/nats/data_stream/connection/manifest.yml` |
| nats | connections | nats/metrics | `packages/nats/data_stream/connections/manifest.yml` |
| nats | log | logfile | `packages/nats/data_stream/log/manifest.yml` |
| nats | route | nats/metrics | `packages/nats/data_stream/route/manifest.yml` |
| nats | routes | nats/metrics | `packages/nats/data_stream/routes/manifest.yml` |
| nats | stats | nats/metrics | `packages/nats/data_stream/stats/manifest.yml` |
| nats | subscriptions | nats/metrics | `packages/nats/data_stream/subscriptions/manifest.yml` |
| nginx | access | logfile | `packages/nginx/data_stream/access/manifest.yml` |
| nginx | error | logfile | `packages/nginx/data_stream/error/manifest.yml` |
| nginx | stubstatus | nginx/metrics | `packages/nginx/data_stream/stubstatus/manifest.yml` |
| nvidia_gpu | stats | prometheus/metrics | `packages/nvidia_gpu/data_stream/stats/manifest.yml` |
| o365_metrics | active_users_services_user_counts | cel | `packages/o365_metrics/data_stream/active_users_services_user_counts/manifest.yml, packages/o365_metrics/data_stream/active_users_services_user_counts/agent/stream/cel.yml.hbs` |
| o365_metrics | app_registrations | cel | `packages/o365_metrics/data_stream/app_registrations/manifest.yml, packages/o365_metrics/data_stream/app_registrations/agent/stream/cel.yml.hbs` |
| o365_metrics | entra_agent | cel | `packages/o365_metrics/data_stream/entra_agent/manifest.yml, packages/o365_metrics/data_stream/entra_agent/agent/stream/cel.yml.hbs` |
| o365_metrics | entra_alerts | cel | `packages/o365_metrics/data_stream/entra_alerts/manifest.yml, packages/o365_metrics/data_stream/entra_alerts/agent/stream/cel.yml.hbs` |
| o365_metrics | entra_features | cel | `packages/o365_metrics/data_stream/entra_features/manifest.yml, packages/o365_metrics/data_stream/entra_features/agent/stream/cel.yml.hbs` |
| o365_metrics | entra_id_users | cel | `packages/o365_metrics/data_stream/entra_id_users/manifest.yml, packages/o365_metrics/data_stream/entra_id_users/agent/stream/cel.yml.hbs` |
| o365_metrics | groups_activity_group_detail | cel | `packages/o365_metrics/data_stream/groups_activity_group_detail/manifest.yml, packages/o365_metrics/data_stream/groups_activity_group_detail/agent/stream/cel.yml.hbs` |
| o365_metrics | mailbox_usage_detail | cel | `packages/o365_metrics/data_stream/mailbox_usage_detail/manifest.yml, packages/o365_metrics/data_stream/mailbox_usage_detail/agent/stream/cel.yml.hbs` |
| o365_metrics | mailbox_usage_quota_status | cel | `packages/o365_metrics/data_stream/mailbox_usage_quota_status/manifest.yml, packages/o365_metrics/data_stream/mailbox_usage_quota_status/agent/stream/cel.yml.hbs` |
| o365_metrics | onedrive_usage_account_counts | cel | `packages/o365_metrics/data_stream/onedrive_usage_account_counts/manifest.yml, packages/o365_metrics/data_stream/onedrive_usage_account_counts/agent/stream/cel.yml.hbs` |
| o365_metrics | onedrive_usage_account_detail | cel | `packages/o365_metrics/data_stream/onedrive_usage_account_detail/manifest.yml, packages/o365_metrics/data_stream/onedrive_usage_account_detail/agent/stream/cel.yml.hbs` |
| o365_metrics | onedrive_usage_file_counts | cel | `packages/o365_metrics/data_stream/onedrive_usage_file_counts/manifest.yml, packages/o365_metrics/data_stream/onedrive_usage_file_counts/agent/stream/cel.yml.hbs` |
| o365_metrics | onedrive_usage_storage | cel | `packages/o365_metrics/data_stream/onedrive_usage_storage/manifest.yml, packages/o365_metrics/data_stream/onedrive_usage_storage/agent/stream/cel.yml.hbs` |
| o365_metrics | outlook_activity | cel | `packages/o365_metrics/data_stream/outlook_activity/manifest.yml, packages/o365_metrics/data_stream/outlook_activity/agent/stream/cel.yml.hbs` |
| o365_metrics | outlook_app_usage_version_counts | cel | `packages/o365_metrics/data_stream/outlook_app_usage_version_counts/manifest.yml, packages/o365_metrics/data_stream/outlook_app_usage_version_counts/agent/stream/cel.yml.hbs` |
| o365_metrics | service_health | cel | `packages/o365_metrics/data_stream/service_health/manifest.yml, packages/o365_metrics/data_stream/service_health/agent/stream/cel.yml.hbs` |
| o365_metrics | sharepoint_site_usage_detail | cel | `packages/o365_metrics/data_stream/sharepoint_site_usage_detail/manifest.yml, packages/o365_metrics/data_stream/sharepoint_site_usage_detail/agent/stream/cel.yml.hbs` |
| o365_metrics | sharepoint_site_usage_storage | cel | `packages/o365_metrics/data_stream/sharepoint_site_usage_storage/manifest.yml, packages/o365_metrics/data_stream/sharepoint_site_usage_storage/agent/stream/cel.yml.hbs` |
| o365_metrics | subscriptions | cel | `packages/o365_metrics/data_stream/subscriptions/manifest.yml, packages/o365_metrics/data_stream/subscriptions/agent/stream/cel.yml.hbs` |
| o365_metrics | teams_call_quality | cel | `packages/o365_metrics/data_stream/teams_call_quality/manifest.yml, packages/o365_metrics/data_stream/teams_call_quality/agent/stream/cel.yml.hbs` |
| o365_metrics | teams_device_usage_user_counts | cel | `packages/o365_metrics/data_stream/teams_device_usage_user_counts/manifest.yml, packages/o365_metrics/data_stream/teams_device_usage_user_counts/agent/stream/cel.yml.hbs` |
| o365_metrics | teams_user_activity_user_counts | cel | `packages/o365_metrics/data_stream/teams_user_activity_user_counts/manifest.yml, packages/o365_metrics/data_stream/teams_user_activity_user_counts/agent/stream/cel.yml.hbs` |
| o365_metrics | teams_user_activity_user_detail | cel | `packages/o365_metrics/data_stream/teams_user_activity_user_detail/manifest.yml, packages/o365_metrics/data_stream/teams_user_activity_user_detail/agent/stream/cel.yml.hbs` |
| o365_metrics | tenant_settings | cel | `packages/o365_metrics/data_stream/tenant_settings/manifest.yml, packages/o365_metrics/data_stream/tenant_settings/agent/stream/cel.yml.hbs` |
| o365_metrics | viva_engage_device_usage_user_counts | cel | `packages/o365_metrics/data_stream/viva_engage_device_usage_user_counts/manifest.yml, packages/o365_metrics/data_stream/viva_engage_device_usage_user_counts/agent/stream/cel.yml.hbs` |
| o365_metrics | viva_engage_groups_activity_group_detail | cel | `packages/o365_metrics/data_stream/viva_engage_groups_activity_group_detail/manifest.yml, packages/o365_metrics/data_stream/viva_engage_groups_activity_group_detail/agent/stream/cel.yml.hbs` |
| openai | audio_speeches | cel | `packages/openai/data_stream/audio_speeches/manifest.yml, packages/openai/data_stream/audio_speeches/agent/stream/cel.yml.hbs` |
| openai | audio_transcriptions | cel | `packages/openai/data_stream/audio_transcriptions/manifest.yml, packages/openai/data_stream/audio_transcriptions/agent/stream/cel.yml.hbs` |
| openai | code_interpreter_sessions | cel | `packages/openai/data_stream/code_interpreter_sessions/manifest.yml, packages/openai/data_stream/code_interpreter_sessions/agent/stream/cel.yml.hbs` |
| openai | completions | cel | `packages/openai/data_stream/completions/manifest.yml, packages/openai/data_stream/completions/agent/stream/cel.yml.hbs` |
| openai | embeddings | cel | `packages/openai/data_stream/embeddings/manifest.yml, packages/openai/data_stream/embeddings/agent/stream/cel.yml.hbs` |
| openai | images | cel | `packages/openai/data_stream/images/manifest.yml, packages/openai/data_stream/images/agent/stream/cel.yml.hbs` |
| openai | moderations | cel | `packages/openai/data_stream/moderations/manifest.yml, packages/openai/data_stream/moderations/agent/stream/cel.yml.hbs` |
| openai | vector_stores | cel | `packages/openai/data_stream/vector_stores/manifest.yml, packages/openai/data_stream/vector_stores/agent/stream/cel.yml.hbs` |
| oracle | database_audit | filestream | `packages/oracle/data_stream/database_audit/manifest.yml` |
| oracle | memory | sql/metrics | `packages/oracle/data_stream/memory/manifest.yml` |
| oracle | performance | sql/metrics | `packages/oracle/data_stream/performance/manifest.yml` |
| oracle | sysmetric | sql/metrics | `packages/oracle/data_stream/sysmetric/manifest.yml` |
| oracle | system_statistics | sql/metrics | `packages/oracle/data_stream/system_statistics/manifest.yml` |
| oracle | tablespace | sql/metrics | `packages/oracle/data_stream/tablespace/manifest.yml` |
| oracle_weblogic | access | logfile | `packages/oracle_weblogic/data_stream/access/manifest.yml` |
| oracle_weblogic | admin_server | logfile | `packages/oracle_weblogic/data_stream/admin_server/manifest.yml` |
| oracle_weblogic | deployed_application | jolokia/metrics | `packages/oracle_weblogic/data_stream/deployed_application/manifest.yml` |
| oracle_weblogic | domain | logfile | `packages/oracle_weblogic/data_stream/domain/manifest.yml` |
| oracle_weblogic | managed_server | logfile | `packages/oracle_weblogic/data_stream/managed_server/manifest.yml` |
| oracle_weblogic | threadpool | jolokia/metrics | `packages/oracle_weblogic/data_stream/threadpool/manifest.yml` |
| panw_metrics | interfaces | panw/metrics | `packages/panw_metrics/data_stream/interfaces/manifest.yml` |
| panw_metrics | routing | panw/metrics | `packages/panw_metrics/data_stream/routing/manifest.yml` |
| panw_metrics | system | panw/metrics | `packages/panw_metrics/data_stream/system/manifest.yml` |
| panw_metrics | vpn | panw/metrics | `packages/panw_metrics/data_stream/vpn/manifest.yml` |
| php_fpm | pool | httpjson | `packages/php_fpm/data_stream/pool/manifest.yml, packages/php_fpm/data_stream/pool/agent/stream/httpjson.yml.hbs` |
| php_fpm | process | httpjson | `packages/php_fpm/data_stream/process/manifest.yml, packages/php_fpm/data_stream/process/agent/stream/httpjson.yml.hbs` |
| postgresql | activity | postgresql/metrics | `packages/postgresql/data_stream/activity/manifest.yml` |
| postgresql | bgwriter | postgresql/metrics | `packages/postgresql/data_stream/bgwriter/manifest.yml` |
| postgresql | database | postgresql/metrics | `packages/postgresql/data_stream/database/manifest.yml` |
| postgresql | log | logfile | `packages/postgresql/data_stream/log/manifest.yml` |
| postgresql | statement | postgresql/metrics | `packages/postgresql/data_stream/statement/manifest.yml` |
| prometheus | collector | prometheus/metrics | `packages/prometheus/data_stream/collector/manifest.yml` |
| prometheus | query | prometheus/metrics | `packages/prometheus/data_stream/query/manifest.yml` |
| rabbitmq | connection | rabbitmq/metrics | `packages/rabbitmq/data_stream/connection/manifest.yml` |
| rabbitmq | exchange | rabbitmq/metrics | `packages/rabbitmq/data_stream/exchange/manifest.yml` |
| rabbitmq | log | logfile | `packages/rabbitmq/data_stream/log/manifest.yml` |
| rabbitmq | node | rabbitmq/metrics | `packages/rabbitmq/data_stream/node/manifest.yml` |
| rabbitmq | queue | rabbitmq/metrics | `packages/rabbitmq/data_stream/queue/manifest.yml` |
| redis | info | redis/metrics | `packages/redis/data_stream/info/manifest.yml` |
| redis | key | redis/metrics | `packages/redis/data_stream/key/manifest.yml` |
| redis | keyspace | redis/metrics | `packages/redis/data_stream/keyspace/manifest.yml` |
| redis | log | logfile | `packages/redis/data_stream/log/manifest.yml` |
| redis | slowlog | redis | `packages/redis/data_stream/slowlog/manifest.yml` |
| redisenterprise | node | prometheus/metrics | `packages/redisenterprise/data_stream/node/manifest.yml` |
| redisenterprise | proxy | prometheus/metrics | `packages/redisenterprise/data_stream/proxy/manifest.yml` |
| rubrik | drives | cel | `packages/rubrik/data_stream/drives/manifest.yml, packages/rubrik/data_stream/drives/agent/stream/cel.yml.hbs` |
| rubrik | filesets | cel | `packages/rubrik/data_stream/filesets/manifest.yml, packages/rubrik/data_stream/filesets/agent/stream/cel.yml.hbs` |
| rubrik | global_cluster_performance | cel | `packages/rubrik/data_stream/global_cluster_performance/manifest.yml, packages/rubrik/data_stream/global_cluster_performance/agent/stream/cel.yml.hbs` |
| rubrik | managed_volumes | cel | `packages/rubrik/data_stream/managed_volumes/manifest.yml, packages/rubrik/data_stream/managed_volumes/agent/stream/cel.yml.hbs` |
| rubrik | monitoring_jobs | cel | `packages/rubrik/data_stream/monitoring_jobs/manifest.yml, packages/rubrik/data_stream/monitoring_jobs/agent/stream/cel.yml.hbs` |
| rubrik | mssql_databases | cel | `packages/rubrik/data_stream/mssql_databases/manifest.yml, packages/rubrik/data_stream/mssql_databases/agent/stream/cel.yml.hbs` |
| rubrik | node_statistics | cel | `packages/rubrik/data_stream/node_statistics/manifest.yml, packages/rubrik/data_stream/node_statistics/agent/stream/cel.yml.hbs` |
| rubrik | physical_hosts | cel | `packages/rubrik/data_stream/physical_hosts/manifest.yml, packages/rubrik/data_stream/physical_hosts/agent/stream/cel.yml.hbs` |
| rubrik | sla_domains | cel | `packages/rubrik/data_stream/sla_domains/manifest.yml, packages/rubrik/data_stream/sla_domains/agent/stream/cel.yml.hbs` |
| rubrik | tasks | cel | `packages/rubrik/data_stream/tasks/manifest.yml, packages/rubrik/data_stream/tasks/agent/stream/cel.yml.hbs` |
| rubrik | unmanaged_objects | cel | `packages/rubrik/data_stream/unmanaged_objects/manifest.yml, packages/rubrik/data_stream/unmanaged_objects/agent/stream/cel.yml.hbs` |
| rubrik | virtual_machines | cel | `packages/rubrik/data_stream/virtual_machines/manifest.yml, packages/rubrik/data_stream/virtual_machines/agent/stream/cel.yml.hbs` |
| salesforce | apex | salesforce | `packages/salesforce/data_stream/apex/manifest.yml, packages/salesforce/data_stream/apex/agent/stream/salesforce.yml.hbs` |
| salesforce | login | salesforce | `packages/salesforce/data_stream/login/manifest.yml, packages/salesforce/data_stream/login/agent/stream/salesforce.yml.hbs` |
| salesforce | logout | salesforce | `packages/salesforce/data_stream/logout/manifest.yml, packages/salesforce/data_stream/logout/agent/stream/salesforce.yml.hbs` |
| salesforce | setupaudittrail | salesforce | `packages/salesforce/data_stream/setupaudittrail/manifest.yml, packages/salesforce/data_stream/setupaudittrail/agent/stream/salesforce.yml.hbs` |
| spring_boot | audit_events | httpjson | `packages/spring_boot/data_stream/audit_events/manifest.yml` |
| spring_boot | gc | jolokia/metrics | `packages/spring_boot/data_stream/gc/manifest.yml` |
| spring_boot | http_trace | httpjson | `packages/spring_boot/data_stream/http_trace/manifest.yml` |
| spring_boot | memory | jolokia/metrics | `packages/spring_boot/data_stream/memory/manifest.yml` |
| spring_boot | threading | jolokia/metrics | `packages/spring_boot/data_stream/threading/manifest.yml` |
| stan | channels | stan/metrics | `packages/stan/data_stream/channels/manifest.yml` |
| stan | log | logfile | `packages/stan/data_stream/log/manifest.yml` |
| stan | stats | stan/metrics | `packages/stan/data_stream/stats/manifest.yml` |
| stan | subscriptions | stan/metrics | `packages/stan/data_stream/subscriptions/manifest.yml` |
| system | core | system/metrics | `packages/system/data_stream/core/manifest.yml` |
| system | cpu | system/metrics | `packages/system/data_stream/cpu/manifest.yml` |
| system | diskio | system/metrics | `packages/system/data_stream/diskio/manifest.yml` |
| system | filesystem | system/metrics | `packages/system/data_stream/filesystem/manifest.yml` |
| system | fsstat | system/metrics | `packages/system/data_stream/fsstat/manifest.yml` |
| system | load | system/metrics | `packages/system/data_stream/load/manifest.yml` |
| system | memory | system/metrics | `packages/system/data_stream/memory/manifest.yml` |
| system | network | system/metrics | `packages/system/data_stream/network/manifest.yml` |
| system | ntp | system/metrics | `packages/system/data_stream/ntp/manifest.yml` |
| system | process | system/metrics | `packages/system/data_stream/process/manifest.yml` |
| system | process_summary | system/metrics | `packages/system/data_stream/process_summary/manifest.yml` |
| system | socket_summary | system/metrics | `packages/system/data_stream/socket_summary/manifest.yml` |
| system | syslog | logfile | `packages/system/data_stream/syslog/manifest.yml` |
| system | syslog | journald | `packages/system/data_stream/syslog/manifest.yml, packages/system/data_stream/syslog/agent/stream/journald.yml.hbs` |
| system | system | winlog | `packages/system/data_stream/system/manifest.yml, packages/system/data_stream/system/agent/stream/winlog.yml.hbs` |
| system | uptime | system/metrics | `packages/system/data_stream/uptime/manifest.yml` |
| tomcat | log | udp | `packages/tomcat/data_stream/log/manifest.yml, packages/tomcat/data_stream/log/agent/stream/udp.yml.hbs` |
| tomcat | log | tcp | `packages/tomcat/data_stream/log/manifest.yml, packages/tomcat/data_stream/log/agent/stream/tcp.yml.hbs` |
| tomcat | log | logfile | `packages/tomcat/data_stream/log/manifest.yml` |
| traefik | access | logfile | `packages/traefik/data_stream/access/manifest.yml` |
| traefik | health | traefik/metrics | `packages/traefik/data_stream/health/manifest.yml` |
| vsphere | cluster | vsphere/metrics | `packages/vsphere/data_stream/cluster/manifest.yml` |
| vsphere | datastore | vsphere/metrics | `packages/vsphere/data_stream/datastore/manifest.yml` |
| vsphere | datastorecluster | vsphere/metrics | `packages/vsphere/data_stream/datastorecluster/manifest.yml` |
| vsphere | host | vsphere/metrics | `packages/vsphere/data_stream/host/manifest.yml` |
| vsphere | log | udp | `packages/vsphere/data_stream/log/manifest.yml` |
| vsphere | log | tcp | `packages/vsphere/data_stream/log/manifest.yml` |
| vsphere | network | vsphere/metrics | `packages/vsphere/data_stream/network/manifest.yml` |
| vsphere | resourcepool | vsphere/metrics | `packages/vsphere/data_stream/resourcepool/manifest.yml` |
| vsphere | virtualmachine | vsphere/metrics | `packages/vsphere/data_stream/virtualmachine/manifest.yml` |
| websphere_application_server | jdbc | prometheus/metrics | `packages/websphere_application_server/data_stream/jdbc/manifest.yml` |
| websphere_application_server | servlet | prometheus/metrics | `packages/websphere_application_server/data_stream/servlet/manifest.yml` |
| websphere_application_server | session_manager | prometheus/metrics | `packages/websphere_application_server/data_stream/session_manager/manifest.yml` |
| websphere_application_server | threadpool | prometheus/metrics | `packages/websphere_application_server/data_stream/threadpool/manifest.yml` |
| zookeeper | connection | zookeeper/metrics | `packages/zookeeper/data_stream/connection/manifest.yml` |
| zookeeper | mntr | zookeeper/metrics | `packages/zookeeper/data_stream/mntr/manifest.yml` |
| zookeeper | server | zookeeper/metrics | `packages/zookeeper/data_stream/server/manifest.yml` |

*Total rows: 344*
