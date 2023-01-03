# Airflow Integration

This integration collects metrics from [Airflow](https://airflow.apache.org/docs/apache-airflow/stable/logging-monitoring/metrics.html) running a
statsd server where airflow will send metrics to. The default metricset is `statsd`.

## Compatibility

The Airflow module is tested with Airflow 2.4.0. It should work with version
2.0.0 and later.

### statsd
statsd datastream retrieves the Airflow metrics using Statsd.
The Airflow integration requires [Statsd](https://www.elastic.co/guide/en/beats/metricbeat/master/metricbeat-module-airflow.html) to receive Statsd metrics. Refer to the link for instructions about how to use Statsd.

Add the following lines to your Airflow configuration file e.g. `airflow.cfg` ensuring `statsd_prefix` is left empty and replace `%HOST%` with the address agent is running:

```
[metrics]
statsd_on = True
statsd_host = %HOST%
statsd_port = 8125
statsd_prefix =
```
**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| airflow.\*.count | Airflow counters | object |
| airflow.\*.max | Airflow max timers metric | object |
| airflow.\*.mean | Airflow mean timers metric | object |
| airflow.\*.mean_rate | Airflow mean rate timers metric | object |
| airflow.\*.median | Airflow median timers metric | object |
| airflow.\*.min | Airflow min timers metric | object |
| airflow.\*.stddev | Airflow standard deviation timers metric | object |
| airflow.\*.value | Airflow gauges | object |
| airflow.dag_file | Airflow dag file metadata | keyword |
| airflow.dag_id | Airflow dag id metadata | keyword |
| airflow.job_name | Airflow job name metadata | keyword |
| airflow.operator_name | Airflow operator name metadata | keyword |
| airflow.pool_name | Airflow pool name metadata | keyword |
| airflow.status | Airflow status metadata | keyword |
| airflow.task_id | Airflow task id metadata | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Service address | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


