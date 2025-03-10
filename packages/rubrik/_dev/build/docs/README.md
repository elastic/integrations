# Rubrik RSC Metrics Integration

This integration periodically collects health and performance metrics from Rubrik Security Cloud and Rubrik cluster hosts using the [Rubrik APIs](https://www.rubrik.com/resources/api-integration). It leverages the [CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html) to retrieve data from both REST and GraphQL endpoints, ensuring comprehensive data coverage.

## Compatibility
This integration has been tested to be compatible with:
- Rubrik Security Cloud(RSC)
- Rubrik CDM 6.0x API
- Rubrik CDM 9.1x API

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Configuration

To configure this integration in Elastic, you need the following information:

 - **Hostname** is the account name of your Rubrik domain.
 - **Client ID** is the client ID of the service account.
 - **Client Secret** is the client secret of the service account.
 - **Cluster UUID** is the ID of the registered Rubrik cluster.
 - **Cluster IP** is the Rubrik cluster IP or a resolvable host name.

NOTE: Cluster IP and Cluster UUID are required to access the Rubrik REST APIs. 

For more details on these settings, refer to the [Rubrik official documentation](https://docs.rubrik.com/en-us/saas/saas/adding_a_service_account.html).

### Enabling the integration in Elastic

1. In Kibana, navigate to **Management > Integrations**
2. In the "Search for integrations" search bar, type **Rubrik**
3. Click on "Rubrik RSC Metrics" integration from the search results
4. Click on the **Add Rubrik RSC Metrics Integration** button to add the integration

## Metrics

### Managed Volumes

The `managed_volumes` dataset provides metrics related to the health and status of managed volumes.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "managed_volumes"}}

{{event "managed_volumes"}}

### Monitoring Jobs

The `monitoring_jobs` dataset provides metrics related to the series of activities on either the RSC or a Rubrik cluster.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "monitoring_jobs"}}

{{event "monitoring_jobs"}}

### Virtual Machines

The `virtualmachines` dataset provides metrics related to the state of the virtual machines.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "virtual_machines"}}

{{event "virtual_machines"}}

### Filesets

The `filesets` dataset provides metrics related to the state of the filesets.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "filesets"}}

{{event "filesets"}}

### Drives

The `drives` dataset provides metrics related to the state of the drives.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "drives"}}

{{event "drives"}}

### Physical Hosts

The `physical_hosts` dataset provides metrics related to the state of the physical hosts.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "physical_hosts"}}

{{event "physical_hosts"}}

### MSSQL Databases

The `mssql_databases` dataset provides metrics related to the state of the MSSQL databases.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "mssql_databases"}}

{{event "mssql_databases"}}

### Tasks

The `tasks` dataset provides metrics related to the state of Rubrik backup and object protection tasks by SLA Domain.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "tasks"}}

{{event "tasks"}}

### Global Cluster Performance

The `global_cluster_performance` dataset provides performance related metrics like IOPS, throughput, storage utilization, storage details, streams, and physical ingest of Rubrik Clusters.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "global_cluster_performance"}}

{{event "global_cluster_performance"}}

### Node Statistics

The `node_statistics` dataset provides metrics related to the performance of the Rubrik cluster nodes.

**IMPORTANT: Setting `interval` to more than `1h` may cause documents to be dropped if node statistics metrics fall outside the index time range.**

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "node_statistics"}}

{{event "node_statistics"}}

### Unmanaged Objects

The `unmanaged_objects` dataset provides unmanaged object snapshot and storage metrics.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "unmanaged_objects"}}

{{event "unmanaged_objects"}}

### SLA Domains

The `sla_domains` dataset captures key metrics and configurations of Service Level Agreement (SLA) policy domains in a Rubrik environment, including details on the number of protected objects, such as virtual machines, databases, filesets, and hosts.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "sla_domains"}}

{{event "sla_domains"}}