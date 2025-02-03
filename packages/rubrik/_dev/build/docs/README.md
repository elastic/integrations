# Rubrik RSC Metrics Integration

This integration periodically fetches metrics from [Rubrik GraphQL API](https://www.rubrik.com/resources/api-integration). It collects a wide range of metrics including virtual machines, filesets, volumes, node statistics, and drives performance.

These metrics help you understand how to properly manage your Rubrik infrastructure.

## Compatibility

The integration uses the [HTTP JSON input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-httpjson.html) to collect metrics from Rubrik APIs.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Configuration

To configure this integration in Elastic, you need the following information:

- Hostname
- Client ID
- Client Secret
- Token URL

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