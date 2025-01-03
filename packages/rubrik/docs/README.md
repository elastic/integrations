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

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| rubrik.managed_volumes.free_size.bytes | Free capacity for the volume across all the channels, in bytes. | long | byte | gauge |
| rubrik.managed_volumes.name | The name of the Managed Volume. | keyword |  |  |
| rubrik.managed_volumes.num_channels.count | Number of channels to divide the volume into. Each channel provides a unique share to write to. | long |  | gauge |
| rubrik.managed_volumes.pending_snapshots.count | The total number of snapshots present for the workload. | long |  | gauge |
| rubrik.managed_volumes.state | State of managed volume. | keyword |  |  |
| rubrik.managed_volumes.total_snapshots.count | The total number of snapshots present for the workload. | long |  | gauge |
| rubrik.managed_volumes.used_size.bytes | Used capacity for the volume across all the channels, in bytes. | long | byte | gauge |
| rubrik.managed_volumes.volume_size.bytes | Maximum capacity for the volume across all the channels, in bytes. | long | byte | gauge |
