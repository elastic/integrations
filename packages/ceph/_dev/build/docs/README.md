# Ceph Integration

## Overview

[Ceph](https://ceph.com/en/) is a framework for distributed storage clusters. The frontend client framework is based on RADOS (Reliable Autonomic Distributed Object Store). Clients can directly access Ceph storage clusters with librados, but also can use RADOSGW (object storage), RBD (block storage), and CephFS (file storage). The backend server framework consists of several daemons that manage nodes, and backend object stores to store user's actual data.

Use the Ceph integration to:

- Collect metrics related to the cluster disk, cluster health, cluster status, Object Storage Daemons (OSD) performance, Object Storage Daemons (OSD) pool stats, Object Storage Daemons (OSD) tree and pool disk.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The Ceph integration collects metrics data.

Metrics give you insight into the statistics of the Ceph. The Metric data streams collected by the Ceph integration are `cluster_disk`, `cluster_health`, `cluster_status`, `osd_performance`, `osd_pool_stats`, `osd_tree` and `pool_disk`, so that the user can monitor and troubleshoot the performance of the Ceph instance.

Data streams:
- `cluster_disk`: Collects information related to overall storage of the cluster.
- `cluster_health`: Collects information related to health of the cluster.
- `cluster_status`: Collects information related to status of the cluster.
- `osd_performance`: Collects information related to Object Storage Daemons (OSD) performance.
- `osd_pool_stats`: Collects information related to client I/O rates.
- `osd_tree`: Collects information related to structure of the Object Storage Daemons (OSD) tree.
- `pool_disk`: Collects information related to memory of each pool.

Note:
- Users can monitor and see the metrics inside the ingested documents for Ceph in the `logs-*` index pattern from `Discover`.

## Compatibility

This integration has been tested against Ceph `15.2.17 (Octopus)` and `14.2.22 (Nautilus)`.

In order to find out the Ceph version of your instance, see following approaches:

1. On the Ceph Dashboard, in the top right corner of the screen, go to `Help` > `About`. You can see the version of Ceph.

2. Please run the following command from Ceph instance:

```
ceph version
```

* The `ceph-rest-api` tool has been deprecated and dropped from Ceph version `Mimic` onwards. Please refer here: https://docs.ceph.com/en/latest/releases/luminous/#id32

## Prerequisites

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

In order to ingest data from the Ceph, user must have

* Enable **RESTful module**. Refer: https://docs.ceph.com/en/octopus/mgr/restful/#restful-module
* Create API keys to allow users to perform API key authentication. To create **API User** and **API Secret Key**, please refer https://docs.ceph.com/en/octopus/mgr/restful/#creating-an-api-user

## Setup
  
For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Configuration

You need the following information from your `Ceph instance` to configure this integration in Elastic:

### Ceph Hostname

Host Configuration Format: `http[s]://<ceph-mgr>:<port>`

Example Host Configuration: `https://127.0.0.1:8003`

### API User and API Secret Key

To list all of your API keys, please run the following command from Ceph instance:

```
ceph restful list-keys
```

The ceph restful list-keys command will output in JSON:
```
{
      "api": "52dffd92-a103-4a10-bfce-5b60f48f764e"
}
```
In the above JSON, please consider `api` as API User and value of `52dffd92-a103-4a10-bfce-5b60f48f764e` as API Secret Key while configuring an integration.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Ceph Integration should display a list of available dashboards. Click on the dashboard available for your configured data stream. It should be populated with the required data.

### Troubleshooting

- If `host.ip` appears conflicted under the ``logs-*`` data view, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Cluster Disk``, ``Cluster health``, ``Cluster Status``, ``OSD Performance``, ``OSD Pool Stats``, ``OSD Tree`` and ``Pool Disk`` data streams.

## Metrics reference

### Cluster Disk

This is the `cluster_disk` data stream. This data stream collects metrics related to the total storage, available storage and used storage of cluster disk.

{{event "cluster_disk"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "cluster_disk"}}

### Cluster Health

This is the `cluster_health` data stream. This data stream collects metrics related to the cluster health.

{{event "cluster_health"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "cluster_health"}}

### Cluster Status

This is the `cluster_status` data stream. This data stream collects metrics related to cluster health status, number of monitors in the cluster, cluster version, cluster placement group (pg) count, cluster osd states and cluster storage.

{{event "cluster_status"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "cluster_status"}}

### OSD Performance

This is the `osd_performance` data stream. This data stream collects metrics related to Object Storage Daemon (OSD) id, commit latency and apply latency.

{{event "osd_performance"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "osd_performance"}}

### OSD Pool Stats

This is the `osd_pool_stats` data stream. This data stream collects metrics related to Object Storage Daemon (OSD) client I/O rates.

{{event "osd_pool_stats"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "osd_pool_stats"}}

### OSD Tree

This is the `osd_tree` data stream. This data stream collects metrics related to Object Storage Daemon (OSD) tree id, name, status, exists, crush_weight, etc.

{{event "osd_tree"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "osd_tree"}}

### Pool Disk

This is the `pool_disk` data stream. This data stream collects metrics related to pool id, pool name, pool objects, used bytes and available bytes of the pool disk.

{{event "pool_disk"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "pool_disk"}}
