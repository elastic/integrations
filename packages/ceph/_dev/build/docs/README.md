# Ceph Integration

## Overview

[Ceph](https://ceph.com/en/) is a framework for distributed storage clusters. The frontend client framework is based on RADOS (Reliable Autonomic Distributed Object Store). Clients can directly access Ceph storage clusters with librados, but also can use RADOSGW (object storage), RBD (block storage), and CephFS (file storage). The backend server framework consists of several daemons that manage nodes, and backend object stores to store user's actual data.

Use the Ceph integration to:

- Collect metrics related to the cluster health and Object Storage Daemons (OSD) performance.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The Ceph integration collects metrics data.

Metrics give you insight into the statistics of the Ceph. The Metric data streams collected by the Ceph integration are `cluster_health` and `osd_performance`, so that the user can monitor and troubleshoot the performance of the Ceph instance.

Data stream:
- `cluster_health`: Represents information related to the health of the cluster.
- `osd_performance`: Tracks Object Storage Daemons (OSD) performance.

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

## Metrics reference

### Cluster Health

This is the `cluster_health` data stream. This data stream collects metrics related to the cluster health.

{{event "cluster_health"}}

{{fields "cluster_health"}}

### OSD Performance

This is the `osd_performance` data stream. This data stream collects metrics related to Object Storage Daemon (OSD) id, commit latency and apply latency.

{{event "osd_performance"}}

{{fields "osd_performance"}}
