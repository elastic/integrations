# Ceph Integration

## Overview

[Ceph](https://ceph.com/en/) is a framework for distributed storage clusters. The frontend client framework is based on RADOS (Reliable Autonomic Distributed Object Store). Clients can directly access Ceph storage clusters with librados, but also can use RADOSGW (object storage), RBD (block storage), and CephFS (file storage). The backend server framework consists of several daemons that manage nodes, and backend object stores to store user's actual data.

Use the Ceph integration to:

- Collect metrics related to the Object Storage Daemons (OSD) tree.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Create alerts to reduce the MTTD and also the MTTR by referencing relevant logs when troubleshooting an issue.

## Data streams

The Ceph integration collects metrics data.

Metrics give you insight into the statistics of the Ceph. The Metric data streams collected by the Ceph integration is `osd_tree`, so that the user can monitor and troubleshoot the performance of the Ceph instance.

Data streams:
- `osd_tree`: Represents information related to structure of the Object Storage Daemons (OSD) tree.

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

### OSD Tree

This is the `osd_tree` data stream. This data stream collects metrics related to Object Storage Daemon (OSD) tree id, name, status, exists, crush_weight, etc.

An example event for `osd_tree` looks as following:

```json
{
    "@timestamp": "2023-01-18T04:38:53.962Z",
    "agent": {
        "ephemeral_id": "b45696a1-ed6f-484c-9343-db852a78f62b",
        "id": "2815400b-70e0-4c6f-99c0-c235ba2af74a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.1"
    },
    "ceph": {
        "osd_tree": {
            "crush_weight": 0.0194854736328125,
            "depth": 2,
            "device_class": "hdd",
            "exists": true,
            "id": 0,
            "name": "osd.0",
            "primary_affinity": {
                "count": 1
            },
            "reweight": 1,
            "status": "up",
            "type": {
                "id": 0,
                "name": "osd"
            }
        }
    },
    "data_stream": {
        "dataset": "ceph.osd_tree",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "2815400b-70e0-4c6f-99c0-c235ba2af74a",
        "snapshot": false,
        "version": "8.5.1"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-01-18T04:38:53.962Z",
        "dataset": "ceph.osd_tree",
        "ingested": "2023-01-18T04:38:55Z",
        "kind": "metric",
        "module": "ceph",
        "original": "{\"crush_weight\":0.0194854736328125,\"depth\":2,\"device_class\":\"hdd\",\"exists\":1,\"id\":0,\"name\":\"osd.0\",\"pool_weights\":{},\"primary_affinity\":1,\"reweight\":1,\"status\":\"up\",\"type\":\"osd\",\"type_id\":0}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "service": {
        "address": "http://elastic-package-service_ceph_1:8080"
    },
    "tags": [
        "preserve_original_event",
        "ceph-osd_tree",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| ceph.osd_tree.children | Bucket children list, separated by a comma. | keyword |  |
| ceph.osd_tree.crush_weight | CRUSH buckets reflect the sum of the weights of the buckets or the devices they contain. For example, a rack containing a two hosts with two OSDs each, might have a weight of 4.0 and each host a weight of 2.0. The sum for each OSD, where the weight per OSD is 1.00. | float | gauge |
| ceph.osd_tree.depth | Depth of OSD node. | long |  |
| ceph.osd_tree.device_class | The device class of OSD. i.e. hdd, ssd etc. | keyword |  |
| ceph.osd_tree.exists | Represent OSD node still exist or not (1-true, 0-false). | boolean |  |
| ceph.osd_tree.id | OSD or bucket node id. | long |  |
| ceph.osd_tree.name | OSD or bucket node name. | keyword |  |
| ceph.osd_tree.primary_affinity.count | The weight of reading data from primary OSD. | float | gauge |
| ceph.osd_tree.reweight | OSD reweight sets an override weight on the OSD. This value is in the range 0 to 1, and forces CRUSH to re-place (1-weight) of the data that would otherwise live on the drive. | float |  |
| ceph.osd_tree.status | Status of the OSD, it should be up or down. | keyword |  |
| ceph.osd_tree.type.id | OSD or bucket node typeID. | long |  |
| ceph.osd_tree.type.name | OSD or bucket node type, illegal type include osd, host, root etc. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |  |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |
| input.type | Type of Filebeat input. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| tags | List of keywords used to tag each event. | keyword |  |

