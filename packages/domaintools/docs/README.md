# DomainTools Real Time Unified Feeds

The DomainTools Real Time Unified Feeds integration allows you to monitor DomainTools Newly Observed Domains. 
The DomainTools NOD Feed provides real-time access to newly registered and observed domains, enabling proactive threat detection and defense. 

With over 300,000 new domains observed daily, the feed empowers security teams to identify and block potentially malicious domains before they can be weaponized. 
Ideal for threat hunting, phishing prevention, and brand protection, the NOD Feed delivers unparalleled visibility into emerging domain activity to stay ahead of evolving threats.

For example, if you wanted to monitor Newly Observed Domains (NOD) feed, you could ingest the DomainTools NOD feed. 
Then you can reference domaintools.nod_feed when using visualizations or alerts.

## Data streams

The DomainTools Real Time Unified Feeds integration collects one type of data streams: logs

Log data streams collected by the DomainTools integration include the Newly Observed Domains (NOD) feed: Apex-level domains (e.g. Example Domain  but not www.example.com) that we observe for the first time, and have not observed previously. 
Populated with our global DNS sensor network.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. 
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You will require a license to one or more DomainTools feeds, and API credentials. 
Your required API credentials will vary with your authentication method, detailed below. 

Obtain your API credentials from your group’s API administrator. 
API administrators can manage their API keys at research.domaintools.com, selecting the drop-down account menu and choosing API admin.

## Setup

For step-by-step instructions on how to set up an integration, see the Getting started guide.

### Newly Observed Domains (NOD) Feed 

The `nod_feed` data stream provides events from [DomainTools Newly Observed Domains Feed](https://www.domaintools.com/products/threat-intelligence-feeds/).

**Exported fields**

| Field                 | Description                                                                  | Type             |
|-----------------------|------------------------------------------------------------------------------|------------------|
| @timestamp            | Event timestamp.                                                             | date             |
| data_stream.dataset   | Data stream dataset name.                                                    | constant_keyword |
| data_stream.namespace | Data stream namespace.                                                       | constant_keyword |
| data_stream.type      | Data stream type.                                                            | constant_keyword |
| host.containerized    | If the host is a container.                                                  | boolean          |
| host.os.build         | OS build information.                                                        | keyword          |
| host.os.codename      | OS codename, if any.                                                         | keyword          |
| input.type            | Type of Filebeat input.                                                      | keyword          |
| domaintools.domain    | The domain. For example "domaintools.com".                                   | keyword          |
| domaintools.timestamp | The timestamp the domain was discovered. For example "2024-12-03T16:20:34Z". | date             |
| message               | The feed raw value. For example "{\"domain\":\"fortworthvirtualrealitytherapy.info\",\"timestamp\":\"2024-12-03T16:20:34Z\"}".                      | keyword          |

An example event for `nod_feed` looks as following:

```json
{
  "_index": ".ds-logs-domaintools.nod_feed-default-2024.12.02-000001",
  "_id": "dfFSjZMBwzELzoTu7QqQ",
  "_version": 1,
  "_score": 0,
  "_source": {
    "input": {
      "type": "httpjson"
    },
    "agent": {
      "name": "docker-fleet-agent",
      "id": "c6ba320f-f527-4328-b052-af726240a90d",
      "type": "filebeat",
      "ephemeral_id": "df14ede3-b6ef-4212-8f3b-8bc2ef01f2ec",
      "version": "8.12.2"
    },
    "@timestamp": "2024-12-03T16:20:41.407Z",
    "ecs": {
      "version": "8.0.0"
    },
    "data_stream": {
      "namespace": "default",
      "type": "logs",
      "dataset": "domaintools.nod_feed"
    },
    "host": {
      "hostname": "docker-fleet-agent",
      "os": {
        "kernel": "6.10.11-linuxkit",
        "codename": "focal",
        "name": "Ubuntu",
        "type": "linux",
        "family": "debian",
        "version": "20.04.6 LTS (Focal Fossa)",
        "platform": "ubuntu"
      },
      "containerized": false,
      "ip": [
        "172.19.0.7"
      ],
      "name": "docker-fleet-agent",
      "id": "29b44b57f32c4ff282841a8a4406ef95",
      "mac": [
        "02-42-AC-13-00-07"
      ],
      "architecture": "aarch64"
    },
    "elastic_agent": {
      "id": "c6ba320f-f527-4328-b052-af726240a90d",
      "version": "8.12.2",
      "snapshot": false
    },
    "domaintools": {
      "domain": "fortworthvirtualrealitytherapy.info",
      "timestamp": "2024-12-03T16:20:34Z"
    },
    "event": {
      "agent_id_status": "verified",
      "ingested": "2024-12-03T16:20:42Z",
      "created": "2024-12-03T16:20:41.407Z",
      "dataset": "domaintools.nod_feed"
    },
    "message": "{\"domain\":\"fortworthvirtualrealitytherapy.info\",\"timestamp\":\"2024-12-03T16:20:34Z\"}"
  },
  "fields": {
    "domaintools.domain": [
      "fortworthvirtualrealitytherapy.info"
    ],
    "elastic_agent.version": [
      "8.12.2"
    ],
    "host.hostname": [
      "docker-fleet-agent"
    ],
    "host.mac": [
      "02-42-AC-13-00-07"
    ],
    "host.ip": [
      "172.19.0.7"
    ],
    "agent.type": [
      "filebeat"
    ],
    "host.os.version": [
      "20.04.6 LTS (Focal Fossa)"
    ],
    "host.os.kernel": [
      "6.10.11-linuxkit"
    ],
    "domaintools.timestamp": [
      "2024-12-03T16:20:34Z"
    ],
    "host.os.name": [
      "Ubuntu"
    ],
    "agent.name": [
      "docker-fleet-agent"
    ],
    "elastic_agent.snapshot": [
      false
    ],
    "host.name": [
      "docker-fleet-agent"
    ],
    "event.agent_id_status": [
      "verified"
    ],
    "host.id": [
      "29b44b57f32c4ff282841a8a4406ef95"
    ],
    "host.os.type": [
      "linux"
    ],
    "elastic_agent.id": [
      "c6ba320f-f527-4328-b052-af726240a90d"
    ],
    "data_stream.namespace": [
      "default"
    ],
    "host.os.codename": [
      "focal"
    ],
    "input.type": [
      "httpjson"
    ],
    "message": [
      "{\"domain\":\"fortworthvirtualrealitytherapy.info\",\"timestamp\":\"2024-12-03T16:20:34Z\"}"
    ],
    "data_stream.type": [
      "logs"
    ],
    "host.architecture": [
      "aarch64"
    ],
    "event.ingested": [
      "2024-12-03T16:20:42.000Z"
    ],
    "@timestamp": [
      "2024-12-03T16:20:41.407Z"
    ],
    "agent.id": [
      "c6ba320f-f527-4328-b052-af726240a90d"
    ],
    "ecs.version": [
      "8.0.0"
    ],
    "host.containerized": [
      false
    ],
    "host.os.platform": [
      "ubuntu"
    ],
    "data_stream.dataset": [
      "domaintools.nod_feed"
    ],
    "event.created": [
      "2024-12-03T16:20:41.407Z"
    ],
    "agent.ephemeral_id": [
      "df14ede3-b6ef-4212-8f3b-8bc2ef01f2ec"
    ],
    "agent.version": [
      "8.12.2"
    ],
    "host.os.family": [
      "debian"
    ],
    "event.dataset": [
      "domaintools.nod_feed"
    ]
  }
}
```

