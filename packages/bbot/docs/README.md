# BBOT integration

The Bighuge BLS OSINT Tool (BBOT) integration is intended for [BBOT](https://www.blacklanternsecurity.com/bbot/) installations, an Attack Surface Management (ASM) Open Source Inteligence (OSINT) Tool.

Once the BBOT scan is complete, the integration will ingest the results into Elastic.

This tool is used to enhance your external knowledge of your environment. This is done through the integration of many tools into BBOT providing a overview of your attack surface. Here is [how it works](https://www.blacklanternsecurity.com/bbot/Stable/how_it_works/).

**Important Note** - You will have to provide the following parameter in your BBOT scan for your output.ndjson to be formatted correctly.
```
-c output_modules.json.siem_friendly=true
```
**Example BBOT Scan**
```
bbot -t elastic.co --strict-scope -f safe passive -c output_modules.json.siem_friendly=true -om json
```

You will have to configure the path for the output file within the integration settings. A common and popular path that could work here is:

**Example BBOT Path**
```
/home/<user>/.bbot/scans/*/output.ndjson
```

BBOT Scanning [Documentation](https://www.blacklanternsecurity.com/bbot/scanning/).

## Data streams

This integration collects the following logs:

- **asm_intel** Made up of the findings found in the BBOT Scans.

## Requirements

Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the  [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).


### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `BBOT`.
3. Select the "BBOT" integration from the search results.
4. Select "Add BBOT" to add the integration.
5. Add all the required integration configuration parameters including the Path to ndjson output file.
6. Save the integration.

## Logs

### ASM Findings

An example event for `asm_intel` looks as following:

```json
{
    "@timestamp": "2024-02-29T01:41:47.779Z",
    "agent": {
        "ephemeral_id": "8ff8221f-4846-4f02-b12b-773332430bab",
        "id": "bcb4b946-41b8-4916-9308-849b3bf23f46",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
    },
    "bbot": {
        "id": "DNS_NAME:f57ba0828becd7bf94faa616db081ed06f31bd3d",
        "module": "TARGET",
        "module_sequence": "TARGET",
        "scan": "SCAN:725368977d3a680e579707504e59428a7e3acc9d",
        "scope_distance": 0,
        "source": "SCAN:725368977d3a680e579707504e59428a7e3acc9d",
        "tags": [
            "resolved",
            "a-record",
            "target",
            "in-scope",
            "subdomain"
        ],
        "type": "DNS_NAME"
    },
    "data_stream": {
        "dataset": "bbot.asm_intel",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "bcb4b946-41b8-4916-9308-849b3bf23f46",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "bbot.asm_intel",
        "ingested": "2024-04-22T19:10:49Z",
        "kind": "asset"
    },
    "host": {
        "name": "example.com"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/log.log"
        },
        "offset": 398
    },
    "message": "{\"type\": \"DNS_NAME\", \"id\": \"DNS_NAME:f57ba0828becd7bf94faa616db081ed06f31bd3d\", \"data\": {\"DNS_NAME\": \"example.com\"}, \"scope_distance\": 0, \"scan\": \"SCAN:725368977d3a680e579707504e59428a7e3acc9d\", \"timestamp\": 1709170907.779394, \"resolved_hosts\": [\"123.123.123.123\"], \"source\": \"SCAN:725368977d3a680e579707504e59428a7e3acc9d\", \"tags\": [\"resolved\", \"a-record\", \"target\", \"in-scope\", \"subdomain\"], \"module\": \"TARGET\", \"module_sequence\": \"TARGET\"}",
    "related": {
        "hosts": [
            "123.123.123.123"
        ]
    },
    "tags": [
        "forwarded",
        "bbot"
    ],
    "url": {
        "domain": [
            "example.com"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| bbot.data.asn.asn | Autonomous system number. | keyword |
| bbot.data.asn.country | ASN country. | keyword |
| bbot.data.asn.description | Description of the asn. | keyword |
| bbot.data.asn.name | Name discovered for the asn. | keyword |
| bbot.data.asn.subnet | Subnet discovered for the asn. | keyword |
| bbot.data.azure_tenant.domains | Domain of the azure tenant. | keyword |
| bbot.data.azure_tenant.tenant-id | ID of the azure tenant. | keyword |
| bbot.data.azure_tenant.tenant-names | Associated names of the azure tenants discovered. | keyword |
| bbot.data.code_repository.url | URL of the code repository. | keyword |
| bbot.data.dns_name | DNS name found. | keyword |
| bbot.data.email_address | Email address found. | keyword |
| bbot.data.finding.description | Description of the finding. | keyword |
| bbot.data.finding.host | Host finding was discovered on. | keyword |
| bbot.data.finding.url | URL finding was discovered on. | keyword |
| bbot.data.open_tcp_port | Open tcp port discovered. | keyword |
| bbot.data.org_stub | The org stub. | keyword |
| bbot.data.protocol.banner | Banner related findings. | keyword |
| bbot.data.protocol.host | Host related to protocol. | keyword |
| bbot.data.protocol.port | Port of the protocol. | integer |
| bbot.data.protocol.protocol | The protocol. | keyword |
| bbot.data.scan | Name of the scan. | keyword |
| bbot.data.social.platform | Social platform discovered. | keyword |
| bbot.data.social.profile_name | Social platform username. | keyword |
| bbot.data.social.url | URL of the social finding. | keyword |
| bbot.data.storage_bucket.name | Name of the storage bucket. | keyword |
| bbot.data.storage_bucket.url | URL of the storage bucket. | keyword |
| bbot.data.technology.host | Host where technology was discovered. | keyword |
| bbot.data.technology.technology | Technology that was discovered. | keyword |
| bbot.data.technology.url | URL of the discovered technology. | keyword |
| bbot.data.url | URL of the data finding. | keyword |
| bbot.data.vulnerability.description | Description of the vulnerabiltiy. | keyword |
| bbot.data.vulnerability.host | Host vulnerability was discovered on. | keyword |
| bbot.data.vulnerability.url | URL of the vulnerability. | keyword |
| bbot.data.waf.host | Host of the WAF. | keyword |
| bbot.data.waf.info | WAF information. | keyword |
| bbot.data.waf.url | URL of the WAF. | keyword |
| bbot.data.waf.waf | WAF data. | keyword |
| bbot.data.webscreenshot.filename | Name of the webscreenshot file. | keyword |
| bbot.data.webscreenshot.url | URL of the webscreenshot. | keyword |
| bbot.id | Unique id for each finding. | keyword |
| bbot.module | Module that discovered the finding. | keyword |
| bbot.module_sequence | Module sequence that discovered the finding. | keyword |
| bbot.resolved_hosts | Large list of hosts discovered per finding, this field can hold numerous values. | keyword |
| bbot.scan | Scan document, this finding is it's own document and contains data about the scan. | keyword |
| bbot.scope_distance | Scope distance of the scan. this is set at runtime of bbot. | integer |
| bbot.source |  | keyword |
| bbot.tags |  | keyword |
| bbot.timestamp |  | date |
| bbot.type |  | keyword |
| bbot.web_spider_distance | How far the web spider crawled to discover the finding. | integer |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |

