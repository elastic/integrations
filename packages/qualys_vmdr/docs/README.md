# Qualys Vulnerability Management, Detection and Response (VMDR)

This [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/) integration is a cloud-based service that gives you immediate, global visibility into where your IT systems might be vulnerable to the latest Internet threats and how to protect them. It helps you to continuously identify threats and monitor unexpected changes in your network before they turn into breaches.

The Qualys VMDR integration uses REST API mode to collect data. Elastic Agent fetches data via API endpoints.

## Compatibility

This module has been tested against the latest Qualys VMDR version **v2**.

## Data streams

The Qualys VMDR integration collects logs for the following two events:

| Event Type                    |
|-------------------------------|
| Asset Host Detection          |
| Knowledge Base                |

Reference for [Rest APIs](https://qualysguard.qg2.apps.qualys.com/qwebhelp/fo_portal/api_doc/index.htm) of Qualys VMDR.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.9.0**.

## Setup

### To collect data through REST API, follow the below steps:

- Considering you already have a Qualys user account, to identify your Qualys platform and get the API URL, refer this [link](https://www.qualys.com/platform-identification/).
- Alternative way to get the API URL is to log in to your Qualys account and go to Help > About. You’ll find your URL under Security Operations Center (SOC).

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Qualys VMDR
3. Click on the "Qualys VMDR" integration from the search results.
4. Click on the Add Qualys VMDR Integration button to add the integration.
5. While adding the integration, if you want to collect Asset Host Detection logs via REST API, then you have to put the following details:
   - username
   - password
   - url
   - interval
   - input parameters
   - batch size

   or if you want to collect Knowledge Base logs via REST API, then you have to put the following details:
   - username
   - password
   - url
   - initial interval
   - interval
   - input parameters

**NOTE**: By default, the input parameter is set to "action=list".

## Logs reference

### Asset Host Detection

This is the `Asset Host Detection` dataset.

#### Example

An example event for `asset_host_detection` looks as following:

```json
{
    "@timestamp": "2023-07-07T06:22:24.455Z",
    "agent": {
        "ephemeral_id": "8faa56a6-6151-40c0-9ccc-7e86663d06c2",
        "id": "3f1418ad-5463-4d9c-80cc-ace99ce34d5e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.9.0"
    },
    "data_stream": {
        "dataset": "qualys_vmdr.asset_host_detection",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.9.0"
    },
    "elastic_agent": {
        "id": "3f1418ad-5463-4d9c-80cc-ace99ce34d5e",
        "snapshot": true,
        "version": "8.9.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "qualys_vmdr.asset_host_detection",
        "ingested": "2023-07-07T06:22:27Z",
        "kind": "alert",
        "original": "{\"DETECTION_LIST\":{\"DETECTION\":[{\"FIRST_FOUND_DATETIME\":\"2023-06-28T06:04:26Z\",\"IS_DISABLED\":\"0\",\"IS_IGNORED\":\"0\",\"LAST_FOUND_DATETIME\":\"2023-07-03T06:23:47Z\",\"LAST_PROCESSED_DATETIME\":\"2023-07-03T06:25:17Z\",\"LAST_TEST_DATETIME\":\"2023-07-03T06:23:47Z\",\"LAST_UPDATE_DATETIME\":\"2023-07-03T06:25:17Z\",\"QID\":\"91680\",\"RESULTS\":\"\",\"SEVERITY\":\"5\",\"SSL\":\"0\",\"STATUS\":\"Active\",\"TIMES_FOUND\":\"11\",\"TYPE\":\"Confirmed\"}]},\"DNS\":\"\",\"DNS_DATA\":{\"DOMAIN\":\"\",\"FQDN\":\"\",\"HOSTNAME\":\"\"},\"ID\":\"12048633\",\"IP\":\"10.50.2.111\",\"LAST_PC_SCANNED_DATE\":\"2023-06-28T09:58:12Z\",\"LAST_SCAN_DATETIME\":\"2023-07-03T06:25:17Z\",\"LAST_VM_SCANNED_DATE\":\"2023-07-03T06:23:47Z\",\"LAST_VM_SCANNED_DURATION\":\"1113\",\"NETBIOS\":\"\",\"OS\":\"\",\"TRACKING_METHOD\":\"IP\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "12048633",
        "ip": [
            "10.50.2.111"
        ]
    },
    "input": {
        "type": "cel"
    },
    "qualys_vmdr": {
        "asset_host_detection": {
            "id": "12048633",
            "ip": "10.50.2.111",
            "last": {
                "pc_scanned_date": "2023-06-28T09:58:12.000Z",
                "scan_datetime": "2023-07-03T06:25:17.000Z",
                "vm": {
                    "scanned_date": "2023-07-03T06:23:47.000Z",
                    "scanned_duration": 1113
                }
            },
            "list": [
                {
                    "first_found_datetime": "2023-06-28T06:04:26.000Z",
                    "is_disabled": false,
                    "is_ignored": false,
                    "last": {
                        "found_datetime": "2023-07-03T06:23:47.000Z",
                        "processed_datetime": "2023-07-03T06:25:17.000Z",
                        "test_datetime": "2023-07-03T06:23:47.000Z",
                        "update_datetime": "2023-07-03T06:25:17.000Z"
                    },
                    "qid": "91680",
                    "severity": 5,
                    "ssl": "0",
                    "status": "Active",
                    "times_found": 11,
                    "type": "Confirmed"
                }
            ],
            "tracking_method": "IP"
        }
    },
    "related": {
        "hosts": [
            "12048633"
        ],
        "ip": [
            "10.50.2.111"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "qualys_vmdr-asset_host_detection"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| qualys_vmdr.asset_host_detection.asset_id |  | keyword |
| qualys_vmdr.asset_host_detection.cloud.provider.name |  | keyword |
| qualys_vmdr.asset_host_detection.cloud.provider.tags.cloud_tag.last_success_date |  | date |
| qualys_vmdr.asset_host_detection.cloud.provider.tags.cloud_tag.name |  | keyword |
| qualys_vmdr.asset_host_detection.cloud.provider.tags.cloud_tag.value |  | keyword |
| qualys_vmdr.asset_host_detection.cloud.resource_id |  | keyword |
| qualys_vmdr.asset_host_detection.cloud.service |  | keyword |
| qualys_vmdr.asset_host_detection.dns.value |  | keyword |
| qualys_vmdr.asset_host_detection.dns_data.domain |  | keyword |
| qualys_vmdr.asset_host_detection.dns_data.fqdn |  | keyword |
| qualys_vmdr.asset_host_detection.dns_data.hostname |  | keyword |
| qualys_vmdr.asset_host_detection.ec2_instance_id |  | keyword |
| qualys_vmdr.asset_host_detection.id |  | keyword |
| qualys_vmdr.asset_host_detection.ip |  | ip |
| qualys_vmdr.asset_host_detection.last.pc_scanned_date |  | date |
| qualys_vmdr.asset_host_detection.last.scan_datetime |  | date |
| qualys_vmdr.asset_host_detection.last.vm.auth.scanned_date |  | date |
| qualys_vmdr.asset_host_detection.last.vm.auth.scanned_duration |  | long |
| qualys_vmdr.asset_host_detection.last.vm.scanned_date |  | date |
| qualys_vmdr.asset_host_detection.last.vm.scanned_duration |  | long |
| qualys_vmdr.asset_host_detection.list.first_found_datetime |  | date |
| qualys_vmdr.asset_host_detection.list.is_disabled |  | boolean |
| qualys_vmdr.asset_host_detection.list.is_ignored |  | boolean |
| qualys_vmdr.asset_host_detection.list.last.found_datetime |  | date |
| qualys_vmdr.asset_host_detection.list.last.processed_datetime |  | date |
| qualys_vmdr.asset_host_detection.list.last.test_datetime |  | date |
| qualys_vmdr.asset_host_detection.list.last.update_datetime |  | date |
| qualys_vmdr.asset_host_detection.list.port |  | long |
| qualys_vmdr.asset_host_detection.list.protocol |  | keyword |
| qualys_vmdr.asset_host_detection.list.qds.severity |  | keyword |
| qualys_vmdr.asset_host_detection.list.qds.text |  | keyword |
| qualys_vmdr.asset_host_detection.list.qds_factors.name |  | keyword |
| qualys_vmdr.asset_host_detection.list.qds_factors.text |  | keyword |
| qualys_vmdr.asset_host_detection.list.qid |  | keyword |
| qualys_vmdr.asset_host_detection.list.results |  | keyword |
| qualys_vmdr.asset_host_detection.list.severity |  | long |
| qualys_vmdr.asset_host_detection.list.ssl |  | keyword |
| qualys_vmdr.asset_host_detection.list.status |  | keyword |
| qualys_vmdr.asset_host_detection.list.times_found |  | long |
| qualys_vmdr.asset_host_detection.list.type |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.ec2.attribute.last.error.date |  | date |
| qualys_vmdr.asset_host_detection.metadata.ec2.attribute.last.error.value |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.ec2.attribute.last.status |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.ec2.attribute.last.success_date |  | date |
| qualys_vmdr.asset_host_detection.metadata.ec2.attribute.name |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.ec2.attribute.value |  | keyword |
| qualys_vmdr.asset_host_detection.netbios |  | keyword |
| qualys_vmdr.asset_host_detection.network_id |  | keyword |
| qualys_vmdr.asset_host_detection.os |  | keyword |
| qualys_vmdr.asset_host_detection.qg_host_id |  | keyword |
| qualys_vmdr.asset_host_detection.tags.id |  | keyword |
| qualys_vmdr.asset_host_detection.tags.name |  | keyword |
| qualys_vmdr.asset_host_detection.tracking_method |  | keyword |
| tags | User defined tags. | keyword |


### Knowledge Base

This is the `Knowledge Base` dataset.

#### Example

An example event for `knowledge_base` looks as following:

```json
{
    "@timestamp": "2023-06-29T12:20:46.000Z",
    "agent": {
        "ephemeral_id": "d6d8fd18-2ee8-4ece-993f-055069187cc7",
        "id": "3f1418ad-5463-4d9c-80cc-ace99ce34d5e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.9.0"
    },
    "data_stream": {
        "dataset": "qualys_vmdr.knowledge_base",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.9.0"
    },
    "elastic_agent": {
        "id": "3f1418ad-5463-4d9c-80cc-ace99ce34d5e",
        "snapshot": true,
        "version": "8.9.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "qualys_vmdr.knowledge_base",
        "id": "11827",
        "ingested": "2023-07-07T06:23:14Z",
        "kind": "alert",
        "original": "{\"CATEGORY\":\"CGI\",\"CONSEQUENCE\":\"\",\"DIAGNOSIS\":\"\",\"DISCOVERY\":{\"REMOTE\":\"1\"},\"LAST_SERVICE_MODIFICATION_DATETIME\":\"2023-06-29T12:20:46Z\",\"PATCHABLE\":\"0\",\"PCI_FLAG\":\"1\",\"PUBLISHED_DATETIME\":\"2017-06-05T21:34:49Z\",\"QID\":\"11827\",\"SEVERITY_LEVEL\":\"2\",\"SOFTWARE_LIST\":{\"SOFTWARE\":[{\"PRODUCT\":\"\",\"VENDOR\":\"\"}]},\"SOLUTION\":\"\",\"THREAT_INTELLIGENCE\":{\"THREAT_INTEL\":[{\"id\":\"8\"}]},\"TITLE\":\"\",\"VULN_TYPE\":\"Vulnerability\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "qualys_vmdr": {
        "knowledge_base": {
            "category": "CGI",
            "discovery": {
                "remote": 1
            },
            "last_service_modification_datetime": "2023-06-29T12:20:46.000Z",
            "patchable": false,
            "pci_flag": true,
            "published_datetime": "2017-06-05T21:34:49.000Z",
            "qid": "11827",
            "severity_level": "2",
            "threat_intelligence": {
                "intel": [
                    {
                        "id": "8"
                    }
                ]
            },
            "vuln_type": "Vulnerability"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "qualys_vmdr-knowledge_base"
    ],
    "vulnerability": {
        "category": [
            "CGI"
        ],
        "severity": "Low"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| qualys_vmdr.knowledge_base.category |  | keyword |
| qualys_vmdr.knowledge_base.changelog_log_list.info.change_date |  | date |
| qualys_vmdr.knowledge_base.changelog_log_list.info.comments |  | keyword |
| qualys_vmdr.knowledge_base.consequence |  | keyword |
| qualys_vmdr.knowledge_base.correlation.exploits.explt_src.list.explt.desc |  | keyword |
| qualys_vmdr.knowledge_base.correlation.exploits.explt_src.list.explt.link |  | keyword |
| qualys_vmdr.knowledge_base.correlation.exploits.explt_src.list.explt.ref |  | keyword |
| qualys_vmdr.knowledge_base.correlation.exploits.explt_src.name |  | keyword |
| qualys_vmdr.knowledge_base.cve_list.id |  | keyword |
| qualys_vmdr.knowledge_base.cve_list.url |  | keyword |
| qualys_vmdr.knowledge_base.diagnosis |  | keyword |
| qualys_vmdr.knowledge_base.discovery.additional_info |  | keyword |
| qualys_vmdr.knowledge_base.discovery.auth_type_list.value |  | keyword |
| qualys_vmdr.knowledge_base.discovery.remote |  | long |
| qualys_vmdr.knowledge_base.is_disabled |  | boolean |
| qualys_vmdr.knowledge_base.last_service_modification_datetime |  | date |
| qualys_vmdr.knowledge_base.patchable |  | boolean |
| qualys_vmdr.knowledge_base.pci_flag |  | boolean |
| qualys_vmdr.knowledge_base.pci_reasons.value |  | keyword |
| qualys_vmdr.knowledge_base.published_datetime |  | date |
| qualys_vmdr.knowledge_base.qid |  | keyword |
| qualys_vmdr.knowledge_base.severity_level |  | keyword |
| qualys_vmdr.knowledge_base.software_list.product |  | keyword |
| qualys_vmdr.knowledge_base.software_list.vendor |  | keyword |
| qualys_vmdr.knowledge_base.solution |  | keyword |
| qualys_vmdr.knowledge_base.supported_modules |  | keyword |
| qualys_vmdr.knowledge_base.threat_intelligence.intel.id |  | keyword |
| qualys_vmdr.knowledge_base.threat_intelligence.intel.text |  | keyword |
| qualys_vmdr.knowledge_base.title |  | keyword |
| qualys_vmdr.knowledge_base.vendor_reference_list.id |  | keyword |
| qualys_vmdr.knowledge_base.vendor_reference_list.url |  | keyword |
| qualys_vmdr.knowledge_base.vuln_type |  | keyword |
| tags | User defined tags. | keyword |
