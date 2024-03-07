# Qualys Vulnerability Management, Detection and Response (VMDR)

This [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/) integration is a cloud-based service that gives you immediate, global visibility into where your IT systems might be vulnerable to the latest Internet threats and how to protect them. It helps you to continuously identify threats and monitor unexpected changes in your network before they turn into breaches.

The Qualys VMDR integration uses REST API mode to collect data. Elastic Agent fetches data via API endpoints.

## Compatibility

This module has been tested against the latest Qualys VMDR version **v2**.

## Data streams

The Qualys VMDR integration collects data for the following two events:

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
5. While adding the integration, if you want to collect Asset Host Detection data via REST API, then you have to put the following details:
   - username
   - password
   - url
   - interval
   - input parameters
   - batch size

   or if you want to collect Knowledge Base data via REST API, then you have to put the following details:
   - username
   - password
   - url
   - initial interval
   - interval
   - input parameters

**NOTE**: By default, the input parameter is set to "action=list".

## Data reference

### Asset Host Detection

This is the `Asset Host Detection` dataset.

#### Example

An example event for `asset_host_detection` looks as following:

```json
{
    "@timestamp": "2024-03-07T04:54:03.747Z",
    "agent": {
        "ephemeral_id": "648c8e7c-cf0a-4b7f-aca2-08a70160d7d0",
        "id": "069f6385-0641-4b35-8f50-779fb950f1fe",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "qualys_vmdr.asset_host_detection",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "069f6385-0641-4b35-8f50-779fb950f1fe",
        "snapshot": false,
        "version": "8.12.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "qualys_vmdr.asset_host_detection",
        "ingested": "2024-03-07T04:54:15Z",
        "kind": "alert",
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
            "tracking_method": "IP",
            "vulnerability": {
                "first": {
                    "found_datetime": "2023-06-28T06:04:26.000Z"
                },
                "is_disabled": false,
                "is_ignored": false,
                "last": {
                    "found_datetime": "2023-07-03T06:23:47.000Z",
                    "processed_datetime": "2023-07-03T06:25:17.000Z",
                    "test_datetime": "2023-07-03T06:23:47.000Z",
                    "update_datetime": "2023-07-03T06:25:17.000Z"
                },
                "qid": "91681",
                "severity": 5,
                "ssl": "0",
                "status": "Active",
                "times": {
                    "found": 11
                },
                "type": "Confirmed"
            }
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
| qualys_vmdr.asset_host_detection.ipv6 |  | ip |
| qualys_vmdr.asset_host_detection.last.pc_scanned_date |  | date |
| qualys_vmdr.asset_host_detection.last.scan_datetime |  | date |
| qualys_vmdr.asset_host_detection.last.vm.auth.scanned_date |  | date |
| qualys_vmdr.asset_host_detection.last.vm.auth.scanned_duration |  | long |
| qualys_vmdr.asset_host_detection.last.vm.scanned_date |  | date |
| qualys_vmdr.asset_host_detection.last.vm.scanned_duration |  | long |
| qualys_vmdr.asset_host_detection.metadata.azure.attribute.last.error.date |  | date |
| qualys_vmdr.asset_host_detection.metadata.azure.attribute.last.error.value |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.azure.attribute.last.status |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.azure.attribute.last.success_date |  | date |
| qualys_vmdr.asset_host_detection.metadata.azure.attribute.name |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.azure.attribute.value |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.ec2.attribute.last.error.date |  | date |
| qualys_vmdr.asset_host_detection.metadata.ec2.attribute.last.error.value |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.ec2.attribute.last.status |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.ec2.attribute.last.success_date |  | date |
| qualys_vmdr.asset_host_detection.metadata.ec2.attribute.name |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.ec2.attribute.value |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.google.attribute.last.error.date |  | date |
| qualys_vmdr.asset_host_detection.metadata.google.attribute.last.error.value |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.google.attribute.last.status |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.google.attribute.last.success_date |  | date |
| qualys_vmdr.asset_host_detection.metadata.google.attribute.name |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.google.attribute.value |  | keyword |
| qualys_vmdr.asset_host_detection.netbios |  | keyword |
| qualys_vmdr.asset_host_detection.network_id |  | keyword |
| qualys_vmdr.asset_host_detection.os.cpe |  | keyword |
| qualys_vmdr.asset_host_detection.os.value |  | keyword |
| qualys_vmdr.asset_host_detection.qg_host_id |  | keyword |
| qualys_vmdr.asset_host_detection.tags.background_color |  | keyword |
| qualys_vmdr.asset_host_detection.tags.color |  | keyword |
| qualys_vmdr.asset_host_detection.tags.id |  | keyword |
| qualys_vmdr.asset_host_detection.tags.name |  | keyword |
| qualys_vmdr.asset_host_detection.tracking_method |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.affect.exploitable_config |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.affect.running.kernel |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.affect.running.service |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.asset_cve |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.first.found_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.first.reopened_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.fqdn |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.instance |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.is_disabled |  | boolean |
| qualys_vmdr.asset_host_detection.vulnerability.is_ignored |  | boolean |
| qualys_vmdr.asset_host_detection.vulnerability.last.fixed_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.last.found_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.last.processed_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.last.reopened_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.last.test_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.last.update_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.port |  | long |
| qualys_vmdr.asset_host_detection.vulnerability.protocol |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.qds.severity |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.qds.text |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.qds_factors.name |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.qds_factors.text |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.qid |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.results |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.service |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.severity |  | long |
| qualys_vmdr.asset_host_detection.vulnerability.ssl |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.status |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.times.found |  | long |
| qualys_vmdr.asset_host_detection.vulnerability.times.reopened |  | long |
| qualys_vmdr.asset_host_detection.vulnerability.type |  | keyword |
| tags | User defined tags. | keyword |


### Knowledge Base

This is the `Knowledge Base` dataset.

#### Example

An example event for `knowledge_base` looks as following:

```json
{
    "@timestamp": "2023-06-29T12:20:46.000Z",
    "agent": {
        "ephemeral_id": "4b9701ba-baa8-4dad-9c50-8a7ea93d1a58",
        "id": "2fe75851-fb2d-4304-b410-3b1195ac0a44",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "qualys_vmdr.knowledge_base",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2fe75851-fb2d-4304-b410-3b1195ac0a44",
        "snapshot": false,
        "version": "8.12.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "qualys_vmdr.knowledge_base",
        "id": "11830",
        "ingested": "2024-03-07T04:46:35Z",
        "kind": "alert",
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
            "last": {
                "service_modification_datetime": "2023-06-29T12:20:46.000Z"
            },
            "patchable": false,
            "pci_flag": true,
            "published_datetime": "2017-06-05T21:34:49.000Z",
            "qid": "11830",
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
        "preserve_duplicate_custom_fields",
        "forwarded",
        "qualys_vmdr-knowledge_base"
    ],
    "vulnerability": {
        "category": [
            "CGI"
        ],
        "severity": "Medium"
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
| qualys_vmdr.knowledge_base.automatic_pci_fail |  | keyword |
| qualys_vmdr.knowledge_base.bugtraq_list.id |  | keyword |
| qualys_vmdr.knowledge_base.bugtraq_list.url |  | keyword |
| qualys_vmdr.knowledge_base.category |  | keyword |
| qualys_vmdr.knowledge_base.changelog_list.info.change_date |  | date |
| qualys_vmdr.knowledge_base.changelog_list.info.comments |  | keyword |
| qualys_vmdr.knowledge_base.compliance_list.description |  | keyword |
| qualys_vmdr.knowledge_base.compliance_list.section |  | keyword |
| qualys_vmdr.knowledge_base.compliance_list.type |  | keyword |
| qualys_vmdr.knowledge_base.consequence.comment |  | keyword |
| qualys_vmdr.knowledge_base.consequence.value |  | keyword |
| qualys_vmdr.knowledge_base.correlation.exploits.explt_src.list.explt.desc |  | keyword |
| qualys_vmdr.knowledge_base.correlation.exploits.explt_src.list.explt.link |  | keyword |
| qualys_vmdr.knowledge_base.correlation.exploits.explt_src.list.explt.ref |  | keyword |
| qualys_vmdr.knowledge_base.correlation.exploits.explt_src.name |  | keyword |
| qualys_vmdr.knowledge_base.correlation.malware.src.list.info.alias |  | keyword |
| qualys_vmdr.knowledge_base.correlation.malware.src.list.info.id |  | keyword |
| qualys_vmdr.knowledge_base.correlation.malware.src.list.info.link |  | keyword |
| qualys_vmdr.knowledge_base.correlation.malware.src.list.info.platform |  | keyword |
| qualys_vmdr.knowledge_base.correlation.malware.src.list.info.rating |  | keyword |
| qualys_vmdr.knowledge_base.correlation.malware.src.list.info.type |  | keyword |
| qualys_vmdr.knowledge_base.correlation.malware.src.name |  | keyword |
| qualys_vmdr.knowledge_base.cve_list.id |  | keyword |
| qualys_vmdr.knowledge_base.cve_list.url |  | keyword |
| qualys_vmdr.knowledge_base.cvss.access.complexity |  | keyword |
| qualys_vmdr.knowledge_base.cvss.access.vector |  | keyword |
| qualys_vmdr.knowledge_base.cvss.authentication |  | keyword |
| qualys_vmdr.knowledge_base.cvss.base |  | keyword |
| qualys_vmdr.knowledge_base.cvss.base_obj |  | flattened |
| qualys_vmdr.knowledge_base.cvss.exploitability |  | keyword |
| qualys_vmdr.knowledge_base.cvss.impact.availability |  | keyword |
| qualys_vmdr.knowledge_base.cvss.impact.confidentiality |  | keyword |
| qualys_vmdr.knowledge_base.cvss.impact.integrity |  | keyword |
| qualys_vmdr.knowledge_base.cvss.remediation_level |  | keyword |
| qualys_vmdr.knowledge_base.cvss.report_confidence |  | keyword |
| qualys_vmdr.knowledge_base.cvss.temporal |  | keyword |
| qualys_vmdr.knowledge_base.cvss.vector_string |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.attack.complexity |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.attack.vector |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.base |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.exploit_code_maturity |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.impact.availability |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.impact.confidentiality |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.impact.integrity |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.privileges_required |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.remediation_level |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.report_confidence |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.scope |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.temporal |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.user_interaction |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.vector_string |  | keyword |
| qualys_vmdr.knowledge_base.cvss_v3.version |  | keyword |
| qualys_vmdr.knowledge_base.detection_info |  | keyword |
| qualys_vmdr.knowledge_base.diagnosis.comment |  | keyword |
| qualys_vmdr.knowledge_base.diagnosis.value |  | keyword |
| qualys_vmdr.knowledge_base.discovery.additional_info |  | keyword |
| qualys_vmdr.knowledge_base.discovery.auth_type_list.value |  | keyword |
| qualys_vmdr.knowledge_base.discovery.remote |  | long |
| qualys_vmdr.knowledge_base.error |  | keyword |
| qualys_vmdr.knowledge_base.id_range |  | keyword |
| qualys_vmdr.knowledge_base.ids |  | keyword |
| qualys_vmdr.knowledge_base.is_disabled |  | boolean |
| qualys_vmdr.knowledge_base.last.customization.datetime |  | date |
| qualys_vmdr.knowledge_base.last.customization.user_login |  | keyword |
| qualys_vmdr.knowledge_base.last.service_modification_datetime |  | date |
| qualys_vmdr.knowledge_base.patchable |  | boolean |
| qualys_vmdr.knowledge_base.pci_flag |  | boolean |
| qualys_vmdr.knowledge_base.pci_reasons.value |  | keyword |
| qualys_vmdr.knowledge_base.published_datetime |  | date |
| qualys_vmdr.knowledge_base.qid |  | keyword |
| qualys_vmdr.knowledge_base.severity_level |  | keyword |
| qualys_vmdr.knowledge_base.software_list.product |  | keyword |
| qualys_vmdr.knowledge_base.software_list.vendor |  | keyword |
| qualys_vmdr.knowledge_base.solution.comment |  | keyword |
| qualys_vmdr.knowledge_base.solution.value |  | keyword |
| qualys_vmdr.knowledge_base.supported_modules |  | keyword |
| qualys_vmdr.knowledge_base.threat_intelligence.intel.id |  | keyword |
| qualys_vmdr.knowledge_base.threat_intelligence.intel.text |  | keyword |
| qualys_vmdr.knowledge_base.title |  | keyword |
| qualys_vmdr.knowledge_base.vendor_reference_list.id |  | keyword |
| qualys_vmdr.knowledge_base.vendor_reference_list.url |  | keyword |
| qualys_vmdr.knowledge_base.vuln_type |  | keyword |
| tags | User defined tags. | keyword |
