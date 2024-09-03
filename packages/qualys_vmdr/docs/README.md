# Qualys Vulnerability Management, Detection and Response (VMDR)

This [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/) integration is a cloud-based service that gives you immediate, global visibility into where your IT systems might be vulnerable to the latest Internet threats and how to protect them. It helps you to continuously identify threats and monitor unexpected changes in your network before they turn into breaches.

The Qualys VMDR integration uses REST API mode to collect data. Elastic Agent fetches data via API endpoints.

## Compatibility

This module has been tested against the latest Qualys VMDR version **v2**.

## Data streams

The Qualys VMDR integration collects data for the following two events:

| Event Type           |
|----------------------|
| Asset Host Detection |
| Knowledge Base       |
| User Activity Log    |

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

   or if you want to collect User Activity log data via REST API, then you have to put the following details:
   - username
   - password
   - url
   - initial interval
   - interval

**NOTE**: By default, the input parameter is set to "action=list".

## Data reference

### Asset Host Detection

This is the `Asset Host Detection` dataset.

#### Example

An example event for `asset_host_detection` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "4ac7c7e4-f06c-4640-9526-3046c63279ef",
        "ephemeral_id": "db334fd8-7add-4929-8e35-82385a633847",
        "type": "filebeat",
        "version": "8.15.0"
    },
    "elastic_agent": {
        "id": "4ac7c7e4-f06c-4640-9526-3046c63279ef",
        "version": "8.15.0",
        "snapshot": false
    },
    "qualys_vmdr": {
        "asset_host_detection": {
            "metadata": {
                "google": {
                    "attribute": [
                        {
                            "last": {
                                "success_date": "2024-09-02T13:09:01.000Z",
                                "status": "Success"
                            },
                            "name": "latest/dynamic/instance-identity/document/imageId",
                            "value": "projects/debian-cloud/global/images/debian-11-bullseye-v20221206"
                        },
                        {
                            "last": {
                                "success_date": "2024-09-02T13:09:01.000Z",
                                "status": "Success"
                            },
                            "name": "latest/dynamic/instance-identity/document/privateIp",
                            "value": "10.0.0.1"
                        },
                        {
                            "last": {
                                "success_date": "2024-09-02T13:09:01.000Z",
                                "status": "Success"
                            },
                            "name": "latest/meta-data/hostname",
                            "value": "myserver.internal"
                        },
                        {
                            "last": {
                                "success_date": "2024-09-02T13:09:01.000Z",
                                "status": "Success"
                            },
                            "name": "latest/meta-data/instance-id",
                            "value": "1234567898765432123"
                        },
                        {
                            "last": {
                                "success_date": "2024-09-02T13:09:01.000Z",
                                "status": "Success"
                            },
                            "name": "latest/meta-data/mac",
                            "value": "aa:bb:cc:dd:ee:ff"
                        },
                        {
                            "last": {
                                "success_date": "2024-09-02T13:09:01.000Z",
                                "status": "Success"
                            },
                            "name": "latest/meta-data/public-ipv4",
                            "value": "34.34.34.34"
                        },
                        {
                            "last": {
                                "success_date": "2024-09-02T13:09:01.000Z",
                                "status": "Success"
                            },
                            "name": "machineType",
                            "value": "e2-standard-4"
                        },
                        {
                            "last": {
                                "success_date": "2024-09-02T13:09:01.000Z",
                                "status": "Success"
                            },
                            "name": "network",
                            "value": "internal"
                        },
                        {
                            "last": {
                                "success_date": "2024-09-02T13:09:01.000Z",
                                "status": "Success"
                            },
                            "name": "projectId",
                            "value": "mysuperproject"
                        },
                        {
                            "last": {
                                "success_date": "2024-09-02T13:09:01.000Z",
                                "status": "Success"
                            },
                            "name": "projectIdNo",
                            "value": "123456789876"
                        },
                        {
                            "last": {
                                "success_date": "2024-09-02T13:09:01.000Z",
                                "status": "Success"
                            },
                            "name": "state",
                            "value": "RUNNING"
                        },
                        {
                            "last": {
                                "success_date": "2024-09-02T13:09:01.000Z",
                                "status": "Success"
                            },
                            "name": "zone",
                            "value": "us-central1-a"
                        }
                    ]
                }
            },
            "qg_hostid": "20247932-9ca8-4351-80ee-3a3769b85db7",
            "os": "Debian Linux 11.11",
            "ip": "10.128.0.2",
            "dns": "myserver.internal",
            "dns_data": {
                "hostname": "myserver",
                "fqdn": "myserver.internal",
                "domain": "internal"
            },
            "cloud_resource_id": "1234567898765432123",
            "last_scan_datetime": "2024-09-03T06:57:35.000Z",
            "cloud_provider": "GCP",
            "asset_id": 123456789,
            "vulnerability": {
                "qds": {
                    "severity": "HIGH",
                    "score": 72
                },
                "last_processed_datetime": "2024-09-02T14:19:14.000Z",
                "type": "Confirmed",
                "qid": 6000245,
                "ssl": "0",
                "first_found_datetime": "2023-10-11T21:50:47.000Z",
                "times_found": 2,
                "is_ignored": false,
                "qds_factors": [
                    {
                        "name": "exploit_maturity",
                        "text": "poc"
                    },
                    {
                        "name": "CVSS",
                        "text": "9.8"
                    },
                    {
                        "name": "CVSS_version",
                        "text": "v3.x"
                    },
                    {
                        "name": "epss",
                        "text": "0.00319"
                    },
                    {
                        "name": "trending",
                        "text": "08092024,08122024,08062024,08282024,08152024"
                    },
                    {
                        "name": "CVSS_vector",
                        "text": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
                ],
                "severity": 4,
                "last_update_datetime": "2024-09-02T14:19:14.000Z",
                "is_disabled": false,
                "unique_vuln_id": "1234567898",
                "last_test_datetime": "2024-09-02T14:19:13.000Z",
                "last_fixed_datetime": "2023-10-12T04:27:09.000Z",
                "status": "Fixed",
                "last_found_datetime": "2023-10-12T00:41:34.000Z"
            },
            "cloud_service": "Compute Engine",
            "tags": [
                {
                    "name": "Cloud Agent",
                    "id": "123456789"
                },
                {
                    "name": "GCP",
                    "id": "234567898"
                }
            ],
            "cloud_provider_tags": {
                "cloud_tag": [
                    {
                        "name": "division",
                        "last_success_date": "2024-09-02T13:09:01.000Z",
                        "value": "IT"
                    }
                ]
            },
            "network_id": "0",
            "last_vm_scanned_date": "2024-09-03T06:57:35.000Z",
            "ec2_instance_id": "1234567898765432123",
            "id": "123456789",
            "last_vm_auth_scanned_date": "2024-09-03T06:57:35.000Z",
            "tracking_method": "AGENT"
        }
    },
    "tags": [
        "preserve_duplicate_custom_fields",
        "forwarded",
        "qualys_vmdr-asset_host_detection",
        "provider_cloud_data"
    ],
    "cloud": {
        "availability_zone": [
            "us-central1-a"
        ],
        "instance": {
            "name": "myserver",
            "id": "1234567898765432123"
        },
        "provider": "gcp",
        "service": {
            "name": "Compute Engine"
        },
        "machine": {
            "type": [
                "e2-standard-4"
            ]
        },
        "project": {
            "name": [
                "myproject"
            ],
            "id": [
                "123456789876"
            ]
        }
    },
    "input": {
        "type": "cel"
    },
    "@timestamp": "2024-09-03T07:13:51.621Z",
    "ecs": {
        "version": "8.11.0"
    },
    "related": {
        "hosts": [
            "myserver.internal",
            "myserver",
            "123456789",
            "20247932-9ca8-4351-80ee-3a3769b85db7"
        ],
        "ip": [
            "10.0.0.1"
        ]
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "qualys_vmdr.asset_host_detection"
    },
    "host": {
        "os": {
            "full": "Debian Linux 11.11"
        },
        "ip": [
            "10.0.0.1"
        ],
        "id": "123456789"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-09-03T07:13:56Z",
        "kind": "alert",
        "category": [
            "host"
        ],
        "type": [
            "info"
        ],
        "dataset": "qualys_vmdr.asset_host_detection"
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
| qualys_vmdr.asset_host_detection.asset_id |  | long |
| qualys_vmdr.asset_host_detection.cloud_provider |  | keyword |
| qualys_vmdr.asset_host_detection.cloud_provider_tags.cloud_tag.last_success_date |  | date |
| qualys_vmdr.asset_host_detection.cloud_provider_tags.cloud_tag.name |  | keyword |
| qualys_vmdr.asset_host_detection.cloud_provider_tags.cloud_tag.value |  | keyword |
| qualys_vmdr.asset_host_detection.cloud_resource_id |  | keyword |
| qualys_vmdr.asset_host_detection.cloud_service |  | keyword |
| qualys_vmdr.asset_host_detection.dns |  | keyword |
| qualys_vmdr.asset_host_detection.dns_data.domain |  | keyword |
| qualys_vmdr.asset_host_detection.dns_data.fqdn |  | keyword |
| qualys_vmdr.asset_host_detection.dns_data.hostname |  | keyword |
| qualys_vmdr.asset_host_detection.ec2_instance_id |  | keyword |
| qualys_vmdr.asset_host_detection.id |  | keyword |
| qualys_vmdr.asset_host_detection.ip |  | ip |
| qualys_vmdr.asset_host_detection.ipv6 |  | ip |
| qualys_vmdr.asset_host_detection.last_pc_scanned_date |  | date |
| qualys_vmdr.asset_host_detection.last_scan_datetime |  | date |
| qualys_vmdr.asset_host_detection.last_vm_auth_scanned_date |  | date |
| qualys_vmdr.asset_host_detection.last_vm_auth_scanned_duration |  | long |
| qualys_vmdr.asset_host_detection.last_vm_scanned_date |  | date |
| qualys_vmdr.asset_host_detection.last_vm_scanned_duration |  | long |
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
| qualys_vmdr.asset_host_detection.os |  | keyword |
| qualys_vmdr.asset_host_detection.os_cpe |  | keyword |
| qualys_vmdr.asset_host_detection.qg_hostid |  | keyword |
| qualys_vmdr.asset_host_detection.tags.background_color |  | keyword |
| qualys_vmdr.asset_host_detection.tags.color |  | keyword |
| qualys_vmdr.asset_host_detection.tags.id |  | keyword |
| qualys_vmdr.asset_host_detection.tags.name |  | keyword |
| qualys_vmdr.asset_host_detection.tracking_method |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.affect_exploitable_config |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.affect_running_kernel |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.affect_running_service |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.asset_cve |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.first_found_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.first_reopened_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.fqdn |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.instance |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.is_disabled |  | boolean |
| qualys_vmdr.asset_host_detection.vulnerability.is_ignored |  | boolean |
| qualys_vmdr.asset_host_detection.vulnerability.last_fixed_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.last_found_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.last_processed_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.last_reopened_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.last_test_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.last_update_datetime |  | date |
| qualys_vmdr.asset_host_detection.vulnerability.port |  | long |
| qualys_vmdr.asset_host_detection.vulnerability.protocol |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.qds.score |  | integer |
| qualys_vmdr.asset_host_detection.vulnerability.qds.severity |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.qds_factors.name |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.qds_factors.text |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.qid |  | integer |
| qualys_vmdr.asset_host_detection.vulnerability.results |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.service |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.severity |  | long |
| qualys_vmdr.asset_host_detection.vulnerability.ssl |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.status |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.times_found |  | long |
| qualys_vmdr.asset_host_detection.vulnerability.times_reopened |  | long |
| qualys_vmdr.asset_host_detection.vulnerability.type |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.unique_vuln_id |  | keyword |


### Knowledge Base

This is the `Knowledge Base` dataset.

#### Example

An example event for `knowledge_base` looks as following:

```json
{
    "@timestamp": "2023-06-29T12:20:46.000Z",
    "agent": {
        "ephemeral_id": "c4d3c4ee-a36e-4fd0-9d4a-dbb192e5ee74",
        "id": "33c44d71-ed50-44dd-be56-70103362ff67",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
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
        "id": "33c44d71-ed50-44dd-be56-70103362ff67",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "qualys_vmdr.knowledge_base",
        "id": "11830",
        "ingested": "2024-05-28T23:08:57Z",
        "kind": "alert",
        "original": "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<!DOCTYPE KNOWLEDGE_BASE_VULN_LIST_OUTPUT SYSTEM \"https://qualysapi.qualys.com/api/2.0/fo/knowledge_base/vuln/knowledge_base_vuln_list_output.dtd\">\n<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>\n    <RESPONSE>\n        <DATETIME>2023-07-06T15:02:16Z</DATETIME>\n        <VULN_LIST>\n            <VULN>\n                <QID>11830</QID>\n                <VULN_TYPE>Vulnerability</VULN_TYPE>\n                <SEVERITY_LEVEL>2</SEVERITY_LEVEL>\n                <TITLE>\n                    <![CDATA[HTTP Security Header Not Detected]]>\n                </TITLE>\n                <CVE_LIST>\n                    <CVE>\n                        <ID><![CDATA[CVE-2022-31629]]></ID>\n                        <URL><![CDATA[http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31629]]></URL>\n                    </CVE>\n                    <CVE>\n                        <ID><![CDATA[CVE-2022-31628]]></ID>\n                        <URL><![CDATA[http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31628]]></URL>\n                    </CVE>\n                </CVE_LIST>\n                <CATEGORY>CGI</CATEGORY>\n                <LAST_SERVICE_MODIFICATION_DATETIME>2023-06-29T12:20:46Z</LAST_SERVICE_MODIFICATION_DATETIME>\n                <PUBLISHED_DATETIME>2017-06-05T21:34:49Z</PUBLISHED_DATETIME>\n                <PATCHABLE>0</PATCHABLE>\n                <SOFTWARE_LIST>\n                    <SOFTWARE>\n                        <PRODUCT>\n                            <![CDATA[None]]>\n                        </PRODUCT>\n                        <VENDOR>\n                            <![CDATA[multi-vendor]]>\n                        </VENDOR>\n                    </SOFTWARE>\n                </SOFTWARE_LIST>\n                <DIAGNOSIS>\n                    <![CDATA[This QID reports the absence of the following]]>\n                </DIAGNOSIS>\n                <CONSEQUENCE>\n                    <![CDATA[Depending on the vulnerability being exploited, an unauthenticated remote attacker could conduct cross-site scripting, clickjacking or MIME-type sniffing attacks.]]>\n                </CONSEQUENCE>\n                <SOLUTION>\n                    <![CDATA[<B>Note:</B> To better debug the results of this QID]]>\n                </SOLUTION>\n                <PCI_FLAG>1</PCI_FLAG>\n                <THREAT_INTELLIGENCE>\n                    <THREAT_INTEL id=\"8\">\n                        <![CDATA[No_Patch]]>\n                    </THREAT_INTEL>\n                </THREAT_INTELLIGENCE>\n                <DISCOVERY>\n                    <REMOTE>1</REMOTE>\n                </DISCOVERY>\n            </VULN>\n        </VULN_LIST>\n    </RESPONSE>\n</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>",
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
            "cve_list": [
                "CVE-2022-31629",
                "CVE-2022-31628"
            ],
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
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "qualys_vmdr-knowledge_base"
    ],
    "vulnerability": {
        "category": [
            "CGI"
        ],
        "id": [
            "CVE-2022-31629",
            "CVE-2022-31628"
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
| qualys_vmdr.knowledge_base.cve_list |  | keyword |
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


### User Activity

This is the `User Activity` dataset. It connects to an [API](
https://docs.qualys.com/en/vm/api/users/index.htm#t=activity%2Fexport_activity.htm)
that exports the user activity log. 

#### Example

An example event for `user_activity` looks as following:

```json
{
    "@timestamp": "2024-02-02T13:26:41.000Z",
    "agent": {
        "ephemeral_id": "af48395e-458a-458f-861f-054f80ca6927",
        "id": "4549f0e8-0878-48fa-9db3-e93d9aa2f9c1",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.4"
    },
    "data_stream": {
        "dataset": "qualys_vmdr.user_activity",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "4549f0e8-0878-48fa-9db3-e93d9aa2f9c1",
        "snapshot": false,
        "version": "8.13.4"
    },
    "event": {
        "action": "request",
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "dataset": "qualys_vmdr.user_activity",
        "ingested": "2024-05-30T03:33:23Z",
        "kind": "event",
        "provider": "auth",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "message": "API: /api/2.0/fo/activity_log/index.php",
    "qualys_vmdr": {
        "user_activity": {
            "Action": "request",
            "Date": "2024-02-02T13:26:41Z",
            "Details": "API: /api/2.0/fo/activity_log/index.php",
            "Module": "auth",
            "User_IP": "10.113.195.136",
            "User_Name": "saand_rn",
            "User_Role": "Manager"
        }
    },
    "related": {
        "ip": [
            "10.113.195.136"
        ],
        "user": [
            "saand_rn"
        ]
    },
    "source": {
        "ip": "10.113.195.136"
    },
    "tags": [
        "preserve_duplicate_custom_fields",
        "forwarded",
        "qualys_vmdr-user_activity"
    ],
    "user": {
        "name": "saand_rn",
        "roles": [
            "Manager"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| qualys_vmdr.user_activity.Action |  | keyword |
| qualys_vmdr.user_activity.Date |  | date |
| qualys_vmdr.user_activity.Details |  | keyword |
| qualys_vmdr.user_activity.Module |  | keyword |
| qualys_vmdr.user_activity.User_IP |  | keyword |
| qualys_vmdr.user_activity.User_Name |  | keyword |
| qualys_vmdr.user_activity.User_Role |  | keyword |
