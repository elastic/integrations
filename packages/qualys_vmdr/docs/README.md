# Qualys Vulnerability Management, Detection and Response (VMDR)

This [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/) integration is a cloud-based service that gives you immediate, global visibility into where your IT systems might be vulnerable to the latest Internet threats and how to protect them. It helps you to continuously identify threats and monitor unexpected changes in your network before they turn into breaches.

The Qualys VMDR integration uses REST API mode to collect data. Elastic Agent fetches data via API endpoints.

## Compatibility

This module has been tested against the latest Qualys VMDR version **v2**.

## Data streams

The Qualys VMDR integration collects data for the following three events:

| Event Type           |
|----------------------|
| Asset Host Detection |
| Knowledge Base       |
| User Activity Log    |

Reference for [Rest APIs](https://qualysguard.qg2.apps.qualys.com/qwebhelp/fo_portal/api_doc/index.htm) of Qualys VMDR.

Starting from Qualys VMDR integration version 6.0, the `Asset Host Detection` data stream includes enriched vulnerabilities data from Qualys Knowledge Base API.

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Permissions

#### Asset host detection

| Role                    | Permission                                     |
|-------------------------|------------------------------------------------|
| _Managers_              | All VM scanned hosts in subscription           |
| _Unit Managers_         | VM scanned hosts in user’s business unit       |
| _Scanners_              | VM scanned hosts in user’s account             |
| _Readers_               | VM scanned hosts in user’s account             |

#### Knowledge base

_Managers_, _Unit Managers_, _Scanners_, _Readers_ have permission to download vulnerability data from the KnowledgeBase.

#### User activity log

| Role                    | Permission                                     |
|-------------------------|------------------------------------------------|
| _Managers_              | All actions taken by all users                 |
| _Unit Managers_         | Actions taken by users in their business unit  |
| _Scanners_              | Own actions only                               |
| _Readers_               | Own actions only                               |

## Setup

### Collect data through REST API

Assuming that you already have a Qualys user account, to identify your Qualys platform and get the API URL, check the [Qualys documentation](https://www.qualys.com/platform-identification/).
Alternatively, to get the API URL log in to your Qualys account and go to **Help** > **About**. You’ll find your URL under **Security Operations Center (SOC)**.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Qualys VMDR**.
3. Select the **Qualys VMDR** integration and add it.
4. While adding the integration, if you want to collect Asset Host Detection data via REST API, then you have to put the following details:
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
5. Save the integration.

**NOTE**: By default, the input parameter is set to `action=list`.

## Data reference

### Asset host detection

This is the `Asset Host Detection` dataset.

#### Example

An example event for `asset_host_detection` looks as following:

```json
{
    "@timestamp": "2025-06-06T07:05:24.052Z",
    "agent": {
        "ephemeral_id": "cfed7d76-3f24-45b8-8ebe-2975c2ce33f5",
        "id": "7a08760a-c972-4143-a43c-960e301c294e",
        "name": "elastic-agent-89453",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "cloud": {
        "instance": {
            "name": "adfssrvr"
        }
    },
    "data_stream": {
        "dataset": "qualys_vmdr.asset_host_detection",
        "namespace": "98699",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7a08760a-c972-4143-a43c-960e301c294e",
        "snapshot": true,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "qualys_vmdr.asset_host_detection",
        "id": "11111111",
        "ingested": "2025-06-06T07:05:26Z",
        "kind": "alert",
        "original": "{\"DETECTION_LIST\":{\"AFFECT_RUNNING_KERNEL\":\"0\",\"FIRST_FOUND_DATETIME\":\"2021-02-05T04:50:45Z\",\"IS_DISABLED\":\"0\",\"IS_IGNORED\":\"0\",\"LAST_FIXED_DATETIME\":\"2022-12-14T06:52:57Z\",\"LAST_FOUND_DATETIME\":\"2024-03-08T20:15:41Z\",\"LAST_PROCESSED_DATETIME\":\"2024-03-08T20:15:41Z\",\"LAST_TEST_DATETIME\":\"2024-03-08T20:15:41Z\",\"LAST_UPDATE_DATETIME\":\"2024-03-08T20:15:41Z\",\"QDS\":{\"#text\":\"35\",\"severity\":\"LOW\"},\"QDS_FACTORS\":{\"QDS_FACTOR\":[{\"#text\":\"7.7\",\"name\":\"CVSS\"},{\"#text\":\"v3.x\",\"name\":\"CVSS_version\"},{\"#text\":\"0.00232\",\"name\":\"epss\"},{\"#text\":\"AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H\",\"name\":\"CVSS_vector\"}]},\"QID\":\"101\",\"RESULTS\":\"Package\\tInstalled Version\\tRequired Version\\nlinux-cloud-tools-4.4.0\\t1074-aws_4.4.0-1074.84\\t1092\\nlinux-aws-tools-4.4.0\\t1074_4.4.0-1074.84\\t1092\\nlinux-aws-headers-4.4.0\\t1074_4.15.0-1126.135\\t1092\\nlinux-tools-4.4.0\\t1074-aws_4.4.0-1074.84\\t1092\\nlinux-aws-cloud-tools-4.4.0\\t1074_4.4.0-1074.84\\t1092\",\"SEVERITY\":\"3\",\"SSL\":\"0\",\"STATUS\":\"Active\",\"TIMES_FOUND\":\"5393\",\"TYPE\":\"Confirmed\",\"UNIQUE_VULN_ID\":\"11111111\"},\"DNS\":\"adfssrvr.adfs.local\",\"DNS_DATA\":{\"DOMAIN\":\"adfs.local\",\"FQDN\":\"adfssrvr.adfs.local\",\"HOSTNAME\":\"adfssrvr\"},\"ID\":\"1\",\"IP\":\"10.50.2.111\",\"KNOWLEDGE_BASE\":{\"CATEGORY\":\"CGI\",\"CONSEQUENCE\":\"Depending on the vulnerability being exploited, an unauthenticated remote attacker could conduct cross-site scripting, clickjacking or MIME-type sniffing attacks.\",\"CVE_LIST\":[\"CVE-2022-31629\",\"CVE-2022-31628\"],\"DIAGNOSIS\":\"This QID reports the absence of the following\",\"DISCOVERY\":{\"REMOTE\":\"1\"},\"LAST_SERVICE_MODIFICATION_DATETIME\":\"2023-06-29T12:20:46Z\",\"PATCHABLE\":\"0\",\"PCI_FLAG\":\"1\",\"PUBLISHED_DATETIME\":\"2017-06-05T21:34:49Z\",\"QID\":\"101\",\"SEVERITY_LEVEL\":\"2\",\"SOFTWARE_LIST\":{\"SOFTWARE\":[{\"PRODUCT\":\"None\",\"VENDOR\":\"multi-vendor\"}]},\"SOLUTION\":\"\\u003cB\\u003eNote:\\u003c/B\\u003e To better debug the results of this QID\",\"THREAT_INTELLIGENCE\":{\"THREAT_INTEL\":[{\"id\":\"8\"}]},\"TITLE\":\"HTTP Security Header Not Detected\",\"VULN_TYPE\":\"Vulnerability\"},\"LAST_PC_SCANNED_DATE\":\"2023-06-28T09:58:12Z\",\"LAST_SCAN_DATETIME\":\"2023-07-03T06:25:17Z\",\"LAST_VM_SCANNED_DATE\":\"2023-07-03T06:23:47Z\",\"LAST_VM_SCANNED_DURATION\":\"1113\",\"NETBIOS\":\"ADFSSRVR\",\"OS\":\"Windows 2016/2019/10\",\"TRACKING_METHOD\":\"IP\",\"interval_id\":\"79023675-8d15-45e7-b97a-7674599ac2ff\",\"interval_start\":\"2025-06-06T07:05:24.044972383Z\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "domain": "ADFSSRVR",
        "hostname": "adfssrvr",
        "id": "1",
        "ip": [
            "10.50.2.111"
        ],
        "name": "adfssrvr.adfs.local",
        "os": {
            "full": "Windows 2016/2019/10",
            "platform": "windows",
            "type": "windows"
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "vendor": "Qualys VMDR"
    },
    "package": {
        "fixed_version": [
            "1092",
            "1092",
            "1092",
            "1092",
            "1092"
        ],
        "name": [
            "linux-cloud-tools-4.4.0",
            "linux-aws-tools-4.4.0",
            "linux-aws-headers-4.4.0",
            "linux-tools-4.4.0",
            "linux-aws-cloud-tools-4.4.0"
        ],
        "version": [
            "1074-aws_4.4.0-1074.84",
            "1074_4.4.0-1074.84",
            "1074_4.15.0-1126.135",
            "1074-aws_4.4.0-1074.84",
            "1074_4.4.0-1074.84"
        ]
    },
    "qualys_vmdr": {
        "asset_host_detection": {
            "dns": "adfssrvr.adfs.local",
            "dns_data": {
                "domain": "adfs.local",
                "fqdn": "adfssrvr.adfs.local",
                "hostname": "adfssrvr"
            },
            "id": "1",
            "interval_id": "79023675-8d15-45e7-b97a-7674599ac2ff",
            "interval_start": "2025-06-06T07:05:24.044Z",
            "ip": "10.50.2.111",
            "knowledge_base": {
                "category": "CGI",
                "consequence": {
                    "value": "Depending on the vulnerability being exploited, an unauthenticated remote attacker could conduct cross-site scripting, clickjacking or MIME-type sniffing attacks."
                },
                "cve_list": [
                    "CVE-2022-31629",
                    "CVE-2022-31628"
                ],
                "diagnosis": {
                    "value": "This QID reports the absence of the following"
                },
                "discovery": {
                    "remote": 1
                },
                "last": {
                    "service_modification_datetime": "2023-06-29T12:20:46.000Z"
                },
                "patchable": false,
                "pci_flag": true,
                "published_datetime": "2017-06-05T21:34:49.000Z",
                "qid": "101",
                "severity_level": "Medium",
                "software_list": [
                    {
                        "product": "None",
                        "vendor": "multi-vendor"
                    }
                ],
                "solution": {
                    "value": "<B>Note:</B> To better debug the results of this QID"
                },
                "threat_intelligence": {
                    "intel": [
                        {
                            "id": "8"
                        }
                    ]
                },
                "title": "HTTP Security Header Not Detected",
                "vuln_type": "Vulnerability"
            },
            "last_pc_scanned_date": "2023-06-28T09:58:12.000Z",
            "last_scan_datetime": "2023-07-03T06:25:17.000Z",
            "last_vm_scanned_date": "2023-07-03T06:23:47.000Z",
            "last_vm_scanned_duration": 1113,
            "netbios": "ADFSSRVR",
            "os": "Windows 2016/2019/10",
            "package_nested": [
                {
                    "fixed_version": "1092",
                    "name": "linux-cloud-tools-4.4.0",
                    "version": "1074-aws_4.4.0-1074.84"
                },
                {
                    "fixed_version": "1092",
                    "name": "linux-aws-tools-4.4.0",
                    "version": "1074_4.4.0-1074.84"
                },
                {
                    "fixed_version": "1092",
                    "name": "linux-aws-headers-4.4.0",
                    "version": "1074_4.15.0-1126.135"
                },
                {
                    "fixed_version": "1092",
                    "name": "linux-tools-4.4.0",
                    "version": "1074-aws_4.4.0-1074.84"
                },
                {
                    "fixed_version": "1092",
                    "name": "linux-aws-cloud-tools-4.4.0",
                    "version": "1074_4.4.0-1074.84"
                }
            ],
            "tracking_method": "IP",
            "vulnerability": {
                "affect_running_kernel": "0",
                "first_found_datetime": "2021-02-05T04:50:45.000Z",
                "is_disabled": false,
                "is_ignored": false,
                "last_fixed_datetime": "2022-12-14T06:52:57.000Z",
                "last_found_datetime": "2024-03-08T20:15:41.000Z",
                "last_processed_datetime": "2024-03-08T20:15:41.000Z",
                "last_test_datetime": "2024-03-08T20:15:41.000Z",
                "last_update_datetime": "2024-03-08T20:15:41.000Z",
                "qds": {
                    "score": 35,
                    "severity": "LOW"
                },
                "qds_factors": [
                    {
                        "name": "CVSS",
                        "text": "7.7"
                    },
                    {
                        "name": "CVSS_version",
                        "text": "v3.x"
                    },
                    {
                        "name": "epss",
                        "text": "0.00232"
                    },
                    {
                        "name": "CVSS_vector",
                        "text": "AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H"
                    }
                ],
                "qid": 101,
                "results": "Package||Installed Version||Required Version;;linux-cloud-tools-4.4.0||1074-aws_4.4.0-1074.84||1092;;linux-aws-tools-4.4.0||1074_4.4.0-1074.84||1092;;linux-aws-headers-4.4.0||1074_4.15.0-1126.135||1092;;linux-tools-4.4.0||1074-aws_4.4.0-1074.84||1092;;linux-aws-cloud-tools-4.4.0||1074_4.4.0-1074.84||1092",
                "severity": 3,
                "ssl": "0",
                "status": "Active",
                "times_found": 5393,
                "type": "Confirmed",
                "unique_vuln_id": "11111111"
            }
        }
    },
    "related": {
        "hosts": [
            "adfssrvr",
            "adfssrvr.adfs.local",
            "1",
            "ADFSSRVR"
        ],
        "ip": [
            "10.50.2.111"
        ]
    },
    "resource": {
        "id": "1",
        "name": "adfssrvr.adfs.local"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "qualys_vmdr-asset_host_detection",
        "provider_cloud_data"
    ],
    "vulnerability": {
        "category": [
            "CGI"
        ],
        "classification": "CVSS",
        "description": "This QID reports the absence of the following",
        "enumeration": "CVE",
        "id": [
            "CVE-2022-31629",
            "CVE-2022-31628"
        ],
        "package": {
            "fixed_version": [
                "1092",
                "1092",
                "1092",
                "1092",
                "1092"
            ],
            "name": [
                "linux-cloud-tools-4.4.0",
                "linux-aws-tools-4.4.0",
                "linux-aws-headers-4.4.0",
                "linux-tools-4.4.0",
                "linux-aws-cloud-tools-4.4.0"
            ],
            "version": [
                "1074-aws_4.4.0-1074.84",
                "1074_4.4.0-1074.84",
                "1074_4.15.0-1126.135",
                "1074-aws_4.4.0-1074.84",
                "1074_4.4.0-1074.84"
            ]
        },
        "reference": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31629",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31628"
        ],
        "scanner": {
            "vendor": "Qualys"
        },
        "score": {
            "base": 7.7
        },
        "severity": "high",
        "title": "HTTP Security Header Not Detected"
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
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| package.fixed_version |  | keyword |
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
| qualys_vmdr.asset_host_detection.interval_id | The universally unique identifier (UUID) values will change with each interval of ingestion. | keyword |
| qualys_vmdr.asset_host_detection.interval_start | The start time of the interval of ingestion. | date |
| qualys_vmdr.asset_host_detection.ip |  | ip |
| qualys_vmdr.asset_host_detection.ipv6 |  | ip |
| qualys_vmdr.asset_host_detection.knowledge_base.automatic_pci_fail |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.bugtraq_list.id |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.bugtraq_list.url |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.category |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.changelog_list.info.change_date |  | date |
| qualys_vmdr.asset_host_detection.knowledge_base.changelog_list.info.comments |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.compliance_list.description |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.compliance_list.section |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.compliance_list.type |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.consequence.comment |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.consequence.value |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.correlation.exploits.explt_src.list.explt.desc |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.correlation.exploits.explt_src.list.explt.link |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.correlation.exploits.explt_src.list.explt.ref |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.correlation.exploits.explt_src.name |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.correlation.malware.src.list.info.alias |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.correlation.malware.src.list.info.id |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.correlation.malware.src.list.info.link |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.correlation.malware.src.list.info.platform |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.correlation.malware.src.list.info.rating |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.correlation.malware.src.list.info.type |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.correlation.malware.src.name |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cve_list |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.access.complexity |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.access.vector |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.authentication |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.base |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.base_obj |  | flattened |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.exploitability |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.impact.availability |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.impact.confidentiality |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.impact.integrity |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.remediation_level |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.report_confidence |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.temporal |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss.vector_string |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.attack.complexity |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.attack.vector |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.base |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.exploit_code_maturity |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.impact.availability |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.impact.confidentiality |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.impact.integrity |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.privileges_required |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.remediation_level |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.report_confidence |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.scope |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.temporal |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.user_interaction |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.vector_string |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.cvss_v3.version |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.detection_info |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.diagnosis.comment |  | match_only_text |
| qualys_vmdr.asset_host_detection.knowledge_base.diagnosis.value |  | match_only_text |
| qualys_vmdr.asset_host_detection.knowledge_base.discovery.additional_info |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.discovery.auth_type_list.value |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.discovery.remote |  | long |
| qualys_vmdr.asset_host_detection.knowledge_base.error |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.id_range |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.ids |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.is_disabled |  | boolean |
| qualys_vmdr.asset_host_detection.knowledge_base.last.customization.datetime |  | date |
| qualys_vmdr.asset_host_detection.knowledge_base.last.customization.user_login |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.last.service_modification_datetime |  | date |
| qualys_vmdr.asset_host_detection.knowledge_base.patch_published_date |  | date |
| qualys_vmdr.asset_host_detection.knowledge_base.patchable |  | boolean |
| qualys_vmdr.asset_host_detection.knowledge_base.pci_flag |  | boolean |
| qualys_vmdr.asset_host_detection.knowledge_base.pci_reasons.value |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.published_datetime |  | date |
| qualys_vmdr.asset_host_detection.knowledge_base.qid |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.severity_level |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.software_list.product |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.software_list.vendor |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.solution.comment |  | match_only_text |
| qualys_vmdr.asset_host_detection.knowledge_base.solution.value |  | match_only_text |
| qualys_vmdr.asset_host_detection.knowledge_base.supported_modules |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.threat_intelligence.intel.id |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.threat_intelligence.intel.text |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.title |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.vendor_reference_list.id |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.vendor_reference_list.url |  | keyword |
| qualys_vmdr.asset_host_detection.knowledge_base.vuln_type |  | keyword |
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
| qualys_vmdr.asset_host_detection.package_nested |  | nested |
| qualys_vmdr.asset_host_detection.package_nested.fixed_version |  | keyword |
| qualys_vmdr.asset_host_detection.package_nested.name |  | keyword |
| qualys_vmdr.asset_host_detection.package_nested.version |  | keyword |
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
| resource.id |  | keyword |
| resource.name |  | keyword |
| vulnerability.package.fixed_version |  | keyword |
| vulnerability.package.name |  | keyword |
| vulnerability.package.version |  | keyword |
| vulnerability.scanner.vendor | The name of the vulnerability scanner vendor. | constant_keyword |
| vulnerability.title |  | keyword |


### Knowledge base

This is the `Knowledge Base` dataset.

#### Example

An example event for `knowledge_base` looks as following:

```json
{
    "@timestamp": "2023-06-29T12:20:46.000Z",
    "agent": {
        "ephemeral_id": "4e6d92f6-8a28-471c-a03f-8c2685171b7b",
        "id": "dc86e78e-6670-441f-acdd-99309474050f",
        "name": "elastic-agent-65730",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "qualys_vmdr.knowledge_base",
        "namespace": "47901",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "dc86e78e-6670-441f-acdd-99309474050f",
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
        "ingested": "2024-09-25T21:49:31Z",
        "kind": "alert",
        "original": "{\"CATEGORY\":\"CGI\",\"CONSEQUENCE\":\"\",\"CVE_LIST\":[\"CVE-2022-31629\",\"CVE-2022-31628\"],\"DIAGNOSIS\":\"\",\"DISCOVERY\":{\"REMOTE\":\"1\"},\"LAST_SERVICE_MODIFICATION_DATETIME\":\"2023-06-29T12:20:46Z\",\"PATCHABLE\":\"0\",\"PCI_FLAG\":\"1\",\"PUBLISHED_DATETIME\":\"2017-06-05T21:34:49Z\",\"QID\":\"11830\",\"SEVERITY_LEVEL\":\"2\",\"SOFTWARE_LIST\":{\"SOFTWARE\":[{\"PRODUCT\":\"\",\"VENDOR\":\"\"}]},\"SOLUTION\":\"\",\"THREAT_INTELLIGENCE\":{\"THREAT_INTEL\":[{\"id\":\"8\"}]},\"TITLE\":\"\",\"VULN_TYPE\":\"Vulnerability\"}",
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
| qualys_vmdr.knowledge_base.diagnosis.comment |  | match_only_text |
| qualys_vmdr.knowledge_base.diagnosis.value |  | match_only_text |
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
| qualys_vmdr.knowledge_base.patch_published_date |  | date |
| qualys_vmdr.knowledge_base.patchable |  | boolean |
| qualys_vmdr.knowledge_base.pci_flag |  | boolean |
| qualys_vmdr.knowledge_base.pci_reasons.value |  | keyword |
| qualys_vmdr.knowledge_base.published_datetime |  | date |
| qualys_vmdr.knowledge_base.qid |  | keyword |
| qualys_vmdr.knowledge_base.severity_level |  | keyword |
| qualys_vmdr.knowledge_base.software_list.product |  | keyword |
| qualys_vmdr.knowledge_base.software_list.vendor |  | keyword |
| qualys_vmdr.knowledge_base.solution.comment |  | match_only_text |
| qualys_vmdr.knowledge_base.solution.value |  | match_only_text |
| qualys_vmdr.knowledge_base.supported_modules |  | keyword |
| qualys_vmdr.knowledge_base.threat_intelligence.intel.id |  | keyword |
| qualys_vmdr.knowledge_base.threat_intelligence.intel.text |  | keyword |
| qualys_vmdr.knowledge_base.title |  | keyword |
| qualys_vmdr.knowledge_base.vendor_reference_list.id |  | keyword |
| qualys_vmdr.knowledge_base.vendor_reference_list.url |  | keyword |
| qualys_vmdr.knowledge_base.vuln_type |  | keyword |


### User activity

This is the `User Activity` dataset. It connects to an [API](
https://docs.qualys.com/en/vm/api/users/index.htm#t=activity%2Fexport_activity.htm)
that exports the user activity log. 

#### Example

An example event for `user_activity` looks as following:

```json
{
    "@timestamp": "2024-01-18T12:45:24.000Z",
    "agent": {
        "ephemeral_id": "8541dd66-de0a-4e54-a66e-3f9dc02867df",
        "id": "3acf31e6-1468-482c-b38b-d3b7397270dd",
        "name": "elastic-agent-32349",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "qualys_vmdr.user_activity",
        "namespace": "28709",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "3acf31e6-1468-482c-b38b-d3b7397270dd",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "request",
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "dataset": "qualys_vmdr.user_activity",
        "ingested": "2024-09-25T21:52:05Z",
        "kind": "event",
        "original": "{\"Action\":\"request\",\"Date\":\"2024-01-18T12:45:24Z\",\"Details\":\"API: /api/2.0/fo/activity_log/index.php\",\"Module\":\"auth\",\"User IP\":\"10.113.195.136\",\"User Name\":\"john\",\"User Role\":\"Reader\"}",
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
            "Date": "2024-01-18T12:45:24Z",
            "Details": "API: /api/2.0/fo/activity_log/index.php",
            "Module": "auth",
            "User_IP": "10.113.195.136",
            "User_Name": "john",
            "User_Role": "Reader"
        }
    },
    "related": {
        "ip": [
            "10.113.195.136"
        ],
        "user": [
            "john"
        ]
    },
    "source": {
        "ip": "10.113.195.136"
    },
    "tags": [
        "preserve_duplicate_custom_fields",
        "preserve_original_event",
        "forwarded",
        "qualys_vmdr-user_activity"
    ],
    "user": {
        "name": "john",
        "roles": [
            "Reader"
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
