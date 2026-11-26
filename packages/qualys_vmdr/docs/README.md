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

### Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

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
    "@timestamp": "2026-08-05T21:44:21.686Z",
    "agent": {
        "ephemeral_id": "b0db066d-696a-4c82-a2a9-9a7436e32f00",
        "id": "960204fc-0824-4557-a45e-858a5f6c6c99",
        "name": "elastic-agent-90390",
        "type": "filebeat",
        "version": "8.19.11"
    },
    "cloud": {
        "instance": {
            "name": "noscore"
        }
    },
    "data_stream": {
        "dataset": "qualys_vmdr.asset_host_detection",
        "namespace": "94127",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "960204fc-0824-4557-a45e-858a5f6c6c99",
        "snapshot": false,
        "version": "8.19.11"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "qualys_vmdr.asset_host_detection",
        "id": "99999991",
        "ingested": "2026-08-05T21:44:24Z",
        "kind": "alert",
        "original": "{\"DETECTION_LIST\":{\"AFFECT_RUNNING_KERNEL\":\"0\",\"FIRST_FOUND_DATETIME\":\"2021-02-05T04:50:45Z\",\"IS_DISABLED\":\"0\",\"IS_IGNORED\":\"0\",\"LAST_FOUND_DATETIME\":\"2024-03-08T20:15:41Z\",\"LAST_PROCESSED_DATETIME\":\"2024-03-08T20:15:41Z\",\"LAST_TEST_DATETIME\":\"2024-03-08T20:15:41Z\",\"LAST_UPDATE_DATETIME\":\"2024-03-08T20:15:41Z\",\"QID\":\"102\",\"SEVERITY\":\"5\",\"SSL\":\"0\",\"STATUS\":\"Active\",\"TIMES_FOUND\":\"5393\",\"TYPE\":\"Confirmed\",\"UNIQUE_VULN_ID\":\"99999991\"},\"DNS\":\"noscore.adfs.local\",\"DNS_DATA\":{\"DOMAIN\":\"adfs.local\",\"FQDN\":\"noscore.adfs.local\",\"HOSTNAME\":\"noscore\"},\"ID\":\"9\",\"IP\":\"10.50.2.119\",\"KNOWLEDGE_BASE\":{\"CATEGORY\":\"Security Policy\",\"CODE_MODIFIED_DATETIME\":\"2024-07-29T12:47:11Z\",\"CONSEQUENCE\":\"Apache no longer provides security updates for 1.x versions. Obsolete software is more vulnerable to viruses and other attacks.\\u003cP\\u003e\",\"CVE_LIST\":[\"CVE-2019-14835\"],\"CVSS\":{\"BASE\":{\"#text\":\"10.0\",\"source\":\"service\"},\"TEMPORAL\":\"8.5\",\"VECTOR_STRING\":\"CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:U/RC:C\"},\"CVSS_V3\":{\"BASE\":\"10.0\",\"CVSS3_VERSION\":\"3.1\",\"TEMPORAL\":\"9.1\",\"VECTOR_STRING\":\"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:U/RC:C\"},\"DIAGNOSIS\":\"On August 5, 2015, the Apache Logging Services Project Management Committee (PMC) has announced that the Log4j 1.x logging framework has reached its end of life (EOL) and is no longer officially supported.\\u003cBR\\u003e\\n\\n    \\u003cP\\u003eQID Detection: (Authenticated) - Linux\\u003cBR\\u003e\\n    This QID uses the OS package manager, locate command and ls proc command to check vulnerable versions of log4j\\u003cP\\u003e\\n\\n    \\u003cP\\u003eQID Detection: (Authenticated) - MacOS\\u003cBR\\u003e\\n    This QID uses the locate command and mdfind command to check vulnerable versions of log4j\\u003cBR\\u003e\\n\\n    QID Detection: (Authenticated) - Windows\\u003cBR\\u003e\\n    On Windows system, the QID identifies vulnerable instance of log4j via WMI query to check log4j included in the running processes via command-line.\\n    \\u003cP\\u003e\",\"DISCOVERY\":{\"AUTH_TYPE_LIST\":{\"AUTH_TYPE\":[\"Unix\",\"Windows\"]},\"REMOTE\":\"0\"},\"LAST_SERVICE_MODIFICATION_DATETIME\":\"2024-07-29T12:47:11Z\",\"PATCHABLE\":\"0\",\"PCI_FLAG\":\"1\",\"PUBLISHED_DATETIME\":\"2022-01-12T13:25:56Z\",\"QID\":\"102\",\"SEVERITY_LEVEL\":\"5\",\"SOFTWARE_LIST\":{\"SOFTWARE\":[{\"PRODUCT\":\"log4j\",\"VENDOR\":\"apache\"}]},\"SOLUTION\":\"Customers are advised to upgrade to Apache Log4j 2.X, for more information please refer to \\u003cA HREF=\\\"https://blogs.apache.org/foundation/entry/apache_logging_services_project_announces\\\" TARGET=\\\"_blank\\\"\\u003e Apache Blog\\u003c/A\\u003e.\\u003cBR\\u003e\",\"THREAT_INTELLIGENCE\":{\"THREAT_INTEL\":[{\"#text\":\"High_Lateral_Movement\",\"id\":\"4\"},{\"#text\":\"Easy_Exploit\",\"id\":\"5\"},{\"#text\":\"High_Data_Loss\",\"id\":\"6\"},{\"#text\":\"Denial_of_Service\",\"id\":\"7\"},{\"#text\":\"No_Patch\",\"id\":\"8\"},{\"#text\":\"Privilege_Escalation\",\"id\":\"13\"},{\"#text\":\"Remote_Code_Execution\",\"id\":\"15\"}]},\"TITLE\":\"EOL/Obsolete Software: Apache Log4j 1.X Detected\",\"VENDOR_REFERENCE_LIST\":{\"VENDOR_REFERENCE\":[{\"ID\":\"Apache Log4j Security Advisory\",\"URL\":\"https://blogs.apache.org/foundation/entry/apache_logging_services_project_announces\"}]},\"VULN_TYPE\":\"Vulnerability\"},\"LAST_PC_SCANNED_DATE\":\"2023-06-28T09:58:12Z\",\"LAST_SCAN_DATETIME\":\"2023-07-03T06:25:17Z\",\"LAST_VM_SCANNED_DATE\":\"2023-07-03T06:23:47Z\",\"LAST_VM_SCANNED_DURATION\":\"1113\",\"NETBIOS\":\"NOSCORE\",\"OS\":\"Windows 2016/2019/10\",\"TRACKING_METHOD\":\"IP\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "domain": "NOSCORE",
        "hostname": "noscore",
        "id": "9",
        "ip": [
            "10.50.2.119"
        ],
        "name": "noscore.adfs.local",
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
    "qualys_vmdr": {
        "asset_host_detection": {
            "dns": "noscore.adfs.local",
            "dns_data": {
                "domain": "adfs.local",
                "fqdn": "noscore.adfs.local",
                "hostname": "noscore"
            },
            "id": "9",
            "interval_id": "2069808d-baa0-4408-8333-f15c65f6390a",
            "interval_start": "2026-08-05T21:44:21.683Z",
            "ip": "10.50.2.119",
            "knowledge_base": {
                "category": "Security Policy",
                "consequence": {
                    "value": "Apache no longer provides security updates for 1.x versions. Obsolete software is more vulnerable to viruses and other attacks.<P>"
                },
                "cve_list": [
                    "CVE-2019-14835"
                ],
                "cvss": {
                    "base_obj": {
                        "#text": "10.0",
                        "source": "service"
                    },
                    "temporal": "8.5",
                    "vector_string": "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:U/RC:C"
                },
                "cvss_v3": {
                    "base": "10.0",
                    "temporal": "9.1",
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:U/RC:C",
                    "version": "3.1"
                },
                "diagnosis": {
                    "value": "On August 5, 2015, the Apache Logging Services Project Management Committee (PMC) has announced that the Log4j 1.x logging framework has reached its end of life (EOL) and is no longer officially supported.<BR>\n\n    <P>QID Detection: (Authenticated) - Linux<BR>\n    This QID uses the OS package manager, locate command and ls proc command to check vulnerable versions of log4j<P>\n\n    <P>QID Detection: (Authenticated) - MacOS<BR>\n    This QID uses the locate command and mdfind command to check vulnerable versions of log4j<BR>\n\n    QID Detection: (Authenticated) - Windows<BR>\n    On Windows system, the QID identifies vulnerable instance of log4j via WMI query to check log4j included in the running processes via command-line.\n    <P>"
                },
                "discovery": {
                    "auth_type_list": {
                        "value": [
                            "Unix",
                            "Windows"
                        ]
                    },
                    "remote": 0
                },
                "last": {
                    "service_modification_datetime": "2024-07-29T12:47:11.000Z"
                },
                "patchable": false,
                "pci_flag": true,
                "published_datetime": "2022-01-12T13:25:56.000Z",
                "qid": "102",
                "severity_level": "Urgent",
                "software_list": [
                    {
                        "product": "log4j",
                        "vendor": "apache"
                    }
                ],
                "solution": {
                    "value": "Customers are advised to upgrade to Apache Log4j 2.X, for more information please refer to <A HREF=\"https://blogs.apache.org/foundation/entry/apache_logging_services_project_announces\" TARGET=\"_blank\"> Apache Blog</A>.<BR>"
                },
                "status": "found",
                "threat_intelligence": {
                    "intel": [
                        {
                            "id": "4",
                            "text": "High_Lateral_Movement"
                        },
                        {
                            "id": "5",
                            "text": "Easy_Exploit"
                        },
                        {
                            "id": "6",
                            "text": "High_Data_Loss"
                        },
                        {
                            "id": "7",
                            "text": "Denial_of_Service"
                        },
                        {
                            "id": "8",
                            "text": "No_Patch"
                        },
                        {
                            "id": "13",
                            "text": "Privilege_Escalation"
                        },
                        {
                            "id": "15",
                            "text": "Remote_Code_Execution"
                        }
                    ]
                },
                "title": "EOL/Obsolete Software: Apache Log4j 1.X Detected",
                "vendor_reference_list": [
                    {
                        "id": "Apache Log4j Security Advisory",
                        "url": "https://blogs.apache.org/foundation/entry/apache_logging_services_project_announces"
                    }
                ],
                "vuln_type": "Vulnerability"
            },
            "last_pc_scanned_date": "2023-06-28T09:58:12.000Z",
            "last_scan_datetime": "2023-07-03T06:25:17.000Z",
            "last_vm_scanned_date": "2023-07-03T06:23:47.000Z",
            "last_vm_scanned_duration": 1113,
            "netbios": "NOSCORE",
            "os": "Windows 2016/2019/10",
            "tracking_method": "IP",
            "vulnerability": {
                "affect_running_kernel": "0",
                "first_found_datetime": "2021-02-05T04:50:45.000Z",
                "is_disabled": false,
                "is_ignored": false,
                "last_found_datetime": "2024-03-08T20:15:41.000Z",
                "last_processed_datetime": "2024-03-08T20:15:41.000Z",
                "last_test_datetime": "2024-03-08T20:15:41.000Z",
                "last_update_datetime": "2024-03-08T20:15:41.000Z",
                "qid": 102,
                "severity": 5,
                "ssl": "0",
                "status": "Active",
                "times_found": 5393,
                "type": "Confirmed",
                "unique_vuln_id": "99999991"
            }
        }
    },
    "related": {
        "hosts": [
            "noscore",
            "noscore.adfs.local",
            "9",
            "NOSCORE"
        ],
        "ip": [
            "10.50.2.119"
        ]
    },
    "resource": {
        "id": "9",
        "name": "noscore.adfs.local"
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
            "Security Policy"
        ],
        "classification": "CVSS",
        "description": "On August 5, 2015, the Apache Logging Services Project Management Committee (PMC) has announced that the Log4j 1.x logging framework has reached its end of life (EOL) and is no longer officially supported.<BR>\n\n    <P>QID Detection: (Authenticated) - Linux<BR>\n    This QID uses the OS package manager, locate command and ls proc command to check vulnerable versions of log4j<P>\n\n    <P>QID Detection: (Authenticated) - MacOS<BR>\n    This QID uses the locate command and mdfind command to check vulnerable versions of log4j<BR>\n\n    QID Detection: (Authenticated) - Windows<BR>\n    On Windows system, the QID identifies vulnerable instance of log4j via WMI query to check log4j included in the running processes via command-line.\n    <P>",
        "enumeration": "CVE",
        "id": [
            "CVE-2019-14835"
        ],
        "reference": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14835"
        ],
        "scanner": {
            "vendor": "Qualys"
        },
        "score": {
            "base": 10,
            "version": "3.1"
        },
        "severity": "Critical",
        "title": "EOL/Obsolete Software: Apache Log4j 1.X Detected"
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
| qualys_vmdr.asset_host_detection.knowledge_base.status | Indicates whether the QID was found in the Knowledge Base (`found`) or not (`not_found`). | keyword |
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
| qualys_vmdr.asset_host_detection.metadata.alicloud.attribute.last.error.date |  | date |
| qualys_vmdr.asset_host_detection.metadata.alicloud.attribute.last.error.value |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.alicloud.attribute.last.status |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.alicloud.attribute.last.success_date |  | date |
| qualys_vmdr.asset_host_detection.metadata.alicloud.attribute.name |  | keyword |
| qualys_vmdr.asset_host_detection.metadata.alicloud.attribute.value |  | keyword |
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
| qualys_vmdr.asset_host_detection.vulnerability.cve |  | keyword |
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
| qualys_vmdr.asset_host_detection.vulnerability.latest_vulnerability_detection_source |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.mitre_tactic_id |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.mitre_tactic_name |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.mitre_technique_id |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.mitre_technique_name |  | keyword |
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
| qualys_vmdr.asset_host_detection.vulnerability.trurisk_elimination_status |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.type |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.unique_vuln_id |  | keyword |
| qualys_vmdr.asset_host_detection.vulnerability.vulnerability_detection_sources |  | keyword |
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
        "ephemeral_id": "da0816f0-0acb-432d-aabc-40ff74ab0b83",
        "id": "af521d3d-fb8f-4a9e-b30a-9c41a680f7d2",
        "name": "elastic-agent-33894",
        "type": "filebeat",
        "version": "8.19.11"
    },
    "data_stream": {
        "dataset": "qualys_vmdr.knowledge_base",
        "namespace": "64767",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "af521d3d-fb8f-4a9e-b30a-9c41a680f7d2",
        "snapshot": false,
        "version": "8.19.11"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "qualys_vmdr.knowledge_base",
        "id": "11830",
        "ingested": "2026-02-25T04:32:39Z",
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
        "ephemeral_id": "e216870f-7101-4fad-9724-9b71ed9ad95c",
        "id": "15eb4582-ca67-48f0-9af3-72657ed5967e",
        "name": "elastic-agent-45371",
        "type": "filebeat",
        "version": "8.19.11"
    },
    "data_stream": {
        "dataset": "qualys_vmdr.user_activity",
        "namespace": "32843",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "15eb4582-ca67-48f0-9af3-72657ed5967e",
        "snapshot": false,
        "version": "8.19.11"
    },
    "event": {
        "action": "request",
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "dataset": "qualys_vmdr.user_activity",
        "ingested": "2026-02-25T04:33:31Z",
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
