# Rapid7 InsightVM

## Overview

The [Rapid7 InsightVM](https://www.rapid7.com/products/insightvm/) integration allows users to monitor Asset and Vulnerability Events. Rapid7 InsightVM discovers risks across all your endpoints, cloud, and virtualized infrastructure. Prioritize risks and provide step-by-step directions to IT and DevOps for more efficient remediation. View your risk in real-time right from your dashboard. Measure and communicate progress on your program goals.

Use the Rapid7 InsightVM integration to collect and parse data from the REST APIs. Then visualize that data in Kibana.

## Data streams

The Rapid7 InsightVM integration collects two type of events: Asset and Vulnerability.

**Asset (Deprecated)** is used to get details related to inventory, assessment, and summary details of assets that the user has access to. See more details in the API documentation [here](https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/searchIntegrationAssets). It is deprecated in version `2.0.0`. Instead, use the `Asset Vulnerability` data stream for enriched vulnerability documents and improved mappings.

**Asset Vulnerability** is used to gather and aggregate data on assets and vulnerabilities to support Native CDR Workflows.

**Vulnerability** is used to retrieve all vulnerabilities that can be assessed. See more details in the API documentation [here](https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/searchIntegrationVulnerabilities).

## Requirements

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

This module uses **InsightVM Cloud Integrations API v4**.

## Setup

### To collect data from the Rapid7 InsightVM APIs, follow the below steps:

1. Generate the platform API key to access all Rapid7 InsightVM APIs. For more details, see [Documentation](https://docs.rapid7.com/insight/managing-platform-api-keys).

## Troubleshooting

### Breaking Changes

#### Support for Elastic Vulnerability Findings page.

Version `2.0.0` of the Rapid7 InsightVM integration adds support for [Elastic Cloud Security workflow](https://www.elastic.co/docs/solutions/security/cloud/ingest-third-party-cloud-security-data#_ingest_third_party_security_posture_and_vulnerability_data). The enhancement enables the users of Rapid7 InsightVM integration to ingest their enriched asset vulnerabilities from Rapid7 InsightVM platform into Elastic and get insights directly from Elastic [Vulnerability Findings page](https://www.elastic.co/docs/solutions/security/cloud/findings-page-3).
This update adds [Elastic Latest Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview) which copies the latest vulnerability findings from source indices matching the pattern `logs-rapid7_insightvm.asset_vulnerability-*` into new destination indices matching the pattern `security_solution-rapid7_insightvm.vulnerability_latest-*`. The Elastic Vulnerability Findings page will display vulnerabilities based on the destination indices.

For existing users of Rapid7 InsightVM integration, before upgrading to `2.0.0` please ensure following requirements are met:

1. Users need [Elastic Security solution](https://www.elastic.co/docs/solutions/security) which has requirements documented [here](https://www.elastic.co/docs/solutions/security/get-started/elastic-security-requirements).
2. To use transforms, users must have:
   - at least one [transform node](https://www.elastic.co/docs/deploy-manage/distributed-architecture/clusters-nodes-shards/node-roles#transform-node-role),
   - management features visible in the Kibana space, and
   - security privileges that:
     - grant use of transforms, and
     - grant access to source and destination indices
   For more details on Transform Setup, refer to the link [here](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup)
3. Because the latest copy of vulnerabilities is now indexed in two places, i.e., in both source and destination indices, users must anticipate storage requirements accordingly.

## Logs Reference

### asset

This is the `asset` dataset.

#### Example

An example event for `asset` looks as following:

```json
{
    "@timestamp": "2025-05-30T11:10:37.869Z",
    "agent": {
        "ephemeral_id": "6545769f-e426-4e1c-9549-44bd7f788ee4",
        "id": "afb159d9-5bc3-429a-b8a7-3cda969112a5",
        "name": "elastic-agent-88629",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "rapid7_insightvm.asset",
        "namespace": "81787",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "afb159d9-5bc3-429a-b8a7-3cda969112a5",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "created": "2025-05-30T11:10:37.869Z",
        "dataset": "rapid7_insightvm.asset",
        "ingested": "2025-05-30T11:10:40Z",
        "kind": "state",
        "original": "{\"assessed_for_policies\":false,\"assessed_for_vulnerabilities\":true,\"critical_vulnerabilities\":0,\"exploits\":0,\"id\":\"452534235-25a7-40a3-9321-28ce0b5cc90e-default-asset-199\",\"ip\":\"10.1.0.128\",\"last_assessed_for_vulnerabilities\":\"2020-03-20T19:19:42.611Z\",\"last_scan_end\":\"2020-03-20T19:19:42.611Z\",\"last_scan_start\":\"2020-03-20T19:18:13.611Z\",\"malware_kits\":0,\"moderate_vulnerabilities\":2,\"new\":[],\"os_architecture\":\"x86_64\",\"os_description\":\"CentOS Linux 2.6.18\",\"os_family\":\"Linux\",\"os_name\":\"Linux\",\"os_system_name\":\"CentOS Linux\",\"os_type\":\"General\",\"os_vendor\":\"CentOS\",\"os_version\":\"2.6.18\",\"remediated\":[],\"risk_score\":0,\"severe_vulnerabilities\":0,\"tags\":[{\"name\":\"lab\",\"type\":\"SITE\"}],\"total_vulnerabilities\":2}",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "id": "452534235-25a7-40a3-9321-28ce0b5cc90e-default-asset-199",
        "ip": [
            "10.1.0.128"
        ],
        "os": {
            "family": "Linux",
            "full": "CentOS Linux 2.6.18",
            "name": "Linux",
            "version": "2.6.18"
        },
        "risk": {
            "static_score": 0
        }
    },
    "input": {
        "type": "httpjson"
    },
    "rapid7": {
        "insightvm": {
            "asset": {
                "assessed_for_policies": false,
                "assessed_for_vulnerabilities": true,
                "critical_vulnerabilities": 0,
                "exploits": 0,
                "id": "452534235-25a7-40a3-9321-28ce0b5cc90e-default-asset-199",
                "ip": "10.1.0.128",
                "last_assessed_for_vulnerabilities": "2020-03-20T19:19:42.611Z",
                "last_scan_end": "2020-03-20T19:19:42.611Z",
                "last_scan_start": "2020-03-20T19:18:13.611Z",
                "malware_kits": 0,
                "moderate_vulnerabilities": 2,
                "os": {
                    "architecture": "x86_64",
                    "description": "CentOS Linux 2.6.18",
                    "family": "Linux",
                    "name": "Linux",
                    "system_name": "CentOS Linux",
                    "type": "General",
                    "vendor": "CentOS",
                    "version": "2.6.18"
                },
                "risk_score": 0,
                "severe_vulnerabilities": 0,
                "tags": [
                    {
                        "name": "lab",
                        "type": "SITE"
                    }
                ],
                "total_vulnerabilities": 2
            }
        }
    },
    "related": {
        "ip": [
            "10.1.0.128"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "rapid7_insightvm-asset"
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
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| rapid7.insightvm.asset.assessed_for_policies | Whether an asset was assessed for policies. | boolean |
| rapid7.insightvm.asset.assessed_for_vulnerabilities | Whether an asset was assessed for vulnerabilities. | boolean |
| rapid7.insightvm.asset.credential_assessments.port | The port the authentication was used on. | long |
| rapid7.insightvm.asset.credential_assessments.protocol | The protocol the authentication was used on. | keyword |
| rapid7.insightvm.asset.credential_assessments.status | The authentication of the last scan performed. | keyword |
| rapid7.insightvm.asset.critical_vulnerabilities | The count of critical vulnerability findings. | long |
| rapid7.insightvm.asset.exploits | The count of known unique exploits that can be used to exploit vulnerabilities on the asset. | long |
| rapid7.insightvm.asset.host_name | The host name (local or FQDN). | keyword |
| rapid7.insightvm.asset.id | The identifier of the asset. | keyword |
| rapid7.insightvm.asset.ip | The IPv4 or IPv6 address. | ip |
| rapid7.insightvm.asset.last_assessed_for_vulnerabilities | The time at which an asset was assessed for vulnerabilities. | date |
| rapid7.insightvm.asset.last_scan_end | The time at which the last scan of the asset ended. | date |
| rapid7.insightvm.asset.last_scan_start | The time at which the last scan of the asset started. | date |
| rapid7.insightvm.asset.mac | The Media Access Control (MAC) address. The format is six groups of two hexadecimal digits separated by colons. | keyword |
| rapid7.insightvm.asset.malware_kits | The count of known unique malware kits that can be used to attack vulnerabilities on the asset. | long |
| rapid7.insightvm.asset.moderate_vulnerabilities | The count of moderate vulnerability findings. | long |
| rapid7.insightvm.asset.new.check_id | The identifier of the vulnerability check. | keyword |
| rapid7.insightvm.asset.new.first_found | The first time the vulnerability was discovered. | date |
| rapid7.insightvm.asset.new.key | The identifier of the assessment key. | keyword |
| rapid7.insightvm.asset.new.last_found | The most recent time the vulnerability was discovered. | date |
| rapid7.insightvm.asset.new.port | For services vulnerabilities, the port that is vulnerable. | long |
| rapid7.insightvm.asset.new.proof | The identifier of the vulnerability proof. | keyword |
| rapid7.insightvm.asset.new.protocol | For services vulnerabilities, the protocol that is vulnerable. | keyword |
| rapid7.insightvm.asset.new.solution.fix | The solution fix for the vulnerability. | keyword |
| rapid7.insightvm.asset.new.solution.id | The identifier of the solution for the vulnerability. | keyword |
| rapid7.insightvm.asset.new.solution.summary | The summary for the solution for the vulnerability. | keyword |
| rapid7.insightvm.asset.new.solution.type | The solution type for the vulnerability. | keyword |
| rapid7.insightvm.asset.new.status | Enum: "EXCEPTION_VULN_EXPL" "UNEXPECTED_ERR" "NOT_VULN_DONT_STORE" "SUPERSEDED" "EXCEPTION_VULN_POTL" "VULNERABLE_EXPL" "OVERRIDDEN_VULN_VERS" "SKIPPED_DISABLED" "VULNERABLE_VERS" "VULNERABLE_POTENTIAL" "SKIPPED_VERS" "EXCEPTION_VULN_VERS" "NOT_VULNERABLE" "UNKNOWN" "SKIPPED_DOS" The status of the vulnerability finding. | keyword |
| rapid7.insightvm.asset.new.vulnerability_id | The identifier of the vulnerability. | keyword |
| rapid7.insightvm.asset.os.architecture | The architecture of the operating system. | keyword |
| rapid7.insightvm.asset.os.description | The description of the operating system (containing vendor, family, product, version and architecture in a single string). | keyword |
| rapid7.insightvm.asset.os.family | The family of the operating system. | keyword |
| rapid7.insightvm.asset.os.name | The name of the operating system. | keyword |
| rapid7.insightvm.asset.os.system_name | A combination of vendor and family (with redundancies removed), suitable for grouping. | keyword |
| rapid7.insightvm.asset.os.type | The type of operating system. | keyword |
| rapid7.insightvm.asset.os.vendor | The vendor of the operating system. | keyword |
| rapid7.insightvm.asset.os.version | The version of the operating system. | keyword |
| rapid7.insightvm.asset.remediated.check_id | The identifier of the vulnerability check. | keyword |
| rapid7.insightvm.asset.remediated.first_found | The first time the vulnerability was discovered. | date |
| rapid7.insightvm.asset.remediated.key | The identifier of the assessment key. | keyword |
| rapid7.insightvm.asset.remediated.last_found | The most recent time the vulnerability was discovered. | date |
| rapid7.insightvm.asset.remediated.port | For services vulnerabilities, the port that is vulnerable. | long |
| rapid7.insightvm.asset.remediated.proof | The identifier of the vulnerability proof. | keyword |
| rapid7.insightvm.asset.remediated.protocol | For services vulnerabilities, the protocol that is vulnerable. | keyword |
| rapid7.insightvm.asset.remediated.solution.fix | The solution fix for the vulnerability. | keyword |
| rapid7.insightvm.asset.remediated.solution.id | The identifier of the solution for the vulnerability. | keyword |
| rapid7.insightvm.asset.remediated.solution.summary | The summary for the solution for the vulnerability. | keyword |
| rapid7.insightvm.asset.remediated.solution.type | The solution type for the vulnerability. | keyword |
| rapid7.insightvm.asset.remediated.status | Enum: "EXCEPTION_VULN_EXPL" "UNEXPECTED_ERR" "NOT_VULN_DONT_STORE" "SUPERSEDED" "EXCEPTION_VULN_POTL" "VULNERABLE_EXPL" "OVERRIDDEN_VULN_VERS" "SKIPPED_DISABLED" "VULNERABLE_VERS" "VULNERABLE_POTENTIAL" "SKIPPED_VERS" "EXCEPTION_VULN_VERS" "NOT_VULNERABLE" "UNKNOWN" "SKIPPED_DOS" The status of the vulnerability finding. | keyword |
| rapid7.insightvm.asset.remediated.vulnerability_id | The identifier of the vulnerability. | keyword |
| rapid7.insightvm.asset.risk_score | The risk score (with criticality adjustments) of the asset. | double |
| rapid7.insightvm.asset.same.check_id | The identifier of the vulnerability check. | keyword |
| rapid7.insightvm.asset.same.first_found | The first time the vulnerability was discovered. | date |
| rapid7.insightvm.asset.same.key | The identifier of the assessment key. | keyword |
| rapid7.insightvm.asset.same.last_found | The most recent time the vulnerability was discovered. | date |
| rapid7.insightvm.asset.same.port | For services vulnerabilities, the port that is vulnerable. | long |
| rapid7.insightvm.asset.same.proof | The identifier of the vulnerability proof. | keyword |
| rapid7.insightvm.asset.same.protocol | For services vulnerabilities, the protocol that is vulnerable. | keyword |
| rapid7.insightvm.asset.same.solution.fix | The solution fix for the vulnerability. | keyword |
| rapid7.insightvm.asset.same.solution.id | The identifier of the solution for the vulnerability. | keyword |
| rapid7.insightvm.asset.same.solution.summary | The summary for the solution for the vulnerability. | keyword |
| rapid7.insightvm.asset.same.solution.type | The solution type for the vulnerability. | keyword |
| rapid7.insightvm.asset.same.status | Enum: "EXCEPTION_VULN_EXPL" "UNEXPECTED_ERR" "NOT_VULN_DONT_STORE" "SUPERSEDED" "EXCEPTION_VULN_POTL" "VULNERABLE_EXPL" "OVERRIDDEN_VULN_VERS" "SKIPPED_DISABLED" "VULNERABLE_VERS" "VULNERABLE_POTENTIAL" "SKIPPED_VERS" "EXCEPTION_VULN_VERS" "NOT_VULNERABLE" "UNKNOWN" "SKIPPED_DOS" The status of the vulnerability finding. | keyword |
| rapid7.insightvm.asset.same.vulnerability_id | The identifier of the vulnerability. | keyword |
| rapid7.insightvm.asset.severe_vulnerabilities | The count of severe vulnerability findings. | long |
| rapid7.insightvm.asset.tags.name | The stored value. | keyword |
| rapid7.insightvm.asset.tags.type | The type of information stored and displayed. For sites, the value is "SITE". | keyword |
| rapid7.insightvm.asset.total_vulnerabilities | The total count of vulnerability findings. | long |
| rapid7.insightvm.asset.type | Enum: "hypervisor" "mobile" "guest" "physical" "unknown" The type of asset. | keyword |
| rapid7.insightvm.asset.unique_identifiers.id | The unique identifier. | keyword |
| rapid7.insightvm.asset.unique_identifiers.source | The source of the unique identifier. | keyword |


### asset_vulnerability

This is the `asset_vulnerability` dataset.

#### Example

An example event for `asset_vulnerability` looks as following:

```json
{
    "@timestamp": "2025-05-27T18:21:36.279Z",
    "agent": {
        "ephemeral_id": "8f30a153-d7fb-4630-8931-752c0f5190e4",
        "id": "3e3bd5a6-8efb-4f70-b560-987a16383f05",
        "name": "elastic-agent-64243",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "rapid7_insightvm.asset_vulnerability",
        "namespace": "30380",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "3e3bd5a6-8efb-4f70-b560-987a16383f05",
        "snapshot": true,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "created": "2025-05-12T16:25:35.000Z",
        "dataset": "rapid7_insightvm.asset_vulnerability",
        "id": "8babcde1-1234-5678-0912-cabcdef1284e-default-asset-6|unix-anonymous-root-logins|2025-05-27T18:21:36.279Z",
        "ingested": "2025-06-07T12:24:02Z",
        "kind": "event",
        "original": "{\"assessed_for_policies\":false,\"assessed_for_vulnerabilities\":true,\"credential_assessments\":[{\"port\":22,\"protocol\":\"TCP\",\"status\":\"NO_CREDS_SUPPLIED\"}],\"critical_vulnerabilities\":3,\"exploits\":0,\"host_name\":\"computer-test\",\"id\":\"8babcde1-1234-5678-0912-cabcdef1284e-default-asset-6\",\"ip\":\"10.50.5.112\",\"last_assessed_for_vulnerabilities\":\"2025-05-27T18:21:36.279Z\",\"last_scan_end\":\"2025-05-27T18:21:36.279Z\",\"last_scan_start\":\"2025-05-27T18:20:41.505Z\",\"mac\":\"00:00:5E:00:53:02\",\"malware_kits\":0,\"moderate_vulnerabilities\":1,\"os_architecture\":\"x86_64\",\"os_description\":\"Red Hat Enterprise Linux 7.9\",\"os_family\":\"Linux\",\"os_name\":\"Enterprise Linux\",\"os_system_name\":\"Red Hat Linux\",\"os_type\":\"\",\"os_vendor\":\"Red Hat\",\"os_version\":\"7.9\",\"risk_score\":18250,\"severe_vulnerabilities\":48,\"tags\":[{\"name\":\"Ahmedabad\",\"type\":\"LOCATION\"},{\"name\":\"test\",\"type\":\"SITE\"},{\"name\":\"rapid7 insight agents\",\"type\":\"SITE\"}],\"total_vulnerabilities\":52,\"type\":\"guest\",\"unique_identifiers\":[{\"id\":\"CEF12345-ABCD-1234-ABCD-95ABCDEF1234\",\"source\":\"dmidecode\"},{\"id\":\"e80644e940123456789abcdef66a8b16\",\"source\":\"R7 Agent\"}],\"vulnerability\":{\"added\":\"2004-11-30T00:00:00Z\",\"categories\":\"CVSS Score Predicted with Rapid7 AI,UNIX\",\"check_id\":null,\"cves\":\"\",\"cvss_v2_access_complexity\":\"low\",\"cvss_v2_access_vector\":\"network\",\"cvss_v2_authentication\":\"single\",\"cvss_v2_availability_impact\":\"partial\",\"cvss_v2_confidentiality_impact\":\"partial\",\"cvss_v2_exploit_score\":7.9520000338554375,\"cvss_v2_impact_score\":6.442976653521584,\"cvss_v2_integrity_impact\":\"partial\",\"cvss_v2_score\":6.5,\"cvss_v2_vector\":\"(AV:N/AC:L/Au:S/C:P/I:P/A:P)\",\"cvss_v3_attack_complexity\":\"low\",\"cvss_v3_attack_vector\":\"local\",\"cvss_v3_availability_impact\":\"high\",\"cvss_v3_confidentiality_impact\":\"high\",\"cvss_v3_exploit_score\":2.515145325,\"cvss_v3_impact_score\":5.873118720000001,\"cvss_v3_integrity_impact\":\"high\",\"cvss_v3_privileges_required\":\"none\",\"cvss_v3_scope\":\"unchanged\",\"cvss_v3_score\":8.4,\"cvss_v3_user_interaction\":\"none\",\"cvss_v3_vector\":\"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\",\"denial_of_service\":false,\"description\":\"Anonymous root logins should only be allowed from system console. /etc/securetty allows you to specify on which tty's and virtual consoles root is allowed to login. The tty and vc's listed in this file will allow root to login on certain tty's and VC's. On other tty or vc's root user will not be allowed and user has to \\\"su\\\" to become root.\",\"exploits\":[],\"first_found\":\"2025-05-12T16:25:35Z\",\"id\":\"unix-anonymous-root-logins\",\"key\":\"\",\"last_found\":\"2025-05-27T18:21:36.279Z\",\"links\":[],\"malware_kits\":[],\"modified\":\"2025-02-18T00:00:00Z\",\"nic\":null,\"pci_cvss_score\":6.5,\"pci_fail\":true,\"pci_severity_score\":4,\"pci_special_notes\":\"\",\"pci_status\":\"fail\",\"port\":null,\"proof\":\"\\u003cp\\u003e\\u003cp\\u003eFollowing entries in /etc/securetty \\n                                 may allow anonymous root logins: \\u003cul\\u003e\\u003cli\\u003ettyS0\\u003c/li\\u003e\\u003cli\\u003ettysclp0\\u003c/li\\u003e\\u003cli\\u003esclp_line0\\u003c/li\\u003e\\u003cli\\u003e3270/tty1\\u003c/li\\u003e\\u003cli\\u003ehvc0\\u003c/li\\u003e\\u003cli\\u003ehvc1\\u003c/li\\u003e\\u003cli\\u003ehvc2\\u003c/li\\u003e\\u003cli\\u003ehvc3\\u003c/li\\u003e\\u003cli\\u003ehvc4\\u003c/li\\u003e\\u003cli\\u003ehvc5\\u003c/li\\u003e\\u003cli\\u003ehvc6\\u003c/li\\u003e\\u003cli\\u003ehvc7\\u003c/li\\u003e\\u003cli\\u003ehvsi0\\u003c/li\\u003e\\u003cli\\u003ehvsi1\\u003c/li\\u003e\\u003cli\\u003ehvsi2\\u003c/li\\u003e\\u003cli\\u003exvc0\\u003c/li\\u003e\\u003c/ul\\u003e\\u003c/p\\u003e\\u003c/p\\u003e\",\"protocol\":null,\"published\":\"2004-11-30T00:00:00Z\",\"references\":\"\",\"reintroduced\":null,\"risk_score\":562,\"severity\":\"severe\",\"severity_score\":7,\"solution_fix\":\"\\u003cp\\u003e\\u003cp\\u003eRemove all the entries in /etc/securetty except console,\\n            tty[0-9]* and vc\\\\[0-9]* \\u003c/p\\u003e\\u003cp\\u003eNote: ssh does not use /etc/securetty. To disable root login\\n            through ssh, use the \\u0026quot;PermitRootLogin\\u0026quot; setting in /etc/ssh/sshd_config\\n            and restart the ssh daemon. \\u003c/p\\u003e\\u003c/p\\u003e\",\"solution_id\":\"unix-anonymous-root-logins\",\"solution_summary\":\"Edit '/etc/securetty' entries\",\"solution_type\":\"workaround\",\"status\":\"VULNERABLE_EXPL\",\"title\":\"Anonymous root login is allowed\",\"vulnerability_id\":\"unix-anonymous-root-logins\"}}",
        "severity": 7,
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "hostname": "computer-test",
        "id": "8babcde1-1234-5678-0912-cabcdef1284e-default-asset-6",
        "ip": [
            "10.50.5.112"
        ],
        "mac": [
            "00-00-5E-00-53-02"
        ],
        "name": "computer-test",
        "os": {
            "family": "Linux",
            "full": "Red Hat Enterprise Linux 7.9",
            "name": "Enterprise Linux",
            "platform": "linux",
            "type": "linux",
            "version": "7.9"
        },
        "risk": {
            "static_score": 18250
        },
        "type": "guest"
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Rapid7 InsightVM",
        "vendor": "Rapid7"
    },
    "rapid7_insightvm": {
        "asset_vulnerability": {
            "assessed_for_policies": false,
            "assessed_for_vulnerabilities": true,
            "critical_vulnerabilities": 3,
            "exploits": 0,
            "host_name": "computer-test",
            "id": "8babcde1-1234-5678-0912-cabcdef1284e-default-asset-6",
            "ip": "10.50.5.112",
            "last_assessed_for_vulnerabilities": "2025-05-27T18:21:36.279Z",
            "last_scan_end": "2025-05-27T18:21:36.279Z",
            "last_scan_start": "2025-05-27T18:20:41.505Z",
            "mac": "00-00-5E-00-53-02",
            "malware_kits": 0,
            "moderate_vulnerabilities": 1,
            "os": {
                "architecture": "x86_64",
                "description": "Red Hat Enterprise Linux 7.9",
                "family": "Linux",
                "name": "Enterprise Linux",
                "system_name": "Red Hat Linux",
                "vendor": "Red Hat",
                "version": "7.9"
            },
            "risk_score": 18250,
            "severe_vulnerabilities": 48,
            "total_vulnerabilities": 52,
            "type": "guest",
            "unique_identifiers": [
                {
                    "id": "CEF12345-ABCD-1234-ABCD-95ABCDEF1234",
                    "source": "dmidecode"
                },
                {
                    "id": "e80644e940123456789abcdef66a8b16",
                    "source": "R7 Agent"
                }
            ],
            "vulnerability": {
                "added": "2004-11-30T00:00:00.000Z",
                "categories": [
                    "CVSS Score Predicted with Rapid7 AI",
                    "UNIX"
                ],
                "cvss_v2": {
                    "access_complexity": "low",
                    "access_vector": "network",
                    "authentication": "single",
                    "availability_impact": "partial",
                    "confidentiality_impact": "partial",
                    "exploit_score": 7.9520000338554375,
                    "impact_score": 6.442976653521584,
                    "integrity_impact": "partial",
                    "score": 6.5,
                    "vector": "(AV:N/AC:L/Au:S/C:P/I:P/A:P)"
                },
                "cvss_v3": {
                    "attack_complexity": "low",
                    "attack_vector": "local",
                    "availability_impact": "high",
                    "confidentiality_impact": "high",
                    "exploit_score": 2.515145325,
                    "impact_score": 5.873118720000001,
                    "integrity_impact": "high",
                    "privileges_required": "none",
                    "scope": "unchanged",
                    "score": 8.4,
                    "user_interaction": "none",
                    "vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                },
                "denial_of_service": false,
                "description": "Anonymous root logins should only be allowed from system console. /etc/securetty allows you to specify on which tty's and virtual consoles root is allowed to login. The tty and vc's listed in this file will allow root to login on certain tty's and VC's. On other tty or vc's root user will not be allowed and user has to \"su\" to become root.",
                "first_found": "2025-05-12T16:25:35.000Z",
                "id": "unix-anonymous-root-logins",
                "last_found": "2025-05-27T18:21:36.279Z",
                "modified": "2025-02-18T00:00:00.000Z",
                "pci": {
                    "cvss_score": 6.5,
                    "fail": true,
                    "severity_score": 4,
                    "status": "fail"
                },
                "proof": "Following entries in /etc/securetty \n                                 may allow anonymous root logins: \n\nttyS0\n\nttysclp0\n\nsclp_line0\n\n3270/tty1\n\nhvc0\n\nhvc1\n\nhvc2\n\nhvc3\n\nhvc4\n\nhvc5\n\nhvc6\n\nhvc7\n\nhvsi0\n\nhvsi1\n\nhvsi2\n\nxvc0",
                "published": "2004-11-30T00:00:00.000Z",
                "risk_score": 562,
                "severity": "severe",
                "severity_score": 7,
                "solution": {
                    "fix": "Remove all the entries in /etc/securetty except console,\n            tty[0-9]* and vc\\[0-9]* \n\nNote: ssh does not use /etc/securetty. To disable root login\n            through ssh, use the \"PermitRootLogin\" setting in /etc/ssh/sshd_config\n            and restart the ssh daemon.",
                    "id": "unix-anonymous-root-logins",
                    "summary": "Edit '/etc/securetty' entries",
                    "type": "workaround"
                },
                "status": "VULNERABLE_EXPL",
                "title": "Anonymous root login is allowed"
            }
        }
    },
    "related": {
        "hosts": [
            "computer-test",
            "8babcde1-1234-5678-0912-cabcdef1284e-default-asset-6"
        ],
        "ip": [
            "10.50.5.112"
        ]
    },
    "resource": {
        "id": "8babcde1-1234-5678-0912-cabcdef1284e-default-asset-6",
        "name": "computer-test"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "rapid7_insightvm-asset_vulnerability"
    ],
    "vulnerability": {
        "category": [
            "CVSS Score Predicted with Rapid7 AI",
            "UNIX"
        ],
        "classification": "CVSS",
        "description": "Anonymous root logins should only be allowed from system console. /etc/securetty allows you to specify on which tty's and virtual consoles root is allowed to login. The tty and vc's listed in this file will allow root to login on certain tty's and VC's. On other tty or vc's root user will not be allowed and user has to \"su\" to become root.",
        "enumeration": "CVE",
        "published_date": "2004-11-30T00:00:00.000Z",
        "scanner": {
            "name": "e80644e940123456789abcdef66a8b16",
            "vendor": "Rapid7"
        },
        "score": {
            "base": 8.4,
            "version": "3.0"
        },
        "severity": "High",
        "title": "Anonymous root login is allowed"
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
| package.name | Package name | keyword |
| package.version | Package version | keyword |
| rapid7_insightvm.asset_vulnerability.assessed_for_policies | Whether an asset was assessed for policies. | boolean |
| rapid7_insightvm.asset_vulnerability.assessed_for_vulnerabilities | Whether an asset was assessed for vulnerabilities. | boolean |
| rapid7_insightvm.asset_vulnerability.credential_assessments.port | The port the authentication was used on. | long |
| rapid7_insightvm.asset_vulnerability.credential_assessments.protocol | The protocol the authentication was used on. | keyword |
| rapid7_insightvm.asset_vulnerability.credential_assessments.status | The authentication of the last scan performed. | keyword |
| rapid7_insightvm.asset_vulnerability.critical_vulnerabilities | The count of critical vulnerability findings. | long |
| rapid7_insightvm.asset_vulnerability.exploits | The count of known unique exploits that can be used to exploit vulnerabilities on the asset. | long |
| rapid7_insightvm.asset_vulnerability.host_name | The host name (local or FQDN). | keyword |
| rapid7_insightvm.asset_vulnerability.id | The identifier of the asset. | keyword |
| rapid7_insightvm.asset_vulnerability.ip | The IPv4 or IPv6 address. | ip |
| rapid7_insightvm.asset_vulnerability.last_assessed_for_vulnerabilities | The time at which an asset was assessed for vulnerabilities. | date |
| rapid7_insightvm.asset_vulnerability.last_scan_end | The time at which the last scan of the asset ended. | date |
| rapid7_insightvm.asset_vulnerability.last_scan_start | The time at which the last scan of the asset started. | date |
| rapid7_insightvm.asset_vulnerability.mac | The Media Access Control (MAC) address. The format is six groups of two hexadecimal digits separated by colons. | keyword |
| rapid7_insightvm.asset_vulnerability.malware_kits | The count of known unique malware kits that can be used to attack vulnerabilities on the asset. | long |
| rapid7_insightvm.asset_vulnerability.moderate_vulnerabilities | The count of moderate vulnerability findings. | long |
| rapid7_insightvm.asset_vulnerability.os.architecture | The architecture of the operating system. | keyword |
| rapid7_insightvm.asset_vulnerability.os.description | The description of the operating system (containing vendor, family, product, version and architecture in a single string). | keyword |
| rapid7_insightvm.asset_vulnerability.os.family | The family of the operating system. | keyword |
| rapid7_insightvm.asset_vulnerability.os.name | The name of the operating system. | keyword |
| rapid7_insightvm.asset_vulnerability.os.system_name | A combination of vendor and family (with redundancies removed), suitable for grouping. | keyword |
| rapid7_insightvm.asset_vulnerability.os.type | The type of operating system. | keyword |
| rapid7_insightvm.asset_vulnerability.os.vendor | The vendor of the operating system. | keyword |
| rapid7_insightvm.asset_vulnerability.os.version | The version of the operating system. | keyword |
| rapid7_insightvm.asset_vulnerability.risk_score | The risk score (with criticality adjustments) of the asset. | double |
| rapid7_insightvm.asset_vulnerability.severe_vulnerabilities | The count of severe vulnerability findings. | long |
| rapid7_insightvm.asset_vulnerability.tags.name | The stored value. | keyword |
| rapid7_insightvm.asset_vulnerability.tags.type | The type of information stored and displayed. For sites, the value is "SITE". | keyword |
| rapid7_insightvm.asset_vulnerability.total_vulnerabilities | The total count of vulnerability findings. | long |
| rapid7_insightvm.asset_vulnerability.type | The type of asset. | keyword |
| rapid7_insightvm.asset_vulnerability.unique_identifiers.id | The unique identifier. | keyword |
| rapid7_insightvm.asset_vulnerability.unique_identifiers.source | The source of the unique identifier. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.added | The date the vulnerability coverage was added. The format is an ISO 8601 date, YYYY-MM-DD. | date |
| rapid7_insightvm.asset_vulnerability.vulnerability.categories | Comma-separated list of categories the vulnerability is classified under. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.check_id | The identifier of the vulnerability check. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cves | All CVEs assigned to this vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v2.access_complexity | Access Complexity (AC) component which measures the complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v2.access_vector | Access Vector (Av) component which reflects how the vulnerability is exploited. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v2.authentication | Authentication (Au) component which measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v2.availability_impact | Availability Impact (A) component which measures the impact to availability of a successfully exploited vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v2.confidentiality_impact | Confidentiality Impact (C) component which measures the impact on confidentiality of a successfully exploited vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v2.exploit_score | The CVSS exploit score. | double |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v2.impact_score | The CVSS impact score. | double |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v2.integrity_impact | Integrity Impact (I) component measures the impact to integrity of a successfully exploited vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v2.score | The CVSS score, which ranges from 0-10. | double |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v2.vector | The CVSS v2 vector. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v3.attack_complexity | Attack Complexity (AC) component with measures the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v3.attack_vector | Attack Vector (AV) component which measures context by which vulnerability exploitation is possible. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v3.availability_impact | Availability Impact (A) measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v3.confidentiality_impact | Confidentiality Impact (C) component which measures the impact on confidentiality of a successfully exploited vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v3.exploit_score | The CVSS exploit score. | double |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v3.impact_score | The CVSS impact score. | double |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v3.integrity_impact | Integrity Impact (I) measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v3.privileges_required | Privileges Required (PR) measures the level of privileges an attacker must possess before successfully exploiting the vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v3.scope | Scope (S) measures the collection of privileges defined by a computing authority (e.g. an application, an operating system, or a sandbox environment) when granting access to computing resources (e.g. files, CPU, memory, etc). These privileges are assigned based on some method of identification and authorization. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v3.score | The CVSS score, which ranges from 0-10. | double |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v3.user_interaction | User Interaction (UI) measures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerable component. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.cvss_v3.vector | The CVSS v3 vector. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.denial_of_service | Whether the vulnerability can lead to Denial of Service (DoS). | boolean |
| rapid7_insightvm.asset_vulnerability.vulnerability.description | A verbose description of the vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.exploits.description | A verbose description of the exploit. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.exploits.id | The identifier of the exploit. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.exploits.name | The name of the exploit. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.exploits.rank | How common the exploit is used. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.exploits.skill_level | The level of skill required to use the exploit. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.exploits.source | Details about where the exploit is defined. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.first_found | The first time the vulnerability was discovered. | date |
| rapid7_insightvm.asset_vulnerability.vulnerability.id | The identifier of the vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.is_enriched | Whether the enriched vulnerability information is available. | boolean |
| rapid7_insightvm.asset_vulnerability.vulnerability.is_remediated | Whether the vulnerability has been remediated. | boolean |
| rapid7_insightvm.asset_vulnerability.vulnerability.key | The identifier of the assessment key. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.last_found | The most recent time the vulnerability was discovered. | date |
| rapid7_insightvm.asset_vulnerability.vulnerability.links.href |  | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.links.id |  | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.links.rel |  | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.links.source |  | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.malware_kits.description | A known Malware Kit that can be used to compromise a vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.malware_kits.name | The name of the malware kit. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.malware_kits.popularity | The popularity of the malware kit. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.modified | The last date the vulnerability was modified. The format is an ISO 8601 date, YYYY-MM-DD. | date |
| rapid7_insightvm.asset_vulnerability.vulnerability.pci.cvss_score | The CVSS score of the vulnerability, adjusted for PCI rules and exceptions, on a scale of 0-10. | double |
| rapid7_insightvm.asset_vulnerability.vulnerability.pci.fail | Whether if present on a host this vulnerability would cause a PCI failure. true if compliance status is "fail", false otherwise. | boolean |
| rapid7_insightvm.asset_vulnerability.vulnerability.pci.severity_score | The severity score of the vulnerability, adjusted for PCI rules and exceptions, on a scale of 0-10. | long |
| rapid7_insightvm.asset_vulnerability.vulnerability.pci.special_notes | Any special notes or remarks about the vulnerability that pertain to PCI compliance. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.pci.status | The PCI compliance status. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.port | For services vulnerabilities, the port that is vulnerable. | long |
| rapid7_insightvm.asset_vulnerability.vulnerability.proof | The identifier of the vulnerability proof. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.protocol | For services vulnerabilities, the protocol that is vulnerable. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.published | The date the vulnerability was first published or announced. The format is an ISO 8601 date, YYYY-MM-DD. | date |
| rapid7_insightvm.asset_vulnerability.vulnerability.references | References to security standards this vulnerability is a part of, in condensed format (comma-separated). | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.risk_score | The risk score of the vulnerability. If using the default Rapid7 Real Risk™ model, this value ranges from 0-1000. | double |
| rapid7_insightvm.asset_vulnerability.vulnerability.severity | The severity of the vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.severity_score | The severity score of the vulnerability, on a scale of 0-10. | long |
| rapid7_insightvm.asset_vulnerability.vulnerability.solution.fix | The solution fix for the vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.solution.id | The identifier of the solution for the vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.solution.summary | The summary for the solution for the vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.solution.type | The solution type for the vulnerability. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.status | The status of the vulnerability finding. | keyword |
| rapid7_insightvm.asset_vulnerability.vulnerability.title | The title (summary) of the vulnerability. | keyword |
| resource.id |  | keyword |
| resource.name |  | keyword |
| vulnerability.published_date |  | date |
| vulnerability.scanner.name |  | keyword |
| vulnerability.scanner.vendor | The name of the vulnerability scanner vendor. | constant_keyword |
| vulnerability.title |  | keyword |


### vulnerability

This is the `vulnerability` dataset.

#### Example

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2018-06-08T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "dbee2821-362a-4d7a-9e8e-0fcd816d4696",
        "id": "6a264171-bdc2-47a0-a131-9a515aa1c01f",
        "name": "elastic-agent-42291",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "rapid7_insightvm.vulnerability",
        "namespace": "75615",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "6a264171-bdc2-47a0-a131-9a515aa1c01f",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "created": "2025-05-30T11:12:58.134Z",
        "dataset": "rapid7_insightvm.vulnerability",
        "id": "7-zip-cve-2008-6536",
        "ingested": "2025-05-30T11:13:00Z",
        "kind": "event",
        "original": "{\"added\":\"2018-05-16T00:00:00Z\",\"categories\":\"7-Zip\",\"cves\":\"CVE-2008-6536\",\"cvss_v2_access_complexity\":\"low\",\"cvss_v2_access_vector\":\"network\",\"cvss_v2_authentication\":\"none\",\"cvss_v2_availability_impact\":\"complete\",\"cvss_v2_confidentiality_impact\":\"complete\",\"cvss_v2_exploit_score\":9.996799,\"cvss_v2_impact_score\":10.000845,\"cvss_v2_integrity_impact\":\"complete\",\"cvss_v2_score\":10,\"cvss_v2_vector\":\"AV:N/AC:L/Au:N/C:C/I:C/A:C\",\"cvss_v3_attack_complexity\":null,\"cvss_v3_attack_vector\":null,\"cvss_v3_availability_impact\":null,\"cvss_v3_confidentiality_impact\":null,\"cvss_v3_exploit_score\":0,\"cvss_v3_impact_score\":0,\"cvss_v3_integrity_impact\":null,\"cvss_v3_privileges_required\":null,\"cvss_v3_scope\":null,\"cvss_v3_score\":0,\"cvss_v3_user_interaction\":null,\"cvss_v3_vector\":null,\"denial_of_service\":false,\"description\":\"Unspecified vulnerability in 7-zip before 4.5.7 has unknown impact and remote attack vectors, as demonstrated by the PROTOS GENOME test suite for Archive Formats (c10).\",\"exploits\":[],\"id\":\"7-zip-cve-2008-6536\",\"links\":[{\"href\":\"http://www.securityfocus.com/bid/28285\",\"id\":\"28285\",\"rel\":\"advisory\",\"source\":\"bid\"},{\"href\":\"https://exchange.xforce.ibmcloud.com/vulnerabilities/41247\",\"id\":\"41247\",\"rel\":\"advisory\",\"source\":\"xf\"},{\"href\":\"http://nvd.nist.gov/vuln/detail/CVE-2008-6536\",\"id\":\"CVE-2008-6536\",\"rel\":\"advisory\",\"source\":\"cve\"},{\"href\":\"http://www.cert.fi/haavoittuvuudet/joint-advisory-archive-formats.html\",\"id\":\"http://www.cert.fi/haavoittuvuudet/joint-advisory-archive-formats.html\",\"rel\":\"advisory\",\"source\":\"url\"},{\"href\":\"http://www.ee.oulu.fi/research/ouspg/protos/testing/c10/archive/\",\"id\":\"http://www.ee.oulu.fi/research/ouspg/protos/testing/c10/archive/\",\"rel\":\"advisory\",\"source\":\"url\"},{\"href\":\"http://www.securityfocus.com/bid/28285\",\"id\":\"http://www.securityfocus.com/bid/28285\",\"rel\":\"advisory\",\"source\":\"url\"},{\"href\":\"http://www.vupen.com/english/advisories/2008/0914/references\",\"id\":\"http://www.vupen.com/english/advisories/2008/0914/references\",\"rel\":\"advisory\",\"source\":\"url\"},{\"href\":\"http://www.xerox.com/download/security/security-bulletin/16287-4d6b7b0c81f7b/cert_XRX13-003_v1.0.pdf\",\"id\":\"http://www.xerox.com/download/security/security-bulletin/16287-4d6b7b0c81f7b/cert_XRX13-003_v1.0.pdf\",\"rel\":\"advisory\",\"source\":\"url\"},{\"href\":\"https://exchange.xforce.ibmcloud.com/vulnerabilities/41247\",\"id\":\"https://exchange.xforce.ibmcloud.com/vulnerabilities/41247\",\"rel\":\"advisory\",\"source\":\"url\"}],\"malware_kits\":[],\"modified\":\"2018-06-08T00:00:00Z\",\"pci_cvss_score\":10,\"pci_fail\":true,\"pci_severity_score\":5,\"pci_special_notes\":\"\",\"pci_status\":\"fail\",\"published\":\"2009-03-29T00:00:00Z\",\"references\":\"bid:28285,xf:41247,cve:CVE-2008-6536,url:http://www.cert.fi/haavoittuvuudet/joint-advisory-archive-formats.html,url:http://www.ee.oulu.fi/research/ouspg/protos/testing/c10/archive/,url:http://www.securityfocus.com/bid/28285,url:http://www.vupen.com/english/advisories/2008/0914/references,url:http://www.xerox.com/download/security/security-bulletin/16287-4d6b7b0c81f7b/cert_XRX13-003_v1.0.pdf,url:https://exchange.xforce.ibmcloud.com/vulnerabilities/41247\",\"risk_score\":885.16,\"severity\":\"critical\",\"severity_score\":10,\"title\":\"7-Zip: CVE-2008-6536: Unspecified vulnerability in 7-zip before 4.5.7\"}",
        "risk_score": 885.16,
        "risk_score_norm": 88.51599999999999,
        "severity": 10,
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "rapid7": {
        "insightvm": {
            "vulnerability": {
                "added": "2018-05-16T00:00:00.000Z",
                "categories": [
                    "7-Zip"
                ],
                "cves": [
                    "CVE-2008-6536"
                ],
                "cvss": {
                    "v2": {
                        "access_complexity": "low",
                        "access_vector": "network",
                        "authentication": "none",
                        "availability_impact": "complete",
                        "confidentiality_impact": "complete",
                        "exploit_score": 9.996799,
                        "impact_score": 10.000845,
                        "integrity_impact": "complete",
                        "score": 10,
                        "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C"
                    },
                    "v3": {
                        "exploit_score": 0,
                        "impact_score": 0,
                        "score": 0
                    }
                },
                "denial_of_service": false,
                "description": "Unspecified vulnerability in 7-zip before 4.5.7 has unknown impact and remote attack vectors, as demonstrated by the PROTOS GENOME test suite for Archive Formats (c10).",
                "id": "7-zip-cve-2008-6536",
                "links": [
                    {
                        "href": "http://www.securityfocus.com/bid/28285",
                        "id": "28285",
                        "rel": "advisory",
                        "source": "bid"
                    },
                    {
                        "href": "https://exchange.xforce.ibmcloud.com/vulnerabilities/41247",
                        "id": "41247",
                        "rel": "advisory",
                        "source": "xf"
                    },
                    {
                        "href": "http://nvd.nist.gov/vuln/detail/CVE-2008-6536",
                        "id": "CVE-2008-6536",
                        "rel": "advisory",
                        "source": "cve"
                    },
                    {
                        "href": "http://www.cert.fi/haavoittuvuudet/joint-advisory-archive-formats.html",
                        "id": "http://www.cert.fi/haavoittuvuudet/joint-advisory-archive-formats.html",
                        "rel": "advisory",
                        "source": "url"
                    },
                    {
                        "href": "http://www.ee.oulu.fi/research/ouspg/protos/testing/c10/archive/",
                        "id": "http://www.ee.oulu.fi/research/ouspg/protos/testing/c10/archive/",
                        "rel": "advisory",
                        "source": "url"
                    },
                    {
                        "href": "http://www.securityfocus.com/bid/28285",
                        "id": "http://www.securityfocus.com/bid/28285",
                        "rel": "advisory",
                        "source": "url"
                    },
                    {
                        "href": "http://www.vupen.com/english/advisories/2008/0914/references",
                        "id": "http://www.vupen.com/english/advisories/2008/0914/references",
                        "rel": "advisory",
                        "source": "url"
                    },
                    {
                        "href": "http://www.xerox.com/download/security/security-bulletin/16287-4d6b7b0c81f7b/cert_XRX13-003_v1.0.pdf",
                        "id": "http://www.xerox.com/download/security/security-bulletin/16287-4d6b7b0c81f7b/cert_XRX13-003_v1.0.pdf",
                        "rel": "advisory",
                        "source": "url"
                    },
                    {
                        "href": "https://exchange.xforce.ibmcloud.com/vulnerabilities/41247",
                        "id": "https://exchange.xforce.ibmcloud.com/vulnerabilities/41247",
                        "rel": "advisory",
                        "source": "url"
                    }
                ],
                "modified": "2018-06-08T00:00:00.000Z",
                "pci": {
                    "cvss_score": 10,
                    "fail": true,
                    "severity_score": 5,
                    "status": "fail"
                },
                "published": "2009-03-29T00:00:00.000Z",
                "references": "bid:28285,xf:41247,cve:CVE-2008-6536,url:http://www.cert.fi/haavoittuvuudet/joint-advisory-archive-formats.html,url:http://www.ee.oulu.fi/research/ouspg/protos/testing/c10/archive/,url:http://www.securityfocus.com/bid/28285,url:http://www.vupen.com/english/advisories/2008/0914/references,url:http://www.xerox.com/download/security/security-bulletin/16287-4d6b7b0c81f7b/cert_XRX13-003_v1.0.pdf,url:https://exchange.xforce.ibmcloud.com/vulnerabilities/41247",
                "risk_score": 885.16,
                "severity": "critical",
                "severity_score": 10,
                "title": "7-Zip: CVE-2008-6536: Unspecified vulnerability in 7-zip before 4.5.7"
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "rapid7_insightvm-vulnerability"
    ],
    "vulnerability": {
        "category": [
            "7-Zip"
        ],
        "classification": "CVSS",
        "description": "Unspecified vulnerability in 7-zip before 4.5.7 has unknown impact and remote attack vectors, as demonstrated by the PROTOS GENOME test suite for Archive Formats (c10).",
        "enumeration": "CVE",
        "id": [
            "CVE-2008-6536"
        ],
        "reference": "bid:28285,xf:41247,cve:CVE-2008-6536,url:http://www.cert.fi/haavoittuvuudet/joint-advisory-archive-formats.html,url:http://www.ee.oulu.fi/research/ouspg/protos/testing/c10/archive/,url:http://www.securityfocus.com/bid/28285,url:http://www.vupen.com/english/advisories/2008/0914/references,url:http://www.xerox.com/download/security/security-bulletin/16287-4d6b7b0c81f7b/cert_XRX13-003_v1.0.pdf,url:https://exchange.xforce.ibmcloud.com/vulnerabilities/41247",
        "scanner": {
            "vendor": "Rapid7"
        },
        "score": {
            "base": [
                10,
                0
            ]
        },
        "severity": "critical"
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
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| rapid7.insightvm.vulnerability.added | The date the vulnerability coverage was added. The format is an ISO 8601 date, YYYY-MM-DD. | date |
| rapid7.insightvm.vulnerability.categories | Comma-separated list of categories the vulnerability is classified under. | keyword |
| rapid7.insightvm.vulnerability.cves | All CVEs assigned to this vulnerability. | keyword |
| rapid7.insightvm.vulnerability.cvss.v2.access_complexity | Enum: "high" "low" "medium" Access Complexity (AC) component which measures the complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system. | keyword |
| rapid7.insightvm.vulnerability.cvss.v2.access_vector | Enum: "adjacent" "local" "network" Access Vector (Av) component which reflects how the vulnerability is exploited. | keyword |
| rapid7.insightvm.vulnerability.cvss.v2.authentication | Enum: "single" "multiple" "none" Authentication (Au) component which measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability. | keyword |
| rapid7.insightvm.vulnerability.cvss.v2.availability_impact | Enum: "none" "complete" "partial" Availability Impact (A) component which measures the impact to availability of a successfully exploited vulnerability. | keyword |
| rapid7.insightvm.vulnerability.cvss.v2.confidentiality_impact | Enum: "none" "complete" "partial" Confidentiality Impact (C) component which measures the impact on confidentiality of a successfully exploited vulnerability. | keyword |
| rapid7.insightvm.vulnerability.cvss.v2.exploit_score | The CVSS exploit score. | double |
| rapid7.insightvm.vulnerability.cvss.v2.impact_score | The CVSS impact score. | double |
| rapid7.insightvm.vulnerability.cvss.v2.integrity_impact | Enum: "none" "complete" "partial" Integrity Impact (I) component measures the impact to integrity of a successfully exploited vulnerability. | keyword |
| rapid7.insightvm.vulnerability.cvss.v2.score | The CVSS score, which ranges from 0-10. | double |
| rapid7.insightvm.vulnerability.cvss.v2.vector | The CVSS v2 vector. | keyword |
| rapid7.insightvm.vulnerability.cvss.v3.attack_complexity | Enum: "high" "low" Attack Complexity (AC) component with measures the conditions beyond control of the attacker that must exist in order to exploit the vulnerability. | keyword |
| rapid7.insightvm.vulnerability.cvss.v3.attack_vector | Enum: "adjacent" "physical" "local" "network" Attack Vector (AV) component which measures context by which vulnerability exploitation is possible. | keyword |
| rapid7.insightvm.vulnerability.cvss.v3.availability_impact | Enum: "high" "low" "none" Availability Impact (A) measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. | keyword |
| rapid7.insightvm.vulnerability.cvss.v3.confidentiality_impact | Enum: "high" "low" "none" Confidentiality Impact (C) component which measures the impact on confidentiality of a successfully exploited vulnerability. | keyword |
| rapid7.insightvm.vulnerability.cvss.v3.exploit_score | The CVSS exploit score. | double |
| rapid7.insightvm.vulnerability.cvss.v3.impact_score | The CVSS impact score. | double |
| rapid7.insightvm.vulnerability.cvss.v3.integrity_impact | Enum: "high" "low" "none" Integrity Impact (I) measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. | keyword |
| rapid7.insightvm.vulnerability.cvss.v3.privileges_required | Enum: "high" "low" "none" Privileges Required (PR) measures the level of privileges an attacker must possess before successfully exploiting the vulnerability. | keyword |
| rapid7.insightvm.vulnerability.cvss.v3.scope | Enum: "unchanged" "changed" Scope (S) measures the collection of privileges defined by a computing authority (e.g. an application, an operating system, or a sandbox environment) when granting access to computing resources (e.g. files, CPU, memory, etc). These privileges are assigned based on some method of identification and authorization. | keyword |
| rapid7.insightvm.vulnerability.cvss.v3.score | The CVSS score, which ranges from 0-10. | double |
| rapid7.insightvm.vulnerability.cvss.v3.user_interaction | Enum: "none" "required" User Interaction (UI) measures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerable component. | keyword |
| rapid7.insightvm.vulnerability.cvss.v3.vector | The CVSS v3 vector. | keyword |
| rapid7.insightvm.vulnerability.denial_of_service | Whether the vulnerability can lead to Denial of Service (DoS). | boolean |
| rapid7.insightvm.vulnerability.description | A verbose description of the vulnerability. | keyword |
| rapid7.insightvm.vulnerability.exploits.description | A verbose description of the exploit. | keyword |
| rapid7.insightvm.vulnerability.exploits.id | The identifier of the exploit. | keyword |
| rapid7.insightvm.vulnerability.exploits.name | The name of the exploit. | keyword |
| rapid7.insightvm.vulnerability.exploits.rank | Enum: "average" "normal" "excellent" "low" "manual" "great" "good" How common the exploit is used. | keyword |
| rapid7.insightvm.vulnerability.exploits.skill_level | Enum: "expert" "intermediate" "novice" The level of skill required to use the exploit. | keyword |
| rapid7.insightvm.vulnerability.exploits.source | Enum: "metasploit" "exploitdb" Details about where the exploit is defined. | keyword |
| rapid7.insightvm.vulnerability.id | The identifier of the vulnerability. | keyword |
| rapid7.insightvm.vulnerability.links.href |  | keyword |
| rapid7.insightvm.vulnerability.links.id |  | keyword |
| rapid7.insightvm.vulnerability.links.rel |  | keyword |
| rapid7.insightvm.vulnerability.links.source |  | keyword |
| rapid7.insightvm.vulnerability.malware_kits.description | A known Malware Kit that can be used to compromise a vulnerability. | keyword |
| rapid7.insightvm.vulnerability.malware_kits.name | The name of the malware kit. | keyword |
| rapid7.insightvm.vulnerability.malware_kits.popularity | Enum: "uncommon" "common" "rare" "favored" "occasional" "popular" "undefined" The popularity of the malware kit. | keyword |
| rapid7.insightvm.vulnerability.modified | The last date the vulnerability was modified. The format is an ISO 8601 date, YYYY-MM-DD. | date |
| rapid7.insightvm.vulnerability.pci.cvss_score | The CVSS score of the vulnerability, adjusted for PCI rules and exceptions, on a scale of 0-10. | double |
| rapid7.insightvm.vulnerability.pci.fail | Whether if present on a host this vulnerability would cause a PCI failure. true if compliance status is "fail", false otherwise. | boolean |
| rapid7.insightvm.vulnerability.pci.severity_score | The severity score of the vulnerability, adjusted for PCI rules and exceptions, on a scale of 0-10. | long |
| rapid7.insightvm.vulnerability.pci.special_notes | Any special notes or remarks about the vulnerability that pertain to PCI compliance. | keyword |
| rapid7.insightvm.vulnerability.pci.status | The PCI compliance status. | keyword |
| rapid7.insightvm.vulnerability.published | The date the vulnerability was first published or announced. The format is an ISO 8601 date, YYYY-MM-DD. | date |
| rapid7.insightvm.vulnerability.references | References to security standards this vulnerability is a part of, in condensed format (comma-separated). | keyword |
| rapid7.insightvm.vulnerability.risk_score | The risk score of the vulnerability. If using the default Rapid7 Real Risk™ model, this value ranges from 0-1000. | double |
| rapid7.insightvm.vulnerability.severity | Enum: "critical" "low" "severe" "informational" "none" "moderate" The severity of the vulnerability. | keyword |
| rapid7.insightvm.vulnerability.severity_score | The severity score of the vulnerability, on a scale of 0-10. | long |
| rapid7.insightvm.vulnerability.title | The title (summary) of the vulnerability. | keyword |
