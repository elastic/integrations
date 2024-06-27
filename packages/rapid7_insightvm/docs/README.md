# Rapid7 InsightVM

## Overview

The [Rapid7 InsightVM](https://www.rapid7.com/products/insightvm/) integration allows users to monitor Asset and Vulnerability Events. Rapid7 InsightVM discovers risks across all your endpoints, cloud, and virtualized infrastructure. Prioritize risks and provide step-by-step directions to IT and DevOps for more efficient remediation. View your risk in real-time right from your dashboard. Measure and communicate progress on your program goals.

Use the Rapid7 InsightVM integration to collect and parse data from the REST APIs. Then visualize that data in Kibana.

## Data streams

The Rapid7 InsightVM integration collects two type of events: Asset and Vulnerability.

**Asset** is used to get details related to inventory, assessment, and summary details of assets that the user has access to. See more details in the API documentation [here](https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/searchIntegrationAssets).

**Vulnerability** is used to retrieve all vulnerabilities that can be assessed. See more details in the API documentation [here](https://help.rapid7.com/insightvm/en-us/api/integrations.html#operation/searchIntegrationVulnerabilities).

## Requirements

Elasticsearch is needed to store and search data, and Kibana is needed for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

This module uses **InsightVM Cloud Integrations API v4**.

## Setup

### To collect data from the Rapid7 InsightVM APIs, follow the below steps:

1. Generate the platform API key to access all Rapid7 InsightVM APIs. For more details, see [Documentation](https://docs.rapid7.com/insight/managing-platform-api-keys).

## Logs Reference

### asset

This is the `asset` dataset.

#### Example

An example event for `asset` looks as following:

```json
{
    "@timestamp": "2023-05-23T16:17:06.996Z",
    "agent": {
        "ephemeral_id": "163d2260-4499-492b-bbd5-4d90487865b9",
        "id": "c157ef08-38bb-40dd-bae1-c6bc8c8f02fa",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.9.0"
    },
    "data_stream": {
        "dataset": "rapid7_insightvm.asset",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c157ef08-38bb-40dd-bae1-c6bc8c8f02fa",
        "snapshot": true,
        "version": "8.9.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "created": "2023-05-23T16:17:06.996Z",
        "dataset": "rapid7_insightvm.asset",
        "ingested": "2023-05-23T16:17:08Z",
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


### vulnerability

This is the `vulnerability` dataset.

#### Example

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2018-06-08T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "9844171e-82cf-4571-bba2-2256a2464500",
        "id": "e4354c0c-ca75-448a-b886-ec73a12bce07",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.11.0"
    },
    "data_stream": {
        "dataset": "rapid7_insightvm.vulnerability",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e4354c0c-ca75-448a-b886-ec73a12bce07",
        "snapshot": false,
        "version": "8.11.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "created": "2023-12-20T15:51:20.233Z",
        "dataset": "rapid7_insightvm.vulnerability",
        "id": "7-zip-cve-2008-6536",
        "ingested": "2023-12-20T15:51:23Z",
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
