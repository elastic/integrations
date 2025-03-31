# Qualys Web Application Scanning (WAS)

[Qualys WAS](https://www.qualys.com/apps/vulnerability-management-detection-response/) integration ingests vulnerability detection data from scans performed by the Qualys Web Application 
Scan product. 
The Qualys Web Application Scanning product is a cloud-based application security product that continuously discovers, 
detects, and catalogs web applications and APIs (Application Programming Interface). Uncovers runtime vulnerabilities, 
misconfigurations, Personal Identifying Information (PII) exposures, and web malware across modern web applications 
or APIs.

The Qualys WAS integration uses REST API mode to collect vulnerability detection data. 
Elastic Agent fetches data via API endpoints. Detection data is augmented with Qualys Knowledge
Base data about each type of detection.

## Compatibility

This module has been tested against the latest Qualys WAS version **4.5**.

## Data streams

The Qualys WAS integration collects data vulnerability reports (findings) that are produced from scans. 
Scans are performed on a schedule and/or manually. 
Vulnerability reports (findings) are produced from the scans. Vulnerabilities have historical context
such as the first time the vulnerability was seen.
This integration ingests the vulnerability reports. 

The API documentation tends to not be comprehensive. The original API was XML based.
The JSON Rest API is based on the XML API. JSON specific documentation is sparse.
This reference covers a few of the JSON Rest endpoints. 
Reference for [Rest API guide](https://cdn2.qualys.com/docs/qualys-was-api-user-guide.pdf)

This reference covers more JSON endpoints and their filters. 
Reference for [Rest API quick start](https://cdn2.qualys.com/docs/qualys-api-quick-reference.pdf)

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Permissions

#### Web Application 

| Role             | Permission                           | API access |
|------------------|--------------------------------------|------------|
| WAS Scanner User | Query access to Web application data | Yes        |

## Setup

### To collect data through REST API, follow the below steps:

- Considering you already have a Qualys user account, to identify your Qualys platform and get the API URL, 
refer this [link](https://www.qualys.com/platform-identification/).
- Alternative way to get the API URL is to log in to your Qualys account and go to Help > About. 
You’ll find your URL under Security Operations Center (SOC). Look for a url that starts with "qualysapi"

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Qualys WAS
3. Click on the "Qualys WAS" integration from the search results.
4. Click on the Add Qualys WAS Integration button to add the integration.
5. Add Required Parameters
   - username
   - password
   - url (Example: https://qualysapi.qg2.apps.qualys.com)
   - initial_interval (how far back to look for initial data)
   - interval (how often call API to get latest results)
   - batch size (how many vulnerabilities per page)
6. Select Optional Parameters to filter out data. See https://docs.qualys.com/en/vm/latest/knowledgebase/severity_levels.htm
for descriptions of type of detection data returned and severity levels.
   - disable Information Gathered. 
   - disable Senstive Content
   - disable Verbose
#### Notes about verbose mode
The integration uses verbose mode by default. The data available with verbose mode are:
- the detection score
- tags associated with the web application on which the vulnerability was found
- OWASP name, code and URL for the detection
- CWE code
- results of the most recent scan including the requests made, the response and details what about the response resulted
  in a vulnerability report (stored as flattened data)


## Data reference

### Web Application Vulnerability Dataset

#### Example

An example response from the Qualys WAS API

```json
{
  "ServiceResponse": {
    "responseCode": "SUCCESS",
    "data": [
      {
        "Finding": {
          "timesDetected": 116,
          "potential": "false",
          "owasp": {
            "count": 1,
            "list": [
              {
                "OWASP": {
                  "code": 5,
                  "name": "Security Misconfiguration",
                  "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
                }
              }
            ]
          },
          "cwe": {
            "count": 1,
            "list": [
              565
            ]
          },
          "severity": "2",
          "name": "Cookies Issued Without User Consent",
          "url": "https://site.com/base/tested/url",
          "status": "ACTIVE",
          "webApp": {
            "tags": {
              "count": 2,
              "list": [
                {
                  "Tag": {
                    "id": 12345678,
                    "name": "data_classification:nan"
                  }
                },
                {
                  "Tag": {
                    "id": 23456789,
                    "name": "asset_criticality:3"
                  }
                }
              ]
            },
            "name": "PCI Serverless Scan",
            "id": 98765432198,
            "url": "https://site.com/base"
          },
          "cvssV3": {
            "attackVector": "Adjacent Network",
            "temporal": 4.4,
            "base": 5.4
          },
          "findingType": "QUALYS",
          "type": "VULNERABILITY",
          "lastDetectedDate": "2025-01-23T14:25:59Z",
          "lastTestedDate": "2025-01-24T14:26:01Z",
          "firstDetectedDate": "2024-08-26T14:23:06Z",
          "uniqueId": "1234fef2-abcd-12fe-1234-123456789012",
          "updatedDate": "2025-01-24T16:11:37Z",
          "fixedDate": "2025-01-24T14:26:01Z",
          "qid": 150476,
          "resultList": {
            "count": 1,
            "list": [
              {
                "Result": {
                  "payloads": {
                    "count": 1,
                    "list": [
                      {
                        "PayloadInstance": {
                          "request": {
                            "method": "GET",
                            "headers": "someheaders",
                            "link": "https://site.com/base/tested/url"
                          },
                          "response": "response data",
                          "payload": "N/A"
                        }
                      }
                    ]
                  },
                  "authentication": "false",
                  "ajax": "false"
                }
              }
            ]
          },
          "isIgnored": "false",
          "detectionScore": 50,
          "id": 12341234
        }
      }
    ],
    "count": 1,
    "lastId": 12341234,
    "hasMoreRecords": "true"
  }
}
```
An example event for a Vulnerability finding after processing by the input pipeline:


```json
{"Finding":{"detection":{"detectionScore":0,"findingType":"QUALYS","firstDetectedDate":"2020-01-22T17:17:06Z","id":12345671,"lastDetectedDate":"2025-03-21T06:11:23Z","lastTestedDate":"2025-03-21T06:11:23Z","name":"Maximum Number of Links Reached During Crawl","potential":"false","qid":150026,"resultList":{"count":1,"list":[{"Result":{"authentication":"false","payloads":{"count":1,"list":[{"PayloadInstance":{"response":"Maximum request count reached: 300\n"}}]}}}]},"severity":"1","type":"INFORMATION_GATHERED","uniqueId":"12345678-1234-1234-1234-521234567890","updatedDate":"2025-03-21T12:48:15Z","webApp":{"id":181609281,"name":"Scan Target","tags":{"count":2,"list":[{"Tag":{"id":77439203,"name":"asset_criticality:3"}},{"Tag":{"id":68447639,"name":"data_classification:nan"}}]},"url":"https://7bcc84396e87475c864b3dc3215d808c.webapp.address:9243"}},"knowledge_base":{"CATEGORY":"Web Application","CODE_MODIFIED_DATETIME":"2008-11-25T08:00:00Z","CONSEQUENCE":"Some links that lead to different areas of the site's functionality may have been missed.","DIAGNOSIS":"The maximum number of links specified for this scan has been reached. The links crawled to reach this threshold can include requests made via HTML form submissions and links requested in anonymous and authenticated states. Consequently, the list of links crawled (QID 150009) may reflect a lower number than the combination of links and forms requested during the crawl.","DISCOVERY":{"REMOTE":"1"},"LAST_SERVICE_MODIFICATION_DATETIME":"2009-01-16T18:02:46Z","PATCHABLE":"0","PCI_FLAG":"0","PUBLISHED_DATETIME":"2008-11-25T08:00:00Z","QID":"150026","SEVERITY_LEVEL":"1","SOLUTION":"Increase the maximum number of links in order to ensure broader coverage of the Web application. It is important to note that increasing the number of links crawled can dramatically increase the time required to test the Web application.","TITLE":"Maximum Number of Links Reached During Crawl","VULN_TYPE":"Information Gathered"}}}

        "Finding": {"detection": {
          "timesDetected": 116,
          "potential": "false",
          "owasp": {
            "count": 1,
            "list": [
              {
                "OWASP": {
                  "code": 5,
                  "name": "Security Misconfiguration",
                  "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
                }
              }
            ]
          },
          "cwe": {
            "count": 1,
            "list": [
              565
            ]
          },
          "severity": "2",
          "name": "Cookies Issued Without User Consent",
          "url": "https://site.com/base/tested/url",
          "status": "ACTIVE",
          "webApp": {
            "tags": {
              "count": 2,
              "list": [
                {
                  "Tag": {
                    "id": 12345678,
                    "name": "data_classification:nan"
                  }
                },
                {
                  "Tag": {
                    "id": 23456789,
                    "name": "asset_criticality:3"
                  }
                }
              ]
            },
            "name": "PCI Serverless Scan",
            "id": 98765432198,
            "url": "https://site.com/base"
          },
          "cvssV3": {
            "attackVector": "Adjacent Network",
            "temporal": 4.4,
            "base": 5.4
          },
          "findingType": "QUALYS",
          "type": "VULNERABILITY",
          "lastDetectedDate": "2025-01-23T14:25:59Z",
          "lastTestedDate": "2025-01-24T14:26:01Z",
          "firstDetectedDate": "2024-08-26T14:23:06Z",
          "uniqueId": "1234fef2-abcd-12fe-1234-123456789012",
          "updatedDate": "2025-01-24T16:11:37Z",
          "fixedDate": "2025-01-24T14:26:01Z",
          "qid": 150476,
          "resultList": {
            "count": 1,
            "list": [
              {
                "Result": {
                  "payloads": {
                    "count": 1,
                    "list": [
                      {
                        "PayloadInstance": {
                          "request": {
                            "method": "GET",
                            "headers": "someheaders",
                            "link": "https://site.com/base/tested/url"
                          },
                          "response": "response data",
                          "payload": "N/A"
                        }
                      }
                    ]
                  },
                  "authentication": "false",
                  "ajax": "false"
                }
              }
            ]
          },
          "isIgnored": "false",
          "detectionScore": 50,
          "id": 12341234
        }
      }
    ],
    "count": 1,
    "lastId": 12341234,
    "hasMoreRecords": "true"
  }
}
```
```json
{
   "Finding": {
      "detectionScore": 50,
      "findingType": "QUALYS",
      "firstDetectedDate": "2025-02-15T06:02:17Z",
      "id": 12345678,
      "isIgnored": "false",
      "lastDetectedDate": "2025-03-17T06:01:51Z",
      "lastTestedDate": "2025-03-17T06:01:51Z",
      "name": "Unencoded characters",
      "param": "show_deleted",
      "potential": "true",
      "qid": 150084,
      "severity": "1",
      "status": "ACTIVE",
      "timesDetected": 21,
      "type": "VULNERABILITY",
      "uniqueId": "12345678-1234-1234-abcd-123456789012",
      "url": "https://webapp.com/actual/page/testes",
      "webApp": {
         "id": 185468750,
         "name": "GScan Target",
         "url": "https://webapp.com"
      }
   }
}
```

**Exported fields**

| Field                                                                                  | Description                                                                                           | Type      
|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|-----------
| @timestamp                                                                             | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events.                                                                                                                                                                                             | date             |
| data_stream.dataset                                                                    | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace                                                                  | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters                               | constant_keyword |
| data_stream.type                                                                       | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future.                                                                                                                                                                                                                                                                                                                                                               | constant_keyword |
| event.dataset                                                                          | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name.                                                                                                                                                                                                                | constant_keyword |
| event.module                                                                           | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module.                                                                                                                                                                                                                                                                                               | constant_keyword |
| qualys_was.vulnerability.id                                                            | Id for the vulnerability report                                                                       | long      
| qualys_was.vulnerability.name                                                          | A descriptive name for vulnerability                                                                  | keyword   
| qualys_was.vulnerability.last_found_datetime                                           | The last scqan date where the vulnerability was found                                                 | date      
| qualys_was.vulnerability.first_found_datetime                                          | The first scan date where the vulnerability was found                                                 | date      
| qualys_was.vulnerability.last_test_datetime                                            | The last date for which the vulnerability was scanned for (can be set to ignored and not scanned for) | date      
| qualys_was.vulnerability.qid                                                           | Qualys ID for the vulnerability                                                                       | long      
| qualys_was.vulnerability.status                                                        | The status (New, Active, Fixed, Reopened)                                                             | keyword   
| qualys_was.vulnerability.detection_score                                               | The detection score                                                                                   | long      
| qualys_was.vulnerability.potential                                                     | Potential vulnerabilities are not verified but should be investiagated                                | boolean   
| qualys_was.vulnerability.is_ignored                                                    | Is the vulnerbaility being ignored                                                                    | boolean   
| qualys_was.vulnerability.url                                                           | The URL that was scanned                                                                              | keyword   
| qualys_was.vulnerability.unique_vuln_id                                                | Unique id for the vulnerability report                                                                | keyword   
| qualys_was.vulnerability.times_detected                                                | The number of times the vilnerability has been detected                                               | long      
| qualys_was.vulnerability.result_list                                                   | Available in verbose mode. Actual scan result with detials on requst, response and details of finding | flattened 
| qualys_was.vulnerability.ignoredBy.id                                                  | Id of person who ignored this vulnerability                                                           | long      
| qualys_was.vulnerability.ignoredBy.name                                                | Name of person who ignored this vulnerability                                                         | keyword   
| qualys_was.vulnerability.ignoredBy.username                                            | Username of person who ignored this vulnerability                                                     | keyword   
| qualys_was.vulnerability.ignoredBy.comment                                             | Comment by person who ignored this vulnerability                                                      | keyword   
| qualys_was.vulnerability.ignoredBy.reason                                              | Reason the vulnerability was ignored                                                                  | keyword   
| qualys_was.vulnerability.ignoredBy.date                                                | Date the vulnerability was ignored                                                                    | date      
| qualys_was.vulnerability.web_app.id                                                    | Web Application ID                                                                                    | long      
| qualys_was.vulnerability.web_app.url                                                   | Web Application base URL                                                                              | keyword   
| qualys_was.vulnerability.web_app.tags                                                  | Web Application tags                                                                                  | keyword   
| qualys_was.vulnerability.wasc_references.code                                          | WASC reference code                                                                                   | long      
| qualys_was.vulnerability.wasc_references.name                                          | WASC reference name                                                                                   | keyword   
| qualys_was.vulnerability.wasc_references.url                                           | WASC reference URL                                                                                    | keyword   
| qualys_was.vulnerability.owasp_references.code                                         | OWASP code | long       
| qualys_was.vulnerability.owasp_references.name                                         | OWASP name | keyword                                                                                               
| qualys_was.vulnerability.owasp_references.url                                          | OWASP reference URL | keyword                                                                                               
| qualys_was.vulnerability.knowledge_base.automatic_pci_fail                             | |keyword
| qualys_was.vulnerability.knowledge_base.bugtraq_list.id                                | |keyword
| qualys_was.vulnerability.knowledge_base.bugtraq_list.id.url                            | |keyword
| qualys_was.vulnerability.knowledge_base.id.category                                    | |keyword
| qualys_was.vulnerability.knowledge_base.changelog_list.info.change_date                | |date
| qualys_was.vulnerability.knowledge_base.changelog_list.info.comments                   | |keyword
| qualys_was.vulnerability.knowledge_base.compliance_list.description                    | |keyword
| qualys_was.vulnerability.knowledge_base.compliance_list.section                        | |keyword
| qualys_was.vulnerability.knowledge_base.compliance_list.type                           | |keyword
| qualys_was.vulnerability.knowledge_base.consequence.comment                            | |keyword
| qualys_was.vulnerability.knowledge_base.consequence.value                              | |keyword
| qualys_was.vulnerability.knowledge_base.correlation.exploits.explt_src.list.explt.desc | |keyword
| qualys_was.vulnerability.knowledge_base.correlation.exploits.explt_src.list.explt.link | |keyword
| qualys_was.vulnerability.knowledge_base.correlation.exploits.explt_src.list.explt.ref  | |keyword
| qualys_was.vulnerability.knowledge_base.correlation.exploits.explt_src.list.name       | |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.alias        | |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.id           | |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.link         | |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.platform     | |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.rating       | |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.type         | |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.name              | |keyword
| qualys_was.vulnerability.knowledge_base.cve_list                                       | |keyword
| qualys_was.vulnerability.knowledge_base.cvss.access.complexity                         | |keyword
| qualys_was.vulnerability.knowledge_base.cvss.access.vector                             | |keyword
| qualys_was.vulnerability.knowledge_base.cvss.authentication                            | |keyword
| qualys_was.vulnerability.knowledge_base.cvss.base                                      | |keyword
| qualys_was.vulnerability.knowledge_base.cvss.base_obj                                  | |flattened
| qualys_was.vulnerability.knowledge_base.cvss.exploitability                            | |keyword
| qualys_was.vulnerability.knowledge_base.cvss.impact.availability.keyword               
| qualys_was.vulnerability.knowledge_base.cvss.impact.confidentiality                    | |keyword
| qualys_was.vulnerability.knowledge_base.cvss.impact.integrity                          | |keyword
| qualys_was.vulnerability.knowledge_base.cvss.remediation_level                         | |keyword
| qualys_was.vulnerability.knowledge_base.cvss.report_confidence                         | |keyword
| qualys_was.vulnerability.knowledge_base.cvss.temporal                                  | |keyword
| qualys_was.vulnerability.knowledge_base.cvss.vector_string                             | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.attack.complexity                      | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.attack.vector                          | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.base                                   | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.exploit_code_maturity                  | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.impact.availability                    | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.impact.confidentiality                 | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.impact.integrity                       | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.privileges_required                    | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.remediation_level                      | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.report_confidence                      | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.scope                                  | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.temporal                               | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.user_interaction                       | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.vector_string                          | |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.version                                | |keyword
| qualys_was.vulnerability.knowledge_base.detection_info                                 | |keyword
| qualys_was.vulnerability.knowledge_base.diagnosis.comment                              | |match_only_text
| qualys_was.vulnerability.knowledge_base.diagnosis.value                                | |match_only_text
| qualys_was.vulnerability.knowledge_base.discovery.auth_type_list.value                 | |keyword
| qualys_was.vulnerability.knowledge_base.discovery.additional_info                      | |keyword
| qualys_was.vulnerability.knowledge_base.discovery.remote                               | |long
| qualys_was.vulnerability.knowledge_base.error                                          | |keyword
| qualys_was.vulnerability.knowledge_base.ids                                            | |keyword
| qualys_was.vulnerability.knowledge_base.id_range                                       | |keyword
| qualys_was.vulnerability.knowledge_base.is_disabled                                    | |boolean
| qualys_was.vulnerability.knowledge_base.last.customization.datetime                    | |date
| qualys_was.vulnerability.knowledge_base.last.customization.user_login                  | |keyword
| qualys_was.vulnerability.knowledge_base.last.service_modification_datetime             | |date
| qualys_was.vulnerability.knowledge_base.patchable                                      | |boolean
| qualys_was.vulnerability.knowledge_base.pci_flag                                       | |boolean
| qualys_was.vulnerability.knowledge_base.pci_reasons.value                              | |keyword
| qualys_was.vulnerability.knowledge_base.published_datetime                             | |date
| qualys_was.vulnerability.knowledge_base.qid                                            | |keyword
| qualys_was.vulnerability.knowledge_base.severity_level                                 | |keyword
| qualys_was.vulnerability.knowledge_base.software_list.product                          | |keyword
| qualys_was.vulnerability.knowledge_base.software_list.vendor                           | |keyword
| qualys_was.vulnerability.knowledge_base.vendor_reference_list.id                       | |keyword
| qualys_was.vulnerability.knowledge_base.vendor_reference_list.url                      | |keyword
| qualys_was.vulnerability.knowledge_base.solution.comment                               | |match_only_text
| qualys_was.vulnerability.knowledge_base.solution.value                                 | |match_only_text
| qualys_was.vulnerability.knowledge_base.supported_modules                              | |keyword
| qualys_was.vulnerability.knowledge_base.threat_intelligence.intel.id                   | |keyword
| qualys_was.vulnerability.knowledge_base.threat_intelligence.intel.text                 | |keyword
| qualys_was.vulnerability.knowledge_base.title                                          | |keyword
| qualys_was.vulnerability.knowledge_base.vuln_type                                      | |keyword
| vulnerability.id                                                                       | The identification (ID) is the number portion of a vulnerability entry                                                                                                                                                                                                                                                                                                                                                                                                                                                        | keyword          |
| vulnerability.classification                                                           | The classification of the vulnerability scoring system                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | constant_keyword |
| vulnerability.enumeration                                                              | The type of identifier used for this vulnerability                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | constant_keyword |
| vulnerability.category                                                                 | The type of system or architecture that the vulnerability affects.                                                                                                                                                                                                                                                                                                                                                                                                                                                            | constant_keyword |
| vulnerability.scanner.vendor                                                           | The name of the vulnerability scanner vendor.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | constant_keyword |
| vulnerability.severity                                                                 | The severity of the vulnerability                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | keyword          |
| vulnerability.score.base                                                               | Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Base scores cover an assessment for exploitability metrics (attack vector, complexity, privileges, and user interaction), impact metrics (confidentiality, integrity, and availability), and scope.                                                                                                                                                                                          | float            |
| vulnerability.score.temporal                                                           | Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Temporal scores cover an assessment for code maturity, remediation level, and confidence.                                                                                                                                                                                                                                                                                                                                                                 | float            |


