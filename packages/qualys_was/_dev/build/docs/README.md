  # Qualys Web Application Scanning (WAS)

[Qualys WAS](https://www.qualys.com/apps/vulnerability-management-detection-response/) integration ingests vulnerability detection data from scans performed by the Qualys Web Application 
Scan product.
The Qualys Web Application Scanning product is a security product that continuously discovers, detects, and catalogs
web applications and APIs (Application Programming Interface), and uncovers runtime vulnerabilities, 
misconfigurations, Personal Identifying Information (PII) exposures, and web malware across modern web applications 
or APIs.

The Qualys WAS integration uses the Qualys REST API mode to collect vulnerability detection data. 
Elastic Agent fetches data via API endpoints. Detection data is augmented by XML based queries to 
the Qualys Knowledge Base about each detection.

## Compatibility

This module has been tested against the latest Qualys WAS version **4.5** ,
the **3.0** version REST API, and the **3.0** version of the detection Knowledge Base API.

## Data streams

The Qualys WAS integration collects data vulnerability reports called findings (detections) that are produced from scans. 
Scans are performed on a schedule and/or manually. 
Vulnerability reports are produced from the scans. Vulnerabilities have historical context
such as the first time the vulnerability was seen, the last time the vulnerability was detected
and status updates.
 
The Rest API reference for vulnerability reports: [Rest API guide](https://cdn2.qualys.com/docs/qualys-was-api-user-guide.pdf).
The XML knowledge base api has been updated to 3.0 since this reference was published due to changes in the DTD. The changes
are minimal.

## Requirements for running with an Elastic Agent

Elastic Agent must be installed. 
For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Agentless enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. 
They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. 
For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality 
is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Permissions

#### Web Application 

| Role   | Module                          | API access |
|--------|---------------------------------|------------|
| Reader | Web Application Scanning Module | Yes        |

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
The integration uses verbose mode by default. The size of scan result details that is returned in verbose is unpredictable.
Should the agent run into memory issues, one or more of the following should solve the problem:
1. Reduce batch_size in the integration configuration.
2. Disable verbose mode if the extra data returned is not valuable to the user. 
3. Increase memory on the agent.
4. Move the integration to its own agent.
5. If your system is using the 3.20 API or before, purge scan history. Scan history is the list of all scans have been  
   run for each vulnerability finding. This list is returned in 3.20 and earlier APIs. This list can be quite large if  
   it is not purged by the customer. Due to its size, this list can effect the amount of memory required to process the  
   Qualys API results. The CEL script that queries the Qualys APIs removes history results before sending the data to  
   Elasticsearch.

The additional data available with verbose mode are:
- Web application tags
- OWASP name, code and URL for the detection
- WASC name, code and URL for the detection
- CWE code (becomes ECS value vulnerability.id)
- updatedDateTime
- param value for the test
- results of the most recent scan including the requests made, the response and details what about the response resulted
  in a vulnerability report. This data is stored as unindexed text data due to its unpredictable size.

## Processing Logic
Cel scripts are used to fetch the data from Qualys endpoints and processed into events that 
are consumed by the pipelines.
The cell script requests Findings (detection) data through the REST API using a filter for the "lastTestedDate",
which is the scan datetime. The qid (qualys id) is the id the vulnerability found that maps to a
knowledge base article in the qualys knowledge base. This id is used to request knowledge base data from an 
endpoint which augments each Finding with the knowledge base data. Findings are paginated
by the qualys_was.vulnerability.id, a unique id for the finding. Knowledge base data is cached between pages to reduce
the volume of data transported during a single run of the cel script. The cel script removes history data that is 
included in verbose mode.

## Data reference

### Web Application Vulnerability Dataset

#### Example

An example response from the Qualys WAS API

```json
{
   "ServiceResponse": {
      "count": 1,
      "data": [
         {
            "Finding": {
               "owasp": {
                  "list": [
                     {
                        "OWASP": {
                           "name": "Injection",
                           "code": 3,
                           "url": "https://owasp.org/Top10/A03_2021-Injection/"
                        }
                     }
                  ],
                  "count": 1
               },
               "ignoredComment": "A comment",
               "cwe": {
                  "list": [
                     79
                  ],
                  "count": 1
               },
               "detectionScore": 50,
               "type": "VULNERABILITY",
               "updatedDate": "2025-06-01T08:56:29Z",
               "name": "Unencoded characters",
               "severity": "1",
               "timesDetected": 448,
               "ignoredReason": "FALSE_POSITIVE",
               "ignoredDate": "2020-06-23T11:38:44Z",
               "param": "show_unusable",
               "status": "ACTIVE",
               "cvssV3": {
                  "attackVector": "Network",
                  "base": 3.1,
                  "temporal": 2.6
               },
               "isIgnored": "true",
               "firstDetectedDate": "2020-06-13T08:01:21Z",
               "lastTestedDate": "2025-06-01T06:02:26Z",
               "wasc": {
                  "list": [
                     {
                        "WASC": {
                           "url": "http://projects.webappsec.org/w/page/13246934/WASC",
                           "name": "IMPROPER OUTPUT HANDLING",
                           "code": 22
                        }
                     }
                  ],
                  "count": 1
               },
               "uniqueId": "12345678-abcd-1234-1234-123456789012",
               "id": 12345678,
               "lastDetectedDate": "2025-06-01T06:02:26Z",
               "ignoredBy": {
                  "lastName": "Last",
                  "username": "username",
                  "firstName": "First",
                  "id": 987654321
               },
               "qid": 150084,
               "webApp": {
                  "tags": {
                     "list": [
                        {
                           "Tag": {
                              "id": 1,
                              "name": "Tag:1"
                           }
                        },
                        {
                           "Tag": {
                              "id": 2,
                              "name": "Tag:2"
                           }
                        }
                     ],
                     "count": 2
                  },
                  "url": "https://web.com/base",
                  "id": 123,
                  "name": "Descriptive Name"
               },
               "resultList": {
                  "list": [
                     {
                        "Result": {
                           "payloads": {
                              "list": [
                                 {
                                    "PayloadInstance": {
                                       "payloadResponce": {
                                          "offset": 272,
                                          "length": 25
                                       },
                                       "response": "response",
                                       "payload": "payload",
                                       "request": {
                                          "link": "https://web.com/base/testurl",
                                          "method": "GET",
                                          "headers": "headers"
                                       }
                                    }
                                 }
                              ],
                              "count": 1
                           },
                           "ajax": "false",
                           "authentication": "true",
                           "accessPath": {
                              "list": [
                                 {
                                    "Url": {
                                       "value": "https://web.com/base"
                                    }
                                 },
                                 {
                                    "Url": {
                                       "value": "https://web.com/base/testurl"
                                    }
                                 }
                              ],
                              "count": 2
                           }
                        }
                     }
                  ],
                  "count": 1
               },
               "findingType": "QUALYS",
               "url": "https://web.com/base/testurl",
               "potential": "true"
            }
         }
      ],
      "hasMoreRecords": "true",
      "responseCode": "SUCCESS",
      "lastId": 12345678
   }
}

```
An example of a Knowledge Base object after decoding from XML to JSON
 ```json
{
  "id": 150004,
  "qid": 150004,
  "name": "Predictable Resource Location Via Forced Browsing",
  "type": "CONFIRMED_VULNERABILITY",
  "severity": 2,
  "originalSeverity": 2,
  "updatedSeverityComment": null,
  "severityUpdatedBy": null,
  "severityUpdatedDate": null,
  "ignored": false,
  "ignoredReason": null,
  "ignoredComment": null,
  "ignoredBy": null,
  "ignoredDate": null,
  "category": "Web Application",
  "updated": "2024-04-06T05:00:01Z",
  "discoveryType": "REMOTE",
  "authenticationType": null,
  "patchAvailable": false,
  "exploitAvailable": false,
  "malwareAvailable": false,
  "supportedBy": [
    "API Security",
    "WAS"
  ],
  "updateStatus": null,
  "complianceTypes": [
    "PCI"
  ],
  "custom": false,
  "cveIds": [],
  "bugtraqIds": [],
  "cweIds": [
    "22"
  ],
  "wascCategories": [
    {
      "id": 114,
      "code": 15,
      "name": "APPLICATION MISCONFIGURATION",
      "url": "http://projects.webappsec.org/w/page/13246914/WASC",
      "fullName": "WASC-15 APPLICATION MISCONFIGURATION"
    },
    {
      "id": 115,
      "code": 16,
      "name": "DIRECTORY INDEXING",
      "url": "http://projects.webappsec.org/w/page/13246922/WASC",
      "fullName": "WASC-16 DIRECTORY INDEXING"
    },
    {
      "id": 116,
      "code": 17,
      "name": "IMPROPER FILESYSTEM PERMISSIONS",
      "url": "http://projects.webappsec.org/w/page/13246932/WASC",
      "fullName": "WASC-17 IMPROPER FILESYSTEM PERMISSIONS"
    }
  ],
  "owaspCategories": [
    {
      "id": 153,
      "year": 2021,
      "code": "A01",
      "name": "Broken Access Control",
      "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    }
  ],
  "apiOwaspCategories": [
    {
      "id": 10001,
      "year": 2023,
      "code": "API01",
      "name": "Broken Object Level Authorization",
      "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization"
    }
  ],
  "softwares": [],
  "vendorRefs": [],
  "exploits": [],
  "malware": [],
  "complianceInfos": [
    {
      "cid": 77,
      "qid": 150004,
      "lang": "EN",
      "complianceType": "PCI",
      "section": "DSS",
      "description": "Help organizations to ensure the safe handling of cardholder information at every step."
    }
  ],
  "cvss3BaseScore": 5.3,
  "cvss3TemporalScore": 4.7,
  "cvss3VectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  "threat": "A file, directory, or directory listing was discovered on the Web server. These resources are confirmed to be present based on our logic. Some of the content on these files might have sensitive information. \n<P>NOTE: Links found in 150004 are found by forced crawling so will not automatically be added to 150009 Links Crawled or the application site map. If links found in 150004 need to be tested they must be added as Explicit URI so they are included in scope and then will be reported in 150009. Once the link is added to be in scope (i.e. Explicit URI)  this same link will no longer be reported for 150004.",
  "impact": "The contents of this file or directory may disclose sensitive information.",
  "solution": "It is advised to review the contents of the disclosed files. If the contents contain sensitive information, please verify that access to this file or directory is permitted. If necessary, remove it or apply access controls to it.",
  "signature": null
}
```

#### Example

{{event "vulnerability"}}

**ECS fields**

| Field | Description | Type |
|---|---|---|
| vulnerability.id                        | The identification (ID) is the number portion of a vulnerability entry                                                                                                                                                                                                                                                                                                                                                                                                                                                         | keyword          |
| vulnerability.classification            | The classification of the vulnerability scoring system                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | constant_keyword |
| vulnerability.enumeration               | The type of identifier used for this vulnerability                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | constant_keyword |
| vulnerability.category                  | The type of system or architecture that the vulnerability affects.                                                                                                                                                                                                                                                                                                                                                                                                                                                             | constant_keyword |
| vulnerability.scanner.vendor            | The name of the vulnerability scanner vendor.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | constant_keyword |
| vulnerability.severity                  | The severity of the vulnerability                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | keyword          |
| vulnerability.score.base                | Available in verbose mode. Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Base scores cover an assessment for exploitability metrics (attack vector, complexity, privileges, and user interaction), impact metrics (confidentiality, integrity, and availability), and scope.                                                                                                                                                                                                                             | float            |
| vulnerability.score.temporal            | Available in verbose mode. Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Temporal scores cover an assessment for code maturity, remediation level, and confidence.                                                                                                                                                                                                                                                                                                                                       | float            |

{{fields "vulnerability"}}