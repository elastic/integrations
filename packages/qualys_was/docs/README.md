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
The integration uses verbose mode by default. The additional data available with verbose mode are:
- the detection score
- tags associated with the web application on which the vulnerability was found
- OWASP name, code and URL for the detection
- CWE code
- results of the most recent scan including the requests made, the response and details what about the response resulted
  in a vulnerability report (stored as flattened data)

## Processing Logic
Cel scripts are used to fetch the data from Qualys endpoints and processing into events that 
are consumed by the pipelines.
The cell script requests Findings (vulnerability) data through the REST API using a filter of timestamps 
for the "lastTestedDate" which is the scan datetime. The qid (qualys id) is the id for the detection type. This id
is used to request knowledge base data from an XML endpoint which augments each Finding. Findings are paginated
by the qualys vulnerability id, an unique id for the finding. Knowledge base data is cached between pages to reduce
the volume of data transported during a single run.


## Data reference

### Web Application Vulnerability Dataset

#### Example

An example response from the Qualys WAS API

```json
{
  "ServiceResponse": {
    "data": [
      {
        "Finding": {
          "timesDetected": 403,
          "name": "Unencoded characters",
          "id": 10641200,
          "detectionScore": 50,
          "lastDetectedDate": "2025-03-07T06:03:03Z",
          "webApp": {
            "url": "https://<web app base url>",
            "name": "Target Name",
            "id": 185468750
          },
          "potential": "true",
          "type": "VULNERABILITY",
          "lastTestedDate": "2025-03-07T06:03:03Z",
          "severity": "1",
          "firstDetectedDate": "2020-06-13T08:01:21Z",
          "uniqueId": "12345678-abcd-1234-1234-123456789012",
          "qid": 150084,
          "url": "https:<test url>",
          "status": "ACTIVE",
          "param": "show_unusable",
          "findingType": "QUALYS",
          "isIgnored": "true"
        }
      }
    ]
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

An example event for a Vulnerability finding after processing by the input pipeline:
```json
{
   "Finding":{
      "detection":{
         "cvssV3":{
            "attackVector":"Network",
            "base":3.1,
            "temporal":2.6
         },
         "cwe":{
            "count":1,
            "list":[
               79
            ]
         },
         "detectionScore":50,
         "findingType":"QUALYS",
         "firstDetectedDate":"2020-06-13T08:01:21Z",
         "id":12345670,
         "ignoredBy":{
            "firstName":"Some",
            "id":142870916,
            "lastName":"Person",
            "username":"someperson123"
         },
         "ignoredComment":"https://github.com/elastic/infosec/issues/3770#issuecomment-648081338",
         "ignoredDate":"2020-06-23T11:39:09Z",
         "ignoredReason":"FALSE_POSITIVE",
         "isIgnored":"true",
         "lastDetectedDate":"2025-03-21T06:01:54Z",
         "lastTestedDate":"2025-03-21T06:01:54Z",
         "name":"Unencoded characters",
         "owasp":{
            "count":1,
            "list":[
               {
                  "OWASP":{
                     "code":3,
                     "name":"Injection",
                     "url":"https://owasp.org/Top10/A03_2021-Injection/"
                  }
               }
            ]
         },
         "param":"show_deleted",
         "potential":"true",
         "qid":150084,
         "resultList":{
            "count":1,
            "list":[
               {
                  "Result":{
                     "accessPath":{
                        "count":1,
                        "list":[
                           {
                              "Url":{
                                 "value":"https://web.address.com/"
                              }
                           }
                        ]
                     },
                     "ajax":"false",
                     "authentication":"false",
                     "payloads":{
                        "count":4,
                        "list":[
                           {
                              "PayloadInstance":{
                                 "payload":"show_deleted=%22'%3E%3CqssbVr8SJHx%20%60%3b!--%3D%26%7b()%7d%3E&show_unusable=false",
                                 "payloadResponce":{
                                    "length":25,
                                    "offset":271
                                 },
                                 "request":{
                                    "headers":"123header456",
                                    "link":"https://web.address.com/api/v1/more/address/stack/versions?show_deleted=%22'%3E%3CqssbVr8SJHx%20%60%3b!--%3D%26%7b()%7d%3E&show_unusable=false",
                                    "method":"GET"
                                 },
                                 "response":"comment: A significant portion of the XSS test payload appeared in the web page, but the response content type is non-HTML.\nResponse content-type: application/json\n\n{\"errors\":[{\"code\":\"root.malformed_query_param\",\"message\":\"The value for show_deleted was malformed. '\\\"'><qssbvr8sjhx `;!--=&{()}>' is not a valid Boolean value\"}]}"
                              }
                           },
                           {
                              "PayloadInstance":{
                                 "payload":"show_deleted=%22&show_unusable=false",
                                 "payloadResponce":{
                                    "length":28,
                                    "offset":271
                                 },
                                 "request":{
                                    "headers":"123header456",
                                    "link":"https://web.address.com/api/v1/more/address/stack/versions?show_deleted=%22&show_unusable=false",
                                    "method":"GET"
                                 },
                                 "response":"comment: A significant portion of the XSS test payload appeared in the web page, but the response content type is non-HTML.\nResponse content-type: application/json\n\n{\"errors\":[{\"code\":\"root.malformed_query_param\",\"message\":\"The value for show_deleted was malformed. '\\\"'><qss a=x93884460340384y1_1z>' is not a valid Boolean value\"}]}"
                              }
                           },
                           {
                              "PayloadInstance":{
                                 "payload":"show_deleted=false%22'%3E%3CqssUbPt9tNM%3E&show_unusable=false",
                                 "payloadResponce":{
                                    "length":13,
                                    "offset":276
                                 },
                                 "request":{
                                    "headers":"123header456",
                                    "link":"https://web.address.com/api/v1/more/address/stack/versions?show_deleted=false%22'%3E%3CqssUbPt9tNM%3E&show_unusable=false",
                                    "method":"GET"
                                 },
                                 "response":"comment: A significant portion of the XSS test payload appeared in the web page, but the response content type is non-HTML.\nResponse content-type: application/json\n\n{\"errors\":[{\"code\":\"root.malformed_query_param\",\"message\":\"The value for show_deleted was malformed. 'false\\\"'><qssubpt9tnm>' is not a valid Boolean value\"}]}"
                              }
                           },
                           {
                              "PayloadInstance":{
                                 "payload":"show_deleted=%22%3E%3CqssOzIA5enZ%3E&show_unusable=false",
                                 "payloadResponce":{
                                    "length":13,
                                    "offset":270
                                 },
                                 "request":{
                                    "headers":"123header456",
                                    "link":"https://web.address.com/api/v1/more/address/stack/versions?show_deleted=%22%3E%3CqssOzIA5enZ%3E&show_unusable=false",
                                    "method":"GET"
                                 },
                                 "response":"comment: A significant portion of the XSS test payload appeared in the web page, but the response content type is non-HTML.\nResponse content-type: application/json\n\n{\"errors\":[{\"code\":\"root.malformed_query_param\",\"message\":\"The value for show_deleted was malformed. '\\\"><qssozia5enz>' is not a valid Boolean value\"}]}"
                              }
                           }
                        ]
                     }
                  }
               }
            ]
         },
         "severity":"1",
         "status":"ACTIVE",
         "timesDetected":416,
         "type":"VULNERABILITY",
         "uniqueId":"12345678-1234-1234-1234-421234567890",
         "updatedDate":"2025-03-21T08:45:25Z",
         "url":"https://web.address.com/api/v1/more/address/stack/versions?show_deleted=%22'%3E%3CqssbVr8SJHx%20%60%3b!--%3D%26%7b()%7d%3E&show_unusable=false",
         "wasc":{
            "count":1,
            "list":[
               {
                  "WASC":{
                     "code":22,
                     "name":"IMPROPER OUTPUT HANDLING",
                     "url":"http://projects.webappsec.org/w/page/13246934/WASC"
                  }
               }
            ]
         },
         "webApp":{
            "id":987654321,
            "name":"GovCloud User Console Scan Target",
            "tags":{
               "count":2,
               "list":[
                  {
                     "Tag":{
                        "id":77439203,
                        "name":"asset_criticality:3"
                     }
                  },
                  {
                     "Tag":{
                        "id":68447639,
                        "name":"data_classification:nan"
                     }
                  }
               ]
            },
            "url":"https://web.address.com"
         }
      },
      "knowledge_base":{
         "CATEGORY":"Web Application",
         "CODE_MODIFIED_DATETIME":"2022-08-10T00:00:00Z",
         "CONSEQUENCE":"No exploit was determined for these reflected characters. The input parameter should be manually analyzed to verify that no other characters can be injected that would lead to an HTML injection (XSS) vulnerability.",
         "CVSS":{
            "BASE":{
               "#text":"5.0",
               "source":"service"
            },
            "TEMPORAL":"3.8",
            "VECTOR_STRING":"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:N/E:U/RL:U/RC:UC"
         },
         "CVSS_V3":{
            "BASE":"3.1",
            "CVSS3_VERSION":"3.1",
            "TEMPORAL":"2.6",
            "VECTOR_STRING":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N/E:U/RL:U/RC:U"
         },
         "DIAGNOSIS":"The web application reflects potentially dangerous characters such as single quotes, double quotes, and angle brackets. These characters are commonly used for HTML injection attacks such as cross-site scripting (XSS).",
         "DISCOVERY":{
            "REMOTE":"1"
         },
         "LAST_SERVICE_MODIFICATION_DATETIME":"2024-02-12T23:24:03Z",
         "PATCHABLE":"0",
         "PCI_FLAG":"0",
         "PUBLISHED_DATETIME":"2011-03-08T18:40:29Z",
         "QID":"150084",
         "SEVERITY_LEVEL":"1",
         "SOLUTION":"Review the reflected characters to ensure that they are properly handled as defined by the web application's coding practice. Typical solutions are to apply HTML encoding or percent encoding to the characters depending on where they are placed in the HTML. For example, a double quote might be encoded as &quot; when displayed in a text node, but as %22 when placed in the value of an href attribute.",
         "THREAT_INTELLIGENCE":{
            "THREAT_INTEL":[
               {
                  "#text":"Easy_Exploit",
                  "id":"5"
               },
               {
                  "#text":"No_Patch",
                  "id":"8"
               }
            ]
         },
         "TITLE":"Unencoded characters",
         "VULN_TYPE":"Potential Vulnerability"
      }
   }
}

```

**Exported fields**

| Field                                                                                  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Type      
|----------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------
| @timestamp                                                                             | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events.                                                                                                                                                                                              | date             |
| data_stream.dataset                                                                    | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace                                                                  | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters                                | constant_keyword |
| data_stream.type                                                                       | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future.                                                                                                                                                                                                                                                                                                                                                                | constant_keyword |
| event.dataset                                                                          | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name.                                                                                                                                                                                                                 | constant_keyword |
| event.module                                                                           | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module.                                                                                                                                                                                                                                                                                                | constant_keyword |
| qualys_was.vulnerability.id                                                            | Id for the vulnerability report                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | long      
| qualys_was.vulnerability.name                                                          | A descriptive name for vulnerability                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | keyword   
| qualys_was.vulnerability.last_found_datetime                                           | The last scqan date where the vulnerability was found                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | date      
| qualys_was.vulnerability.first_found_datetime                                          | The first scan date where the vulnerability was found                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | date      
| qualys_was.vulnerability.last_test_datetime                                            | The last date for which the vulnerability was scanned for (can be set to ignored and not scanned for)                                                                                                                                                                                                                                                                                                                                                                                                                          | date      
| qualys_was.vulnerability.updated_datetime                                              | Available in verbose mode. Datetime that this detection was updated.                                                                                                                                                                                                                                                                                                                                                                                                                                                           | date      
| qualys_was.vulnerability.fixed_datetime                                                | Datetime that this detection was set to "FIXED" status                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | date      
| qualys_was.vulnerability.qid                                                           | Qualys ID for the vulnerability                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | long      
| qualys_was.vulnerability.status                                                        | The status (New, Active, Fixed, Reopened)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | keyword   
| qualys_was.vulnerability.detection_score                                               | The detection score                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | long      
| qualys_was.vulnerability.potential                                                     | Potential vulnerabilities are not verified but should be investiagated                                                                                                                                                                                                                                                                                                                                                                                                                                                         | boolean   
| qualys_was.vulnerability.param                                                         | Available in verbose mode. Param set used in scan request                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | boolean   
| qualys_was.vulnerability.is_ignored                                                    | Is the vulnerbaility being ignored                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | boolean   
| qualys_was.vulnerability.url                                                           | The URL that was scanned                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | keyword   
| qualys_was.vulnerability.unique_vuln_id                                                | Unique id for the vulnerability report                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | keyword   
| qualys_was.vulnerability.times_detected                                                | The number of times the vilnerability has been detected                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | long      
| qualys_was.vulnerability.result_list                                                   | Available in verbose mode. Actual scan result with detials on requst, response and details of finding                                                                                                                                                                                                                                                                                                                                                                                                                          | flattened 
| qualys_was.vulnerability.ignoredBy.id                                                  | Id of person who ignored this vulnerability                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | long      
| qualys_was.vulnerability.ignoredBy.name                                                | Name of person who ignored this vulnerability                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | keyword   
| qualys_was.vulnerability.ignoredBy.username                                            | Username of person who ignored this vulnerability                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | keyword   
| qualys_was.vulnerability.ignoredBy.comment                                             | Comment by person who ignored this vulnerability                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | keyword   
| qualys_was.vulnerability.ignoredBy.reason                                              | Reason the vulnerability was ignored                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | keyword   
| qualys_was.vulnerability.ignoredBy.date                                                | Date the vulnerability was ignored                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | date      
| qualys_was.vulnerability.web_app.id                                                    | Web Application ID                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | long      
| qualys_was.vulnerability.web_app.url                                                   | Web Application base URL                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | keyword   
| qualys_was.vulnerability.web_app.tags                                                  | Available in verbose mode. Web Application tags                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | keyword   
| qualys_was.vulnerability.wasc_references.code                                          | Available in verbose mode. WASC reference code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | long      
| qualys_was.vulnerability.wasc_references.name                                          | Available in verbose mode. WASC reference name                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | keyword   
| qualys_was.vulnerability.wasc_references.url                                           | Available in verbose mode. WASC reference URL                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | keyword   
| qualys_was.vulnerability.owasp_references.code                                         | Available in verbose mode. OWASP code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | long       
| qualys_was.vulnerability.owasp_references.name                                         | Available in verbose mode. OWASP name                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | keyword                                                                                               
| qualys_was.vulnerability.owasp_references.url                                          | Available in verbose mode. OWASP reference URL                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | keyword                                                                                               
| qualys_was.vulnerability.knowledge_base.automatic_pci_fail                             |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.bugtraq_list.id                                |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.bugtraq_list.id.url                            |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.id.category                                    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.changelog_list.info.change_date                |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |date
| qualys_was.vulnerability.knowledge_base.changelog_list.info.comments                   |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.compliance_list.description                    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.compliance_list.section                        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.compliance_list.type                           |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.consequence.comment                            |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.consequence.value                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.correlation.exploits.explt_src.list.explt.desc |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.correlation.exploits.explt_src.list.explt.link |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.correlation.exploits.explt_src.list.explt.ref  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.correlation.exploits.explt_src.list.name       |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.alias        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.id           |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.link         |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.platform     |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.rating       |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.type         |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.name              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cve_list                                       |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss.access.complexity                         |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss.access.vector                             |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss.authentication                            |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss.base                                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss.base_obj                                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |flattened
| qualys_was.vulnerability.knowledge_base.cvss.exploitability                            |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss.impact.availability.keyword               
| qualys_was.vulnerability.knowledge_base.cvss.impact.confidentiality                    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss.impact.integrity                          |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss.remediation_level                         |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss.report_confidence                         |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss.temporal                                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss.vector_string                             |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.attack.complexity                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.attack.vector                          |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.base                                   |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.exploit_code_maturity                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.impact.availability                    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.impact.confidentiality                 |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.impact.integrity                       |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.privileges_required                    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.remediation_level                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.report_confidence                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.scope                                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.temporal                               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.user_interaction                       |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.vector_string                          |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.cvss_v3.version                                |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.detection_info                                 |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.diagnosis.comment                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |match_only_text
| qualys_was.vulnerability.knowledge_base.diagnosis.value                                |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |match_only_text
| qualys_was.vulnerability.knowledge_base.discovery.auth_type_list.value                 |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.discovery.additional_info                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.discovery.remote                               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |long
| qualys_was.vulnerability.knowledge_base.error                                          |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.ids                                            |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.id_range                                       |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.is_disabled                                    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |boolean
| qualys_was.vulnerability.knowledge_base.last.customization.datetime                    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |date
| qualys_was.vulnerability.knowledge_base.last.customization.user_login                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.last.service_modification_datetime             |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |date
| qualys_was.vulnerability.knowledge_base.patchable                                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |boolean
| qualys_was.vulnerability.knowledge_base.pci_flag                                       |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |boolean
| qualys_was.vulnerability.knowledge_base.pci_reasons.value                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.published_datetime                             |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |date
| qualys_was.vulnerability.knowledge_base.qid                                            |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.severity_level                                 |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.software_list.product                          |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.software_list.vendor                           |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.vendor_reference_list.id                       |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.vendor_reference_list.url                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.solution.comment                               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |match_only_text
| qualys_was.vulnerability.knowledge_base.solution.value                                 |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |match_only_text
| qualys_was.vulnerability.knowledge_base.supported_modules                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.threat_intelligence.intel.id                   |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.threat_intelligence.intel.text                 |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.title                                          |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| qualys_was.vulnerability.knowledge_base.vuln_type                                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |keyword
| vulnerability.id                                                                       | The identification (ID) is the number portion of a vulnerability entry                                                                                                                                                                                                                                                                                                                                                                                                                                                         | keyword          |
| vulnerability.classification                                                           | The classification of the vulnerability scoring system                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | constant_keyword |
| vulnerability.enumeration                                                              | The type of identifier used for this vulnerability                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | constant_keyword |
| vulnerability.category                                                                 | The type of system or architecture that the vulnerability affects.                                                                                                                                                                                                                                                                                                                                                                                                                                                             | constant_keyword |
| vulnerability.scanner.vendor                                                           | The name of the vulnerability scanner vendor.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | constant_keyword |
| vulnerability.severity                                                                 | The severity of the vulnerability                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | keyword          |
| vulnerability.score.base                                                               | Available in verbose mode. Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Base scores cover an assessment for exploitability metrics (attack vector, complexity, privileges, and user interaction), impact metrics (confidentiality, integrity, and availability), and scope.                                                                                                                                                                                                                             | float            |
| vulnerability.score.temporal                                                           | Available in verbose mode. Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Temporal scores cover an assessment for code maturity, remediation level, and confidence.                                                                                                                                                                                                                                                                                                                                       | float            |


