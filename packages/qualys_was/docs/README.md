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
The integration uses verbose mode by default. IN addition to the ingested data enumerated below,
verbose mode returns the history of all scans on the target. If the Qualys WAS application is not configured to
delete old scans, the amount of data that is returned is significant. The agent may experience issues related
to memory exhaustion. Deleting old scans on a schedule will mitigate the issue. Removing old scan data will not affect 
vulnerability reports. If deleting old scans in not an option, other ways to mitigate the issue are:
- turning off verbose mode
- reducing batch size
- increasing memory on the agent 

The additional data available with verbose mode are:
- Web application tags
- OWASP name, code and URL for the detection
- WASC name, code and URL for the detection
- CWE code (becomes ECS value vulnerability.id)
- updatedDateTime
- param value for the test
- results of the most recent scan including the requests made, the response and details what about the response resulted
  in a vulnerability report (stored as flattened data)

## Processing Logic
Cel scripts are used to fetch the data from Qualys endpoints and processed into events that 
are consumed by the pipelines.
The cell script requests Findings (detection) data through the REST API using a filter for the "lastTestedDate",
which is the scan datetime. The qid (qualys id) is the id the vulnerability found that maps to a
knowledge base article in the qualys knowledge base. This id is used to request knowledge base data from an 
endpoint which augments each Finding the knowledge base data. Findings are paginated
by the qualys_was.vulnerability.id, a unique id for the finding. Knowledge base data is cached between pages to reduce
the volume of data transported during a single run of the cel script.


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
                              "name": "Tag:1
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

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2025-04-22T06:18:42.000Z",
    "agent": {
        "ephemeral_id": "c53530b5-27c4-4589-af1b-e109fa027659",
        "id": "7261472e-5b72-4691-9320-0ad2b10c109c",
        "name": "elastic-agent-42837",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "qualys_was.vulnerability",
        "namespace": "93053",
        "type": "logs"
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "7261472e-5b72-4691-9320-0ad2b10c109c",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "created": "2025-06-03T20:29:37.908Z",
        "dataset": "qualys_was.vulnerability",
        "ingested": "2025-06-03T20:29:38Z",
        "kind": "event",
        "original": "{\"Finding\":{\"detection\":{\"cvssV3\":{\"attackVector\":\"Network\",\"base\":3.7,\"temporal\":3.6},\"cwe\":{\"count\":1,\"list\":[200]},\"detectionScore\":45,\"findingType\":\"QUALYS\",\"firstDetectedDate\":\"2021-01-27T10:00:41Z\",\"id\":12499746,\"ignoredBy\":{\"firstName\":\"User\",\"id\":1234,\"lastName\":\"LastName\",\"username\":\"username\"},\"ignoredComment\":\"ignored\",\"ignoredDate\":\"2021-02-22T15:58:34Z\",\"ignoredReason\":\"FALSE_POSITIVE\",\"isIgnored\":\"true\",\"lastDetectedDate\":\"2025-04-22T06:18:42Z\",\"lastTestedDate\":\"2025-04-22T06:18:42Z\",\"name\":\"Sensitive form field has not disabled autocomplete\",\"owasp\":{\"count\":1,\"list\":[{\"OWASP\":{\"code\":5,\"name\":\"Security Misconfiguration\",\"url\":\"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/\"}}]},\"potential\":\"false\",\"qid\":150112,\"resultList\":{\"count\":1,\"list\":[{\"Result\":{\"ajax\":\"false\",\"authentication\":\"true\",\"payloads\":{\"count\":4,\"list\":[{\"PayloadInstance\":{\"payload\":\"N/A\",\"request\":{\"body\":null,\"headers\":\"REDACTED\",\"link\":\"https://testurl.com\",\"method\":\"POST\"},\"response\":\"The following password field(s) in the form do not set autocomplete=\\\"off\\\":\\n(Field name: password, Field id: ibe0d2341-1f42-11f0-95f7-4f1cebf89922)\\nParent URL of form is: https://testurl.com\\n\"}},{\"PayloadInstance\":{\"payload\":\"N/A\",\"request\":{\"body\":null,\"headers\":\"REDACTED\",\"link\":\"https://testurl.com\",\"method\":\"POST\"},\"response\":\"The following password field(s) in the form do not set autocomplete=\\\"off\\\":\\n(Field name: password, Field id: icb0bdbe1-1f42-11f0-b97b-21fc91009e0d)\\nParent URL of form is: https://testurl.com\\n\"}},{\"PayloadInstance\":{\"payload\":\"N/A\",\"request\":{\"body\":null,\"headers\":\"REDACTED\",\"link\":\"https://testurl.com\",\"method\":\"POST\"},\"response\":\"The following password field(s) in the form do not set autocomplete=\\\"off\\\":\\n(Field name: password, Field id: if25e6321-1f42-11f0-81c4-87753333478b)\\nParent URL of form is: https://testurl.com\\n\"}},{\"PayloadInstance\":{\"payload\":\"N/A\",\"request\":{\"body\":null,\"headers\":\"REDACTED\",\"link\":\"https://testurl.com\",\"method\":\"POST\"},\"response\":\"error respoonse message\"}}]}}}]},\"severity\":\"2\",\"status\":\"ACTIVE\",\"timesDetected\":1460,\"type\":\"VULNERABILITY\",\"uniqueId\":\"12345678-abcd-efabcd-234-123456789012\",\"updatedDate\":\"2025-04-22T09:26:31Z\",\"url\":\"https://testurl.com\",\"wasc\":{\"count\":1,\"list\":[{\"WASC\":{\"code\":13,\"name\":\"INFORMATION LEAKAGE\",\"url\":\"http://projects.webappsec.org/w/page/13246936/WASC\"}}]},\"webApp\":{\"id\":1,\"name\":\"PCI Serverless Scan\",\"tags\":{\"count\":2,\"list\":[{\"Tag\":{\"id\":12,\"name\":\"Tag:2\"}},{\"Tag\":{\"id\":13,\"name\":\"Tag:1\"}}]},\"url\":\"https://testurl.com\"}},\"knowledge_base\":{\"CATEGORY\":\"Web Application\",\"CODE_MODIFIED_DATETIME\":\"2013-03-07T19:48:34Z\",\"CONSEQUENCE\":\"If the browser is used in a shared computing environment where more than one person may use the browser, then \\u0026quot;autocomplete\\u0026quot; values may be submitted by an unauthorized user.\",\"CVSS\":{\"BASE\":\"0.0\",\"TEMPORAL\":\"0.0\",\"VECTOR_STRING\":\"CVSS:2.0/AV:N/AC:L/Au:S/C:N/I:N/A:N/E:POC/RL:U/RC:C\"},\"CVSS_V3\":{\"BASE\":\"3.7\",\"CVSS3_VERSION\":\"3.1\",\"TEMPORAL\":\"3.6\",\"VECTOR_STRING\":\"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N/E:H/RL:W/RC:C\"},\"DIAGNOSIS\":\"An HTML form that collects sensitive information does not prevent the browser from prompting the user to save the populated values for later reuse.\\n  Autocomplete should be turned off for any input that takes sensitive information such as credit card number, CVV2/CVC code, U.S. social security number, etc.\",\"DISCOVERY\":{\"REMOTE\":\"1\"},\"LAST_SERVICE_MODIFICATION_DATETIME\":\"2017-10-06T22:01:46Z\",\"PATCHABLE\":\"0\",\"PCI_FLAG\":\"0\",\"PUBLISHED_DATETIME\":\"2013-03-07T19:48:34Z\",\"QID\":\"150112\",\"SEVERITY_LEVEL\":\"2\",\"SOLUTION\":\"Add the following attribute to the form or input element: autocomplete=\\u0026quot;off\\u0026quot;\\n  This attribute prevents the browser from prompting the user to save the populated form values for later reuse.\\n  Most browsers no longer honor autocomplete=\\u0026quot;off\\u0026quot; for password input fields.\\n  These browsers include\\n  Chrome, Firefox, Microsoft Edge, IE, Opera\\n  However, there is still an ability to turn off autocomplete through the browser and that is recommended for a shared computing environment.\\n  Since the ability to turn autocomplete off for password inputs fields is controlled by the user it is highly recommended for application to enforce strong password rules.\",\"THREAT_INTELLIGENCE\":{\"THREAT_INTEL\":[{\"#text\":\"Easy_Exploit\",\"id\":\"5\"},{\"#text\":\"No_Patch\",\"id\":\"8\"}]},\"TITLE\":\"Sensitive form field has not disabled autocomplete\",\"VULN_TYPE\":\"Vulnerability\"}}}",
        "type": [
            "info"
        ]
    },
    "event.original": "{\"cvssV3\":{\"attackVector\":\"Network\",\"base\":3.7,\"temporal\":3.6},\"cwe\":{\"count\":1,\"list\":[200]},\"detectionScore\":45,\"findingType\":\"QUALYS\",\"firstDetectedDate\":\"2021-01-27T10:00:41Z\",\"id\":12499746,\"ignoredBy\":{\"firstName\":\"User\",\"id\":1234,\"lastName\":\"LastName\",\"username\":\"username\"},\"ignoredComment\":\"ignored\",\"ignoredDate\":\"2021-02-22T15:58:34Z\",\"ignoredReason\":\"FALSE_POSITIVE\",\"isIgnored\":\"true\",\"lastDetectedDate\":\"2025-04-22T06:18:42Z\",\"lastTestedDate\":\"2025-04-22T06:18:42Z\",\"name\":\"Sensitive form field has not disabled autocomplete\",\"owasp\":{\"count\":1,\"list\":[{\"OWASP\":{\"code\":5,\"name\":\"Security Misconfiguration\",\"url\":\"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/\"}}]},\"potential\":\"false\",\"qid\":150112,\"resultList\":{\"count\":1,\"list\":[{\"Result\":{\"ajax\":\"false\",\"authentication\":\"true\",\"payloads\":{\"count\":4,\"list\":[{\"PayloadInstance\":{\"payload\":\"N/A\",\"request\":{\"body\":null,\"headers\":\"REDACTED\",\"link\":\"https://testurl.com\",\"method\":\"POST\"},\"response\":\"The following password field(s) in the form do not set autocomplete=\\\"off\\\":\\n(Field name: password, Field id: ibe0d2341-1f42-11f0-95f7-4f1cebf89922)\\nParent URL of form is: https://testurl.com\\n\"}},{\"PayloadInstance\":{\"payload\":\"N/A\",\"request\":{\"body\":null,\"headers\":\"REDACTED\",\"link\":\"https://testurl.com\",\"method\":\"POST\"},\"response\":\"The following password field(s) in the form do not set autocomplete=\\\"off\\\":\\n(Field name: password, Field id: icb0bdbe1-1f42-11f0-b97b-21fc91009e0d)\\nParent URL of form is: https://testurl.com\\n\"}},{\"PayloadInstance\":{\"payload\":\"N/A\",\"request\":{\"body\":null,\"headers\":\"REDACTED\",\"link\":\"https://testurl.com\",\"method\":\"POST\"},\"response\":\"The following password field(s) in the form do not set autocomplete=\\\"off\\\":\\n(Field name: password, Field id: if25e6321-1f42-11f0-81c4-87753333478b)\\nParent URL of form is: https://testurl.com\\n\"}},{\"PayloadInstance\":{\"payload\":\"N/A\",\"request\":{\"body\":null,\"headers\":\"REDACTED\",\"link\":\"https://testurl.com\",\"method\":\"POST\"},\"response\":\"error respoonse message\"}}]}}}]},\"severity\":\"2\",\"status\":\"ACTIVE\",\"timesDetected\":1460,\"type\":\"VULNERABILITY\",\"uniqueId\":\"12345678-abcd-efabcd-234-123456789012\",\"updatedDate\":\"2025-04-22T09:26:31Z\",\"url\":\"https://testurl.com\",\"wasc\":{\"count\":1,\"list\":[{\"WASC\":{\"code\":13,\"name\":\"INFORMATION LEAKAGE\",\"url\":\"http://projects.webappsec.org/w/page/13246936/WASC\"}}]},\"webApp\":{\"id\":1,\"name\":\"PCI Serverless Scan\",\"tags\":{\"count\":2,\"list\":[{\"Tag\":{\"id\":12,\"name\":\"Tag:2\"}},{\"Tag\":{\"id\":13,\"name\":\"Tag:1\"}}]},\"url\":\"https://testurl.com\"}}",
    "input": {
        "type": "cel"
    },
    "qualys_was": {
        "vulnerability": {
            "detection_score": 45,
            "first_found_datetime": "2021-01-27T10:00:41.000Z",
            "id": 12499746,
            "ignoredBy": {
                "comment": "ignored",
                "date": "2021-02-22T15:58:34.000Z",
                "id": 1234,
                "reason": "FALSE_POSITIVE",
                "username": "username"
            },
            "is_ignored": "true",
            "knowledge_base": {
                "category": "Web Application",
                "consequence": {
                    "value": "If the browser is used in a shared computing environment where more than one person may use the browser, then &quot;autocomplete&quot; values may be submitted by an unauthorized user."
                },
                "cvss": {
                    "base": "0.0",
                    "temporal": "0.0",
                    "vector_string": "CVSS:2.0/AV:N/AC:L/Au:S/C:N/I:N/A:N/E:POC/RL:U/RC:C"
                },
                "cvss_v3": {
                    "base": "3.7",
                    "temporal": "3.6",
                    "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N/E:H/RL:W/RC:C",
                    "version": "3.1"
                },
                "diagnosis": {
                    "value": "An HTML form that collects sensitive information does not prevent the browser from prompting the user to save the populated values for later reuse.\n  Autocomplete should be turned off for any input that takes sensitive information such as credit card number, CVV2/CVC code, U.S. social security number, etc."
                },
                "discovery": {
                    "remote": 1
                },
                "last": {
                    "service_modification_datetime": "2017-10-06T22:01:46.000Z"
                },
                "patchable": false,
                "pci_flag": false,
                "published_datetime": "2013-03-07T19:48:34.000Z",
                "qid": "150112",
                "severity_level": "2",
                "solution": {
                    "value": "Add the following attribute to the form or input element: autocomplete=&quot;off&quot;\n  This attribute prevents the browser from prompting the user to save the populated form values for later reuse.\n  Most browsers no longer honor autocomplete=&quot;off&quot; for password input fields.\n  These browsers include\n  Chrome, Firefox, Microsoft Edge, IE, Opera\n  However, there is still an ability to turn off autocomplete through the browser and that is recommended for a shared computing environment.\n  Since the ability to turn autocomplete off for password inputs fields is controlled by the user it is highly recommended for application to enforce strong password rules."
                },
                "threat_intelligence": {
                    "intel": [
                        {
                            "id": "5",
                            "text": "Easy_Exploit"
                        },
                        {
                            "id": "8",
                            "text": "No_Patch"
                        }
                    ]
                },
                "title": "Sensitive form field has not disabled autocomplete",
                "vuln_type": "Vulnerability"
            },
            "last_found_datetime": "2025-04-22T06:18:42.000Z",
            "last_test_datetime": "2025-04-22T06:18:42.000Z",
            "name": "Sensitive form field has not disabled autocomplete",
            "potential": "false",
            "qid": 150112,
            "result_list": [
                {
                    "Result": {
                        "ajax": "false",
                        "authentication": "true",
                        "payloads": {
                            "count": 4,
                            "list": [
                                {
                                    "PayloadInstance": {
                                        "payload": "N/A",
                                        "request": {
                                            "headers": "REDACTED",
                                            "link": "https://testurl.com",
                                            "method": "POST"
                                        },
                                        "response": "The following password field(s) in the form do not set autocomplete=\"off\":\n(Field name: password, Field id: 1\nParent URL of form is: https://testurl.com\n"
                                    }
                                }
                            ]
                        }
                    }
                }
            ],
            "status": "ACTIVE",
            "times_detected": 1460,
            "type": "VULNERABILITY",
            "unique_vuln_id": "12345678-abcd-efabcd-234-123456789012",
            "updated_datetime": "2025-04-22T09:26:31.000Z",
            "wasc_references": [
                {
                    "code": 13,
                    "name": "INFORMATION LEAKAGE",
                    "url": "http://projects.webappsec.org/w/page/13246936/WASC"
                }
            ],
            "web_app": {
                "id": 1,
                "name": "PCI Serverless Scan",
                "tags": [
                    "Tag:2",
                    "Tag:1"
                ],
                "url": "https://testurl.com"
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "qualys_was_vulnerability"
    ],
    "url": {
        "full": "https://testurl.com"
    },
    "vulnerability": {
        "category": [
            "Web Application"
        ],
        "classification": "CVSS",
        "description": "An HTML form that collects sensitive information does not prevent the browser from prompting the user to save the populated values for later reuse.\n  Autocomplete should be turned off for any input that takes sensitive information such as credit card number, CVV2/CVC code, U.S. social security number, etc.",
        "enumeration": "CWE",
        "id": [
            "200"
        ],
        "reference": [
            "https://cwe.mitre.org/data/definitions/200.html"
        ],
        "scanner": {
            "vendor": "Qualys"
        },
        "severity": "Medium"
    }
}
```


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
| log.offset | Offset of the entry in the log file. | long |
| qualys_was.vulnerability.detection_score | The detection score. | long |
| qualys_was.vulnerability.first_found_datetime | The first scan date on which the vulnerability was found. | date |
| qualys_was.vulnerability.fixed_datetime | Datetime that this detection was fixed. Available in verbose mode. | date |
| qualys_was.vulnerability.id | ID for the vulnerability report. | long |
| qualys_was.vulnerability.ignoredBy.comment | Comment by the person who set this detection to ignored. | keyword |
| qualys_was.vulnerability.ignoredBy.date | Date this detection  was set to ignored. | date |
| qualys_was.vulnerability.ignoredBy.id | ID of person who set this detection to ignored. | long |
| qualys_was.vulnerability.ignoredBy.name | Name of person who set this detection to ignored. | keyword |
| qualys_was.vulnerability.ignoredBy.reason | Reason why this detection was set to ignored. | keyword |
| qualys_was.vulnerability.ignoredBy.username | Username of person who set this detection to ignored. | keyword |
| qualys_was.vulnerability.is_ignored | If true, the vulnerability will not be rescanned. | boolean |
| qualys_was.vulnerability.knowledge_base.automatic_pci_fail |  | keyword |
| qualys_was.vulnerability.knowledge_base.bugtraq_list.id |  | keyword |
| qualys_was.vulnerability.knowledge_base.bugtraq_list.url |  | keyword |
| qualys_was.vulnerability.knowledge_base.category |  | keyword |
| qualys_was.vulnerability.knowledge_base.changelog_list.info.change_date |  | date |
| qualys_was.vulnerability.knowledge_base.changelog_list.info.comments |  | keyword |
| qualys_was.vulnerability.knowledge_base.compliance_list.description |  | keyword |
| qualys_was.vulnerability.knowledge_base.compliance_list.section |  | keyword |
| qualys_was.vulnerability.knowledge_base.compliance_list.type |  | keyword |
| qualys_was.vulnerability.knowledge_base.consequence.comment |  | keyword |
| qualys_was.vulnerability.knowledge_base.consequence.value |  | match_only_text |
| qualys_was.vulnerability.knowledge_base.correlation.exploits.explt_src.list.explt.desc |  | keyword |
| qualys_was.vulnerability.knowledge_base.correlation.exploits.explt_src.list.explt.link |  | keyword |
| qualys_was.vulnerability.knowledge_base.correlation.exploits.explt_src.list.explt.ref |  | keyword |
| qualys_was.vulnerability.knowledge_base.correlation.exploits.explt_src.name |  | keyword |
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.alias |  | keyword |
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.id |  | keyword |
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.link |  | keyword |
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.platform |  | keyword |
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.rating |  | keyword |
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.list.info.type |  | keyword |
| qualys_was.vulnerability.knowledge_base.correlation.malware.src.name |  | keyword |
| qualys_was.vulnerability.knowledge_base.cve_list |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss.access.complexity |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss.access.vector |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss.authentication |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss.base |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss.base_obj |  | flattened |
| qualys_was.vulnerability.knowledge_base.cvss.exploitability |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss.impact.availability |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss.impact.confidentiality |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss.impact.integrity |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss.remediation_level |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss.report_confidence |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss.temporal |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss.vector_string |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.attack.complexity |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.attack.vector |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.base |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.exploit_code_maturity |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.impact.availability |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.impact.confidentiality |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.impact.integrity |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.privileges_required |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.remediation_level |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.report_confidence |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.scope |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.temporal |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.user_interaction |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.vector_string |  | keyword |
| qualys_was.vulnerability.knowledge_base.cvss_v3.version |  | keyword |
| qualys_was.vulnerability.knowledge_base.detection_info |  | keyword |
| qualys_was.vulnerability.knowledge_base.diagnosis.comment |  | match_only_text |
| qualys_was.vulnerability.knowledge_base.diagnosis.value |  | match_only_text |
| qualys_was.vulnerability.knowledge_base.discovery.additional_info |  | keyword |
| qualys_was.vulnerability.knowledge_base.discovery.auth_type_list.value |  | keyword |
| qualys_was.vulnerability.knowledge_base.discovery.remote |  | long |
| qualys_was.vulnerability.knowledge_base.error |  | keyword |
| qualys_was.vulnerability.knowledge_base.id_range |  | keyword |
| qualys_was.vulnerability.knowledge_base.ids |  | keyword |
| qualys_was.vulnerability.knowledge_base.is_disabled |  | boolean |
| qualys_was.vulnerability.knowledge_base.last.customization.datetime |  | date |
| qualys_was.vulnerability.knowledge_base.last.customization.user_login |  | keyword |
| qualys_was.vulnerability.knowledge_base.last.service_modification_datetime |  | date |
| qualys_was.vulnerability.knowledge_base.patchable |  | boolean |
| qualys_was.vulnerability.knowledge_base.pci_flag |  | boolean |
| qualys_was.vulnerability.knowledge_base.pci_reasons.value |  | keyword |
| qualys_was.vulnerability.knowledge_base.published_datetime |  | date |
| qualys_was.vulnerability.knowledge_base.qid |  | keyword |
| qualys_was.vulnerability.knowledge_base.severity_level |  | keyword |
| qualys_was.vulnerability.knowledge_base.software_list.product |  | keyword |
| qualys_was.vulnerability.knowledge_base.software_list.vendor |  | keyword |
| qualys_was.vulnerability.knowledge_base.solution.comment |  | match_only_text |
| qualys_was.vulnerability.knowledge_base.solution.value |  | match_only_text |
| qualys_was.vulnerability.knowledge_base.supported_modules |  | keyword |
| qualys_was.vulnerability.knowledge_base.threat_intelligence.intel.id |  | keyword |
| qualys_was.vulnerability.knowledge_base.threat_intelligence.intel.text |  | keyword |
| qualys_was.vulnerability.knowledge_base.title |  | keyword |
| qualys_was.vulnerability.knowledge_base.vendor_reference_list.id |  | keyword |
| qualys_was.vulnerability.knowledge_base.vendor_reference_list.url |  | keyword |
| qualys_was.vulnerability.knowledge_base.vuln_type |  | keyword |
| qualys_was.vulnerability.last_found_datetime | The last scan date on which the vulnerability was found. | date |
| qualys_was.vulnerability.last_test_datetime | The last date on which the vulnerability was scanned for. | date |
| qualys_was.vulnerability.name | A descriptive name for vulnerability. | keyword |
| qualys_was.vulnerability.owasp_references.code | OWASP reference code. Available in verbose mode. | long |
| qualys_was.vulnerability.owasp_references.name | OWASP reference name. Available in verbose mode. | keyword |
| qualys_was.vulnerability.owasp_references.url | OWASP reference URL. Available in verbose mode. | keyword |
| qualys_was.vulnerability.param | Parameter set used in scan request. Available in verbose mode. | keyword |
| qualys_was.vulnerability.potential | Potential vulnerability but not verified. | boolean |
| qualys_was.vulnerability.qid | Qualys ID for the vulnerability. | long |
| qualys_was.vulnerability.result_list | Actual scan result with details on request, response and details of finding. Available in verbose mode. | flattened |
| qualys_was.vulnerability.status | The status of the detection (New, Active, Fixed, Reopened). | keyword |
| qualys_was.vulnerability.times_detected | The number of times the vulnerability has been detected. | long |
| qualys_was.vulnerability.type | The type of vulnerability detected (VULNERABILITY, POTENTIAL_VULNERABILITY, SENSITIVE_CONTENT,INFORMATION_GATHERED). | keyword |
| qualys_was.vulnerability.unique_vuln_id | Unique id for the vulnerability report in UUID format. | keyword |
| qualys_was.vulnerability.updated_datetime | Datetime that this detection record was updated. Available in verbose mode. | date |
| qualys_was.vulnerability.url | The URL that was scanned for a specific test of vulnerabilities. | keyword |
| qualys_was.vulnerability.wasc_references.code | WASC reference code. Available in verbose mode. | long |
| qualys_was.vulnerability.wasc_references.name | WASC reference name. Available in verbose mode. | keyword |
| qualys_was.vulnerability.wasc_references.url | WASC reference URL. Available in verbose mode. | keyword |
| qualys_was.vulnerability.web_app.id | Web Application ID. | long |
| qualys_was.vulnerability.web_app.name | Web Application name. | keyword |
| qualys_was.vulnerability.web_app.tags | Web Application tags. Available in verbose mode. | keyword |
| qualys_was.vulnerability.web_app.url | Web Application base URL. | keyword |
