# Imperva Cloud WAF

Imperva Cloud WAF is a cloud-based application delivery service that includes web security, DDoS protection, CDN, and load balancing.

## Data streams

This integration supports ingestion of events from Imperva Cloud WAF, via AWS S3 input or via [Imperva API](https://docs.imperva.com/bundle/cloud-application-security/page/settings/log-integration.htm).

**Event** is used to retrieve access and security events. See more details in the documentation [here](https://docs.imperva.com/bundle/cloud-application-security/page/more/log-file-structure.htm).

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).  

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### Steps to setup Amazon S3 Connection(Push Mode):

1. Login to your [Imperva Cloud WAF console](https://authentication-management.service.imperva.com/login).
2. On the sidebar, click Logs > Log Setup.
3. Connection. Select **Amazon S3**.
4. Next, fill in your credentials:  
   Your S3 Access key, Secret key, and Path, where path is the location of the folder where you want to store the logs. Enter the path in the following format: <Amazon S3 bucket name>/<log folder>. For example: MyBucket/MyIncapsulaLogFolder.
5. Click Test connection to perform a full testing cycle in which a test file will be transferred to your designated folder. The test file does not contain real data, and will be removed by Incapsula when the transfer is complete.
6. Configure the additional options:
    - Format. Select the format for the log files: CEF
    - Compress logs. By default, log files are compressed. Clear this option to keep the logs uncompressed.

### Steps to obtain API URL, API Key and API ID(Pull Mode):

1. Login to your [Imperva Cloud WAF console](https://authentication-management.service.imperva.com/login).
2. On the sidebar, click Logs > Log Setup.
3. Connection. Select **Imperva API**.
4. From this window copy and keep API Key handy, this will be required for further Integration configuration.
5. Copy **API ID** and **Log Server URI**.
6. Configure the additional options:
    - Format. Select the format for the log files: CEF
    - Compress logs. By default, log files are compressed. Clear this option to keep the logs uncompressed.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Imperva Cloud WAF
3. Click on the "Imperva Cloud WAF" integration from the search results.
4. Click on the "Add Imperva Cloud WAF" button to add the integration.
5. While adding the integration, if you want to collect logs via AWS S3, keep **Collect Imperva Cloud WAF logs via AWS S3 or AWS SQS** toggle on and then configure following parameters:
   - access key id
   - secret access key
   - bucket arn
   - collect logs via S3 Bucket toggled on

   or if you want to collect logs via AWS SQS, keep **Collect Imperva Cloud WAF logs via AWS S3 or AWS SQS** toggle on and then configure following parameters:
   - access key id
   - secret access key
   - queue url
   - collect logs via S3 Bucket toggled off

   or if you want to collect logs via API, keep **Collect Imperva Cloud WAF logs via API** toggle on and and then configure following parameters:
   - API ID
   - API Key
   - URL
6. Save the integration.

**NOTE**: There are other input combination options available for AWS S3 input, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

## Logs Reference

### Event

This is the `Event` dataset.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2024-01-31T09:22:42.456Z",
    "agent": {
        "ephemeral_id": "7d22d234-404b-426a-be1c-8ca128c3357b",
        "id": "1c0e504b-c5db-46af-aa55-bd7efb79ed8c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "aws": {
        "s3": {
            "bucket": {
                "arn": "arn:aws:s3:::elastic-package-imperva-cloud-waf-bucket-13510",
                "name": "elastic-package-imperva-cloud-waf-bucket-13510"
            },
            "object": {
                "key": "events.log"
            }
        }
    },
    "cloud": {
        "region": "us-east-1"
    },
    "data_stream": {
        "dataset": "imperva_cloud_waf.event",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "1c0e504b-c5db-46af-aa55-bd7efb79ed8c",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "code": "1",
        "dataset": "imperva_cloud_waf.event",
        "end": "2019-08-20T11:31:10.892Z",
        "ingested": "2024-01-31T09:22:43Z",
        "kind": "event",
        "original": "CEF:0|Incapsula|SIEMintegration|1|1|Normal|0| sourceServiceName=site123.abcd.info siteid=1509732 suid=50005477 requestClientApplication=Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0 deviceFacility=mia ccode=IL tag=www.elvis.com cicode=Rehovot cs7=31.8969 cs7Label=latitude cs8=34.8186 cs8Label=longitude Customer=CEFcustomer123 siteTag=my-site-tag start=1453290121336 request=site123.abcd.info/main.css ref=www.incapsula.com/lama requestmethod=GET cn1=200 app=HTTP deviceExternalID=33411452762204224 in=54 xff=44.44.44.44 cpt=443 src=12.12.12.12 ver=TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 end=1566300670892 additionalReqHeaders=[{\"Accept\":\"*/*\"},{\"x-v\":\"1\"},{\"x-fapi-interaction-id\":\"10.10.10.10\"}] additionalResHeaders=[{\"Content-Type\":\"text/html; charset\\=UTF-8\"}]",
        "severity": 0,
        "start": "2016-01-20T11:42:01.336Z",
        "type": [
            "info"
        ]
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 200
        }
    },
    "imperva_cloud_waf": {
        "event": {
            "extensions": {
                "additional": {
                    "req_headers": [
                        {
                            "Accept": "*/*"
                        },
                        {
                            "x-v": "1"
                        },
                        {
                            "x-fapi-interaction-id": "10.10.10.10"
                        }
                    ],
                    "res_headers": [
                        {
                            "Content-Type": "text/html; charset=UTF-8"
                        }
                    ]
                },
                "cicode": "Rehovot",
                "cs7Label": "latitude",
                "cs8Label": "longitude",
                "customer": "CEFcustomer123",
                "device": {
                    "externalId": "33411452762204224",
                    "facility": "mia"
                },
                "ref": "www.incapsula.com/lama",
                "site": {
                    "id": "1509732",
                    "tag": "my-site-tag"
                },
                "source": {
                    "service_name": "site123.abcd.info"
                },
                "tag": "www.elvis.com",
                "ver": "TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256"
            },
            "name": "Normal",
            "version": "0"
        }
    },
    "input": {
        "type": "aws-s3"
    },
    "log": {
        "file": {
            "path": "https://elastic-package-imperva-cloud-waf-bucket-13510.s3.us-east-1.amazonaws.com/events.log"
        },
        "offset": 134
    },
    "message": "Normal",
    "network": {
        "application": "http",
        "forwarded_ip": "44.44.44.44"
    },
    "observer": {
        "product": "SIEMintegration",
        "vendor": "Incapsula",
        "version": "1"
    },
    "related": {
        "ip": [
            "12.12.12.12",
            "44.44.44.44"
        ],
        "user": [
            "50005477"
        ]
    },
    "source": {
        "bytes": 54,
        "geo": {
            "country_iso_code": "IL",
            "location": {
                "lat": 31.8969,
                "lon": 34.8186
            }
        },
        "ip": "12.12.12.12",
        "port": 443,
        "service": {
            "name": "site123.abcd.info"
        },
        "user": {
            "id": "50005477"
        }
    },
    "tags": [
        "collect_sqs_logs",
        "preserve_original_event",
        "forwarded",
        "imperva_cloud_waf-event"
    ],
    "tls": {
        "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "version": "1.2"
    },
    "url": {
        "extension": "css",
        "original": "site123.abcd.info/main.css",
        "path": "site123.abcd.info/main.css"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Firefox",
        "original": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
        "os": {
            "full": "Windows 7",
            "name": "Windows",
            "version": "7"
        },
        "version": "40.0."
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.s3.bucket.arn | The AWS S3 bucket ARN. | keyword |
| aws.s3.bucket.name | The AWS S3 bucket name. | keyword |
| aws.s3.object.key | The AWS S3 Object key. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.process.name |  | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| imperva_cloud_waf.event.device.event_class_id | Signature Id. | keyword |
| imperva_cloud_waf.event.device.product | The product or service that is generating the logs. | keyword |
| imperva_cloud_waf.event.device.vendor | The vendor that is generating the logs. | keyword |
| imperva_cloud_waf.event.device.version | An integer that identifies the version of the log format. | keyword |
| imperva_cloud_waf.event.extensions.action | The method in which Imperva processed the request. | keyword |
| imperva_cloud_waf.event.extensions.additional.req_headers | Request headers in JSON format, with each field represented as a name-value pair. | object |
| imperva_cloud_waf.event.extensions.additional.res_headers | Response headers in JSON format, with each field represented as a name-value pair. | object |
| imperva_cloud_waf.event.extensions.application_protocol | The request protocol. | keyword |
| imperva_cloud_waf.event.extensions.bytes_in | The content length. | long |
| imperva_cloud_waf.event.extensions.ccode | The country code of the site visitor. | keyword |
| imperva_cloud_waf.event.extensions.cicode | The city code of the site visitor. | keyword |
| imperva_cloud_waf.event.extensions.cpt | The client port used to communicate the request. | long |
| imperva_cloud_waf.event.extensions.cs10 | JSON describing all actions that were applied to a specific request. | object |
| imperva_cloud_waf.event.extensions.cs10Label |  | keyword |
| imperva_cloud_waf.event.extensions.cs11 | Additional information on the violation that triggered the rule, in JSON format. | object |
| imperva_cloud_waf.event.extensions.cs11Label |  | keyword |
| imperva_cloud_waf.event.extensions.cs7 | The latitude of the event. | double |
| imperva_cloud_waf.event.extensions.cs7Label |  | keyword |
| imperva_cloud_waf.event.extensions.cs8 | The longitude of the event. | double |
| imperva_cloud_waf.event.extensions.cs8Label |  | keyword |
| imperva_cloud_waf.event.extensions.cs9 | The threat rule name that this request triggered. | keyword |
| imperva_cloud_waf.event.extensions.cs9Label |  | keyword |
| imperva_cloud_waf.event.extensions.customer | The account name of the site owner. | keyword |
| imperva_cloud_waf.event.extensions.destination_process_name | The browser type. | keyword |
| imperva_cloud_waf.event.extensions.device.custom_number1 | The HTTP response code returned to the client. | long |
| imperva_cloud_waf.event.extensions.device.custom_string1 | Whether or not the client application supports Captcha. | keyword |
| imperva_cloud_waf.event.extensions.device.custom_string1_label |  | keyword |
| imperva_cloud_waf.event.extensions.device.custom_string2 | Whether or not the client application supports JavaScript. | boolean |
| imperva_cloud_waf.event.extensions.device.custom_string2_label |  | keyword |
| imperva_cloud_waf.event.extensions.device.custom_string3 | Whether or not the client application supports cookies. | boolean |
| imperva_cloud_waf.event.extensions.device.custom_string3_label |  | keyword |
| imperva_cloud_waf.event.extensions.device.custom_string4 | The ID of the visitor. | keyword |
| imperva_cloud_waf.event.extensions.device.custom_string4_label |  | keyword |
| imperva_cloud_waf.event.extensions.device.custom_string5 | For internal use. | keyword |
| imperva_cloud_waf.event.extensions.device.custom_string5_label |  | keyword |
| imperva_cloud_waf.event.extensions.device.custom_string6 | The client application software. | keyword |
| imperva_cloud_waf.event.extensions.device.custom_string6_label |  | keyword |
| imperva_cloud_waf.event.extensions.device.externalId | A unique identifier of the request that can be used to correlate with reports and data from the Imperva Cloud Security Console. | keyword |
| imperva_cloud_waf.event.extensions.device.facility | The Imperva PoP that handled the request. | keyword |
| imperva_cloud_waf.event.extensions.end_time | The end time of the response to the request, in UTC. In UNIX epoch time format. | date |
| imperva_cloud_waf.event.extensions.file.permission | Imperva attack id. | keyword |
| imperva_cloud_waf.event.extensions.file.type | The type of attack. | keyword |
| imperva_cloud_waf.event.extensions.file_id | The unique identification. | keyword |
| imperva_cloud_waf.event.extensions.postbody | The post body data of the request. | keyword |
| imperva_cloud_waf.event.extensions.qstr | The query string of the request. | keyword |
| imperva_cloud_waf.event.extensions.ref | The URL of the previous page that the client visited. | keyword |
| imperva_cloud_waf.event.extensions.request.client_application | The UserAgent header value. | keyword |
| imperva_cloud_waf.event.extensions.request.method | The request method. | keyword |
| imperva_cloud_waf.event.extensions.request.url | The URL of the request. | keyword |
| imperva_cloud_waf.event.extensions.sip | The IP address of the server. | ip |
| imperva_cloud_waf.event.extensions.site.id | The numeric identifier of the site. | keyword |
| imperva_cloud_waf.event.extensions.site.tag | Site level reference ID. | keyword |
| imperva_cloud_waf.event.extensions.source.address | The client IP that made the request. | ip |
| imperva_cloud_waf.event.extensions.source.port | The port of the server. | long |
| imperva_cloud_waf.event.extensions.source.service_name | The name of the site. | keyword |
| imperva_cloud_waf.event.extensions.source.user_id | The numeric identifier of the account of the site owner. | keyword |
| imperva_cloud_waf.event.extensions.start_time | The time in which this visit started, in UTC. In UNIX epoch time format. | date |
| imperva_cloud_waf.event.extensions.tag | Account level reference ID. | keyword |
| imperva_cloud_waf.event.extensions.ver | The TLS version and encryption algorithms used in the request. | keyword |
| imperva_cloud_waf.event.extensions.xff | The X-Forwarded-For request header. | ip |
| imperva_cloud_waf.event.name | The rule type that was triggered. | keyword |
| imperva_cloud_waf.event.severity | Imperva internal rule ID number. | long |
| imperva_cloud_waf.event.version | An integer that identifies the version of the log format. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| source.service.name |  | keyword |

