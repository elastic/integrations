# F5 BIG-IP

## Overview

The [F5 BIG-IP](https://www.f5.com/products/big-ip-services) integration allows users to monitor LTM, AFM, APM, ASM, and AVR activity. F5 BIG-IP covers software and hardware designed around application availability, access control, and security solutions.

Use the F5 BIG-IP integration to collect and parse data from F5 BIG-IP using **telemetry streaming** and then visualize that data in Kibana.

The F5 BIG-IP integration can be used in three different modes to collect data:
- **HTTP Endpoint mode** - F5 BIG-IP pushes logs directly to an HTTP endpoint hosted by users’ Elastic Agent.
- **AWS S3 polling mode** - F5 BIG-IP writes data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- **AWS S3 SQS mode** - F5 BIG-IP writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

For example, users can use the data from this integration to analyze the traffic that passes through their F5 BIG-IP network.

## Data streams

The F5 BIG-IP integration collects one type of data stream: log.

**Log** help users to keep a record of events happening on the network using telemetry streaming.
The log data stream collected by the F5 BIG-IP integration includes events that are related to network traffic. See more details in the [Logs](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/output-example.html#ltm-request-log).

This integration targets the five types of events as mentioned below:

- **LTM** provides the platform for creating virtual servers, performance, service, protocol, authentication, and security profiles to define and shape users’ application traffic. For more information, refer to the link [here](https://www.f5.com/products/big-ip-services/local-traffic-manager).
- **AFM** is designed to reduce the hardware and extra hops required when ADC's are paired with traditional firewalls and helps to protect traffic destined for the user's data center. For more information, refer to the link [here](https://www.f5.com/products/security/advanced-firewall-manager).
- **APM** provides federation, SSO, application access policies, and secure web tunneling and allows granular access to users' various applications, virtualized desktop environments, or just go full VPN tunnel. For more information, refer to the link [here](https://www.f5.com/products/security/access-policy-manager).
- **ASM** is F5's web application firewall (WAF) solution. It allows users to tailor acceptable and expected application behavior on a per-application basis. For more information, refer to the link [here](https://www.f5.com/pdf/products/big-ip-application-security-manager-overview.pdf).
- **AVR** provides detailed charts and graphs to give users more insight into the performance of web applications, with detailed views on HTTP and TCP stats, as well as system performance (CPU, memory, etc.). For more information, refer to the link [here](https://clouddocs.f5.com/training/community/analytics/html/class1/class1.html).

## Requirements

Elasticsearch is needed to store and search data, and Kibana is needed for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

The reference link for requirements of telemetry streaming is [here](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/prereqs.html).

The reference link for requirements of Application Services 3(AS3) Extension is [here](https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/userguide/prereqs.html).

This module has been tested against `F5 BIG-IP version 16.1.0`, `Telemetry Streaming version 1.32.0` and `AS3 version 3.40.0`.

## Setup

### To collect LTM, AFM, APM, ASM, and AVR data from F5 BIG-IP, the user has to configure modules in F5 BIG-IP as per the requirements.

To set up the F5 BIG-IP environment, users can use the BIG-IP system browser-based Configuration Utility or the command line tools that are provided. For more information related to the configuration of F5 BIG-IP servers, refer to F5 support website [here](https://support.f5.com/csp/knowledge-center/software).

### Configuration of Telemetry Streaming in F5

For downloading and installing Telemetry Streaming, refer to the link [here](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/installation.html).

Telemetry Streaming will send logs in the JSON format to the destination. Telemetry Streaming is compatible with **BIG-IP versions 13.0 and later**. Users have to prepare F5 servers for it and set up the Telemetry Streaming Consumer.

To use telemetry streaming, user have to send **POST** request on `https://<BIG-IP>/mgmt/shared/telemetry/declare` for declaration.

Sample declaration to set up Telemetry Streaming Consumer(Generic_HTTP) is as follows:
```
{
    "class": "Telemetry",
       "My_System": {
        "class": "Telemetry_System",
        "systemPoller": {
            "interval": <INTERVAL>
        }
    },
    "My_Listener": {
        "class": "Telemetry_Listener",
        "port": 6514
    },
    "My_Consumer": {
        "class": "Telemetry_Consumer",
        "type": "Generic_HTTP",
        "host": "<HOST-IP>",
        "protocol": "http",
        "port": <PORT>,
        "path": "/",
        "method": "POST",
        "headers": [
            {
                "name": "content-type",
                "value": "application/json"
            }
        ],
        "outputMode": "processed"
    }
}
```
For more information related to Generic HTTP consumers, refer to the link [here](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/setting-up-consumer.html#generic-http).

To set up TLS client authentication in Generic HTTP consumer, refer to the link [here](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/declarations.html#generic-http-consumer-with-tls-client-authentication).

Sample declaration to set up Telemetry Streaming Consumer(AWS_S3) is as follows:
```
{
    "class": "Telemetry",
    "My_System": {
        "class": "Telemetry_System",
        "systemPoller": {
            "interval": <INTERVAL>
        }
    },
    "My_Listener": {
        "class": "Telemetry_Listener",
        "port": 6514
    },
    "My_Consumer": {
        "class": "Telemetry_Consumer",
        "type": "AWS_S3",
        "region": "<AWS_REGION>",
        "bucket": "<BUCKET_NAME>",
        "username": "<ACCESS_KEY_ID>",
        "passphrase": {
            "cipherText": "<SECRET_ACCESS_KEY>"
        }
    }
}
```
F5 BIG-IP modules named LTM, AFM, ASM, and APM are not configured by Telemetry Streaming, they must be configured with AS3 or another method. Reference link for setup AS3 extension in F5 BIG-IP is [here](https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/).

To configure logging using AS3, refer to the link [here](https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/event-listener.html?highlight=as3#configure-logging-using-as3).

### To collect data from AWS S3 Bucket, follow the below steps:
- Create an Amazon S3 bucket. Refer to the link [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-bucket-overview.html).
- The default value of the "Bucket List Prefix" is listed below. However, the user can set the parameter "Bucket List Prefix" according to the requirement.


  | Data Stream Name  | Bucket List Prefix                                                |
  | ----------------- | ----------------------------------------------------------------- |
  | Log               | `<Bucket list prefix which has been created in AWS S3>`           |

### To collect data from AWS SQS, follow the below steps:
1. If data forwarding to an AWS S3 Bucket hasn't been configured, then first set up an AWS S3 Bucket as mentioned in the above documentation.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
  - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
3. Set up event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - Users have to set the prefix parameter the same as the S3 Bucket List Prefix as created earlier. (for example, `log/` for a log data stream.)
  - Select the event type as s3:ObjectCreated:*, select the destination type SQS Queue, and select the queue that has been created in Step 2.

**Note**:
  - Credentials for the above AWS S3 and SQS input types should be configured using the [link](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**.
2. In the "Search for integrations" search bar, type **F5 BIG-IP**.
3. Click on **F5 BIG-IP** integration from the search results.
4. Click on the **Add F5 BIG-IP** button to add F5 BIG-IP integration.
5. Enable the Integration to collect logs via AWS S3 or HTTP endpoint input.

## Logs Reference

### log

This is the `log` dataset.

#### Example

An example event for `log` looks as following:

```json
{
    "@timestamp": "2018-11-19T22:34:40.000Z",
    "agent": {
        "ephemeral_id": "e53fc33d-3e0e-4f88-a338-d65c29e5d7de",
        "hostname": "docker-fleet-agent",
        "id": "121c9eba-d12d-4405-9bf4-83bc92e8c764",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "client": {
        "ip": "81.2.69.142"
    },
    "data_stream": {
        "dataset": "f5_bigip.log",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "81.2.69.142",
        "port": 80
    },
    "ecs": {
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "121c9eba-d12d-4405-9bf4-83bc92e8c764",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "f5_bigip.log",
        "ingested": "2022-10-21T06:12:02Z",
        "kind": "event",
        "original": "{\"application\":\"app.app\",\"attack_type\":\"Detection Evasion\",\"blocking_exception_reason\":\"test\",\"captcha_result\":\"not_received\",\"date_time\":\"2018-11-19 22:34:40\",\"dest_ip\":\"81.2.69.142\",\"dest_port\":\"80\",\"device_id\":\"12bdca32\",\"fragment\":\"test_Fragment\",\"geo_location\":\"US\",\"hostname\":\"hostname\",\"http_class_name\":\"/Common/abc/test\",\"ip_address_intelligence\":\"host1\",\"ip_client\":\"81.2.69.142\",\"management_ip_address\":\"81.2.69.142\",\"management_ip_address_2\":\"81.2.69.144\",\"method\":\"GET\",\"policy_apply_date\":\"2018-11-19 22:17:57\",\"policy_name\":\"/Common/abc\",\"protocol\":\"HTTP\",\"query_string\":\"name=abc\",\"request\":\"GET /admin/.\",\"request_status\":\"blocked\",\"response_code\":\"0\",\"route_domain\":\"example.com\",\"session_id\":\"abc123abcd\",\"severity\":\"Critical\",\"sig_ids\":\"abc12bcd\",\"sig_names\":\"Sig_Name\",\"src_port\":\"49804\",\"staged_sig_ids\":\"abc23121bc\",\"staged_sig_names\":\"test_name\",\"staged_threat_campaign_names\":\"test\",\"sub_violations\":\"Evasion technique detected:Directory traversals\",\"support_id\":\"123456789\",\"telemetryEventCategory\":\"ASM\",\"tenant\":\"Common\",\"threat_campaign_names\":\"threat\",\"uri\":\"/directory/file\",\"username\":\"test User\",\"violation_rating\":\"3\",\"violations\":\"Evasion technique detected\",\"virus_name\":\"test Virus\",\"web_application_name\":\"/Common/abc\",\"websocket_direction\":\"test\",\"websocket_message_type\":\"test\",\"x_forwarded_for_header_value\":\"81.2.69.144\"}",
        "type": [
            "info"
        ]
    },
    "f5_bigip": {
        "log": {
            "application": {
                "name": "app.app"
            },
            "attack": {
                "type": "Detection Evasion"
            },
            "blocking_exception_reason": "test",
            "captcha_result": "not_received",
            "client": {
                "ip": "81.2.69.142"
            },
            "date_time": "2018-11-19T22:34:40.000Z",
            "dest": {
                "ip": "81.2.69.142",
                "port": 80
            },
            "device": {
                "id": "12bdca32"
            },
            "fragment": "test_Fragment",
            "geo": {
                "location": "US"
            },
            "hostname": "hostname",
            "http": {
                "class_name": "/Common/abc/test"
            },
            "ip_address_intelligence": "host1",
            "management": {
                "ip_address": "81.2.69.142",
                "ip_address_2": "81.2.69.144"
            },
            "method": "GET",
            "policy": {
                "apply_date": "2018-11-19T22:17:57.000Z",
                "name": "/Common/abc"
            },
            "protocol": "HTTP",
            "query": {
                "string": "name=abc"
            },
            "request": {
                "detail": "GET /admin/.",
                "status": "blocked"
            },
            "response": {
                "code": 0
            },
            "route_domain": "example.com",
            "session": {
                "id": "abc123abcd"
            },
            "severity": {
                "name": "Critical"
            },
            "sig": {
                "ids": "abc12bcd",
                "names": "Sig_Name"
            },
            "src": {
                "port": 49804
            },
            "staged": {
                "sig": {
                    "ids": "abc23121bc",
                    "names": "test_name"
                },
                "threat_campaign_names": "test"
            },
            "sub_violations": "Evasion technique detected:Directory traversals",
            "support": {
                "id": "123456789"
            },
            "telemetry": {
                "event": {
                    "category": "ASM"
                }
            },
            "tenant": "Common",
            "threat_campaign_names": "threat",
            "uri": "/directory/file",
            "username": "test User",
            "violation": {
                "rating": 3
            },
            "violations": "Evasion technique detected",
            "virus_name": "test Virus",
            "web_application_name": "/Common/abc",
            "websocket": {
                "direction": "test",
                "message_type": "test"
            },
            "x_forwarded_for_header_value": "81.2.69.144"
        }
    },
    "host": {
        "geo": {
            "country_iso_code": "US"
        },
        "id": "12bdca32",
        "name": "hostname"
    },
    "http": {
        "request": {
            "method": "GET"
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "log": {
        "level": "critical"
    },
    "network": {
        "application": "app.app",
        "protocol": "http"
    },
    "related": {
        "hosts": [
            "hostname",
            "12bdca32",
            "example.com"
        ],
        "ip": [
            "81.2.69.142",
            "81.2.69.144"
        ],
        "user": [
            "test User"
        ]
    },
    "source": {
        "port": 49804
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "f5_bigip-log"
    ],
    "user": {
        "name": "test User"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.type | The type of record being queried. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| f5_bigip.log.abandoned_conns |  | long |
| f5_bigip.log.accept_fails |  | long |
| f5_bigip.log.accepts |  | long |
| f5_bigip.log.access.policy_result |  | keyword |
| f5_bigip.log.access.profile |  | keyword |
| f5_bigip.log.acl.policy.name |  | keyword |
| f5_bigip.log.acl.policy.type |  | keyword |
| f5_bigip.log.acl.rule.name |  | keyword |
| f5_bigip.log.acl.rule.uuid |  | keyword |
| f5_bigip.log.action |  | keyword |
| f5_bigip.log.active_conns |  | double |
| f5_bigip.log.aggr_interval |  | long |
| f5_bigip.log.application.name |  | keyword |
| f5_bigip.log.application.response.max_time |  | long |
| f5_bigip.log.application.response.min_time |  | long |
| f5_bigip.log.application.response.time |  | long |
| f5_bigip.log.application_name |  | keyword |
| f5_bigip.log.attack.count |  | long |
| f5_bigip.log.attack.id |  | keyword |
| f5_bigip.log.attack.mitigation_name |  | keyword |
| f5_bigip.log.attack.trigger_name |  | keyword |
| f5_bigip.log.attack.type |  | keyword |
| f5_bigip.log.attack.vector_name |  | keyword |
| f5_bigip.log.bad_actor.detection.avg |  | long |
| f5_bigip.log.bad_actor.drops |  | long |
| f5_bigip.log.bad_actor.events |  | long |
| f5_bigip.log.bad_actor.mitigation.max |  | long |
| f5_bigip.log.bad_actor.mitigation.min |  | long |
| f5_bigip.log.blocking_exception_reason |  | keyword |
| f5_bigip.log.browser_name |  | keyword |
| f5_bigip.log.bytes.in |  | long |
| f5_bigip.log.bytes.out |  | long |
| f5_bigip.log.bytes.total |  | long |
| f5_bigip.log.captcha_result |  | keyword |
| f5_bigip.log.client.ip |  | ip |
| f5_bigip.log.client.ip_route_domain |  | keyword |
| f5_bigip.log.client.latency.hit_count |  | long |
| f5_bigip.log.client.latency.max |  | long |
| f5_bigip.log.client.latency.total |  | long |
| f5_bigip.log.client.type |  | keyword |
| f5_bigip.log.client_side.network.latency |  | long |
| f5_bigip.log.client_side.network.max_latency |  | long |
| f5_bigip.log.client_side.network.min_latency |  | long |
| f5_bigip.log.client_ttfb.hit_count |  | long |
| f5_bigip.log.client_ttfb.max |  | long |
| f5_bigip.log.client_ttfb.min |  | long |
| f5_bigip.log.client_ttfb.value |  | long |
| f5_bigip.log.compression_method |  | keyword |
| f5_bigip.log.concurrent.connections.avg |  | long |
| f5_bigip.log.concurrent.connections.health |  | long |
| f5_bigip.log.concurrent.connections.max |  | long |
| f5_bigip.log.concurrent.users.max |  | long |
| f5_bigip.log.context.name |  | keyword |
| f5_bigip.log.context.type |  | keyword |
| f5_bigip.log.continent |  | keyword |
| f5_bigip.log.conviction_traps |  | keyword |
| f5_bigip.log.cookie |  | keyword |
| f5_bigip.log.country |  | keyword |
| f5_bigip.log.country_code |  | keyword |
| f5_bigip.log.cpu.analysis_plane.avg |  | long |
| f5_bigip.log.cpu.avg |  | long |
| f5_bigip.log.cpu.control_plane.avg |  | long |
| f5_bigip.log.cpu.data_plane.avg |  | long |
| f5_bigip.log.cpu.health |  | long |
| f5_bigip.log.credential_stuffing_lookup_result |  | keyword |
| f5_bigip.log.date_time |  | date |
| f5_bigip.log.dest.fqdn |  | keyword |
| f5_bigip.log.dest.ip |  | ip |
| f5_bigip.log.dest.ipint_categories |  | keyword |
| f5_bigip.log.dest.port |  | long |
| f5_bigip.log.dest.vlan |  | keyword |
| f5_bigip.log.dest.zone |  | keyword |
| f5_bigip.log.detection.avg |  | long |
| f5_bigip.log.device.id |  | keyword |
| f5_bigip.log.device.product |  | keyword |
| f5_bigip.log.device.vendor |  | keyword |
| f5_bigip.log.device.version |  | keyword |
| f5_bigip.log.dos.mobile_app.client_type |  | keyword |
| f5_bigip.log.dos.mobile_app.display_name |  | keyword |
| f5_bigip.log.dos.mobile_app.version |  | keyword |
| f5_bigip.log.dos.profile_name |  | keyword |
| f5_bigip.log.drop_reason |  | keyword |
| f5_bigip.log.dst.geo |  | keyword |
| f5_bigip.log.enforced_by |  | keyword |
| f5_bigip.log.enforcement_action |  | keyword |
| f5_bigip.log.entity |  | keyword |
| f5_bigip.log.eoc.timestamp |  | date |
| f5_bigip.log.epoch_time |  | date |
| f5_bigip.log.errdefs.msg_name |  | keyword |
| f5_bigip.log.errdefs.msgno |  | keyword |
| f5_bigip.log.event.source |  | keyword |
| f5_bigip.log.event.timestamp |  | date |
| f5_bigip.log.events.total |  | long |
| f5_bigip.log.expired_conns |  | long |
| f5_bigip.log.failed_conns |  | long |
| f5_bigip.log.flow.id |  | keyword |
| f5_bigip.log.fragment |  | keyword |
| f5_bigip.log.geo.code |  | keyword |
| f5_bigip.log.geo.country |  | keyword |
| f5_bigip.log.geo.info |  | keyword |
| f5_bigip.log.geo.location |  | keyword |
| f5_bigip.log.global_bigiq_conf |  | keyword |
| f5_bigip.log.hardware_drops |  | long |
| f5_bigip.log.headers |  | keyword |
| f5_bigip.log.hit_count |  | long |
| f5_bigip.log.hostname |  | keyword |
| f5_bigip.log.http.class_name |  | keyword |
| f5_bigip.log.http.content_type |  | keyword |
| f5_bigip.log.http.host |  | keyword |
| f5_bigip.log.http.method |  | keyword |
| f5_bigip.log.http.referrer |  | keyword |
| f5_bigip.log.http.status |  | keyword |
| f5_bigip.log.http.uri |  | keyword |
| f5_bigip.log.http.url |  | keyword |
| f5_bigip.log.http.user_agent |  | keyword |
| f5_bigip.log.http.version |  | keyword |
| f5_bigip.log.hw.cookie_valid |  | long |
| f5_bigip.log.ip_address_intelligence |  | keyword |
| f5_bigip.log.ip_protocol |  | keyword |
| f5_bigip.log.ip_reputation |  | keyword |
| f5_bigip.log.ip_route_domain |  | keyword |
| f5_bigip.log.ip_with_route_domain |  | keyword |
| f5_bigip.log.is_attacking_ip |  | boolean |
| f5_bigip.log.is_internal_activity |  | boolean |
| f5_bigip.log.is_mobile_device |  | boolean |
| f5_bigip.log.is_truncated |  | keyword |
| f5_bigip.log.is_trunct |  | keyword |
| f5_bigip.log.latency_histogram |  | keyword |
| f5_bigip.log.likely_false_positive_sig_ids |  | keyword |
| f5_bigip.log.listener |  | keyword |
| f5_bigip.log.login_result |  | keyword |
| f5_bigip.log.management.ip_address |  | ip |
| f5_bigip.log.management.ip_address_2 |  | ip |
| f5_bigip.log.max_active_conns |  | long |
| f5_bigip.log.memory.avg |  | long |
| f5_bigip.log.memory.health |  | long |
| f5_bigip.log.method |  | keyword |
| f5_bigip.log.mgmt_ip |  | ip |
| f5_bigip.log.microservice |  | keyword |
| f5_bigip.log.mitigation.max |  | long |
| f5_bigip.log.mitigation.min |  | long |
| f5_bigip.log.mobile_application.name |  | keyword |
| f5_bigip.log.mobile_application.version |  | keyword |
| f5_bigip.log.module |  | keyword |
| f5_bigip.log.network.protocol |  | keyword |
| f5_bigip.log.new_conns |  | long |
| f5_bigip.log.node |  | ip |
| f5_bigip.log.node_port |  | long |
| f5_bigip.log.object_tags_list |  | keyword |
| f5_bigip.log.operation.id |  | keyword |
| f5_bigip.log.osname |  | keyword |
| f5_bigip.log.partition |  | keyword |
| f5_bigip.log.partition_name |  | keyword |
| f5_bigip.log.password_hash_prefix |  | keyword |
| f5_bigip.log.policy.apply_date |  | date |
| f5_bigip.log.policy.name |  | keyword |
| f5_bigip.log.pool.ip |  | ip |
| f5_bigip.log.pool.ip_route_domain |  | keyword |
| f5_bigip.log.pool.port |  | long |
| f5_bigip.log.profile.name |  | keyword |
| f5_bigip.log.protocol |  | keyword |
| f5_bigip.log.protocol_info |  | keyword |
| f5_bigip.log.query.name |  | keyword |
| f5_bigip.log.query.string |  | keyword |
| f5_bigip.log.query.type |  | keyword |
| f5_bigip.log.reputation |  | keyword |
| f5_bigip.log.req.elapsed_time |  | long |
| f5_bigip.log.req.start_time |  | date |
| f5_bigip.log.request.detail |  | keyword |
| f5_bigip.log.request.duration |  | long |
| f5_bigip.log.request.duration_hit_count |  | long |
| f5_bigip.log.request.max_duration |  | long |
| f5_bigip.log.request.min_duration |  | long |
| f5_bigip.log.request.status |  | keyword |
| f5_bigip.log.res.start_time |  | date |
| f5_bigip.log.resp |  | keyword |
| f5_bigip.log.response.code |  | long |
| f5_bigip.log.response.duration |  | long |
| f5_bigip.log.response.duration_hit_count |  | long |
| f5_bigip.log.response.max_duration |  | long |
| f5_bigip.log.response.min_duration |  | long |
| f5_bigip.log.response.value |  | keyword |
| f5_bigip.log.route_domain |  | keyword |
| f5_bigip.log.rxbad_cookie |  | long |
| f5_bigip.log.rxbadseg |  | long |
| f5_bigip.log.rxbadsum |  | long |
| f5_bigip.log.rxcookie |  | long |
| f5_bigip.log.rxooseg |  | long |
| f5_bigip.log.rxrst |  | long |
| f5_bigip.log.sa_translation.pool |  | keyword |
| f5_bigip.log.sa_translation.type |  | keyword |
| f5_bigip.log.send_to_vs |  | keyword |
| f5_bigip.log.server.hit_count |  | long |
| f5_bigip.log.server.ip |  | ip |
| f5_bigip.log.server.latency.max |  | long |
| f5_bigip.log.server.latency.min |  | long |
| f5_bigip.log.server.latency.total |  | long |
| f5_bigip.log.server_side.network.latency |  | long |
| f5_bigip.log.server_side.network.max_latency |  | long |
| f5_bigip.log.server_side.network.min_latency |  | long |
| f5_bigip.log.session.id |  | keyword |
| f5_bigip.log.severity.code |  | long |
| f5_bigip.log.severity.name |  | keyword |
| f5_bigip.log.sig.cves |  | keyword |
| f5_bigip.log.sig.ids |  | keyword |
| f5_bigip.log.sig.names |  | keyword |
| f5_bigip.log.sig.set_names |  | keyword |
| f5_bigip.log.slot.id |  | keyword |
| f5_bigip.log.slot.number |  | long |
| f5_bigip.log.sndpack |  | long |
| f5_bigip.log.software_drops |  | long |
| f5_bigip.log.sos.application_response_time |  | long |
| f5_bigip.log.sos.client_side_network_latency |  | long |
| f5_bigip.log.sos.client_ttfb |  | long |
| f5_bigip.log.sos.request_duration |  | long |
| f5_bigip.log.sos.response_duration |  | long |
| f5_bigip.log.sos.server_side_network_latency |  | long |
| f5_bigip.log.source.fqdn |  | keyword |
| f5_bigip.log.source.ip |  | ip |
| f5_bigip.log.source.ip_route_domain |  | keyword |
| f5_bigip.log.source.ipint_categories |  | keyword |
| f5_bigip.log.source.port |  | long |
| f5_bigip.log.source.user |  | keyword |
| f5_bigip.log.source.user_group |  | keyword |
| f5_bigip.log.src.geo |  | keyword |
| f5_bigip.log.src.ip |  | ip |
| f5_bigip.log.src.port |  | long |
| f5_bigip.log.src.zone |  | keyword |
| f5_bigip.log.staged.sig.cves |  | keyword |
| f5_bigip.log.staged.sig.ids |  | keyword |
| f5_bigip.log.staged.sig.names |  | keyword |
| f5_bigip.log.staged.sig.set_names |  | keyword |
| f5_bigip.log.staged.threat_campaign_names |  | keyword |
| f5_bigip.log.stat_src |  | keyword |
| f5_bigip.log.state |  | keyword |
| f5_bigip.log.sub_violations |  | keyword |
| f5_bigip.log.subnet.ip |  | ip |
| f5_bigip.log.subnet.name |  | keyword |
| f5_bigip.log.subnet.route_domain |  | keyword |
| f5_bigip.log.support.id |  | keyword |
| f5_bigip.log.syncacheover |  | long |
| f5_bigip.log.tap.event_id |  | keyword |
| f5_bigip.log.tap.requested_actions |  | keyword |
| f5_bigip.log.tap.sent_token |  | long |
| f5_bigip.log.tap.transaction_id |  | keyword |
| f5_bigip.log.tap.vid |  | keyword |
| f5_bigip.log.tcp_prof |  | keyword |
| f5_bigip.log.telemetry.event.category |  | keyword |
| f5_bigip.log.telemetry.timestamp |  | date |
| f5_bigip.log.tenant |  | keyword |
| f5_bigip.log.threat_campaign_names |  | keyword |
| f5_bigip.log.throughput.avg |  | long |
| f5_bigip.log.throughput.health |  | long |
| f5_bigip.log.throughput.req_per_interval.total |  | long |
| f5_bigip.log.throughput.req_per_sec.max |  | long |
| f5_bigip.log.throughput.resp_per_interval.total |  | long |
| f5_bigip.log.throughput.resp_per_sec.max |  | long |
| f5_bigip.log.tps.max |  | long |
| f5_bigip.log.transaction_outcome |  | keyword |
| f5_bigip.log.translated.dest.ip |  | ip |
| f5_bigip.log.translated.dest.port |  | long |
| f5_bigip.log.translated.ip_protocol |  | keyword |
| f5_bigip.log.translated.route_domain |  | keyword |
| f5_bigip.log.translated.source.ip |  | ip |
| f5_bigip.log.translated.source.port |  | long |
| f5_bigip.log.translated.vlan |  | keyword |
| f5_bigip.log.txrexmits |  | long |
| f5_bigip.log.unit_host |  | keyword |
| f5_bigip.log.unit_hostname |  | keyword |
| f5_bigip.log.uri |  | keyword |
| f5_bigip.log.url |  | keyword |
| f5_bigip.log.user.agent |  | keyword |
| f5_bigip.log.user.name |  | keyword |
| f5_bigip.log.user.sessions.new_total |  | long |
| f5_bigip.log.username |  | keyword |
| f5_bigip.log.violate_details |  | keyword |
| f5_bigip.log.violation.details |  | keyword |
| f5_bigip.log.violation.rating |  | long |
| f5_bigip.log.violations |  | keyword |
| f5_bigip.log.vip |  | keyword |
| f5_bigip.log.virtual.ip |  | ip |
| f5_bigip.log.virtual.name |  | keyword |
| f5_bigip.log.virtual.server |  | keyword |
| f5_bigip.log.virus_name |  | keyword |
| f5_bigip.log.vlan |  | keyword |
| f5_bigip.log.vs_name |  | keyword |
| f5_bigip.log.web_application_name |  | keyword |
| f5_bigip.log.websocket.direction |  | keyword |
| f5_bigip.log.websocket.message_type |  | keyword |
| f5_bigip.log.wl_events |  | long |
| f5_bigip.log.x_forwarded_for_header_value |  | ip |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.geo.continent_name | Name of the continent. | keyword |
| host.geo.country_iso_code | Country ISO code. | keyword |
| host.geo.country_name | Country name. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| network.application | When a specific application or service is identified from network connection details (source/dest IPs, ports, certificates, or wire format), this field captures the application's or service's name. For example, the original event identifies the network connection being from a specific web service in a `https` network connection, like `facebook` or `twitter`. The field value must be normalized to lowercase for querying. | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| source.user.group.name | Name of the group. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.username | Username of the request. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

