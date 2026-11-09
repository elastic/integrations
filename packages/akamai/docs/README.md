# Akamai Integration

The Akamai integration collects events from the Akamai API, specifically reading from the [Akamai SIEM API](https://techdocs.akamai.com/siem-integration/reference/api).

> **Breaking change in 4.0.0 — CEL to OpenTelemetry migration**

Starting with version 4.0.0, Akamai SIEM API collection uses the OpenTelemetry receiver instead of CEL and requires Elastic Stack 9.5.0 or later.

When upgrading from a CEL-based integration, compatible API settings and credentials can be preserved through automatic input migration.

**Before upgrading, review the following settings:**

- **Initial Interval:** Ensure this value is `12h` or less. The previous CEL input accepted larger values and automatically limited requests to 12 hours. The OpenTelemetry receiver rejects values exceeding `12h`, preventing collection from starting.
- **SSL Configuration:** Existing Beats SSL settings such as `certificate_authorities`, `verification_mode`, and `supported_protocols` are not automatically converted to the OpenTelemetry TLS schema. Review and rewrite custom SSL configurations using the supported options (`ca_file`, `ca_pem`, `cert_file`, `cert_pem`, `key_file`, `key_pem`, `insecure_skip_verify`, `min_version`, and `max_version`).
- **Custom Processors:** Custom CEL/Beats processors are not migrated to the OpenTelemetry input. Any filtering, enrichment, or transformations implemented through these processors will no longer be applied. Review and reimplement the required processing before upgrading, for example using an Elasticsearch custom ingest pipeline (`logs-akamai.siem@custom`). Note that Elasticsearch ingest pipelines process events after they are transmitted from Elastic Agent, rather than filtering them at the source.

The Akamai SIEM API provides access to only the previous 12 hours of events. Verify that data collection resumes promptly after upgrading to avoid permanent gaps. Collection from Google Cloud Storage is unaffected.

## Logs

### SIEM

The Security Information and Event Management API allows you to capture security events generated on the Akamai platform in your SIEM application.

Use this API to get security event data generated on the Akamai platform and correlate it with data from other sources in your SIEM solution. Capture security event data incrementally, or replay missed security events from the past 12 hours. You can store, query, and analyze the data delivered through this API on your end, then go back and adjust your Akamai security settings. If you’re coding your own SIEM connector, it needs to adhere to these specifications in order to pull in security events from Akamai Security Events Collector (ASEC) and process them properly.

See [Akamai API get started](https://techdocs.akamai.com/siem-integration/reference/api-get-started) to set up your Akamai account and get your credentials.

### To collect data via API, follow the steps below:
- Enable the "Collect Akamai SIEM logs via API" toggle; it is disabled by default.
- Configure the API Host, Zone IDs and the EdgeGrid credentials (Client Token, Client Secret, Access Token) under the "Collect Akamai SIEM logs via API" section.
- If the integration policy uses a namespace other than `default`, set the "Data Stream Namespace" option to the same value.

API collection uses the native OpenTelemetry `akamai_siem` receiver behind the scenes. This is an internal backend detail and does not change the Akamai event data you collect.

**Note**:
- Events collected via the API carry fewer agent fields than events collected by the earlier Beats-based input. `agent.name` is the host name of the Elastic Agent (or the `ELASTIC_AGENT_HOSTNAME` override), and `input.type` is `otelcol` (the CEL input used `cel`). `agent.type`, `agent.id`, `agent.version`, `agent.ephemeral_id` and the `elastic_agent.*` fields are not set, so `event.agent_id_status` is `missing`.
- Cursor persistence is enabled by default, so collection resumes from where it left off after an Elastic Agent restart. It can be turned off via the "Persist Cursor" advanced option. Cursor persistence is also not guaranteed across stack upgrades and breaking changes. Whenever the cursor is unavailable, the integration re-fetches the configured Initial Interval window; replayed events are deduplicated by the ingest pipeline's `event.original` fingerprint as long as the data stream is still writing to the same backing index.

### To collect data from GCS Bucket, follow the steps below:
- Configure the [Data Forwarder](https://techdocs.akamai.com/datastream2/docs/stream-google-cloud/) to ingest data into a GCS bucket.
- Configure the GCS bucket names and credentials along with the required configs under the "Collect Akamai SIEM logs via Google Cloud Storage" section. 
- Make sure the service account and authentication being used, has proper levels of access to the GCS bucket [Manage Service Account Keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys/)

**Note**:
- The GCS input currently does not support fetching of buckets using bucket prefixes, so the bucket names have to be configured manually for each data stream.
- The GCS input currently only accepts a service account JSON key or a service account JSON file for authentication.
- The GCS input currently only supports JSON data.

### To collect data from Amazon S3

Akamai [DataStream 2 security logs](https://techdocs.akamai.com/datastream2/docs/security-logs) can be delivered to an [Amazon S3 destination](https://techdocs.akamai.com/datastream2/docs/stream-amazon-s3). The Akamai integration can collect these files using the `aws-s3` input, either by consuming S3 object notifications from Amazon SQS (recommended) or by directly polling an S3 bucket. Both methods use the existing `akamai.siem` data stream and ingest pipeline.

#### Configure native Akamai delivery to Amazon S3

1. In Akamai DataStream 2, create a security logs (SIEM) stream and select the relevant security configurations. See [Create a security log stream](https://techdocs.akamai.com/datastream2/docs/create-a-security-log-stream).
2. Select **Amazon S3** as the delivery destination and configure the bucket name, region, optional folder path, and AWS access credentials. Follow [Akamai's Amazon S3 destination instructions](https://techdocs.akamai.com/datastream2/docs/stream-amazon-s3).
3. Choose JSON security logs. Akamai DataStream 2 delivers log files gzip-compressed by default. The AWS S3 input reads supported compressed objects and processes newline-delimited JSON records individually.
4. Verify that files are arriving in the intended S3 bucket and prefix. Note that Akamai might also create a small access-verification file while validating the destination. Use a dedicated prefix or filtering where appropriate to avoid ingesting non-log files.

#### Collect data from AWS SQS (recommended)

1. Create a **Standard** SQS queue in the same AWS region as the S3 bucket. Do not use a FIFO queue for native S3 event notifications.
2. Configure the queue's resource-based access policy to allow the `s3.amazonaws.com` service principal to perform `sqs:SendMessage`, restricted to the intended bucket ARN (`aws:SourceArn`) and AWS account (`aws:SourceAccount`). See [AWS S3 event notification permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/grant-destinations-permissions-to-s3.html).
3. On the S3 bucket, create an event notification for **All object create events** (`s3:ObjectCreated:*`) with the SQS queue as the destination. Set an optional prefix or suffix filter if only Akamai log objects should generate notifications.
4. Grant the Elastic Agent's AWS identity `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:ChangeMessageVisibility`, and `sqs:GetQueueAttributes` on the queue, plus `s3:GetObject` on the relevant S3 objects. If a customer-managed AWS KMS key protects the resources, include the required KMS permissions.
5. In Fleet, enable **Collect Akamai SIEM logs via AWS S3 / SQS**, leave **Collect via direct S3 bucket polling** disabled, and set **SQS Queue URL**. Configure the AWS region and authentication. Prefer an IAM role or the standard AWS credential chain to long-lived access keys where available.
6. Adjust **SQS Visibility Timeout**, **SQS API Timeout**, and **Workers** for the expected object sizes and traffic. The API timeout must not exceed half the visibility timeout.

SQS messages must contain S3 `ObjectCreated` event notifications. They can be sent directly by S3 or routed through SNS or EventBridge; the `aws-s3` input supports all three without custom notification parsing. For a shared queue, use file selectors carefully. Do not have multiple independent consumers compete for the same messages.

#### Collect data by direct S3 bucket polling

1. In Fleet, enable **Collect Akamai SIEM logs via AWS S3 / SQS** and turn on **Collect via direct S3 bucket polling**.
2. Enter the **S3 Bucket ARN** (`arn:aws:s3:::your-bucket`). Optionally set **S3 Bucket Prefix** and **S3 Bucket List Interval**.
3. Grant the Elastic Agent's AWS identity `s3:ListBucket` and `s3:GetObject`, and `s3:GetBucketLocation` if required by your environment. Configure AWS credentials and region, and save the policy.

Use either SQS notifications or direct bucket polling for a given input, not both. SQS is preferred for ongoing collection because it avoids repeated bucket listing. Avoid collecting the same objects through multiple inputs, which can result in duplicate processing.

**Note**:
- These instructions cover **Amazon S3**. Although Akamai also supports [S3-compatible destinations](https://techdocs.akamai.com/datastream2/docs/stream-s3-compatible), this input currently exposes an Amazon S3 bucket ARN or an AWS SQS queue URL, not the `non_aws_bucket_name` configuration required for generic S3-compatible storage.
- This integration supports Akamai DataStream 2 [Security Logs (SIEM)](https://techdocs.akamai.com/datastream2/docs/security-logs) exported in JSON format to Amazon S3. Other DataStream 2 log types are not supported by the `akamai.siem` ingest pipeline.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| akamai.siem.bot.response_segment | Numeric response segment indicator. Segments are used to group and categorize bot scores. | long |
| akamai.siem.bot.score | Score assigned to the request by Botman Manager. | long |
| akamai.siem.client_data.app_bundle_id | Unique identifier of the app bundle. An app bundle contains both the software itself and the accompanying configuration information. | keyword |
| akamai.siem.client_data.app_version | Version number of the app. | keyword |
| akamai.siem.client_data.sdk_version | SDK version | keyword |
| akamai.siem.client_data.telemetry_type | Specifies the telemetry type in use. | long |
| akamai.siem.client_reputation | Client IP scores for Client Reputation. | keyword |
| akamai.siem.config_id | ID of the Security Configuration applied to the request. | keyword |
| akamai.siem.identity.ja4 | A JA4 TLS client fingerprint value. | keyword |
| akamai.siem.identity.tls_fingerprint_v2 | A client TLS fingerprint V2 value. | keyword |
| akamai.siem.identity.tls_fingerprint_v3 | A client TLS fingerprint V3 value. | keyword |
| akamai.siem.policy_id | ID of the Firewall policy applied to the request. | keyword |
| akamai.siem.request.headers | HTTP Request headers | flattened |
| akamai.siem.response.headers | HTTP response headers | flattened |
| akamai.siem.rule_actions | Actions taken for this request. | keyword |
| akamai.siem.rule_tags | The set of categories for the triggered rule. | keyword |
| akamai.siem.rules | Rules triggered by this request | nested |
| akamai.siem.rules.ruleActions | Actions of rules that triggered for this request. | keyword |
| akamai.siem.rules.ruleData | User data of rules that triggered for this request. | keyword |
| akamai.siem.rules.ruleMessages | Messages of rules that triggered for this request. | keyword |
| akamai.siem.rules.ruleSelectors | Selectors of rules that triggered for this request. | keyword |
| akamai.siem.rules.ruleTags | Tags of rules that triggered for this request. | keyword |
| akamai.siem.rules.ruleVersions | Versions of rules triggered for this request. | keyword |
| akamai.siem.rules.rules | Rules that triggered for this request. | keyword |
| akamai.siem.slow_post_action | Action taken if a Slow POST attack is detected: W for Warn or A for deny (abort). | keyword |
| akamai.siem.slow_post_rate | Recorded rate of a detected Slow POST attack. | long |
| akamai.siem.user_risk.allow | Indicates whether the user is on the allow list. A 0 indicates that the user was not on the list; a 1 indicates that the user was on the list. | long |
| akamai.siem.user_risk.general | Indicators of general behavior observed for relevant attributes. For example, duc_1h represents the number of users recorded on a specific device in the past hour. | flattened |
| akamai.siem.user_risk.risk | Indicators that increased the calculated risk score. For example, the value udfp represents the risk of the device fingerprint based on the user's behavioral profile. | flattened |
| akamai.siem.user_risk.score | Calculated risk scores. Scores range from 0 (no risk) to 100 (the highest possible risk). | long |
| akamai.siem.user_risk.status | Status code indicating any errors that might have occurred when calculating the risk score. | long |
| akamai.siem.user_risk.trust | Indicators that were trusted. For example, the value ugp indicates that the user’s country or area is trusted. | flattened |
| akamai.siem.user_risk.uuid | Unique identifier of the user whose risk data is being provided. | keyword |
| aws.s3.bucket.arn | The AWS S3 bucket ARN. | keyword |
| aws.s3.bucket.name | The AWS S3 bucket name. | keyword |
| aws.s3.object.key | The AWS S3 object key. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gcs.storage.bucket.name | The name of the Google Cloud Storage Bucket. | keyword |
| gcs.storage.object.content_type | The content type of the Google Cloud Storage object. | keyword |
| gcs.storage.object.name | The content type of the Google Cloud Storage object. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |


An example event for `siem` looks as following:

```json
{
    "@timestamp": "2016-08-11T13:45:33.026Z",
    "agent": {
        "ephemeral_id": "ca186677-5301-4e63-8aa5-1ded49198d1f",
        "id": "9d70aadf-eebc-4a79-9154-d09492f8ce88",
        "name": "elastic-agent-72124",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "akamai": {
        "siem": {
            "bot": {
                "response_segment": 3,
                "score": 100
            },
            "client_data": {
                "app_bundle_id": "com.mydomain.myapp",
                "app_version": "1.23",
                "sdk_version": "4.7.1",
                "telemetry_type": 2
            },
            "config_id": "6724",
            "policy_id": "scoe_5426",
            "request": {
                "headers": {
                    "Accept": "text/html,application/xhtml xml",
                    "User-Agent": "BOT/0.1 (BOT for JCE)"
                }
            },
            "response": {
                "headers": {
                    "Content-Type": "text/html",
                    "Mime-Version": "1.0",
                    "Server": "AkamaiGHost"
                }
            },
            "rule_actions": [
                "alert",
                "deny"
            ],
            "rule_tags": [
                "web_attack/xss",
                "automation/misc"
            ],
            "rules": [
                {
                    "ruleActions": "ALERT",
                    "ruleData": "alert(",
                    "ruleMessages": "Cross-site Scripting (XSS) Attack",
                    "ruleSelectors": "ARGS:a",
                    "ruleTags": "WEB_ATTACK/XSS",
                    "rules": "950004"
                },
                {
                    "ruleActions": "DENY",
                    "ruleData": "curl",
                    "ruleMessages": "Request Indicates an automated program explored the site",
                    "ruleSelectors": "REQUEST_HEADERS:User-Agent",
                    "ruleTags": "AUTOMATION/MISC",
                    "rules": "990011"
                }
            ],
            "user_risk": {
                "allow": 0,
                "general": {
                    "duc_1d": "30",
                    "duc_1h": "10"
                },
                "risk": {
                    "udfp": "1325gdg4g4343g/M",
                    "unp": "74256/H"
                },
                "score": 75,
                "status": 0,
                "trust": {
                    "ugp": "US"
                },
                "uuid": "964d54b7-0821-413a-a4d6-8131770ec8d5"
            }
        }
    },
    "client": {
        "address": "89.160.20.156",
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.156"
    },
    "cloud": {
        "provider": "google cloud"
    },
    "data_stream": {
        "dataset": "akamai.siem",
        "namespace": "72529",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9d70aadf-eebc-4a79-9154-d09492f8ce88",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "akamai.siem",
        "id": "2ab418ac8515f33",
        "ingested": "2026-01-09T09:24:59Z",
        "kind": "event",
        "start": "2016-08-11T13:45:33.026Z"
    },
    "gcs": {
        "storage": {
            "bucket": {
                "name": "testbucket"
            },
            "object": {
                "content_type": "application/x-ndjson",
                "name": "siem.log"
            }
        }
    },
    "http": {
        "request": {
            "id": "2ab418ac8515f33",
            "method": "POST"
        },
        "response": {
            "bytes": 34523,
            "status_code": 301
        },
        "version": "2"
    },
    "input": {
        "type": "gcs"
    },
    "log": {
        "file": {
            "path": "gs://testbucket/siem.log"
        },
        "offset": 0
    },
    "network": {
        "protocol": "http",
        "transport": "tcp"
    },
    "observer": {
        "type": "proxy",
        "vendor": "akamai"
    },
    "related": {
        "ip": [
            "89.160.20.156"
        ]
    },
    "source": {
        "address": "89.160.20.156",
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.156"
    },
    "tags": [
        "forwarded",
        "akamai-siem"
    ],
    "tls": {
        "version": "1.2",
        "version_protocol": "tls"
    },
    "url": {
        "domain": "www.example.com",
        "full": "www.example.com/examples/1/?a%3D..%2F..%2F..%2Fetc%2Fpasswd",
        "path": "/examples/1/",
        "port": 80,
        "query": "a=../../../etc/passwd"
    }
}
```
