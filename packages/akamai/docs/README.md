# Akamai Integration

The Akamai integration collects events from the Akamai API, specifically reading from the [Akamai SIEM API](https://techdocs.akamai.com/siem-integration/reference/api).

## Logs

### SIEM

The Security Information and Event Management API allows you to capture security events generated on the Akamai platform in your SIEM application.

Use this API to get security event data generated on the Akamai platform and correlate it with data from other sources in your SIEM solution. Capture security event data incrementally, or replay missed security events from the past 12 hours. You can store, query, and analyze the data delivered through this API on your end, then go back and adjust your Akamai security settings. If you’re coding your own SIEM connector, it needs to adhere to these specifications in order to pull in security events from Akamai Security Events Collector (ASEC) and process them properly.

See [Akamai API get started](https://techdocs.akamai.com/siem-integration/reference/api-get-started) to set up your Akamai account and get your credentials.

### To collect data from GCS Bucket, follow the below steps:
- Configure the [Data Forwarder](https://techdocs.akamai.com/datastream2/docs/stream-google-cloud/) to ingest data into a GCS bucket.
- Configure the GCS bucket names and credentials along with the required configs under the "Collect Akamai SIEM logs via Google Cloud Storage" section. 
- Make sure the service account and authentication being used, has proper levels of access to the GCS bucket [Manage Service Account Keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys/)

**Note**:
- The GCS input currently does not support fetching of buckets using bucket prefixes, so the bucket names have to be configured manually for each data stream.
- The GCS input currently only accepts a service account JSON key or a service account JSON file for authentication.
- The GCS input currently only supports JSON data.

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
        "ephemeral_id": "0141275b-4c93-4f80-af66-e78e49d1ac2b",
        "id": "9f1b0ff2-268e-45b7-a318-b5ac07ed663d",
        "name": "elastic-agent-37151",
        "type": "filebeat",
        "version": "8.13.0"
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
        "namespace": "23956",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9f1b0ff2-268e-45b7-a318-b5ac07ed663d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "akamai.siem",
        "id": "2ab418ac8515f33",
        "ingested": "2025-10-08T10:34:19Z",
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