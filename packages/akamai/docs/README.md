# Akamai Integration

The Akamai integration collects events from the Akamai API, specifically reading from the [Akamai SIEM API](https://techdocs.akamai.com/siem-integration/reference/api).

## Logs

### SIEM

The Security Information and Event Management API allows you to capture security events generated on the ​Akamai​ platform in your SIEM application.

Use this API to get security event data generated on the ​Akamai​ platform and correlate it with data from other sources in your SIEM solution. Capture security event data incrementally, or replay missed security events from the past 12 hours. You can store, query, and analyze the data delivered through this API on your end, then go back and adjust your Akamai security settings. If you’re coding your own SIEM connector, it needs to adhere to these specifications in order to pull in security events from Akamai Security Events Collector (ASEC) and process them properly.

See [Akamai API get started](https://techdocs.akamai.com/siem-integration/reference/api-get-started) to set up your Akamai account and get your credentials.

### To collect data from GCS Bucket [Beta], follow the below steps:
- Configure the [Data Forwarder](https://techdocs.akamai.com/datastream2/docs/stream-google-cloud/) to ingest data into a GCS bucket.
- Configure the GCS bucket names and credentials along with the required configs under the "Collect Akamai SIEM logs via Google Cloud Storage" section. 
- Make sure the service account and authentication being used, has proper levels of access to the GCS bucket [Manage Service Account Keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys/)

**Note**:
- The GCS input currently does not support fetching of buckets using bucket prefixes, so the bucket names have to be configured manually for each data stream.
- The GCS input currently only accepts a service account JSON key or a service account JSON file for authentication.
- The GCS input currently only supports JSON data.
- This input is still in beta.

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
        "ephemeral_id": "9bba2ff8-f15b-4c09-8ac9-60ee0045a851",
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.0"
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
    "data_stream": {
        "dataset": "akamai.siem",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "snapshot": true,
        "version": "8.8.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2023-05-09T21:06:11.267Z",
        "dataset": "akamai.siem",
        "id": "2ab418ac8515f33",
        "ingested": "2023-05-09T21:06:12Z",
        "kind": "event",
        "original": "{\"attackData\":{\"clientIP\":\"89.160.20.156\",\"configId\":\"6724\",\"policyId\":\"scoe_5426\",\"ruleActions\":\"QUxFUlQ;REVOWQ==\",\"ruleData\":\"YWxlcnQo;Y3VybA==\",\"ruleMessages\":\"Q3Jvc3Mtc2l0ZSBTY3 JpcHRpbmcgKFhTUykgQXR0YWNr; UmVxdWVzdCBJbmRpY2F0ZXMgYW4 gYXV0b21hdGVkIHByb2 dyYW0gZXhwbG9yZWQgdGhlIHNpdGU=\",\"ruleSelectors\":\"QVJHUzph;UkVRVUVTVF9IRU FERVJTOlVzZXItQWdlbnQ=\",\"ruleTags\":\"V0VCX0FUVEFDSy9YU1M=;QV VUT01BVElPTi9NSVND\",\"ruleVersions\":\";\",\"rules\":\"OTUwMDA0;OTkwMDEx\"},\"botData\":{\"botScore\":\"100\",\"responseSegment\":\"3\"},\"clientData\":{\"appBundleId\":\"com.mydomain.myapp\",\"appVersion\":\"1.23\",\"sdkVersion\":\"4.7.1\",\"telemetryType\":\"2\"},\"format\":\"json\",\"geo\":{\"asn\":\"12271\",\"city\":\"NEWYORK\",\"continent\":\"NA\",\"country\":\"US\",\"regionCode\":\"NY\"},\"httpMessage\":{\"bytes\":\"34523\",\"host\":\"www.example.com\",\"method\":\"POST\",\"path\":\"/examples/1/\",\"port\":\"80\",\"protocol\":\"http/2\",\"query\":\"a%3D..%2F..%2F..%2Fetc%2Fpasswd\",\"requestHeaders\":\"User-Agent%3a%20BOT%2f0.1%20(BOT%20for%20JCE)%0d%0aAccept%3a%20text%2fhtml,application%2fxhtml+xml\",\"requestId\":\"2ab418ac8515f33\",\"responseHeaders\":\"Server%3a%20AkamaiGHost%0d%0aMime-Version%3a%201.0%0d%0aContent-Type%3a%20text%2fhtml\",\"start\":\"1470923133.026\",\"status\":\"301\",\"tls\":\"TLSv1.2\"},\"type\":\"akamai_siem\",\"userRiskData\":{\"allow\":\"0\",\"general\":\"duc_1h:10|duc_1d:30\",\"risk\":\"udfp:1325gdg4g4343g/M|unp:74256/H\",\"score\":\"75\",\"status\":\"0\",\"trust\":\"ugp:US\",\"uuid\":\"964d54b7-0821-413a-a4d6-8131770ec8d5\"},\"version\":\"1.0\"}",
        "start": "2016-08-11T13:45:33.026Z"
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
        "type": "httpjson"
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
        "akamai-siem",
        "forwarded",
        "preserve_original_event"
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