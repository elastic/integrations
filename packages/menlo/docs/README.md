# Menlo Security

Menlo Security’s isolation-centric approach splits web browsing and document retrieval between the user’s device and an isolated, Disposable Virtual Container (DVC) away from the endpoint. All risky code is executed in the isolated DVC and never reaches the endpoint. Only safe display data is sent to the user’s browser. User traffic is automatically sent to this infrastructure without any impact on the users themselves.

## Web

Menlo Security's cloud based Browser Security prevents phishing and malware attacks on any browser and any device across your hybrid enterprise.

## DLP

Data Loss Prevention (also known as Data Leak Prevention) detects potential data breaches or data ex-filtration transmissions and prevents them by detecting and optionally blocking sensitive data passing through the Menlo Security platform.

## Compatibility

This module has been tested against the Menlo Security API **version 2.0**

## Data streams

The Menlo Security integration collects data for the following two events:

| Event Type                    |
|-------------------------------|
| Web                           |
| DLP                           |

## Setup

To collect data through the REST API you will need your Menlo Security API URL and an API token.

The API token to collect logs must have the *Log Export API* permission

## Logs Reference

### Web

This is the `Web` dataset.

#### Example

An example event for `web` looks as following:

```json
{
    "@timestamp": "2023-11-21T13:12:37.102Z",
    "agent": {
        "ephemeral_id": "22fb9f42-0c3b-4c46-9fae-06cd89923a5b",
        "id": "9a98930c-439d-4a0b-81f0-f4228f8c523f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
    },
    "client": {
        "geo": {
            "country_iso_code": "US"
        },
        "ip": "192.18.1.3"
    },
    "cloud": {
        "region": "us-east-1c"
    },
    "data_stream": {
        "dataset": "menlo.web",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "geo": {
            "country_iso_code": "US"
        },
        "ip": "192.18.1.1"
    },
    "dns": {
        "answers": {
            "data": [
                "192.18.1.1"
            ]
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9a98930c-439d-4a0b-81f0-f4228f8c523f",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web",
            "network",
            "threat"
        ],
        "dataset": "menlo.web",
        "ingested": "2024-03-28T13:32:25Z",
        "kind": "alert",
        "outcome": "unknown",
        "reason": "a77757d5-d3be-47ab-9394-cfff5887ade4"
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 308
        }
    },
    "input": {
        "type": "cel"
    },
    "menlo": {
        "web": {
            "categories": "Business and Economy",
            "content_type": "text/html; charset=UTF-8",
            "has_password": false,
            "is_iframe": "false",
            "request_type": "page_request",
            "risk_score": "low",
            "tab_id": "1",
            "tally": -1,
            "ua_type": "supported_browser"
        }
    },
    "network": {
        "protocol": "http"
    },
    "observer": {
        "geo": {
            "country_iso_code": "US"
        },
        "ip": [
            "192.18.1.2"
        ],
        "product": "MSIP",
        "vendor": "Menlo Security",
        "version": "2.0"
    },
    "related": {
        "ip": [
            "192.18.1.3",
            "192.18.1.1"
        ],
        "user": [
            "example_user"
        ]
    },
    "server": {
        "geo": {
            "country_iso_code": "US"
        },
        "ip": "192.18.1.1"
    },
    "source": {
        "geo": {
            "country_iso_code": "US"
        },
        "ip": "192.18.1.3"
    },
    "tags": [
        "menlo",
        "forwarded"
    ],
    "url": {
        "domain": "elastic.co",
        "original": "http://elastic.co/",
        "path": "/",
        "registered_domain": "elastic.co",
        "scheme": "http",
        "top_level_domain": "co"
    },
    "user": {
        "name": "example_user"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "os": {
            "full": "Mac OS X 10.15.7",
            "name": "Mac OS X",
            "version": "10.15.7"
        },
        "version": "119.0.0.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| menlo.web.cached | Indicates whether the resource was obtained from the isolated browser’s cache (True) or by downloading from the origin server (False) | boolean |
| menlo.web.casb_app_name | Cloud application name | keyword |
| menlo.web.casb_cat_name | Application category ID | keyword |
| menlo.web.casb_fun_name | Application function name | keyword |
| menlo.web.casb_org_name | Application organization name | keyword |
| menlo.web.casb_profile_id | Menlo CASB profile ID | keyword |
| menlo.web.casb_profile_name | Menlo CASB profile name attached to application or exception rule | keyword |
| menlo.web.casb_profile_type | Menlo CASB profile type (sanctioned/unsanctioned/unclassified) | keyword |
| menlo.web.casb_risk_score | Menlo risk score for application (0-10) | keyword |
| menlo.web.categories | Category Rules Category type classification | keyword |
| menlo.web.content_type | Page type | keyword |
| menlo.web.has_password | Presence of password in form POST request | boolean |
| menlo.web.is_iframe | Is inline frame (iframe) element | boolean |
| menlo.web.request_type | Request type | keyword |
| menlo.web.risk_score | Risk calculated for URL | keyword |
| menlo.web.sbox | Sandbox Inspection Result | keyword |
| menlo.web.sbox_mal_act | List of malicious activities found | keyword |
| menlo.web.soph | Full file scan result | keyword |
| menlo.web.tab_id | Tab creation number within a surrogate | keyword |
| menlo.web.tally | Count of risks encountered | long |
| menlo.web.threat_types | Top level risk | keyword |
| menlo.web.threats | Threat type identified by Menlo Security internal data | keyword |
| menlo.web.ua_type | The type of user agent | keyword |
| menlo.web.virus_details | Virus detail | keyword |
| menlo.web.xff_ip | X-Forwarded-For HTTP header field originating client IP address | keyword |


### DLP

This is the `DLP` dataset.

#### Example

An example event for `dlp` looks as following:

```json
{
    "@timestamp": "2024-03-28T13:30:21.204Z",
    "agent": {
        "ephemeral_id": "1054908a-63b4-46fd-8028-f975d0f878c2",
        "id": "9a98930c-439d-4a0b-81f0-f4228f8c523f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
    },
    "data_stream": {
        "dataset": "menlo.dlp",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9a98930c-439d-4a0b-81f0-f4228f8c523f",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "action": "block",
        "agent_id_status": "verified",
        "category": [
            "intrusion_detection",
            "network"
        ],
        "created": "2020-03-09T17:17:22.227Z",
        "dataset": "menlo.dlp",
        "id": "a4c2161b3f81a287ec46d3c993a33f3b97ded5fd854fa184e7f50679303111ce",
        "ingested": "2024-03-28T13:30:33Z",
        "kind": "alert",
        "outcome": "success",
        "severity": 5
    },
    "file": {
        "hash": {
            "sha256": "fd1aee671d92aba0f9f0a8a6d5c6b843e09c8295ced9bb85e16d97360b4d7b3a"
        },
        "name": "more_credit_cards.csv"
    },
    "http": {
        "request": {
            "method": "GET"
        }
    },
    "input": {
        "type": "cel"
    },
    "menlo": {
        "dlp": {
            "alerted": "false",
            "category": "Download Sites",
            "ccl": {
                "id": "CreditordebitcardnumbersGlobal",
                "match_counts": 1,
                "score": 1
            },
            "status": "dirty",
            "stream_name": "/safefile-input/working_file",
            "user_input": "false"
        }
    },
    "observer": {
        "product": "MSIP",
        "vendor": "Menlo Security",
        "version": "2.0"
    },
    "related": {
        "hash": [
            "fd1aee671d92aba0f9f0a8a6d5c6b843e09c8295ced9bb85e16d97360b4d7b3a"
        ],
        "user": [
            "admin@menlosecurity.com"
        ]
    },
    "rule": {
        "id": "1f3ef32c-ec62-42fb-8cad-e1fee3375099",
        "name": "Credit card block rule"
    },
    "tags": [
        "menlo",
        "forwarded"
    ],
    "url": {
        "domain": "tinynewupload.com",
        "original": "http://tinynewupload.com/",
        "path": "/",
        "registered_domain": "tinynewupload.com",
        "scheme": "http",
        "top_level_domain": "com"
    },
    "user": {
        "name": "admin@menlosecurity.com"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| menlo.dlp.alerted | Whether or not an email alert was sent to a DLP Auditor profile | boolean |
| menlo.dlp.category | Category Rules Category type classification | keyword |
| menlo.dlp.ccl.id | Name of DLP dictionary that was violated | keyword |
| menlo.dlp.ccl.match_counts | Number of matches of the string that caused the violation | long |
| menlo.dlp.ccl.score | DLP score from the dictionary that caused the violation | long |
| menlo.dlp.status | Result from the DLP engine | keyword |
| menlo.dlp.stream_name | Internal name used for the file (usually working_file) or text stream (uid) | keyword |
| menlo.dlp.user_input | Whether or not this event was generated as a result of user form input | boolean |

