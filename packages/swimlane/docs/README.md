# Swimlane Turbine

The [Swimlane Turbine](https://swimlane.com/swimlane-turbine/) integration allows you to ingest on-prem audit logs from Swimlane Turbine, the Enterprise AI Hyperautomation & Orchestration Platform. 

Use the Swimlane Turbine integration to stream container pod logs into your Elastic deployment. 

## Data streams
The Swimlane Turbine integration collects two type of data streams: logs and cel.

### swimlane.audit_logs
Swimlane Audit Logs help logs keep a record of all audit events occurring within both on-premises and cloud environments. These logs provide a comprehensive history of user actions, configuration changes, access attempts, system events, and other critical activities that support security and compliance monitoring.
All fields ingested to this data stream are stored under `swimlane.audit_log` as an event.

### swimlane.api 
Swimlane API help logs keep a record of events happening in Swimlane API which are related to Workspaces, Dashboards, Reports, Application, Applets, Records, Role Based Access Control (RBAC).
All fields ingested to this data stream are stored under `swimlane.api` as an event.

### swimlane.tenant
Tenant API help logs keep a record of events happening in Tenant API which are related to Account & Tenant Management, Settings, and Authentication.
All fields ingested to this data stream are stored under `swimlane.tenant` as an event.

### turbine.api 
Turbine API help logs keep a record of events happening in Turbine API which are related to Connectors, Assets, Sensors, Solutions, Playbook, Schema Definitions, and Components.
All fields ingested to this data stream are stored under `turbine.api` as an event.

## Requirements 

### For Turbine Cloud Deployments
Generate a personal access token for an administrator user.
![Turbine Cloud Personal Access Token](/img/turbine-cloud-pat.png "Turbine Cloud Personal Access Token")

Configure the settings page with your Turbine Cloud URL, Account Id, and Private Token
![Turbine Cloud Settings](/img/turbine-cloud-settings.png "Turbine Cloud Settings")

### For Turbie Platform Installs (TPI)
TPI settings can be configured in the administrator dashboard as seen below:

![TPI Audit Log Settings](/img/tpi-audit-log-settings.png "TPI Audit Log Settings")

### For Helm or Kustomize Installs
The following environment variables will need to be set for Audit logs to be outputted into the container pod logs.

```
swimlane-api & swimlane-tenant:
	"SWIMLANE_Logging__Level=Info"
	"SWIMLANE_Logging__IncludeAudit=true"

turbine-api:
	"LOG_LEVEL_API=info"
	"LOG_LEVEL_DEFAULT=info"
	"LOG_LEVEL_SYSTEM=info"
	"LOG_FILES_ENABLED=false"
```
## Data Stream

### swimlane.audit_logs

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2025-04-23T22:17:40.362Z",
    "agent": {
        "ephemeral_id": "134e9a56-7243-4d21-971a-2ff89abad819",
        "id": "8fdd30a1-e5f1-4c7f-aa82-034c42c4c9c0",
        "name": "elastic-agent-88365",
        "type": "filebeat",
        "version": "8.17.4"
    },
    "cloud": {
        "origin": {
            "account": {
                "id": "01966444-24d9-7a76-b517-3699a780b068"
            },
            "project": {
                "id": "0196648c-68b6-78f0-9f56-e0eea2faa288"
            }
        }
    },
    "data_stream": {
        "dataset": "swimlane.audit_logs",
        "namespace": "97938",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "8fdd30a1-e5f1-4c7f-aa82-034c42c4c9c0",
        "snapshot": false,
        "version": "8.17.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "swimlane.audit_logs",
        "ingested": "2025-09-12T11:02:25Z",
        "kind": "event",
        "original": "{\"$type\":\"Core.Models.ElasticAudit.AuditLogSchema, Core\",\"accountId\":\"01966444-24d9-7a76-b517-3699a780b068\",\"actionType\":\"Update\",\"authenticationType\":\"JWT\",\"category\":\"Record\",\"description\":\"admin@domain.tld updated report 68095b8dce404ef1b500f7e8\",\"endpoint\":\"/app/a8FJwIi_XeE5big7m\",\"eventOutcome\":\"Success\",\"eventTime\":\"2025-04-23T22:17:40.362641Z\",\"id\":\"68095b8dce404ef1b500f7e8\",\"isAdmin\":true,\"newValue\":\"{\\\"GroupBys\\\":[],\\\"Aggregates\\\":[],\\\"ApplicationIds\\\":[\\\"a8FJwIi_XeE5big7m\\\"],\\\"Keywords\\\":null,\\\"Columns\\\":[\\\"68095b8dce404ef1b500f7e6\\\"],\\\"Sorts\\\":{\\\"68095b8dce404ef1b500f7e6\\\":1},\\\"Filters\\\":[],\\\"CountByApplicationFacet\\\":false,\\\"PageSize\\\":10,\\\"Offset\\\":0,\\\"DefaultSearchReport\\\":true,\\\"Allowed\\\":[],\\\"Permissions\\\":{},\\\"CreatedDate\\\":\\\"2025-04-23T21:28:45.686Z\\\",\\\"ModifiedDate\\\":\\\"2025-04-23T22:17:40.3466444Z\\\",\\\"CreatedByUser\\\":{\\\"Id\\\":\\\"01966448-16a7-7474-9f83-40b1dd9a2fb2\\\",\\\"Name\\\":\\\"admin@swimlane.com\\\"},\\\"ModifiedByUser\\\":{\\\"Id\\\":\\\"01966448-16a7-7474-9f83-40b1dd9a2fb2\\\",\\\"Name\\\":\\\"admin@swimlane.com\\\"},\\\"ChartOptions\\\":null,\\\"StatsDrillin\\\":null,\\\"FilterType\\\":\\\"And\\\",\\\"ColorCoding\\\":[],\\\"Uid\\\":\\\"default-6bbd7\\\",\\\"Version\\\":4,\\\"Id\\\":\\\"68095b8dce404ef1b500f7e8\\\",\\\"Name\\\":\\\"Default\\\",\\\"Disabled\\\":false}\",\"sourceIp\":[\"81.2.69.144\"],\"tenantId\":\"0196648c-68b6-78f0-9f56-e0eea2faa288\",\"user\":\"admin@domain.tld\",\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36\",\"userId\":\"01966448-16a7-7474-9f83-40b1dd9a2fb2\"}",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "log": {
        "category": "Record"
    },
    "message": "admin@domain.tld updated report 68095b8dce404ef1b500f7e8",
    "related": {
        "user": [
            "admin@domain.tld"
        ]
    },
    "source": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.144"
    },
    "tags": [
        "preserve_original_event",
        "forwarded"
    ],
    "url": {
        "path": "/app/a8FJwIi_XeE5big7m"
    },
    "user": {
        "authentication": {
            "type": "jwt"
        },
        "id": "01966448-16a7-7474-9f83-40b1dd9a2fb2",
        "name": "admin@domain.tld"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "os": {
            "full": "Mac OS X 10.15.7",
            "name": "Mac OS X",
            "version": "10.15.7"
        },
        "version": "135.0.0.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.account.origin.account.id | Cloud Account Id | keyword |
| cloud.account.origin.project.id | Cloud Account Project Id | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| destination.user.changes.id | Unique identifier of the user which was modified | keyword |
| destination.user.changes.name | Name of the user which was modified | keyword |
| log.category | Log Category | keyword |
| log.feature_category | Log Feature Category | keyword |
| log.source.type | Log Source | keyword |
| log.type | Log Type | keyword |
| source.user.changes.id | Unique identifier of the user which made the modification | keyword |
| user.authentication.type | The authentication type used by the user for this request | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |


### swimlane.api

An example event for `swimlane_api` looks as following:

```json
{
    "@timestamp": "2025-04-10T19:26:36.081Z",
    "agent": {
        "ephemeral_id": "58ff8985-f039-4e2a-9b0b-bb030ceb4438",
        "id": "a36b25fe-52f1-4683-94e9-63b9743e1468",
        "name": "elastic-agent-37131",
        "type": "filebeat",
        "version": "8.17.4"
    },
    "cloud": {
        "origin": {
            "account": {
                "id": "5fbee706-0909-4t1a-ada7-3e8e2a1f3117"
            },
            "project": {
                "id": "5941becf-5ac4-493e-97eb-50da36f80582"
            }
        }
    },
    "data_stream": {
        "dataset": "swimlane.api",
        "namespace": "94113",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "a36b25fe-52f1-4683-94e9-63b9743e1468",
        "snapshot": false,
        "version": "8.17.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "swimlane.api",
        "ingested": "2025-09-12T11:03:12Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "creation"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "elastic-agent-37131",
        "ip": [
            "192.168.249.2",
            "192.168.242.7"
        ],
        "mac": [
            "02-42-C0-A8-F2-07",
            "02-42-C0-A8-F9-02"
        ],
        "name": "elastic-agent-37131",
        "os": {
            "family": "",
            "kernel": "3.10.0-1160.119.1.el7.x86_64",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "log": {
        "category": "Settings",
        "source": {
            "type": "api"
        },
        "type": "Audit"
    },
    "message": "admin@domain.tld created a new permission",
    "related": {
        "user": [
            "admin",
            "admin@domain.tld"
        ]
    },
    "source": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.144"
    },
    "url": {
        "path": "/app/aK_JIlwxET4gA7RWN"
    },
    "user": {
        "authentication": {
            "type": "jwt"
        },
        "domain": "domain.tld",
        "email": "admin@domain.tld",
        "id": "1af3bd48-d46e-490f-c015-004d198d0558",
        "name": "admin"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "os": {
            "full": "Mac OS X 10.15.7",
            "name": "Mac OS X",
            "version": "10.15.7"
        },
        "version": "135.0.0.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.account.origin.project.id | Cloud Account Project Id | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| destination.user.changes.id | Unique identifier of the user which was modified | keyword |
| destination.user.changes.name | Name of the user which was modified | keyword |
| log.category | Log Category | keyword |
| log.feature_category | Log Feature Category | keyword |
| log.source.type | Log Source | keyword |
| log.type | Log Type | keyword |
| source.user.changes.id | Unique identifier of the user which made the modification | keyword |
| user.authentication.type | The authentication type used by the user for this request | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |


### swimlane.tenant

An example event for `tenant_api` looks as following:

```json
{
    "@timestamp": "2025-04-09T22:09:49.893Z",
    "agent": {
        "ephemeral_id": "c3227a0e-955b-4d59-8a9a-d14520c31dba",
        "id": "d39716d0-ed8d-4615-a7d5-c5e471902984",
        "name": "elastic-agent-14549",
        "type": "filebeat",
        "version": "8.17.4"
    },
    "data_stream": {
        "dataset": "swimlane.tenant",
        "namespace": "38616",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "d39716d0-ed8d-4615-a7d5-c5e471902984",
        "snapshot": false,
        "version": "8.17.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "swimlane.tenant",
        "ingested": "2025-09-12T11:04:00Z",
        "kind": "event",
        "outcome": "failure",
        "type": [
            "start"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "elastic-agent-14549",
        "ip": [
            "192.168.240.2",
            "192.168.242.7"
        ],
        "mac": [
            "02-42-C0-A8-F0-02",
            "02-42-C0-A8-F2-07"
        ],
        "name": "elastic-agent-14549",
        "os": {
            "family": "",
            "kernel": "3.10.0-1160.119.1.el7.x86_64",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "log": {
        "category": "Login",
        "level": "INFO",
        "source": {
            "type": "Tenant Service"
        },
        "type": "Audit"
    },
    "message": "Failed login attempt registered for the swimlane user admin@domain.tld, current failed login attempts:1",
    "related": {
        "user": [
            "admin",
            "admin@domain.tld"
        ]
    },
    "source": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.144"
    },
    "url": {
        "domain": "turbine.domain.tld",
        "path": "api/users/login"
    },
    "user": {
        "domain": "domain.tld",
        "email": "admin@domain.tld",
        "id": "1af3bd48-d46e-490f-c015-004d198d0558",
        "name": "admin"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "os": {
            "full": "Mac OS X 10.15.7",
            "name": "Mac OS X",
            "version": "10.15.7"
        },
        "version": "135.0.0.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.account.origin.account.id | Cloud Account Id | keyword |
| cloud.account.origin.project.id | Cloud Account Project Id | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| destination.user.changes.id | Unique identifier of the user which was modified | keyword |
| destination.user.changes.name | Name of the user which was modified | keyword |
| log.category | Log Category | keyword |
| log.feature_category | Log Feature Category | keyword |
| log.source.type | Log Source | keyword |
| log.type | Log Type | keyword |
| source.user.changes.id | Unique identifier of the user which made the modification | keyword |
| user.authentication.type | The authentication type used by the user for this request | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
.

### turbine.api

An example event for `turbine_api` looks as following:

```json
{
    "@timestamp": "2025-04-10T20:32:26.677Z",
    "agent": {
        "ephemeral_id": "204a6444-81c4-463b-906b-1589f4cec3e6",
        "id": "4a1ee2bb-8dac-48b6-943a-992907919c96",
        "name": "elastic-agent-78203",
        "type": "filebeat",
        "version": "8.17.4"
    },
    "cloud": {
        "origin": {
            "account": {
                "id": "5fbee706-0909-4f1a-ada7-3e8e2a1f3117"
            },
            "project": {
                "id": "5941becf-5ac4-493e-97eb-50da36e80582"
            }
        }
    },
    "data_stream": {
        "dataset": "turbine.api",
        "namespace": "78136",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "4a1ee2bb-8dac-48b6-943a-992907919c96",
        "snapshot": false,
        "version": "8.17.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "turbine.api",
        "ingested": "2025-09-12T11:04:50Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "creation"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "elastic-agent-78203",
        "ip": [
            "192.168.244.2",
            "192.168.242.7"
        ],
        "mac": [
            "02-42-C0-A8-F2-07",
            "02-42-C0-A8-F4-02"
        ],
        "name": "elastic-agent-78203",
        "os": {
            "family": "",
            "kernel": "3.10.0-1160.119.1.el7.x86_64",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "log": {
        "category": "Asset",
        "type": "Audit"
    },
    "message": "admin@domain.tld Created asset 67f82ada9deafb2d6ec46987: ECK with Id: 67f82ada9deafb2d6ec46987",
    "related": {
        "user": [
            "admin",
            "admin@domain.tld"
        ]
    },
    "source": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.144"
    },
    "url": {
        "path": "/v1/asset"
    },
    "user": {
        "authentication": {
            "type": "jwt"
        },
        "domain": "domain.tld",
        "email": "admin@domain.tld",
        "id": "1af3bd48-d46e-490f-b015-004c198d0558",
        "name": "admin"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "os": {
            "full": "Mac OS X 10.15.7",
            "name": "Mac OS X",
            "version": "10.15.7"
        },
        "version": "135.0.0.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.account.origin.account.id | Cloud Account Id | keyword |
| cloud.account.origin.project.id | Cloud Account Project Id | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| destination.user.changes.id | Unique identifier of the user which was modified | keyword |
| destination.user.changes.name | Name of the user which was modified | keyword |
| log.category | Log Category | keyword |
| log.feature_category | Log Feature Category | keyword |
| log.source.type | Log Source | keyword |
| log.type | Log Type | keyword |
| source.user.changes.id | Unique identifier of the user which made the modification | keyword |
| user.authentication.type | The authentication type used by the user for this request | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
