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
        "ephemeral_id": "bc351be3-80bf-4251-abfd-0b0313e10026",
        "id": "9da55cfc-0368-44dd-9f29-94d730a7e3b4",
        "name": "elastic-agent-80635",
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
        "namespace": "42763",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "9da55cfc-0368-44dd-9f29-94d730a7e3b4",
        "snapshot": false,
        "version": "8.17.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "swimlane.audit_logs",
        "ingested": "2025-06-16T22:20:19Z",
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
| @timestamp | Event timestamp. | date |
| cloud.account.origin.account.id | Cloud Account Id | keyword |
| cloud.account.origin.project.id | Cloud Account Project Id | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.user.changes.id | Unique identifier of the user which was modified | keyword |
| destination.user.changes.name | Name of the user which was modified | keyword |
| log.category | Log Category | keyword |
| log.feature_category | Log Feature Category | keyword |
| log.source | Log Source | keyword |
| log.type | Log Type | keyword |
| source.user.changes.id | Unique identifier of the user which made the modification | keyword |
| user.authentication.type | The authentication type used by the user for this request | keyword |
| user_agent.original | The original user agent string | keyword |


### swimlane.api

An example event for `swimlane_api` looks as following:

```json
{
    "@timestamp": "2025-04-10T19:26:36.081Z",
    "agent": {
        "ephemeral_id": "0d2a7069-5df2-49b4-91dc-aef8e1c782f0",
        "id": "95814b2f-7045-4d93-a5a9-eae85b296921",
        "name": "elastic-agent-52619",
        "type": "filebeat",
        "version": "8.17.5"
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
        "namespace": "29410",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "95814b2f-7045-4d93-a5a9-eae85b296921",
        "snapshot": false,
        "version": "8.17.5"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "swimlane.api",
        "ingested": "2025-05-22T23:29:41Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "creation"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-52619",
        "ip": [
            "192.168.160.2",
            "172.18.0.4"
        ],
        "mac": [
            "02-42-AC-12-00-04",
            "02-42-C0-A8-A0-02"
        ],
        "name": "elastic-agent-52619",
        "os": {
            "family": "",
            "kernel": "6.8.0-50-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "log": {
        "category": "Settings",
        "source": "api",
        "type": "Audit"
    },
    "message": "admin@domain.tld created a new permission",
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
    "url": {
        "path": "/app/aK_JIlwxET4gA7RWN"
    },
    "user": {
        "authentication": {
            "type": "jwt"
        },
        "id": "1af3bd48-d46e-490f-c015-004d198d0558",
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
| @timestamp | Event timestamp. | date |
| cloud.account.origin.project.id | Cloud Account Project Id | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.user.changes.id | Unique identifier of the user which was modified | keyword |
| destination.user.changes.name | Name of the user which was modified | keyword |
| log.category | Log Category | keyword |
| log.feature_category | Log Feature Category | keyword |
| log.source | Log Source | keyword |
| log.type | Log Type | keyword |
| source.user.changes.id | Unique identifier of the user which made the modification | keyword |
| user.authentication.type | The authentication type used by the user for this request | keyword |
| user_agent.original | The original user agent string | keyword |


### swimlane.tenant

An example event for `tenant_api` looks as following:

```json
{
    "@timestamp": "2025-04-09T22:09:49.893Z",
    "agent": {
        "ephemeral_id": "9972d741-2798-4f0e-849a-7d6c16ee63a8",
        "id": "b291389f-da6c-4a98-9b4d-6f00deaef4e1",
        "name": "elastic-agent-23448",
        "type": "filebeat",
        "version": "8.17.5"
    },
    "data_stream": {
        "dataset": "swimlane.tenant",
        "namespace": "51350",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "b291389f-da6c-4a98-9b4d-6f00deaef4e1",
        "snapshot": false,
        "version": "8.17.5"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "swimlane.tenant",
        "ingested": "2025-05-22T23:30:31Z",
        "kind": "event",
        "outcome": "failure",
        "type": [
            "start"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-23448",
        "ip": [
            "192.168.160.2",
            "172.18.0.4"
        ],
        "mac": [
            "02-42-AC-12-00-04",
            "02-42-C0-A8-A0-02"
        ],
        "name": "elastic-agent-23448",
        "os": {
            "family": "",
            "kernel": "6.8.0-50-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "log": {
        "category": "Login",
        "level": "INFO",
        "source": "Tenant Service",
        "type": "Audit"
    },
    "message": "Failed login attempt registered for the swimlane user admin@domain.tld, current failed login attempts:1",
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
    "url": {
        "domain": "turbine.domain.tld",
        "path": "api/users/login"
    },
    "user": {
        "id": "1af3bd48-d46e-490f-c015-004d198d0558",
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
| @timestamp | Event timestamp. | date |
| cloud.account.origin.account.id | Cloud Account Id | keyword |
| cloud.account.origin.project.id | Cloud Account Project Id | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.user.changes.id | Unique identifier of the user which was modified | keyword |
| destination.user.changes.name | Name of the user which was modified | keyword |
| log.category | Log Category | keyword |
| log.feature_category | Log Feature Category | keyword |
| log.source | Log Source | keyword |
| log.type | Log Type | keyword |
| source.user.changes.id | Unique identifier of the user which made the modification | keyword |
| user.authentication.type | The authentication type used by the user for this request | keyword |
| user_agent.original | The original user agent string | keyword |
.

### turbine.api

An example event for `turbine_api` looks as following:

```json
{
    "@timestamp": "2025-04-10T20:32:26.677Z",
    "agent": {
        "ephemeral_id": "6c9536b5-3586-4488-b79c-a03cbf53b9de",
        "id": "e74f511e-2580-4664-ad66-99364b1de05a",
        "name": "elastic-agent-76912",
        "type": "filebeat",
        "version": "8.17.5"
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
        "namespace": "49565",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "e74f511e-2580-4664-ad66-99364b1de05a",
        "snapshot": false,
        "version": "8.17.5"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "turbine.api",
        "ingested": "2025-05-22T23:31:21Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "creation"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-76912",
        "ip": [
            "192.168.160.2",
            "172.18.0.4"
        ],
        "mac": [
            "02-42-AC-12-00-04",
            "02-42-C0-A8-A0-02"
        ],
        "name": "elastic-agent-76912",
        "os": {
            "family": "",
            "kernel": "6.8.0-50-generic",
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
        "id": "1af3bd48-d46e-490f-b015-004c198d0558",
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
| @timestamp | Event timestamp. | date |
| cloud.account.origin.account.id | Cloud Account Id | keyword |
| cloud.account.origin.project.id | Cloud Account Project Id | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.user.changes.id | Unique identifier of the user which was modified | keyword |
| destination.user.changes.name | Name of the user which was modified | keyword |
| log.category | Log Category | keyword |
| log.feature_category | Log Feature Category | keyword |
| log.source | Log Source | keyword |
| log.type | Log Type | keyword |
| source.user.changes.id | Unique identifier of the user which made the modification | keyword |
| user.authentication.type | The authentication type used by the user for this request | keyword |
| user_agent.original | The original user agent string | keyword |
