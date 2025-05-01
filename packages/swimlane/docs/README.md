# Swimlane Turbine

The [Swimlane Turbine](https://swimlane.com/swimlane-turbine/) integration allows you to ingest on-prem audit logs from Swimlane Turbine, the Enterprise AI Hyperautomation & Orchestration Platform. 

Use the Swimlane Turbine integration to stream container pod logs into your Elastic deployment. 

## Data streams
The Swimlane Turbine integration collects one type of data streams: logs.

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

### swimlane.api

An example event for `swimlane_api` looks as following:

```json
{
    "@timestamp": "2025-04-10T19:26:36.081Z",
    "agent": {
        "ephemeral_id": "c41bb125-5578-43f5-8911-e8fdea7753e8",
        "id": "8efb35cf-33ab-4eeb-b650-84aae800563e",
        "name": "elastic-agent-66447",
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
        "namespace": "78608",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "8efb35cf-33ab-4eeb-b650-84aae800563e",
        "snapshot": false,
        "version": "8.17.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "swimlane.api",
        "ingested": "2025-04-30T19:44:51Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "creation"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-66447",
        "ip": [
            "172.30.0.2",
            "172.18.0.8"
        ],
        "mac": [
            "02-42-AC-12-00-08",
            "02-42-AC-1E-00-02"
        ],
        "name": "elastic-agent-66447",
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
        "ephemeral_id": "4530d416-4170-489f-8e3c-6cc5f5980be4",
        "id": "bfc1090b-cacb-458c-9cb4-47dc41107376",
        "name": "elastic-agent-50027",
        "type": "filebeat",
        "version": "8.17.4"
    },
    "data_stream": {
        "dataset": "swimlane.tenant",
        "namespace": "84385",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "bfc1090b-cacb-458c-9cb4-47dc41107376",
        "snapshot": false,
        "version": "8.17.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "swimlane.tenant",
        "ingested": "2025-04-30T19:47:12Z",
        "kind": "event",
        "outcome": "failure",
        "type": [
            "start"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-50027",
        "ip": [
            "172.30.0.2",
            "172.18.0.8"
        ],
        "mac": [
            "02-42-AC-12-00-08",
            "02-42-AC-1E-00-02"
        ],
        "name": "elastic-agent-50027",
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
        "ephemeral_id": "aed374ea-1c5b-4c68-9422-44723f6b1352",
        "id": "85f0adb8-ed1f-4746-9ca4-001c3891428a",
        "name": "elastic-agent-77444",
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
        "namespace": "62358",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "85f0adb8-ed1f-4746-9ca4-001c3891428a",
        "snapshot": false,
        "version": "8.17.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "turbine.api",
        "ingested": "2025-04-30T19:48:09Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "creation"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-77444",
        "ip": [
            "172.30.0.2",
            "172.18.0.8"
        ],
        "mac": [
            "02-42-AC-12-00-08",
            "02-42-AC-1E-00-02"
        ],
        "name": "elastic-agent-77444",
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
