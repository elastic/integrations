# Swimlane Turbine

The Swimlane Turbine integration allows you to ingest on-prem audit logs from Swimlane Turbine, the Enterprise AI Hyperautomation & Orchestration Platform. 

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
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "kind": "event",
        "original": "{ \"EventTime\": \"2025-04-10T19:26:36.0810390Z\", \"User\": \"admin@domain.tld\", \"UserId\": \"1af3bd48-d46e-490f-c015-004d198d0558\", \"Category\": \"Settings\", \"LogSource\": \"api\", \"LogType\": \"Audit\", \"Description\": \"admin@domain.tld created a new permission\", \"AccountId\": \"5fbee706-0909-4t1a-ada7-3e8e2a1f3117\", \"TenantId\": \"5941becf-5ac4-493e-97eb-50da36f80582\", \"SourceIp\": \"::ffff:81.2.69.144\", \"UserAgent\": \"Mozilla\\/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit\\/537.36 (KHTML, like Gecko) Chrome\\/135.0.0.0 Safari\\/537.36\", \"ActionType\": \"Create\", \"Id\": \"a7SAfL4_XghbfVNQm\", \"NewValue\": \"{\\\"Permission\\\":{\\\"Access\\\":12743,\\\"Id\\\":\\\"a6VKjVcgS7I5a3sl0\\\",\\\"Fields\\\":{}},\\\"Source\\\":{\\\"Type\\\":\\\"Role\\\",\\\"Id\\\":\\\"0196201d-ba14-76a3-9a0c-2fbf1510f458\\\",\\\"Name\\\":\\\"Tier-2 IR Specialist\\\",\\\"Disabled\\\":false},\\\"Target\\\":{\\\"Type\\\":\\\"Application\\\",\\\"Id\\\":\\\"aK_JIlwxET4gA7RWN\\\",\\\"Name\\\":\\\"Swimlane System of Record\\\",\\\"Disabled\\\":false},\\\"Id\\\":\\\"a7SAfL4_XghbfVNQm\\\",\\\"Name\\\":null,\\\"Uid\\\":null,\\\"Disabled\\\":false}\", \"EventOutcome\": \"Success\", \"Endpoint\": \"\\/app\\/aK_JIlwxET4gA7RWN\", \"IsAdmin\": \"True\", \"AuthenticationType\": \"JWT\" }",
        "outcome": "success",
        "type": [
            "creation"
        ]
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


### swimlane.tenant

An example event for `tenant_api` looks as following:

```json
{
    "@timestamp": "2025-04-09T22:09:49.893Z",
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "kind": "event",
        "original": "{\"EventTime\": \"2025-04-09T22:09:49.89364Z\", \"User\": \"admin@domain.tld\", \"UserId\": \"1af3bd48-d46e-490f-c015-004d198d0558\", \"Category\": \"Login\", \"LogSource\": \"Tenant Service\", \"LogType\": \"Audit\", \"LoggedInUserId\": \"1af3bd48-d46e-490f-c015-004d198d0558\", \"Description\": \"Failed login attempt registered for the swimlane user admin@domain.tld, current failed login attempts:1\", \"RequestEndPoint\": \"://\", \"SourceIp\": \"81.2.69.144, 10.42.134.224\", \"EndPoint\": \"turbine.domain.tld/api/users/login\", \"UserAgent\": \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36\", \"IsAdmin\": \"False\", \"ActionType\": \"Login\", \"EventOutcome\": \"Failure\", \"LogLevel\": \"INFO\"}",
        "outcome": "failure",
        "type": [
            "start"
        ]
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
.

### turbine.api

An example event for `turbine_api` looks as following:

```json
{
    "@timestamp": "2025-04-10T20:32:26.677Z",
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
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "kind": "event",
        "original": "{\"level\": \"info\", \"time\": \"2025-04-10T20:32:26.677Z\", \"instance\": \"api-turbine-api-55674d58c-xphlb-d56157c8-db02-4c48-a6a7-02c1abf40598\", \"host\": \"turbine-api-55674d58c-xphlb\", \"service\": \"turbine-api\", \"version\": \"25.0.7 (gh-readonly-queue/release/25.0/pr-9272-d5359d7a7f3aa093359ca89a42a5c009fd000b17:b6f5d273)\", \"LogType\": \"Audit\", \"EventTime\": \"2025-04-10T20:32:26.677Z\", \"TenantId\": \"5941becf-5ac4-493e-97eb-50da36e80582\", \"AccountId\": \"5fbee706-0909-4f1a-ada7-3e8e2a1f3117\", \"User\": \"admin@domain.tld\", \"UserId\": \"1af3bd48-d46e-490f-b015-004c198d0558\", \"Category\": \"Asset\", \"Description\": \"admin@domain.tld Created asset 67f82ada9deafb2d6ec46987\", \"ActionType\": \"Create\", \"Id\": \"67f82ada9deafb2d6ec46987\", \"NewValue\": \"{\\\"name\\\":\\\"ECK\\\",\\\"title\\\":\\\"ECK\\\",\\\"description\\\":\\\"\\\",\\\"testingEnabled\\\":false,\\\"interval\\\":15,\\\"poolId\\\":\\\"67f702c8921c9ee6262ed50a\\\",\\\"status\\\":\\\"inactive\\\",\\\"docSchemaVersion\\\":1,\\\"connectorAsset\\\":\\\"elasticsearch.http_basic\\\",\\\"params\\\":{\\\"url\\\":\\\"https://eck.domain.tld\\\",\\\"username\\\":\\\"turbine-audit\\\",\\\"password\\\":\\\"**********\\\"},\\\"paramSchema\\\":{\\\"type\\\":\\\"object\\\",\\\"properties\\\":{\\\"url\\\":{\\\"title\\\":\\\"URL\\\",\\\"description\\\":\\\"A URL to the target host.\\\",\\\"type\\\":\\\"string\\\"},\\\"username\\\":{\\\"title\\\":\\\"Username\\\",\\\"description\\\":\\\"Username\\\",\\\"type\\\":\\\"string\\\"},\\\"password\\\":{\\\"title\\\":\\\"Password\\\",\\\"description\\\":\\\"Password\\\",\\\"type\\\":\\\"string\\\",\\\"format\\\":\\\"password\\\"},\\\"verify_ssl\\\":{\\\"title\\\":\\\"Verify SSL Certificates\\\",\\\"description\\\":\\\"Verify SSL certificate\\\",\\\"type\\\":\\\"boolean\\\"},\\\"http_proxy\\\":{\\\"title\\\":\\\"HTTP(s) Proxy\\\",\\\"description\\\":\\\"A proxy to route requests through.\\\",\\\"type\\\":\\\"string\\\"}},\\\"required\\\":[\\\"url\\\",\\\"username\\\",\\\"password\\\"]},\\\"testParams\\\":{},\\\"testParamSchema\\\":{\\\"type\\\":\\\"object\\\",\\\"properties\\\":{\\\"url\\\":{\\\"title\\\":\\\"URL\\\",\\\"description\\\":\\\"A URL to the target host.\\\",\\\"type\\\":\\\"string\\\"},\\\"username\\\":{\\\"title\\\":\\\"Username\\\",\\\"description\\\":\\\"Username\\\",\\\"type\\\":\\\"string\\\"},\\\"password\\\":{\\\"title\\\":\\\"Password\\\",\\\"description\\\":\\\"Password\\\",\\\"type\\\":\\\"string\\\",\\\"format\\\":\\\"password\\\"},\\\"verify_ssl\\\":{\\\"title\\\":\\\"Verify SSL Certificates\\\",\\\"description\\\":\\\"Verify SSL certificate\\\",\\\"type\\\":\\\"boolean\\\"},\\\"http_proxy\\\":{\\\"title\\\":\\\"HTTP(s) Proxy\\\",\\\"description\\\":\\\"A proxy to route requests through.\\\",\\\"type\\\":\\\"string\\\"}},\\\"required\\\":[\\\"url\\\",\\\"username\\\",\\\"password\\\"]},\\\"isCustom\\\":false,\\\"meta\\\":{\\\"sharingUid\\\":\\\"2a6cedfe-2818-4a69-89f8-c6c1853fa433\\\"},\\\"audit\\\":{\\\"version\\\":1,\\\"created\\\":{\\\"date\\\":\\\"2025-04-10T20:32:26.533Z\\\",\\\"user\\\":{\\\"id\\\":\\\"1af3bd48-d46e-490f-b015-004c198d0558\\\",\\\"username\\\":\\\"admin@domain.tld\\\"},\\\"authProvider\\\":{\\\"id\\\":\\\"\\\",\\\"title\\\":\\\"Swimlane\\\"}},\\\"modified\\\":{\\\"date\\\":\\\"2025-04-10T20:32:26.533Z\\\",\\\"user\\\":{\\\"id\\\":\\\"1af3bd48-d46e-490f-b015-004c198d0558\\\",\\\"username\\\":\\\"admin@domain.tld\\\"},\\\"authProvider\\\":{\\\"id\\\":\\\"\\\",\\\"title\\\":\\\"Swimlane\\\"}}},\\\"id\\\":\\\"67f82ada9deafb2d6ec46987\\\"}\", \"SourceIp\": \"81.2.69.144\", \"UserAgent\": \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36\", \"EventOutcome\": \"Success\", \"Endpoint\": \"/v1/asset\", \"Referer\": \"https://turbine.domain.tld/account/5fbee706-0909-4f1a-ada7-3e8e2a1f3117/tenant/5941becf-5ac4-493e-97eb-50da36e80582/canvas/assets\", \"IsAdmin\": true, \"AuthenticationType\": \"JWT\"}",
        "outcome": "success",
        "type": [
            "creation"
        ]
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
