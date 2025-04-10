# Swimlane Turbine Audit Logs

The Swimlane Turbine integration allows you to ingest on-prem audit logs. Swimlane Turbine, the Enterprise AI Hyperautomation & Orchestration Platform. 

Use the Swimlane Turbine Audit Logs integration to stream container pod logs into your Elastic deployment. 

This integration is used for change management & control, authentication, authorization activities are restricted to POST, PUT, PATCH, DELETE.  

## Data streams
The Swimlane Turbine Audit Logs integration collects one type of data streams: logs.

### swimlane.api 
Swimlane API help you keep a record of events happening in Swimlane API which are related to Workspaces, Dashboards, Reports, Application, Applets, Records, Role Based Access Control (RBAC).
All fields ingested to this data stream are stored under swimlane.api as an event.

### tenant.api 
Tenant API help you keep a record of events happening in Tenant API which are related to Account & Tenant Management, Settings, and Authentication.
All fields ingested to this data stream are stored under tenant.api as an event.

### turbine.api 
Turbine API help you keep a record of events happening in Turbine API which are related to Connectors, Assets, Sensors, Solutions, Playbook, Schema Definitions, and Components.
All fields ingested to this data stream are stored under turbine.api as an event.

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

## Setup
For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

### swimlane.api
An example event for `swimlane.api` looks as following:
```
{
	"@timestamp": "2025-04-10T19:26:36.081Z",
	"cloud": {
		"origin": {
			"account": {
				"id": "5fbee706-0909-4t1a-ada7-3e8e2a1f3117"
			},
			"tenant": {
				"id": "5941becf-5ac4-493e-97eb-50da36f80582"
			}
		}
	},
	"event": {
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
	"source": {
		"geo": {
			"city_name": "Hale",
			"continent_name": "Europe",
			"country_iso_code": "GB",
			"country_name": "United Kingdom",
			"location": {
				"lat": 51.6261,
				"lon": -0.2568
			},
			"region_iso_code": "GB-BNE",
			"region_name": "Barnet"
		},
		"ip": "81.2.69.144"
	},
	"url": {
		"path": "app/aK_JIlwxET4gA7RWN"
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

#### Exported fields
| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.origin.account.id | Unique identifier for the originating cloud account. | keyword |
| cloud.origin.tenant.id | Cloud Account Tenant Id. | keyword |
| event.outcome | Outcome of the event, e.g., success or failure. | keyword |
| event.type | Type(s) of the event, e.g., creation, deletion. | keyword |
| log.category | Log Category. | keyword |
| log.source | Log Source. | keyword |
| log.type | Log Type. | keyword |
| message | Human-readable message summarizing the event. | text |
| source.geo.city_name | Source city name based on IP geolocation. | keyword |
| source.geo.continent_name | Continent name of the IP source. | keyword |
| source.geo.country_iso_code | Country ISO code of the source. | keyword |
| source.geo.country_name | Full country name of the source. | keyword |
| source.geo.location.lat | Latitude of the source IP location. | float |
| source.geo.location.lon | Longitude of the source IP location. | float |
| source.geo.region_iso_code | ISO code for the source region. | keyword |
| source.geo.region_name | Name of the region of the source. | keyword |
| source.ip | IP address of the event source. | ip |
| url.path | Path component of the accessed URL. | keyword |
| user.authentication.type | The authentication type used by the user. | keyword |
| user.id | Unique user identifier. | keyword |
| user.name | Name or identifier of the user (e.g., email). | keyword |
| user_agent.device.name | Device name used by the user. | keyword |
| user_agent.name | Browser name. | keyword |
| user_agent.original | Full original user agent string. | text |
| user_agent.os.full | Full OS name and version. | keyword |
| user_agent.os.name | Operating system name. | keyword |
| user_agent.os.version | OS version. | keyword |
| user_agent.version | Browser version. | keyword |

### tenant.api
An example event for `tenant.api` looks as following:
```
{
	"@timestamp": "2025-04-09T22:09:49.893Z",
	"event": {
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
	"source": {
		"geo": {
			"city_name": "Hale",
			"continent_name": "Europe",
			"country_iso_code": "GB",
			"country_name": "United Kingdom",
			"location": {
				"lat": 51.6261,
				"lon": -0.2568
			},
			"region_iso_code": "GB-BNE",
			"region_name": "Barnet"
		},
		"ip": "81.2.69.144"
	},
	"url": {
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

#### Exported fields
| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| event.outcome | Outcome of the event (e.g., success, failure). | keyword |
| event.type | Type(s) of the event, e.g., start, stop. | keyword |
| log.category | Log Category (e.g., Login). | keyword |
| log.level | Log severity level (e.g., INFO, ERROR). | keyword |
| log.source | Log Source (e.g., service generating the log). | keyword |
| log.type | Log Type (e.g., Audit). | keyword |
| message | Human-readable message summarizing the event. | text |
| source.geo.city_name | Source city name based on IP geolocation. | keyword |
| source.geo.continent_name | Continent name of the IP source. | keyword |
| source.geo.country_iso_code | Country ISO code of the source. | keyword |
| source.geo.country_name | Full country name of the source. | keyword |
| source.geo.location.lat | Latitude of the source IP location. | float |
| source.geo.location.lon | Longitude of the source IP location. | float |
| source.geo.region_iso_code | ISO code for the source region. | keyword |
| source.geo.region_name | Name of the region of the source. | keyword |
| source.ip | IP address of the event source. | ip |
| url.path | Path component of the accessed URL. | keyword |
| user.id | Unique user identifier. | keyword |
| user.name | Name or identifier of the user (e.g., email). | keyword |
| user_agent.device.name | Device name used by the user. | keyword |
| user_agent.name | Browser name. | keyword |
| user_agent.original | Full original user agent string. | text |
| user_agent.os.full | Full OS name and version. | keyword |
| user_agent.os.name | Operating system name. | keyword |
| user_agent.os.version | OS version. | keyword |
| user_agent.version | Browser version. | keyword |

### turbine.api
An example event for `turbine.api` looks as following:
```
{
	"@timestamp": "2025-04-10T20:32:26.677Z",
	"cloud": {
		"origin": {
			"account": {
				"id": "5fbee706-0909-4f1a-ada7-3e8e2a1f3117"
			},
			"tenant": {
				"id": "5941becf-5ac4-493e-97eb-50da36e80582"
			}
		}
	},
	"event": {
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
	"source": {
		"geo": {
			"city_name": "Hale",
			"continent_name": "Europe",
			"country_iso_code": "GB",
			"country_name": "United Kingdom",
			"location": {
				"lat": 51.6261,
				"lon": -0.2568
			},
			"region_iso_code": "GB-BNE",
			"region_name": "Barnet"
		},
		"ip": "81.2.69.144"
	},
	"url": {
		"path": "v1/asset"
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

#### Exported fields
| Field | Description | Type |
|---|---|---|
| @timestamp | Timestamp when the event occurred. | date |
| cloud.origin.account.id | Unique identifier of the originating cloud account. | keyword |
| cloud.origin.tenant.id | Unique identifier of the tenant in the cloud account. | keyword |
| event.outcome | Result of the event (e.g., success, failure). | keyword |
| event.type | Type(s) of the event (e.g., creation). | keyword |
| log.category | Category of the log (e.g., Asset). | keyword |
| log.type | Type of log, such as Audit. | keyword |
| message | Human-readable message summarizing the event action. | text |
| source.geo.city_name | City from which the source request originated. | keyword |
| source.geo.continent_name | Continent of the source. | keyword |
| source.geo.country_iso_code | ISO country code (e.g., GB). | keyword |
| source.geo.country_name | Full name of the source country. | keyword |
| source.geo.location.lat | Latitude of the source’s location. | float |
| source.geo.location.lon | Longitude of the source’s location. | float |
| source.geo.region_iso_code | ISO region code of the source. | keyword |
| source.geo.region_name | Name of the region from the source. | keyword |
| source.ip | IP address of the request source. | ip |
| url.path | Path accessed in the API or application (e.g., v1/asset). | keyword |
| user.authentication.type | Authentication method used (e.g., jwt). | keyword |
| user.id | Unique identifier of the user who performed the action. | keyword |
| user.name | Email or name of the user who performed the action. | keyword |
| user_agent.device.name | Name of the device used by the user. | keyword |
| user_agent.name | Name of the browser used (e.g., Chrome). | keyword |
| user_agent.original | Full User-Agent string for client device identification. | text |
| user_agent.os.full | Full operating system name and version. | keyword |
| user_agent.os.name | Operating system name (e.g., Mac OS X). | keyword |
| user_agent.os.version | Version of the operating system. | keyword |
| user_agent.version | Browser version. | keyword |
