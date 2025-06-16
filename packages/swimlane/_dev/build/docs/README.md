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

{{event "audit_logs"}}

{{fields "audit_logs"}}

### swimlane.api

{{event "swimlane_api"}}

{{fields "swimlane_api"}}

### swimlane.tenant

{{event "tenant_api"}}

{{fields "tenant_api"}}.

### turbine.api

{{event "turbine_api"}}

{{fields "turbine_api"}}