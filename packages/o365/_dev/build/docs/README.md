# Microsoft Office 365 Integration

This integration is for [Microsoft Office 365](https://docs.microsoft.com/en-us/previous-versions/office/office-365-api/). It currently supports user, admin, system, and policy actions and events from Office 365 and Azure AD activity logs exposed by the Office 365 Management Activity API.

## Setup

To use this package you need to enable _Audit Log Search_ and register an application in Azure AD.

Once this application is registered, note the _Application (client) ID_ and the _Directory (tenant) ID._ Then configure the authentication in the _Certificates & Secrets_ section.

To use client-secret authentication, add your secret to the _Client Secret_ field.

**NOTE:** As Microsoft is no longer supporting Azure Active Directory Authentication Library (ADAL), the existing o365audit input is being deprecated in favor of new [CEL](https://www.elastic.co/guide/en/beats/filebeat/8.6/filebeat-input-cel.html) input in version `1.18.0`. Hence for versions `>= 1.18.0`, certificate based authentication (provided by earlier o365audit input) is no longer supported. 

We request users upgrading from integration version `< 1.18.0` to `>= 1.18.0` to follow these steps:

1. Upgrade the Elastic Stack version to `>= 8.7.1`.
2. Upgrade the integration navigating via `Integrations -> Microsoft 365 -> Settings -> Upgrade`
3. Upgrade the integration policy navigating via `Integrations -> Microsoft 365 -> integration policies -> Version (Upgrade)`. If `Upgrade` option doesn't appear under the `Version`, that means the policy is already upgraded in the previous step. Please go to the next step.
4. Modify the integration policy:
    
    * Disable existing configuration (marked as `Deprecated`) and enable `Collect Office 365 audit logs via CEL` configuration.
    * Add the required parameters such as `Directory (tenant) ID`, `Application (client) ID`, `Client Secret` based on the previous configuration.
    * Verify/Update `Initial Interval` configuration parameter to start fetching events from. This defaults to 7 days. Even if there is overlap in times, the events are not duplicated.
    * Update the other configuration parameters as required and hit `Save Integration`.

Please refer [Upgrade an integration](https://www.elastic.co/guide/en/fleet/current/upgrade-integration.html) in case of any issues while performing integration upgrade.

## Compatibility

The `ingest-geoip` and `ingest-user_agent` Elasticsearch plugins are required to run this module.

## Logs

### Audit

Uses the Office 365 Management Activity API to retrieve audit messages from Office 365 and Azure AD activity logs. These are the same logs that are available under Audit Log Search in the Security and Compliance Center.

{{event "audit"}}

{{fields "audit"}}
