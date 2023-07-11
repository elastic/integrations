# Microsoft Office 365 Integration

This integration is for [Microsoft Office 365](https://docs.microsoft.com/en-us/previous-versions/office/office-365-api/). It currently supports user, admin, system, and policy actions and events from Office 365 and Azure AD activity logs exposed by the Office 365 Management Activity API.

## Setup

To use this package you need to enable _Audit Log Search_ and register an application in Azure AD.

Once this application is registered note the _Application (client) ID_ and the _Directory (tenant) ID._ Then configure the authentication in the _Certificates & Secrets_ section.

To use client-secret authentication, add you secret to the _Client Secret_ field. Starting integration version `1.17.0`, certificate authentication is no longer supported.

**NOTE:** Users upgrading from integration version `< 1.7.0` to `>= 1.7.0` must follow following steps:

1. Upgrade the integration navigating via `Integrations -> Microsoft 365 -> Settings -> Upgrade`
2. Upgrade the integration policy navigating via `Integrations -> Microsoft 365 -> integration policies -> Version (upgrade)`. If `Upgrade` option doesn't appear under the `Version`, go to the next step.
3. Update the integration policy:
    
    * Disable existing configuration (marked as `Deprecated`) and enable `Collect Office 365 audit logs via CEL` configuration.
    * Add the required parameters such as `Directory (tenant) ID`, `Application (client) ID`, `Client Secret` based on the previous configuration.
    * Update the other configuration parameters as required and hit `Save Integration`.

## Compatibility

The `ingest-geoip` and `ingest-user_agent` Elasticsearch plugins are required to run this module.

## Logs

### Audit

Uses the Office 365 Management Activity API to retrieve audit messages from Office 365 and Azure AD activity logs. These are the same logs that are available under Audit Log Search in the Security and Compliance Center.

{{event "audit"}}

{{fields "audit"}}
