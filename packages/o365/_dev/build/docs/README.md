# Microsoft Office 365 Integration

This integration is for [Microsoft Office 365](https://docs.microsoft.com/en-us/previous-versions/office/office-365-api/). It currently supports user, admin, system, and policy actions and events from Office 365 and Azure AD activity logs exposed by the Office 365 Management Activity API.

## Configuration

To use this package you need to enable _Audit Log Search_ and register an application in Azure AD.

Once this application is registered note the _Application (client) ID_ and the _Directory (tenant) ID._ Then configure the authentication in the _Certificates & Secrets_ section.

To use client-secret authentication, add you secret to the _Client Secret (API key)_ field.

To use certificate-based authentication, set the paths to the certificate and private key files. If the key file is protected with a passphrase, set this passphrase in the _Private key passphrase_ field. Paths must be absolute and files must exist in the host where _Elastic Agent_ is running.


Add your tenant ID(s) to the _Directory (tenant) IDs_ field, then add the hostname that this tenant identifies to the _Directory (tenant) domains_ field. For example:
- Directory IDs: `my-id-a` `my-id-b`
- Directory domains: `a.onmicrosoft.com` `b.onmicrosoft.com`

## Compatibility

The `ingest-geoip` and `ingest-user_agent` Elasticsearch plugins are required to run this module.

## Logs

### Audit

Uses the Office 365 Management Activity API to retrieve audit messages from Office 365 and Azure AD activity logs. These are the same logs that are available under Audit Log Search in the Security and Compliance Center.

{{event "audit"}}

{{fields "audit"}}
