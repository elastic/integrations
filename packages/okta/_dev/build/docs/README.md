# Okta Integration

The Okta integration collects events from the Okta API, specifically reading from the Okta System Log API.

## Logs

### System

The Okta System Log records system events related to your organization in order to provide an audit trail that can be used to understand platform activity and to diagnose problems. This module is implemented using the httpjson input and is configured to paginate through the logs while honoring any rate-limiting headers sent by Okta.

{{event "system"}}

{{fields "system"}}