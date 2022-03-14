# Cloudflare Integration

The Cloudflare integration collects events from the Cloudflare API.

## Logs

### Audit

The Cloudflare Audit records all events related to your Cloudflare account. 
To use this integration, you must have the `Account.Access: Audit Logs: Read` permission and you must use your email and your Global API Key (not an API Token).

{{fields "audit"}}

{{event "audit"}}

### Logpull

The Cloudflare Logpull records network events related to your organization in order to provide an audit trail that can be used to understand platform activity and to diagnose problems. This module is implemented using the httpjson input.

{{fields "logpull"}}

{{event "logpull"}}