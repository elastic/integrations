# Cloudflare Integration

The Cloudflare integration collects events from the Cloudflare API, specifically reading from the Cloudflare Logpull API.

## Logs

### Log

The Cloudflare Log records network events related to your organization in order to provide an audit trail that can be used to understand platform activity and to diagnose problems. This module is implemented using the httpjson input and the AWS S3 input.

{{fields "log"}}
