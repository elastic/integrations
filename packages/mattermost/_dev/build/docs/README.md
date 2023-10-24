# Mattermost Integration

The Mattermost integration collects logs from [Mattermost](
https://docs.mattermost.com/) servers.  This integration has been tested with
Mattermost version 5.31.9 but is expected to work with other versions.

## Logs

### Audit

All access to the Mattermost REST API or CLI is audited.

{{fields "audit"}}

{{event "audit"}}
