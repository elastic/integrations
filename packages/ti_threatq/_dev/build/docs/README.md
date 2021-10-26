# ThreatQuotient Integration

The ThreatQuotient integration uses the available REST API to retrieve indicators and Threat Intelligence.

## Logs

### Threat

The ThreatQ integration requires you to set a valid URL, combination of Oauth2 credentials and the ID of the collection to retrieve
indicators from.
By default the indicators will be collected every 1 minute, and deduplication is handled by the API itself.

{{fields "threat"}}

{{event "threat"}}