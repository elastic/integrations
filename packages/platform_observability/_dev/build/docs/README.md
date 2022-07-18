# Platform Observability

## Compatibility

This package works with Kibana 8.3.0 and later.

## Kibana logs

The Kibana integration collects logs from [Kibana](https://www.elastic.co/guide/en/kibana/current/introduction.html) instance.

### Logs

#### Audit

Configure `Path` pointing to the location where audit logs will be created, based on the [Kibana Audit logging settings](https://www.elastic.co/guide/en/kibana/current/security-settings-kb.html#audit-logging-settings) in `kibana.yml`

{{fields "kibana_audit"}}

#### Log

Configure `Path` pointing to the location where the logs will be created, based on the [Kibana logging settings](https://www.elastic.co/guide/en/kibana/current/logging-configuration.html#logging-appenders) in `kibana.yml`

{{fields "kibana_log"}}
