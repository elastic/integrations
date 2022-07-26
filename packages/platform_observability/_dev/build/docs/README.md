# Platform Observability

## Compatibility

This package works with Kibana 8.3.0 and later.

## Kibana logs

The Kibana integration collects logs from [Kibana](https://www.elastic.co/guide/en/kibana/current/introduction.html) instance.

### Logs

#### Audit

Audit logs collects the [Kibana audit logs](https://www.elastic.co/guide/en/kibana/current/security-settings-kb.html).

{{event "kibana_audit"}}

{{fields "kibana_audit"}}

#### Log

Log collects the [Kibana logs](https://www.elastic.co/guide/en/kibana/current/logging-configuration.html).

{{event "kibana_log"}}

{{fields "kibana_log"}}
