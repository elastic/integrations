# Platform Observability

## Compatibility

This package works with Kibana 8.3.0 and later.

## Kibana logs

The Kibana integration collects logs from {{ url "kibana-introduction" "Kibana" }} instance.

### Logs

#### Audit

Audit logs collects the {{ url "kibana-security-settings" "Kibana audit logs" }}.

{{event "kibana_audit"}}

{{fields "kibana_audit"}}

#### Log

Log collects the {{ url "kibana-logging-configuration" "Kibana logs" }}.

{{event "kibana_log"}}

{{fields "kibana_log"}}
