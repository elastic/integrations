# Modsecuriy Integration

This integration periodically fetches audit logs from [Modsecurity](https://github.com/SpiderLabs/ModSecurity/) servers. It can parse audit logs created by the HTTP server.

## Compatibility

The logs were tested with Modsecurity v3 with nginx connector.Change the default modsecurity logging format to json as per configuration

```
SecAuditLogType Serial
SecAuditLog /var/log/modsec_audit.json
SecAuditLogFormat JSON
```

### Audit Log

The `Audit Log` dataset collects Modsecurity Audit logs.

{{fields "auditlog"}}
