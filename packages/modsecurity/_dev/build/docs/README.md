# Modsecuriy Integration

This integration periodically fetches audit logs from [Modsecurity](https://github.com/SpiderLabs/ModSecurity/) servers. It can parse audit logs created by the HTTP server.

## Compatibility

The logs were tested with Modsecurity v3 with nginx connector.Change the default modsecurity logging format to json as per configuration

```
SecAuditLogParts ABDEFHIJZ
SecAuditLogType Serial
SecAuditLog /var/log/modsec_audit.json
SecAuditLogFormat JSON
```

> Be cautious to drop **the list of all rules that matched for the transaction (K)** in SecAuditLogParts. That part can make raw logs too long to parse.

### Audit Log

The `Audit Log` dataset collects Modsecurity Audit logs.

{{fields "auditlog"}}
