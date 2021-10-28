# CyberArk Privileged Access Security

The CyberArk Privileged Access Security integration collects audit logs from CyberArk's Vault server.

## Audit

The `audit` dataset receives Vault Audit logs for User and Safe activities over the syslog protocol.

### Vault Configuration

Follow the steps under [Security Information and Event Management (SIEM) Applications](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PASIMP/DV-Integrating-with-SIEM-Applications.htm) documentation to setup the integration:

- Copy the [elastic-json-v1.0.xsl](https://raw.githubusercontent.com/elastic/beats/master/x-pack/filebeat/module/cyberarkpas/_meta/assets/elastic-json-v1.0.xsl) XSL Translator file to
the `Server\Syslog` folder.

- Sample syslog configuration for `DBPARM.ini`:

```ini
[SYSLOG]
UseLegacySyslogFormat=No
SyslogTranslatorFile=Syslog\elastic-json-v1.0.xsl
SyslogServerIP=<INSERT FILEBEAT IP HERE>
SyslogServerPort=<INSERT FILEBEAT PORT HERE>
SyslogServerProtocol=TCP
```

For proper timestamping of events, it's recommended to use the newer RFC5424 Syslog format
(`UseLegacySyslogFormat=No`). To avoid event loss, use `TCP` or `TLS` protocols instead of `UDP`.

### Example event

{{event "audit"}}

**Exported fields**

{{fields "audit"}}
