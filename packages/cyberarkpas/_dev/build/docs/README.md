# CyberArk Privileged Access Security

The CyberArk Privileged Access Security integration collects audit logs and monitoring data from [CyberArk's Vault](https://docs.cyberark.com/Product-Doc/OnlineHelp/Portal/Content/Resources/_TopNav/cc_Portal.htm) server.

## Data streams

The `audit` data stream receives Vault Audit logs for User and Safe activities over the syslog protocol.

It will also receive **monitoring** data from the server and route it to the `monitor` data stream (e.g. `logs-cyberarkpas.monitor-default`).

### Vault Configuration

Follow the steps under [Security Information and Event Management (SIEM) Applications](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PASIMP/DV-Integrating-with-SIEM-Applications.htm) documentation to setup the integration:

- Copy the [elastic-json-v1.0.xsl](https://raw.githubusercontent.com/elastic/beats/master/x-pack/filebeat/module/cyberarkpas/_meta/assets/elastic-json-v1.0.xsl) XSL Translator file to
the `Server\Syslog` folder.

- Sample syslog configuration for `DBPARM.ini`:

```ini
[SYSLOG]
UseLegacySyslogFormat=no
SyslogTranslatorFile=Syslog\elastic-json-v1.0.xsl
SyslogServerIP=<INSERT FILEBEAT IP HERE>
SyslogServerPort=<INSERT FILEBEAT PORT HERE>
SyslogServerProtocol=TCP
SendMonitoringMessage=yes
```

For proper timestamping of events, it's recommended to use the newer RFC5424 Syslog format
(`UseLegacySyslogFormat=No`). To avoid event loss, use `TCP` or `TLS` protocols instead of `UDP`.

The sample configuration above will include monitoring data. For more information about monitoring, see
[Monitor the Vault in SIEM Applications Using Syslog](https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/monitoring-the-vault-using-syslog.htm).

### Example audit event

{{event "audit"}}

{{fields "audit"}}

### Example monitor event

{{event "monitor"}}

{{fields "monitor"}}
