# pfSense Integration

This is an integration to parse certain logs from the PFsense firewall. It parses logs
received over the network via syslog (UDP). Currently the integration supports parsing the
Firewall, Unbound, DHCP Daemon, OpenVPN, IPsec, and HAProxy logs.  All other events will be dropped.
The firewall, VPN, DHCP, and DNS logs are able to be individually selected via the "Remote Logging Options"
section within the pfSense settings page.  In order to collect HAProxy or other "package" logs, the "Everything" option
must be selected. The module is by default configured to run with the `udp` input on port `9001`.

*The HAProxy logs are setup to be compatible with the dashboards from the HAProxy integration.  Install the HAPrxoy integration assets to utilize them.

**Important**  
The pfSense integration supports both the BSD logging format and the Syslog format.
However the syslog format is recommended. It will provide the firewall hostname and timestamps with timezone information.
When using the BSD format, the `Timezone Offset` config must be set when deploying the agent or else the timezone will default to the timezone of the agent. See `https://<pfsense url>/status_logs_settings.php` and https://docs.netgate.com/pfsense/en/latest/monitoring/logs/settings.html for more information.


## Logs

### pfSense log

This is the pfSense `log` dataset.

{{event "log"}}

{{fields "log"}}
