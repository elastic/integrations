# pfSense Integration

This is an integration to parse certain logs from [pfSense and OPNsense firewalls](https://docs.netgate.com/pfsense/en/latest/). It parses logs received over the network via syslog (UDP/TCP/TLS). pfSense natively only supports UDP. OPNsense supports all 3 transports.

Currently the integration supports parsing the Firewall, Unbound, DHCP Daemon, OpenVPN, IPsec, HAProxy, Squid, and PHP-FPM (Authentication) logs.  
All other events will be dropped.
The HAProxy logs are setup to be compatible with the dashboards from the HAProxy integration. Install the HAPrxoy integration assets to use them.

## pfSense Setup
1. Navigate to _Status -> System Logs_, then click on _Settings_
2. At the bottom check _Enable Remote Logging_
3. (Optional) Select a specific interface to use for forwarding
4. Input the agent IP address and port as set via the integration config into the field _Remote log servers_ (e.g. 192.168.100.50:5140)
5. Under _Remote Syslog Contents_ select what logs to forward to the agent
   * Select _Everything_ to forward all logs to the agent or select the individual services to forward. Any log entry not in the list above will be dropped. This will cause additional data to be sent to the agent and Elasticsearch. The firewall, VPN, DHCP, DNS, and Authentication (PHP-FPM) logs are able to be individually selected. In order to collect HAProxy and Squid or other "package" logs, the _Everything_ option must be selected.

## OPNsense Setup
1. Navigate to _System -> Settings -> Logging/Targets_
2. Add a new _Logging/Target_ (Click the plus icon)
    - Transport = UDP or TCP or TLS
    - Applications = Select a list of applications to send to remote syslog. Leave empty for all.
    - Levels = Nothing Selected
    - Facilities = Nothing Selected
    - Hostname = IP of Elastic agent as configured in the integration config
    - Port = Port of Elastic agent as configured in the integration config
    - Certificate = Client certificate to use (when selecting a tls transport type)
    - Description = Syslog to Elasticsearch
    - Click Save   

 The module is by default configured to run with the `udp` input on port `9001`.

**Important**  
The pfSense integration supports both the BSD logging format (used by pfSense by default and OPNsense) and the Syslog format (optional for pfSense).
However the syslog format is recommended. It will provide the firewall hostname and timestamps with timezone information.
When using the BSD format, the `Timezone Offset` config must be set when deploying the agent or else the timezone will default to the timezone of the agent. See `https://<pfsense url>/status_logs_settings.php` and https://docs.netgate.com/pfsense/en/latest/monitoring/logs/settings.html for more information.

A huge thanks to [a3ilson](https://github.com/a3ilson) for the https://github.com/pfelk/pfelk repo, which is the foundation for the majority of the grok patterns and dashboards in this integration.

## Logs

### pfSense log

This is the pfSense `log` dataset.

{{event "log"}}

{{fields "log"}}
