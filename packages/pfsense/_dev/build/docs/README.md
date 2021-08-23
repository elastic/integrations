# pfSense Integration

This is an integration to parse certain logs from the PFsense firewall. It parses logs
received over the network via syslog (UDP). Currently the integration supports parsing the
Firewall, Unbound, DHCP Daemon, OpenVPN, IPsec, and HAProxy logs.  All other events will be dropped.
The firewall, VPN, DHCP, and DNS logs are able to be individually selected via the "Remote Logging Options"
section within the pfSense settings page.  In order to collect HAProxy or other "package" logs, the "Everything" option
must be selected. The module is by default configured to run with the `udp` input on port `9001`.

*The HAProxy logs are setup to be compatible with the dashboards from the HAProxy integration.  Install the HAPrxoy integration assets to utilize them.

## Logs

### pfSense log

This is the pfSense `log` dataset.

{{event "log"}}

{{fields "log"}}
