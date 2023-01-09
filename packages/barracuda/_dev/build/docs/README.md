# Barracuda integration

This integration is for Barracuda device's logs. It includes the following
datasets for receiving logs over syslog or read from a file:
- `waf` dataset: supports Barracuda Web Application Firewall logs.
- `spamfirewall` dataset: supports Barracuda Spam Firewall logs.

### Waf

The `waf` dataset collects Barracuda Web Application Firewall logs.

{{fields "waf"}}

### Spamfirewall

The `spamfirewall` dataset collects Barracuda Spam Firewall logs.

{{fields "spamfirewall"}}
