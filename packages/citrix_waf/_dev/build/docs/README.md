# Citrix Web App Firewall

The Citrix Web App Firewall prevents security breaches, data loss, and possible unauthorized modifications to websites that access sensitive business or customer information. It does so by filtering both requests and responses, examining them for evidence of malicious activity, and blocking requests that exhibit such activity. Your site is protected not only from common types of attacks, but also from new, as yet unknown attacks. In addition to protecting web servers and websites from unauthorized access, the Web App Firewall protects against vulnerabilities in legacy CGI code or scripts, web frameworks, web server software, and other underlying operating systems.

## Compatibility

FIXME

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In "Search for integrations" search bar type **Citrix**
3. Click on "Citrix WAF" integration from the search results.
4. Click on **Add Citrix WAF Integration** button to add the integration.

### Citrix WAF Dashboard Configuration

#### Syslog

The Citrix WAF GUI can be used to configure syslog servers and WAF message types to be sent to the syslog servers. Refer to [How to Send Application Firewall Messages to a Separate Syslog Server](https://support.citrix.com/article/CTX138973) and [How to Send NetScaler Application Firewall Logs to Syslog Server and NS.log](https://support.citrix.com/article/CTX211543) for details.

### Configure the Citrix WAF integration

#### Syslog

Depending on the syslog server setup in your environment check one/more of the following options "Collect syslog from Citrix WAF via UDP", "Collect syslog from Citrix WAF via TCP", "Collect syslog from Citrix WAF via file".

Enter the values for syslog host and port OR file path based on the chosen configuration options.

### Log Events

Enable to collect Citrix WAF log events for all the applications configured for the chosen log stream.

## Logs

### Syslog

The `citrix_waf.log` dataset provides events from the configured syslog server. All Citrix WAF syslog specific fields are available in the `citrix_waf.log` field group.

An example event for `log` looks as following:

{{event "log"}}

{{fields "log"}}
