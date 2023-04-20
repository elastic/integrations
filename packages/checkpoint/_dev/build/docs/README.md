# Check Point Integration

The Check Point integration allows you to monitor [Check Point](http://checkpoint.com/) Firewall logs from appliances running [Check Point Management](https://sc1.checkpoint.com/documents/latest/APIs/#introduction~v1.9%20).

Use the Check Point integration to collect and parse firewall event logs. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference the firewall data stream when troubleshooting an issue.

For example, you could use the data from this integration to spot unusual network activity and malicious traffic on your network. You could also use the data to review or troubleshoot the rules that have been set up to block these activities. You can do this by looking at additional context in the logs, such as the source of the requests, and more.

## Data streams

The Check Point integration collects one type of data: logs.

**Logs** help you keep a record of events logged by your firewall device.
Logs collected by the Check Point integration include all logged network events specified by the firewall's rules. See more details in the [Logs reference](#logs-reference).
 
## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You will need one or more Check Point Firewall appliances to monitor.

### Compatibility

This integration has been tested against Check Point Log Exporter on R80.X and R81.X.

## Setup

1. Install Elastic Agent on a host between your Check Point Log Exporter instance and Elastic Cluster. The agent will be used to receive syslog data from your Check Point firewalls and ship the events to Elasticsearch. 
2. For each firewall device you wish to monitor, create a new [Log Exporter/SIEM object](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter-Configuration-in-SmartConsole.htm?tocpath=Log%20Exporter%7C_____2) in Check Point *SmartConsole*. Set the target server and target port to the Elastic Agent IP address and port number. Set the protocol to UDP or TCP, the Check Point integration supports both. Set the format to syslog.
3. Configure the Management Server or Dedicated Log Server object in *SmartConsole*.
4. Install the database within *SmartConsole* (steps included in the Checkpoint docs linked above).
5. Within Kibana, browse to Integrations and locate the Check Point integration, and 'Add Check Point'
6. Configure the TCP or UDP input, depending on the protocol you configured Check Point to use. 
7. Add a certificate if using Secure Syslog over TCP with TLS (optional)
8. Add integration to a New/Existing policy. 
9. Browse to dashboard/discover to validate data is flowing from Check Point. 

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Logs reference

### Firewall

The Check Point integration collects data in a single data stream, the **firewall** data set. This consists of log entries from the [Log Exporter](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk122323) in the Syslog format.

{{event "firewall"}}

{{fields "firewall"}}
