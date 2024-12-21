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

This integration has been tested against Check Point Log Exporter on R81.X.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

In some instances firewall events may have the same Checkpoint `loguid` and arrive during the same timestamp resulting in a fingerprint collision. To avoid this [enable semi-unified logging](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter-Appendix.htm?TocPath=Log%20Exporter%7C_____9) in the Checkpoint dashboard.

### TCP or UDP

Elastic Agent can receive log messages directly via TCP or UDP syslog messages. The Elastic Agent will be used to receive syslog data from your Check Point firewalls and ship the events to Elasticsearch. 

1. For each firewall device you wish to monitor, create a new [Log Exporter/SIEM object](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter-Configuration-in-SmartConsole.htm?tocpath=Log%20Exporter%7C_____2) in Check Point *SmartConsole*. Set the target server and target port to the Elastic Agent IP address and port number. Set the protocol to UDP or TCP, the Check Point integration supports both. Set the format to syslog.
2. Configure the Management Server or Dedicated Log Server object in *SmartConsole*.
3. Install the database within *SmartConsole* (steps included in the Checkpoint docs linked above).
4. Within Kibana, browse to Integrations and locate the Check Point integration, and 'Add Check Point'.
5. Add Elastic Agent to host with Fleet, or install Elastic Agent manually after configuring the integration.
6. Configure the TCP or UDP input, depending on the protocol you configured Check Point to use.
7. Add a certificate if using Secure Syslog over TCP with TLS (optional)
8. Add integration to a New/Existing policy.
9. Browse to dashboard/discover to validate data is flowing from Check Point.

### Logfile

Elastic Agent can process log messages by monitoring a log file on a host receiving syslog messages. The syslog server will receive messages from Check Point, write to a logfile, and Elastic Agent will watch the log file to send to the Elastic Cluster. 

1. Install a syslog server on a host between your Check Point Log Exporter instance and Elastic Cluster. 
2. Configure the syslog server to write logs to a logfile.
3. For each firewall device you wish to monitor, create a new [Log Exporter/SIEM object](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter-Configuration-in-SmartConsole.htm?tocpath=Log%20Exporter%7C_____2) in Check Point *SmartConsole*. Set the target server and target port to the syslog server. Set the protocol to UDP or TCP, the Check Point integration supports both. Set the format to syslog.
4. Configure the Management Server or Dedicated Log Server object in *SmartConsole*.
5. Install the database within *SmartConsole* (steps included in the Checkpoint docs linked above).
6. Within Kibana, navigate to the Integrations section and locate the Check Point integration. Click on the "Add Check Point" button to initiate the integration process.
7. Add Elastic Agent to host with Fleet, or install Elastic Agent manually after configuring the integration.
8. Configure the logfile input, to monitor the logfile pattern that the syslog server will write to.
9. Add integration to a New/Existing policy.
10. Browse to dashboard/discover to validate data is flowing from Check Point.

## Logs reference

### Firewall

The Check Point integration collects data in a single data stream, the **firewall** data set. This consists of log entries from the [Log Exporter](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk122323) in the Syslog format.

{{event "firewall"}}

{{fields "firewall"}}
