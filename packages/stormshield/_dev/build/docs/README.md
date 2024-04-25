# Stormshield SNS

Stormshield Network Security (SNS) firewalls are a stable and efficient security solution to protect corporate networks from cyberattacks. Real-time protection (intrusion prevention and detection, application control, antivirus, etc.), control and supervision (URL filtering, IP geolocation, vulnerability detection, etc.) and content filtering (antispam, antispyware, antiphishing, etc.) all guarantee secure communications. All Stormshield Network Security firewalls are based on the same firmware, and with their core features, Stormshield Network Security firewalls give you comprehensive security and high performance network protection.

Use the Stormshield SNS integration to ingest log data into Elastic Security and leverage the data for threat detection, incident response, and visualization.


## Data streams

The Stormshield SNS integration collects audit, traffic, and connection (including NAT) logs. Available log types are available here: https://documentation.stormshield.eu/SNS/v4/en/Content/Description_of_Audit_logs/Configure_logs.htm .


**Logs** help you keep a record of events happening in your firewalls.
The SNS integration handles activity logs and firewall (filter and NAT) logs. See more details in the [Logs](#logs-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

The SNS integration ingests logs via a UDP/syslog parser, so the SNS appliance needs to be configured to send syslogs to a listening Agent. This is configured in the `CONFIGURATION` tab, in the `NOTIFICATIONS` / `LOGS-SYSLOG-IPFIX` section.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Log

The `log` dataset collects SNS syslog logs.

{{ event "log" }}

{{ fields "log" }}
