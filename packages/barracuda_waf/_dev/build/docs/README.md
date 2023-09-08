# Barracuda Web Application Firewall

The Barracuda Web Application Firewall integration allows you to monitor Barracuda Web Application Firewall. 

Barracuda Web Application Firewall protects applications, APIs, and mobile app backends against a variety of attacks including the OWASP Top 10, zero-day threats, data leakage, and application-layer denial of service (DoS) attacks. By combining signature-based policies and positive security with robust anomaly-detection capabilities, Barracuda Web Application Firewall can defeat today’s most sophisticated attacks targeting your web applications.


Use the Barracuda Web Application Firewall integration to ingest Barracuda WAF's logs. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference `data_stream.dataset:barracuda_waf.logs` when troubleshooting an issue.

## Data streams

The Barracuda Web Application Firewall integration collects one type of data streams: logs.

**Logs** help you keep a record of events happening in Barracuda WAF.
Log data streams collected by the Barracuda WAF integration include Firewall logs. See more details in the [Logs](#logs-reference).

## Upgrade

The Technical preview `spamfirewall` data stream has been deprecated and removed, as of v1.0 of this integration. As we work on a replacement for the Spam Firewall integration, you can continue to use the [Spam Firewall filebeat module](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-barracuda.html).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This integration is built and tested against the Barracuda Web Application Firewall version **12.1**. Earlier versions may work, but have not been tested.

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

### WAF Events

The `barracuda_waf.logs` dataset provides events from the configured syslog server. All Barracuda WAF syslog specific fields are available in the `barracuda.waf` field group.

{{fields "logs"}}
