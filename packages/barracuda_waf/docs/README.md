# Barracuda WAF
Barracuda Web Application Firewall protects applications, APIs, and mobile app backends against a variety of attacks including the OWASP Top 10, zero-day threats, data leakage, and application-layer denial of service (DoS) attacks. By combining signature-based policies and positive security with robust anomaly-detection capabilities, Barracuda Web Application Firewall can defeat today’s most sophisticated attacks targeting your web applications.


The Barracuda WAF integration allows you to monitor different log types namely - Web Firewall Logs , Network Firewall Logs , Access Logs.

Use the Barracuda WAF integration to ingest log data. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data_stream:log when troubleshooting an issue.

For example, if you wanted to look at the spike of events in your Web Firewall, you could filter events based on `data_stream.dataset : "barracuda_waf.log" and barracuda_waf.log.log_type : "WF"` Then you can troubleshoot the spike of events based on other parameters

## Data streams

 The Barracuda WAF integration collects one type of data streams: logs
 **Logs** help you keep a record of events happening in Barracuda WAF.

 There is a single data stream that collects different kinds of logs from the barrcuda waf service and visualizes them separately.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

<!-- Additional set up instructions -->

<!-- If applicable -->
<!-- ## Logs reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

<!-- Optional -->
<!-- #### Example

An example event for `{data stream name}` looks as following:

{code block with example} -->

<!-- #### Exported fields

{insert table} -->

<!-- If applicable -->
<!-- ## Metrics reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

<!-- Optional -->
<!-- #### Example

An example event for `{data stream name}` looks as following:

{code block with example} -->

<!-- #### Exported fields

{insert table} -->