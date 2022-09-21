# Salesforce Integration

## Overview

The Salesforce integration allows you to monitor {{ url "salesforce-url" "Salesforce" }} instance. Salesforce provides customer relationship management service and also provides enterprise applications focused on customer service, marketing automation, analytics, and application development.

Use the Salesforce integration to get visibility into the Salesforce Org operations and hold Salesforce accountable to the Service Level Agreements. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

For example, if you want to check the number of successful and failed login attempts over time, you could check the same based on the ingested events or the visualization. Then you can create visualizations, alerts and troubleshoot by looking at the documents ingested in Elasticsearch.

## Data streams

The Salesforce integration collects log events using REST and Streaming API of Salesforce.

**Logs** help you keep a record of events happening in Salesforce.
Log data streams collected by the Salesforce integration include {{ url "salesforce-login" "Login" }} (using REST and Streaming API), {{ url "salesforce-logout" "Logout" }} (using REST and Streaming API), {{ url "salesforce-apex" "Apex" }}, and {{ url "salesforce-setupaudittrail" "SetupAuditTrail" }}.

This integration uses:
- `httpjson` filebeat input to collect `login_rest`, `logout_rest`, `apex` and `setupaudittrail` events.
- `cometd` filebeat input to collect `login_stream` and `logout_stream` events.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Logs reference

### Login Rest

This is the `login_rest` data stream. It represents events containing details about your organization's user login history.

{{event "login_rest"}}

{{fields "login_rest"}}
