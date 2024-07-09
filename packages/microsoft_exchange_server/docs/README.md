# Microsoft Exchange Server
The Microsoft Exchange Server integration allows you to monitor Exchange Server installations.

## Data streams

The Microsoft Exchange Server integration collects logs of the following streams:
- Exchange HTTPProxy Logs
- Exchange Server IMAP4 POP3 Logs
- Exchange Messagetracking Logs
- Exchange SMTP logs

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Setup Exchange Server

To collect the SMTP Logs, the logs have to be configured on the exchange Server. To enable it, you can follow this [guide](https://learn.microsoft.com/en-us/exchange/mail-flow/connectors/configure-protocol-logging)
The other logs are enabled by default, and no further configurations are required
