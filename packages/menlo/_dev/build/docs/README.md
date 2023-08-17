# Menlo Security

This integration periodically fetches logs from Menlo Security API. It includes the following data sets

- Web
- DLP

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

- Menlo API URL
- Menlo API Token

## Logs

### Web

Contains events from the Web data source

{{ fields "web" }}

{{ event "web" }}

### DLP

Contains events from the DLP data source

{{ fields "dlp" }}

{{ event "dlp" }}