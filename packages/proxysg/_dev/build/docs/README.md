# Broadcom ProxySG

ProxySG is a secure web gateway solution that enhances the security, performance, and management of web traffic for enterprises by providing URL
filtering, advanced threat protection, and SSL inspection to identify and block malicious activities. It improves web application performance and
reduces bandwidth usage by caching frequently accessed content, while supporting user authentication and access control policies based on various
attributes. Additionally, ProxySG offers detailed reporting and analytics tools for insights into web usage patterns, security incidents, and policy
compliance. Deployed as a physical or virtual appliance or in the cloud, ProxySG serves as a proxy server that inspects, filters, and manages web
traffic to strengthen an organization's network security posture.

## Data streams

The ProxySG integration collects access logs from an appliance. Log can be provided with syslog or files uploaded from the appliance.

Log formats supported by ProxySG are available [here](https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg/7-3/getting-started/page-help-administration/page-help-logging/log-formats/default-formats.html).
Currently the ProxySG integration supports the following formats:

* main

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

ProxySG access logs can be exported from the appliance via syslog or file upload; the integration supports both.

### Syslog

Configure ProxySG to send access logs via syslog to a remote server.

Add the integration, and configure it with "Collect logs from ProxySG via UDP" or "Collect logs from ProxySG via TCP".

In advanced options, select the "Access Log Format" value that matches the configured appliance access log format. 

### File Upload

Configure ProxySG to upload access logs to a remove server on a schedule.

Add the integration, and configure it with "Collect access logs from ProxySG via logging server file"

In advanced options, set "Paths" to the file pattern that matches the location files will be uploaded to on the remote server.
Select the "Access Log Format" value that matches the configured appliance access log format.

### Access Logs

{{ event "log" }}

{{ fields "log" }}
