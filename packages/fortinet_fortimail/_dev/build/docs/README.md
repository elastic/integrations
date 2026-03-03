# Fortinet FortiMail

## Overview

The [Fortinet FortiMail](https://www.fortinet.com/products/email-security) integration allows users to monitor History, System, Mail, Antispam, Antivirus, and Encryption events. FortiMail delivers advanced multi-layered protection against the full spectrum of email-borne threats. Powered by FortiGuard Labs threat intelligence and integrated into the Fortinet Security Fabric, FortiMail helps your organization prevent, detect, and respond to email-based threats including spam, phishing, malware, zero-day threats, impersonation, and Business Email Compromise (BEC) attacks.

Use the Fortinet FortiMail integration to collect and parse data from the Syslog. Then visualize that data in Kibana.

## Data streams

The Fortinet FortiMail integration collects one type of data stream: log.

**Log** helps users to keep a record of email activity and traffic including system-related events, such as system restarts and HA activity, virus detections, spam filtering results, POP3, SMTP, IMAP, and webmail events. See more details [About FortiMail logging](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/435158/about-fortimail-logging)

This integration targets the six types of events as mentioned below:

- **History** records all email traffic going through the FortiMail unit.

- **System** records system management activities, including changes to the system configuration as well as administrator and user login and logouts.

- **Mail** records mail activities.

- **Antispam** records spam detection events.

- **Antivirus** records virus intrusion events.

- **Encryption** records detection of IBE-related events.

## Requirements

Elasticsearch is needed to store and search data, and Kibana is needed for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

This module has been tested against **Fortinet FortiMail version 7.2.2**.

**Note:** The User must have to **Enable CSV format** option.

## Setup

### To collect data from Fortinet FortiMail Syslog server, follow the below steps:

- [Configure Syslog server](https://docs.fortinet.com/document/fortimail/7.2.2/administration-guide/332364/configuring-logging#logging_2063907032_1949484)

![Fortinet FortiMail Syslog Server](../img/fortinet-fortimail-configure-syslog-server.png)

## Logs Reference

### Log

This is the `Log` dataset.

#### Example

{{event "log"}}

{{fields "log"}}