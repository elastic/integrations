# PingOne

## Overview

The [PingOne](https://www.pingidentity.com/en.html) integration allows you to monitor audit activity. PingOne is a cloud-based framework for secure identity access management.

Use the PingOne integration to collect and parse data from the REST APIs or HTTP Endpoint input. Then visualize that data in Kibana.

For example, you could use the data from this integration to know which action or activity is performed against a defined PingOne resource, and also track the actor or agent who initiated the action.

## Data streams

The PingOne integration collects logs for one type of event: Audit.

**Audit** reporting stores incoming audit messages in a cache and provides endpoints for requesting audit events for a specific time period.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has been tested against `PingOne API version 1.0`.

## Setup

### To collect data from PingOne REST APIs, follow below steps:

1. Go to the [PingOne console](https://www.pingidentity.com/en/account/sign-on.html), select PingOne as an Account and add username and password.
2. Select Environment.
3. Go to **Connections -> Applications**.
4. Click **+** to create an application.
5. Enter an Application Name.
6. Select **Worker** as an application type.
7. Click Save.
8. Click the toggle switch to enable the application, if it is not already enabled.
9. Go to **Configuration**.
10. Copy **Token Endpoint**.
11. Copy **Environment ID**, **Client ID** and **Client Secret** from General Section.

For more details, see [Documentation](https://docs.pingidentity.com/bundle/pingone/page/vpz1564020488577.html).

**Note** : Value of initial interval must be less than 2 years.

### To collect data from PingOne via HTTP Endpoint, follow below steps:

1. Reference link for configuring [HTTP Endpoint Remote logging](https://docs.pingidentity.com/bundle/pingone/page/sxi1589922927893.html) for PingOne.
2. In Destination, enter the full URL, including the port.  
`Example Format: http[s]://{AGENT_ADDRESS}:{AGENT_PORT}/{URL}`.

**Note** :  
- Select Ping Activity Format (JSON) in the format drop down.
- HTTP Endpoint Remote logging will expose the port to the internet, therefore it is advised to have proper network access configured.

## Logs Reference

#### audit

This is the `audit` dataset.

{{event "audit"}}

{{fields "audit"}}