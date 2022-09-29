# Infoblox BloxOne DDI

## Overview

The [Infoblox BloxOne DDI](https://www.infoblox.com/products/bloxone-ddi/) integration allows you to monitor DNS, DHCP and IP address management activity. DDI is the foundation of core network services that enables all communications over an IP-based network.

Use the Infoblox BloxOne DDI integration to collects and parses data from the REST APIs and then visualize that data in Kibana.

## Data streams

The Infoblox BloxOne DDI integration collects logs for three types of events: DHCP lease, DNS data and DNS config.

**DHCP Lease** is a Infoblox BloxOne DDI service that stores information about leases. See more details about its API [here](https://csp.infoblox.com/apidoc?url=https%3A%2F%2Fcsp.infoblox.com%2Fapidoc%2Fdocs%2FDhcpLeases).

**DNS Config** is a Infoblox BloxOne DDI service that provides cloud-based DNS configuration with on-prem host serving DNS protocol. See more details about its API [here](https://csp.infoblox.com/apidoc?url=https%3A%2F%2Fcsp.infoblox.com%2Fapidoc%2Fdocs%2FDnsConfig).

**DNS Data** is a Infoblox BloxOne DDI service providing primary authoritative zone support. DNS Data is authoritative for all DNS resource records and is acting as a primary DNS server. See more details about its API [here](https://csp.infoblox.com/apidoc?url=https%3A%2F%2Fcsp.infoblox.com%2Fapidoc%2Fdocs%2FDnsData).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has been tested against `Infoblox BloxOne DDI API (v1)`.

## Setup

### To collect data from Infoblox BloxOne DDI APIs, the user must have API Key. To create an API key follow the below steps:

1. Log on to the Cloud Services Portal.
2. Go to **<User_Name> -> User Profile**.
3. Go to **User API Keys** page.
4. Click **Create** to create a new API key. Specify the following:
    - **Name**: Specify the name of the key.
    - **Expires at**: Specify the expiry.
5. Click **Save & Close**. The API Access Key Generated dialog is shown.
6. Click **Copy**.

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**.
2. In the "Search for integrations" search bar, type **Infoblox BloxOne DDI**.
3. Click on **Infoblox BloxOne DDI** integration from the search results.
4. Click on **Add Infoblox BloxOne DDI** button to add Infoblox BloxOne DDI integration.
5. Enable the Integration to collect logs via API.

## Logs Reference

### dhcp_lease

This is the `dhcp_lease` dataset.

#### Example

{{event "dhcp_lease"}}

{{fields "dhcp_lease"}}

### dns_config

This is the `dns_config` dataset.

#### Example

{{event "dns_config"}}

{{fields "dns_config"}}

### dns_data

This is the `dns_data` dataset.

#### Example

{{event "dns_data"}}

{{fields "dns_data"}}
