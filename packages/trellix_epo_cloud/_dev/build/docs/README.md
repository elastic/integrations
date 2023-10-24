# Trellix ePO Cloud

## Overview

The [Trellix ePO Cloud](https://www.trellix.com/en-us/products/epo.html) integration allows users to monitor devices, events and groups. Trellix ePolicy Orchestrator is centralized security management platform to orchestrate and manage all your endpoints.

Use the Trellix ePO integration to collect and parse data from ePO Cloud. This integration does not support on-premises installations of ePO. Then visualize that data from Trellix to identify threats through search, correlation and visualisation within Elastic Security.

## Data streams

The Trellix ePO Cloud integration collects three types of data: devices, events and groups.

**Devices** fetch all devices.

**Events** fetch all events.

**Groups** fetch all groups.

Reference for [Rest APIs](https://developer.manage.trellix.com/mvision/apis/home) of Trellix ePO Cloud.

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).  
The minimum **kibana.version** required is **8.7.1**.  
This module has been tested against the **Trellix ePO Cloud API Version v2**.

## Setup

### To collect data from Trellix ePO Cloud REST APIs, follow the below steps:

1. Go to the [Trellix Developer Portal](https://developer.manage.trellix.com/) and Login by entering an email address and password.
2. Go to **Self Service → API Access Management**.
3. Enter **Client Type**.
4. Select **IAM Scopes** as below:

    | APIs | Method Types |
    |---|---|
    | Devices | GET |
    | Events | GET |
    | Groups | GET |
5. Click **Request**.
6. Copy **Client ID**, **Client Secret** and **API Key**.
7. Go to kibana and select **integration -> Trellix ePO Cloud**.
8. Click **Add Trellix ePO Cloud**.
9. Provide **Client ID**, **Client Secret** and **API Key** that we've copied from Trellix.

**Note:**
  - The data retention period for events available via this API is 3 days.

## Logs Reference

### Device

This is the `Device` dataset.

#### Example

{{event "device"}}

{{fields "device"}}

### Event

This is the `Event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}

### Group

This is the `Group` dataset.

#### Example

{{event "group"}}

{{fields "group"}}