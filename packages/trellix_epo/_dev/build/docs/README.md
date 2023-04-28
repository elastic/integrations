# Trellix ePO

## Overview

The [Trellix ePO](https://www.trellix.com/en-us/products/epo.html) integration allows users to monitor devices, events and groups. Trellix ePolicy Orchestrator is centralized security management platform to orchestrate and manage all your endpoints.

Use the Trellix ePO integration to collect and parse data from the REST APIs. Then visualize that data in Kibana.

## Data streams

The Trellix ePO integration collects three types of data: devices, events and groups.

**Devices** fetch all devices.

**Events** fetch all events.

**Groups** fetch all groups.

Reference for [Rest APIs](https://developer.manage.trellix.com/mvision/apis/home) of Trellix ePO.

## Requirements

Elasticsearch is needed to store and search data. Kibana is needed for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

This module has been tested against **Trellix ePO API Version v2**.

## Setup

### To collect data from Trellix ePO REST APIs, follow the below steps:

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