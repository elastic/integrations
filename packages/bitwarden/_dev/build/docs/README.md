# Bitwarden

## Overview

The [Bitwarden](https://bitwarden.com) integration allows users to monitor collections, members, groups, events and policies. Bitwarden is a free and open-source password management service that stores sensitive information such as website credentials in an encrypted vault. The Bitwarden platform offers a variety of client applications including a web interface, desktop applications, browser extensions, mobile apps and a command-line interface. Bitwarden offers a cloud-hosted service as well as the ability to deploy the solution on-premises.

Use the Bitwarden integration to collect and parse data from the REST APIs. Then visualize that data in Kibana.

## Data streams

The Bitwarden integration collects five types of data: collections, events, groups, members and policies.

**Collections** returns a list of organization's collections.

**Events** returns a list of organization's event logs.

**Groups** returns a list of organization's groups.

**Members** returns the details of organization's members.

**Policies** returns a list of organization's policies.

Reference for [Rest APIs](https://bitwarden.com/help/api/) of Bitwarden.

## Requirements

Elasticsearch is needed to store and search data, and Kibana is needed for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

This module has been tested against **Bitwarden Version 2023.2.0**.

## Setup

### To collect data from Bitwarden REST APIs, follow the below steps:

1. Go to the [Bitwarden console](https://vault.bitwarden.com/#/vault), enter an email address and master password.
2. Click **Organizations**.
3. Go to **Settings → Organization info**.
4. Click **View API Key** from API key Section.
5. Enter master password.
6. Click **View API Key**.
7. Copy **client_id** and **client_secret**.

## Logs Reference

### Collection

This is the `Collection` dataset.

#### Example

{{event "collection"}}

{{fields "collection"}}

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

### Member

This is the `Member` dataset.

#### Example

{{event "member"}}

{{fields "member"}}

### Policy

This is the `Policy` dataset.

#### Example

{{event "policy"}}

{{fields "policy"}}