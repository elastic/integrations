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

### To collect data from the PingOne REST API, follow the steps below:

Create a worker application in PingOne and copy the credentials, as follows:

1. Go to [pingidentity.com](https://pingidentity.com/), click
   [Sign On](https://www.pingidentity.com/bin/ping/signOnLink) and carry out
   any necessary authentication steps. You will arrive at the PingIdentity
   console.
2. From the navigation sidebar, expand the **Applications** section and
   select **Applications**.
3. Click **+** to begin creating a new application.
4. Enter an **Application Name**.
5. Select **Worker** as the application type.
6. Click **Save**.
7. On the application flyout, ensure that the toggle switch in the header is
   activated, in order to enable the application.
8. Select the **Roles** tab of the application flyout.
9. Click the **Grant Roles** button.
10. Under **Available responsibilities**, in the **Environment Admin**,
    section, select the environment(s) to grant access to, then click **Save**.
11. Select the **Configuration** tab of the application flyout.
12. Expand the **URLs** section and copy the **Token Endpoint**.
13. From the **General** section, copy the **Client ID**, **Client Secret** and
    **Environment ID**.

For more information, see the PingOne documentation about
[Adding an application](https://docs.pingidentity.com/r/en-us/pingone/p1_add_app_worker).

In Elastic, navigate to the PingOne integration, then:

1. Click **Add PingOne**.
2. Deactivate the **Collect PingOne logs via HTTP Endpoint** input.
3. Activate the **Collect PingOne logs via API** input.
4. Enter the PingOne API URL for your region in the **URL** field.
5. Enter the credentails copied from the PingOne console into the corresponding
   fields.
6. In the **Audit logs** data stream section, set an **Initial Interval** of
   no more than 2 years.
7. Choose an agent policy to add the integration to and click
   **Save and Continue**.

### To collect data from PingOne via HTTP Endpoint, follow below steps:

In Elastic, navigate to the PingOne integration, then:

1. Click **Add PingOne**.
2. Deactivate the **Collect PingOne logs via API** input.
3. Activate the **Collect PingOne logs via HTTP Endpoint** input.
4. Set the **Listen Address**, and (from the **Audit logs** data stream
   settings) set and copy the **Listen Port** and (under **Advanced options**)
   the **URL Path**.
5. In the input settings, enter any **SSL Configuration** and **Secret header**
   settings appropriate for the endpoint. Make a note of these details for use
   while configuring the PingOne webhook. **Note**: This endpoint will expose a
   port to the Internet, so it is advised to have proper network access
   configured. PingOne webhooks will only work with a `https://` destination
   URL.
6. Choose an agent policy to add the integration to and click
   **Save and Continue**.

Create a webhook in PingOne, as follows:

1. Go to [pingidentity.com](https://pingidentity.com/), click
   [Sign On](https://www.pingidentity.com/bin/ping/signOnLink) and carry out
   any necessary authentication steps. You will arrive at the PingIdentity
   console.
2. From the navigation sidebar, expand the **Integrations** section and
   select **Webhooks**.
3. Click the **+ Add Webhook** button to begin creating a new webhook.
4. In **Destination URL**, enter the full endpoint URL, including the port.
   Example format: `https://{EXTERNAL_AGENT_LISTEN_ADDRESS}:{AGENT_LISTEN_PORT}/{URL_PATH}`.
5. As **Format** select **Ping Activity Format (JSON)**.
6. In the **Filters** section, select all the **Event Types** you want to
   collect.
7. Enter any **TLS settings** and **Headers** required for the webhook to
   establish connections with the Agent's HTTP endpoint.
8. Click **Save**.
9. Ensure that the toggle switch for the webhook is activated, so that the
   webhook is enabled.

For more information, see the PingOne documentation about
[Creating or editing a webhook](https://docs.pingidentity.com/r/en-us/pingone/p1_create_webhook).

## Logs Reference

#### audit

This is the `audit` dataset.

{{event "audit"}}

{{fields "audit"}}
