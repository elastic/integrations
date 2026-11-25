# Zero Networks Integration

[Zero Networks](https://www.zeronetworks.com) is used by numerous orgazations to microsegment the network and apply MFA anywhere.

The **Zero Networks** integration uses Zero Networks' API to retrieve audit events and ingest them into Elasticsearch. This allows you to search, observe, and visualize the **Zero Networks** audit events through Elasticsearch.

The Elastic agent running this integration interacts with Zero Networks' infrastructure using their APIs to retrieve audit logs for an environment.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

## Data streams

The **Zero Networks** integration collects one type of data streams: logs.

**Logs** help you keep a record of events happening in **Zero Networks**.
Log data streams collected by the **Zero Networks** integration include Audit events. 

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Other requirements including:
 - Zero Networks API Token with Read access

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.


### Get an API Token

1. Log into the [Zero Networks portal](https://portal.zeronetworks.com).
2. Click **Setting**.
3. Click **API** under **Integrations**.
4. Click **Add new token**.
5. Enter a **Token Name** such as *Elastic Integration*. Set the **Expiry** to ** 36 Months**.  Click **Add**.
6. Copy the generated token for later use.

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**.
2. In the **"Search for integrations"** search bar type **Zero Networks**.
3. Click on **"Zero Networks"** integration from the search results.
4. Click on **Add Zero Networks** button to add the Zero Networks integration.

### Configure Zero Networks Audit logs data stream

Enter values **"API Token"**.

1. **API Token** copied from earlier steps.

***NOTE:*** Some operating systems may not have the root CA installed.  You can download the **[USERTrust RSA Certification Authority](https://ssl-tools.net/subjects/cd30d24c343a82ab1f0570158ad7a107762992e9)** and install it. As a work around, not recommended, you can set **verification_mode: none** in the **SSL** box under **Settings** by clicking **Advanced Options**.

## Logs reference

### Audit

The `audit` data stream provides audit events from Zero Networks, such as asset segmentation changes, rule and policy changes, and portal logons.

{{event "audit"}}

{{fields "audit"}}
