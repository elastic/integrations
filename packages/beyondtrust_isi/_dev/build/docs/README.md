# BeyondTrust Identity Security Insights for Elastic

## Overview

[BeyondTrust ISI](https://www.beyondtrust.com/products/identity-security-insights) helps you understand and act on identity risk. It maps how access works—and how it can escalate—so you can detect threats, reduce privilege, and improve posture across hybrid environments. Built to fit into your existing identity stack, Insights gives you real-time visibility and contextual recommendations without requiring a reset.

The BeyondTrust ISI integration for Elastic collects **incidents** that are sent directly to Elasticsearch via [BeyondTrust ISI's native Elastic push](https://docs.beyondtrust.com/insights/docs/elastic), so you can search, alert, and build dashboards in Kibana.

### How it works

BeyondTrust ISI pushes incidents directly to Elasticsearch in real-time using its native Elastic integration.

## What data does this integration collect?

This integration collects events of the following type:

- `Incidents`: Collects BeyondTrust ISI incidents pushed directly to Elasticsearch via the **native Elastic integration**.

### Supported use cases

BeyondTrust ISI incident dashboards provide a unified view of identity risk, surfacing total incidents, breakdowns by severity, code, and rule version, and the most impacted entities for fast assessment and investigation.

## What do I need to use this integration?

### Configure the native Elastic integration in BeyondTrust ISI

Before configuring the integration, gather the following from your Elastic Cloud deployment:

- **Cloud ID**: From your Elastic Cloud deployment overview page.
- **API Key**: Generated under Elastic **Security > API Keys**.

Then, in BeyondTrust ISI:

1. Open Insights and go to the menu **> Integrations**.
2. Click **Elastic**.
3. Click **Create Integration**.
4. Enter the **Elastic Cloud ID** and **API Key**.
5. Click **Create Integration**.

The integration will appear under the **Configured** section. Changes to the Cloud ID or API Key may take up to two minutes to take effect.

For more details, check [Documentation](https://docs.beyondtrust.com/insights/docs/elastic).

## How do I deploy this integration?

No Elastic Agent is required. BeyondTrust ISI pushes incidents directly to your Elasticsearch cluster.

### Configure

1. In Kibana, navigate to **Management** > **Integrations**.
2. Search for **BeyondTrust ISI** and add the integration to install its assets (ingest pipelines, index templates, and dashboards).
3. In BeyondTrust ISI, configure the native Elastic integration with your Elastic **Cloud ID** and **API Key** as described above.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **BeyondTrust ISI**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

### Data ingestion

Data is sent directly to Elasticsearch by BeyondTrust ISIs [native Elastic integration](https://docs.beyondtrust.com/insights/docs/elastic).
