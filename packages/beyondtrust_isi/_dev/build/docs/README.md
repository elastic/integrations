# BeyondTrust Identity Security Insights for Elastic

## Overview

[BeyondTrust ISI](https://www.beyondtrust.com/products/identity-security-insights) helps you understand and act on identity risk. It maps how access works—and how it can escalate—so you can detect threats, reduce privilege, and improve posture across hybrid environments. Built to fit into your existing identity stack, Insights gives you real-time visibility and contextual recommendations without requiring a reset.

The BeyondTrust ISI integration for Elastic collects **incidents** from BeyondTrust ISI using the Elastic Agent [HTTP Endpoint](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-http_endpoint) input and also **incidents** that are sent directly to Elasticsearch via [BeyondTrust ISI's native Elastic push](https://docs.beyondtrust.com/insights/docs/elastic). Events are normalized to Elastic Common Schema (ECS), enriched in ingest pipelines, and indexed in Elasticsearch so you can search, alert, and build dashboards in Kibana.

### Compatibility

The BeyondTrust ISI integration is compatible with BeyondTrust ISI version **26.04.1**.

### How it works

This integration collects incidents from BeyondTrust ISI using HTTP Endpoint and BeyondTrust ISI pushes incidents directly to Elasticsearch in real-time using its native Elastic integration. BeyondTrust ISI incidents are forwarded to the Elastic Agent using HTTP Endpoint in real-time, processes them through ingest pipelines, indexes them in Elasticsearch.

## What data does this integration collect?

This integration collects events of the following type:

- `Incidents`: Collects BeyondTrust ISI incidents using the **HTTP Endpoint**.
- `Events`: BeyondTrust ISI incidents pushed directly to Elasticsearch via the **native Elastic integration**.

### Supported use cases

BeyondTrust ISI incident dashboards provide a unified view of identity risks and overall security posture by surfacing total incidents, severity breakdowns, incident types, rule versions, top sources, locations, and the most impacted entities. Integrating BeyondTrust ISI incident data into SIEM dashboards enables quick risk assessment, efficient investigation, and enhanced security monitoring through centralized visibility and actionable insights.

## What do I need to use this integration?

### Collect BeyondTrust ISI data using HTTP Endpoint

- In your **BeyondTrust ISI instance**, go to the main menu and select **Insights > Integrations**.  
  The Integrations page displays the available integrations.
- Click **Webhooks**.  
  The Summary page displays.
- Click **Create Integration**.  
  The Configure Integration page displays.
- Provide the following information:
    - Webhook Name: Enter your desired name for this webhook.
    - Webhook URL: The URL where Insights will send information. This can represent the location of a Teams or Slack channel or other application URL.
    - (Optional) Click Add Header, then enter the name and value of a custom header to add to every webhook.
    - Authorization Type: If your webhook requires **Basic** or **Bearer** authorization, select it from the dropdown (see [BeyondTrust webhook documentation](https://docs.beyondtrust.com/insights/docs/webhooks)):
      - **Bearer:** Provide a long-lived access token in the Token field.
      - **Basic:** Provide a username and password to use for authentication.
- Webhook Template: A JSON object, which represents the information sent from Insights. Add the following JSON:
     ```
     {  
     "incidentType": "%%incidentType%%",  
     "incidentId": "%%incidentId%%",  
     "severity": "%%severity%%",  
     "definitionSummary": "%%definitionSummary%%",  
     "definitionId": "%%definitionId%%",  
     "entityType": "%%entityType%%",  
     "entityName": "%%entityName%%",  
     "source": "%%source%%",  
     "location": "%%location%%",  
     "tenantId": "%%tenantId%%",  
     "timestamp": "%%timestamp%%",  
     "link": "%%link%%"  
     }
     ```

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

For more details, check documentation for [HTTP Endpoint](https://docs.beyondtrust.com/insights/docs/webhooks) and [Native Elastic Push](https://docs.beyondtrust.com/insights/docs/elastic).

## How do I deploy this integration?

This integration supports Agent-based installations. And for Event data streams no Elastic Agent is required, BeyondTrust ISI pushes incidents directly to your Elasticsearch cluster.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### configure

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **BeyondTrust ISI**.
3. Select the **BeyondTrust ISI** integration and add it.
4. Configure all the required integration parameters, including the listen address, listen port, and authentication method along with its corresponding required fields for the HTTP Endpoint input type and configure the native Elastic integration with your Elastic **Cloud ID** and **API Key** as described above.
5. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **BeyondTrust ISI**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

### Data ingestion

Data is sent directly to Elasticsearch by BeyondTrust ISIs [Native Elastic integration](https://docs.beyondtrust.com/insights/docs/elastic).

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### incident

This is the `incident` dataset.

{{event "incident"}}

{{fields "incident"}}

### Inputs used

This input is used in the integration::

- [HTTP Endpoint](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-http_endpoint)
