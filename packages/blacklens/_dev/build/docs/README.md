# blacklens.io

The [blacklens.io](https://blacklens.io) integration allows you to monitor alerts. blacklens.io is a comprehensive Attack Surface Management platform that helps businesses understand and secure their external attack surface. By combining automated security analysis, continuous monitoring, and penetration testing, it identifies and addresses vulnerabilities early. With features like Darknet Monitoring, Vulnerability Scanning, and XDR Response, blacklens.io provides a proactive defense strategy to protect companies from cyber threats while offering a clear view of their security posture at all times.

Use the blacklens.io integration to fetch all related alerts about your Attack Surface. Then visualize that data in Kibana and create further alerts or enrich the data with other security solutions.

## Data streams

The blacklens.io integration collects one type of data streams: logs

**Alerts** returns a list of blacklens.io alerts (The API Docs are referenced within the portal)
## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.
You will require the `alerts:read` permission in order to fetch the Alerts via the API.

You need an active blacklens.io subscription and a user with the `alerts:read` permission to retrieve alerts via the API.

## Setup

### Copy blacklens.io required configuration properties

1. Login to your blacklens.io Portal (This URL will be used for the Instance URL: 'https://portal-(ID).blacklens.io')
2. Go to **Profile → Generate API Key** and copy it. 
3. Go to **Settings → Company**.
4. Copy **ws_id** and **tenant_id**.

### Enable the blacklens.io Integration in Elastic

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type blacklens.io.
3. Click on the "blacklens.io" integration from the search results.
4. Click on the "Add blacklens.io" button to add the integration.
5. Configure all required integration parameters. 
    - Alert data requires following parameters:
        - `URL`
        - `Tenant ID (tenant_id)`
        - `Workspace ID (ws_id)`
        - `API Key`
6. Save the integration.

For detailed setup instructions, please refer to the blacklens.io Knowledge Base (The link is referenced within the portal).

## Logs reference

### alerts

This is the `alerts` dataset

#### Example

{{ event "alerts"}}

{{ fields "alerts"}}