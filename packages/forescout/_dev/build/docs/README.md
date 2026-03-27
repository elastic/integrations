# Forescout Integration for Elastic

## Overview
[Forescout](https://www.forescout.com) is a leading device visibility and control platform that enables organizations to continuously identify, classify, and enforce security policies across all connected devices. It provides real-time visibility into IT, IoT, OT, and unmanaged devices across enterprise networks.

The Forescout integration for Elastic allows you to collect host data sent by the Forescout eyeExtend Connect app, then visualize the data in Kibana.

### Compatibility
The Forescout integration is compatible with Forescout product version **8.5.2** and the Elastic eyeExtend Connect app version **0.2.0**.

### How it works
This integration receives host data sent directly by the Forescout eyeExtend Connect app to Elastic.

The integration processes the incoming host data using ingest pipelines to parse, normalize, and map the host information to Elastic Common Schema (ECS).

## What data does this integration collect?
This integration collects host data of the following type:

- `host`: Collect host information sent by the Forescout eyeExtend Connect app from the Forescout platform.

### Supported use cases
Integrating Forescout host data with Elastic delivers centralized visibility into device inventory. Kibana dashboards provide breakdowns by compliance state and network segments for rapid asset discovery and risk assessment.

## What do I need to use this integration?
### From Elastic
- Elastic Stack with ingest pipelines capability to process incoming host data.

### From Forescout
- [Forescout eyeExtend Connect app](https://docs.forescout.com/bundle/connect-1-4-1-h/page/connect-1-4-1-h.About-the-Connect-Plugin.html) configured to send host data to Elastic.

## How do I deploy this integration?

This integration does not include a data collector. Host data is sent directly by the Forescout eyeExtend Connect app to Elastic. You only need to install this integration to provide the necessary ingest pipelines and Kibana dashboards for processing and visualizing the host data.

## Setup
1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Forescout**.
3. Install the **Forescout** integration.

> **Note**: This integration does not include a data collector. It provides ingest pipelines and Kibana dashboards to process host data sent directly by the Forescout eyeExtend Connect app to Elastic. No additional configuration is required.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Forescout**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

If host data is not appearing in Elastic, verify that the Forescout eyeExtend Connect app is properly configured to send data to your Elastic instance.

## Reference

- [Forescout eyeExtend Connect Plugin](https://docs.forescout.com/bundle/connect-1-4-1-h/page/connect-1-4-1-h.About-the-Connect-Plugin.html)
