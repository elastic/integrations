# Trend Micro Vision One Integration for Elastic

## Overview
The [Trend Micro Vision One](https://www.trendmicro.com/en_gb/business/products/one-platform.html) integration allows you to monitor Alert, Audit, Detection, Endpoint activity, Network activity, and Telemetry activity. Trend Micro Vision One refers to the ability to do detection and response across email, endpoints, servers, cloud workloads, and networks using a single Trend Micro Vision One platform or the managed Trend Micro Vision One service.

### Compatibility

This module has been tested against `Trend Micro Vision One API version 3.0`.

### How it works

This integration periodically queries the Trend Micro Vision One REST API to retrieve Alert, Audit, Detection, Endpoint activity, Network activity, and Telemetry logs.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Alert`: Displays information about workbench alerts. Refer to more details in the doc [here](https://portal.xdr.trendmicro.com/ui/amc/redoc/index.html?from=v3.0#tag/Workbench/paths/~1v3.0~1workbench~1alerts/get).
- `Audit`: Displays log entries that match the specified search criteria. Refer to more details in the doc [here](https://portal.xdr.trendmicro.com/ui/amc/redoc/index.html?from=v3.0#tag/Audit-Logs).
- `Detection`: Displays search results from the Detection Data source. Refer to more details in the doc [here](https://portal.xdr.trendmicro.com/ui/amc/redoc/index.html?from=v3.0#tag/Search/paths/~1v3.0~1search~1detections/get).
- `Endpoint activity`: Displays search results from the Endpoint activity Data source. Refer to more details in the doc [here](https://portal.xdr.trendmicro.com/ui/amc/redoc/index.html?from=v3.0#tag/Search/paths/~1v3.0~1search~1endpointActivities/get).
- `Network activity`: Displays search results from the Network activity Data source. Refer to more details in the doc [here](https://portal.xdr.trendmicro.com/ui/amc/redoc/index.html?from=v3.0#tag/Search/paths/~1v3.0~1search~1networkActivities/get).
- `Telemetry`: Displays telemetry events from the Datalake Pipeline API. Refer to more details in the doc [here](https://portal.xdr.trendmicro.com/ui/amc/redoc/index.html?from=v3.0#tag/Datalake-Pipeline).

### Supported Use Cases

Integrating Trend Micro Vision One alert, audit, detection, endpoint activity, network activity, and telemetry events with Elastic SIEM provides centralized visibility into security events and operations.

## What do I need to use this integration?

### From Trend Micro Vision One

#### Collecting data from Trend Micro Vision One API

1. Log on to the Trend Micro Vision One console.
2. On the Trend Vision One console, go to **Administration -> API Keys**.
3. Generate a new API Key. Click **Add API key**. Specify the settings of the new API key.
    - **Name**: A meaningful name that can help you identify the API key.
    - **Role**: The user role assigned to the key. API keys can use either predefined or custom user roles. Custom roles can be created by navigating to **Administration -> User Roles -> Add Role**. The role must have appropriate API access permission to fetch relevant data. The following table outlines the access permissions to apps and features needed to fetch relevant data from Trend Vision API.

        | Datastream        | Section                                                          | Permissions                                                  |
        |-------------------|------------------------------------------------------------------|--------------------------------------------------------------|
        | Alert             | Platform Capabilities > Agentic SIEM & XDR > Workbench           | `View, filter, and search`.                                  |
        | Audit             | Settings > Administration > Audit Logs                           | `View, filter, and search`, `Export and Download`.           |
        | Detection         | Platform Capabilities > Agentic SIEM and XDR > XDR Data Explorer | `View queries and Watchlist, and filter and search queries`. |
        | Endpoint activity | Platform Capabilities > Agentic SIEM and XDR > XDR Data Explorer | `View queries and Watchlist, and filter and search queries`. |
        | Network activity  | Platform Capabilities > Agentic SIEM and XDR > XDR Data Explorer | `View queries and Watchlist, and filter and search queries`. |
        | Telemetry         | Platform Capabilities > Agentic SIEM and XDR > XDR Data Explorer | `View queries and Watchlist, and filter and search queries`. |

        Refer to [Account Role Permissions](https://automation.trendmicro.com/xdr/Guides/Authentication/) for more details.

    - **Expiration time**: The time the API key remains valid. By default, API keys expire one year after creation. However, a master administrator can delete and re-generate API keys at any time.
    - **Status**: Whether the API key is enabled.
    - **Details**: Extra information about the API key.

    Click **Add**.
4. Copy the value of the API key.

Refer to [First steps toward using the APIs](https://automation.trendmicro.com/xdr/Guides/First-steps-toward-using-the-APIs/) for more details on setting up an API key.

**Important**: For the Telemetry data stream, which uses the Datalake Pipeline APIs, you need to allocate Trend Vision One credits for Data Transfer. For more information, see [Credit requirements for Trend Vision One solutions, capabilities and services > Data Transfer](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-credit-req-for-apps-services#GUID-001E41E3-6F8A-499E-85E5-14A3DBD67C6C__section_zxw_5k2_qbc).

When the Telemetry data stream starts for the first time it will use the Datalake Pipeline API to bind all telemetry data types to a new pipeline with a distinctive description. If a pipeline with that description already exists, it will be reused. It will never delete the pipeline, so if you stop using the integration, that pipeline should be removed manually.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed using the integration's ingest pipelines.

### Onboard / configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Trend Micro Vision One**.
3. Select the **Trend Micro Vision One** integration from the search results.
4. Select **Add Trend Micro Vision One** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To collect the logs from Trend Micro Vision One using API, you'll need to:

        - Configure **Regional Domain URL** and **API Token**.
        - Adjust the integration configuration parameters if required, including the Interval, Preserve original event etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trend Micro Vision One**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Logs reference

### alert

This is the `alert` dataset.

#### Example

{{event "alert"}}

{{fields "alert"}}

### audit

This is the `audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}

### detection

This is the `detection` dataset.

#### Example

{{event "detection"}}

{{fields "detection"}}

### endpoint activity

This is the `endpoint activity` dataset.

#### Example

{{event "endpoint_activity"}}

{{fields "endpoint_activity"}}

### network activity

This is the `network activity` dataset.

#### Example

{{event "network_activity"}}

{{fields "network_activity"}}

### telemetry

This is the `telemetry` dataset.

#### Example

{{event "telemetry"}}

{{fields "telemetry"}}

### Inputs used

These inputs are used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)
- [httpjson](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-httpjson)

### API usage

This integration dataset uses the following APIs:

- `Alert`: [Get alerts list](https://portal.xdr.trendmicro.com/ui/amc/redoc/index.html?from=v3.0#tag/Workbench/paths/~1v3.0~1workbench~1alerts/get).
- `Audit`: [Get entries from audit logs](https://portal.xdr.trendmicro.com/ui/amc/redoc/index.html?from=v3.0#tag/Audit-Logs).
- `Detection`: [Get detection data](https://portal.xdr.trendmicro.com/ui/amc/redoc/index.html?from=v3.0#tag/Search/paths/~1v3.0~1search~1detections/get).
- `Endpoint activity`: [Get endpoint activity data](https://portal.xdr.trendmicro.com/ui/amc/redoc/index.html?from=v3.0#tag/Search/paths/~1v3.0~1search~1endpointActivities/get).
- `Network activity`: [Get network activity data](https://portal.xdr.trendmicro.com/ui/amc/redoc/index.html?from=v3.0#tag/Search/paths/~1v3.0~1search~1networkActivities/get).
- `Telemetry`: [Datalake Pipeline](https://portal.xdr.trendmicro.com/ui/amc/redoc/index.html?from=v3.0#tag/Datalake-Pipeline).
