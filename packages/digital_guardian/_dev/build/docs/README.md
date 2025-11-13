# Digital Guardian

This integration is for ingesting events and alerts from [Fortra's Digital Guardian](https://www.digitalguardian.com/). Fortra’s Digital Guardian helps organizations protect data, performing across the corporate network, traditional endpoints, and cloud applications. Digital Guardian's data loss prevention, available as a software-as-a-service or managed service, helps to see that data, support compliance initiatives, and protect against serious risk. 

The integration allows collection of events and alerts from [Digital Guardian Analytics & Reporting Cloud (ARC)](https://www.digitalguardian.com/blog/new-dawn-dlp-digital-guardian-releases-its-analytics-reporting-cloud-arc) via the REST API.

## Data streams

The Digital Guardian integration collects events to populate the following data stream:

- **digital_guardian.arc**: Collects all events and alerts from `Digital Guardian Analytics & Reporting Cloud (ARC)` via the REST API.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Copy the required configuration properties for Digital Guardian ARC 

1. Copy `Client ID`: From ARC Tenant Settings, copy the Tenant ID.
2. Copy `Client Secret`: From ARC Tenant Settings, copy the Authentication Token.
3. Copy `ARC Server URL`: From Digital Guardian Management Console (DGMC), copy the Access Gateway Base URL.
4. Copy `Authorization Server URL`: From Digital Guardian Management Console (DGMC), copy the Authorization server URL.
5. Copy `ARC Export Profile ID`: 
    - Navigate to `Admin > reports > export profiles`
    - Copy only the GUID part from the export profile.

### Enable the Digital Guardian integration in Elastic with ARC dataset

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Digital Guardian**.
3. Select the **Digital Guardian** integration and add it.
4. Configure the following parameters:
        - `Client ID`
        - `Client Secret`
        - `ARC Server URL`
        - `Authorization Server URL`
        - `ARC Export Profile ID`
5. Save the integration.

## Logs reference

### arc

This is the `arc` dataset.

The `@timestamp` field will be assigned one of several values, in the following order of precedence:
1. `digital_guardian.arc.dg_time`
2. `digital_guardian.arc.dg_processed_time`
3. `digital_guardian.arc.inc_mtime`
4. The time received by the pipeline (if none of the above are available).

#### Example

{{event "arc"}}

{{fields "arc"}}
