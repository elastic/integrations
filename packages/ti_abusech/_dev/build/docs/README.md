# AbuseCH integration

This integration is for [AbuseCH](https://urlhaus.abuse.ch/) logs. It includes the following datasets for retrieving indicators from the AbuseCH API:

- `url` dataset: Supports URL based indicators from AbuseCH API.
- `malware` dataset: Supports Malware based indicators from AbuseCH API.
- `malwarebazaar` dataset: Supports indicators from the MalwareBazaar from AbuseCH.
- `threatfox` dataset: Supports indicators from AbuseCH Threat Fox API.

## Expiration of Indicators of Compromise (IOCs)
All AbuseCH datasets now support indicator expiration. For `URL` dataset, a full list of active indicators are ingested every interval. For other datasets namely `Malware`, `MalwareBazaar`, and `ThreatFox`, the indicators are expired after duration `IOC Expiration Duration` configured in the integration setting. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to facilitate only active indicators be available to the end users. Each transform creates a destination index named `logs-ti_abusech_latest.dest_*` which only contains active and unexpired indicators. The indiator match rules and dashboards are updated to list only active indicators.
Destinations indices are aliased to `logs-ti_abusech_latest.<datastream_name>`.

| Source Datastream                  | Destination Index Pattern                        | Destination Alias                       |
|:-----------------------------------|:-------------------------------------------------|-----------------------------------------|
| `logs-ti_abusech.url-*`            | `logs-ti_abusech_latest.dest_url-*`              | `logs-ti_abusech_latest.url`            |
| `logs-ti_abusech.malware-*`        | `logs-ti_abusech_latest.dest_malware-*`          | `logs-ti_abusech_latest.malware`        |
| `logs-ti_abusech.malwarebazaar-*`  | `logs-ti_abusech_latest.dest_malwarebazaar-*`    | `logs-ti_abusech_latest.malwarebazaar`  |
| `logs-ti_abusech.threatfox-*`      | `logs-ti_abusech_latest.dest_threatfox-*`        | `logs-ti_abusech_latest.threatfox`      |

### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_abusech.<datastream_name>-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-ti_abusech.<datastream_name>-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

## Logs

### URL

The AbuseCH URL data_stream retrieves full list of active threat intelligence indicators every interval from the Active Indicators URL database dump `https://urlhaus.abuse.ch/downloads/json/`.

{{fields "url"}}

### Malware

The AbuseCH malware data_stream retrieves threat intelligence indicators from the payload API endpoint `https://urlhaus-api.abuse.ch/v1/payloads/recent/`.

{{fields "malware"}}

### MalwareBazaar

The AbuseCH malwarebazaar data_stream retrieves threat intelligence indicators from the MalwareBazaar API endpoint `https://mb-api.abuse.ch/api/v1/`.

{{fields "malwarebazaar"}}

### Threat Fox

The AbuseCH threatfox data_stream retrieves threat intelligence indicators from the Threat Fox API endpoint `https://threatfox-api.abuse.ch/api/v1/`.

{{fields "threatfox"}}