# MISP Integration

The MISP integration uses the [REST API from the running MISP instance](https://www.circl.lu/doc/misp/automation/#automation-api) to retrieve indicators and Threat Intelligence.

## Logs

### Threat

The MISP integration configuration allows to set the polling interval, how far back it
should look initially, and optionally any filters used to filter the results.

The filters themselves are based on the [MISP API documentation](https://www.circl.lu/doc/misp/automation/#search) and should support all documented fields.

{{fields "threat"}}

{{event "threat"}}

### Threat Attributes

The MISP integration configuration allows to set the polling interval, how far back it should look initially, and optionally any filters used to filter the results.
This data stream uses the `/attributes/restSearch` API endpoint which returns more granular information regarding MISP attributes and additional information.

{{fields "threat_attributes"}}

