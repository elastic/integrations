# Proofpoint TAP

The Proofpoint TAP integration collects and parses data from the Proofpoint TAP REST APIs.

## Compatibility

This module has been tested against `SIEM API v2`.

## Configurations

The service principal and secret are used to authenticate to the SIEM API. To generate TAP Service Credentials please follow the following steps.  
1. Log in to the [_TAP dashboard_](https://threatinsight.proofpoint.com).  
2. Navigate to **Settings > Connected Applications**.  
3. Click **Create New Credential**.  
4. Name the new credential set and click **Generate**.  
5. Copy the **Service Principal** and **Secret** and save them for later use.  
For the more information on generating TAP credentials please follow the steps mentioned in the link [_Generate TAP Service Credentials_](https://ptr-docs.proofpoint.com/ptr-guides/integrations-files/ptr-tap/#generate-tap-service-credentials).


## Logs

### Clicks Blocked

This is the `clicks_blocked` dataset.

NOTE: For the `clicks_blocked` dataset, `source.ip` corresponds to the Proofpoint `senderIP` — the IP of the email sender — and `destination.ip` corresponds to `clickIP` — the IP of the click destination.

{{event "clicks_blocked"}}

{{fields "clicks_blocked"}}

### Clicks Permitted

This is the `clicks_permitted` dataset.

NOTE: For the `clicks_permitted` dataset, `source.ip` corresponds to the Proofpoint `senderIP` — the IP of the email sender — and `destination.ip` corresponds to `clickIP` — the IP of the click destination.

{{event "clicks_permitted"}}

{{fields "clicks_permitted"}}

### Message Blocked 

This is the `message_blocked` dataset.

{{event "message_blocked"}}

{{fields "message_blocked"}}

### Message Delivered 

This is the `message_delivered` dataset.

{{event "message_delivered"}}

{{fields "message_delivered"}}
