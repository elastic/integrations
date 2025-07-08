# Netskope

This integration is for Netskope. It can be used to receive logs sent by [Netskope Cloud Log Shipper](https://docs.netskope.com/en/cloud-exchange-feature-lists.html#UUID-e7c43f4b-8aad-679e-eea0-59ce19f16e29_section-idm4547044691454432680066508785) and [Netskope Log Streaming](https://docs.netskope.com/en/log-streaming/). To receive log from Netskope Cloud Log Shipper use TCP input and for Netskope Log Streaming use any of the Cloud based input(AWS, GCS, Azure Blob Storage).

The log message is expected to be in JSON format. The data is mapped to
ECS fields where applicable and the remaining fields are written under
`netskope.<data-stream-name>.*`.

## Setup steps

### For receiving log from Netskope Cloud Shipper
1. Configure this integration with the TCP input in Kibana.
2. For all Netskope Cloud Exchange configurations refer to the [Log Shipper](https://docs.netskope.com/en/cloud-exchange-feature-lists.html#UUID-e7c43f4b-8aad-679e-eea0-59ce19f16e29_section-idm4547044691454432680066508785).
3. In Netskope Cloud Exchange please enable Log Shipper, add your Netskope Tenant.
4. Configure input connectors:
    1. First with all Event types, and
    2. Second with all Alerts type.
    For detailed steps refer to [Configure the Netskope Plugin for Log Shipper](https://docs.netskope.com/en/configure-the-netskope-plugin-for-log-shipper.html).
5. Configure output connectors:
    1. Navigate to Settings -> Plugins.
    2. Add separate output connector **Elastic CLS** for both Alerts and Events and select mapping **"Elastic Default Mappings (Recommended)"** for both.
6. Create business rules:
    1. Navigate to Home Page > Log Shipper > Business Rules.
    2. Create business rules with Netskope Alerts.
    3. Create business rules with Netskope Events.
    For detailed steps refer to [Manage Log Shipper Business Rules](https://docs.netskope.com/en/manage-log-shipper-business-rules.html).
7. Adding SIEM mappings:
    1. Navigate to Home Page > Log Shipper > SIEM Mappings
    2. Add SIEM mapping for events:
        * Add **Rule** put rule created in step 6.
        * Add **Source Configuration** put input created for Events in step 4.
        * Add **Destination Configuration**, put output created for Events in step 5.

> Note: For detailed steps refer to [Configure Log Shipper SIEM Mappings](https://docs.netskope.com/en/configure-log-shipper-siem-mappings.html).
Please make sure to use the given response formats.

### For receiving log from Netskope Log Streaming
1. To configure Log streaming please refer to the [Log Streaming Configuration](https://docs.netskope.com/en/configuring-streams). While Configuring make sure compression is set to GZIP as other compression type is not supported.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Netskope.
3. Select the "Netskope" integration from the search results.
4. Select the Add Netskope Integration button to add the integration.
5. While adding the integration, if you want to collect logs via AWS S3, you'll need to provide the following details:
   - Collect logs via S3 Bucket toggled on
   - Access Key ID
   - Secret Access Key
   - Bucket ARN
   - Session Token

   or if you want to collect logs via AWS SQS, you'll need to provide the following details:
   - Collect logs via S3 Bucket toggled off
   - Queue URL
   - Secret Access Key
   - Access Key ID

   or if you want to collect logs via GCS, you'll need to provide the following details:
   - Project ID
   - Buckets
   - Service Account Key/Service Account Credentials File

   or if you want to collect logs via Azure Blob Storage, you'll need to provide the following details:
   For OAuth2 (Microsoft Entra ID RBAC):
   - Toggle on **Collect logs using OAuth2 authentication**
   - Account Name
   - Client ID
   - Client Secret
   - Tenant ID
   - Container Details.

   For Service Account Credentials:
   - Service Account Key or the URI
   - Account Name
   - Container Details

   Or if you want to collect logs via TCP, you'll need to provide the following details:
   - Listen Address
   - Listen Port

## Compatibility

This package has been tested against `Netskope version 95.1.0.645` and `Netskope Cloud Exchange version 3.4.0`.

## Documentation and configuration

### Alerts

Default port: _9020_

### Events

Default port: _9021_

## Fields and Sample event

### Alerts

{{fields "alerts"}}

{{event "alerts"}}

### Alerts V2

{{fields "alerts_v2"}}

{{event "alerts_v2"}}

### Events

{{fields "events"}}

{{event "events"}}