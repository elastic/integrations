# Cloudflare Logpush

- The [Cloudflare](https://www.cloudflare.com/) Integration collects and parses data received from Cloudflare via an AWS S3 bucket or directly to an Elastic Agent running the HTTP Endpoint.

## Compatibility

This package has been tested for Cloudflare version v4.

## Requirements

### Enabling the integration in Elastic
1. In Kibana, go to Management > Integrations
2. In the integrations search bar type **Cloudflare Logpush**.
3. Click the **Cloudflare Logpush** integration from the search results.
4. Click the **Add Cloudflare Logpush** button to add Cloudflare Logpush integration.
5. Enable the Integration with the HTTP Endpoint or AWS S3 Bucket input.
6. Configure Cloudflare to send logs to the Elastic Agent.

### In order to ingest data from the AWS S3 Bucket you must:
- Configure the [Data Forwarder](https://developers.cloudflare.com/logs/get-started/enable-destinations/aws-s3/) to ingest data into an AWS S3 bucket.
- Create an [AWS Access Keys and Secret Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys).

### In order to ingest data from the HTTP Endpoint:
- Reference link to [Enable HTTP destination](https://developers.cloudflare.com/logs/get-started/enable-destinations/http/) for Cloudflare Logpush.

>  Note: The default value of the "Number of Workers" is set to 5. This option is available under 'Collect Cloudflare Logpush logs via AWS S3' Advance options. Set the parameter "Number of Workers" according to the requirement.

## Logs

### Audit Logs

- Default port for HTTP Endpoint: _9560_

### DNS

- Default port for HTTP Endpoint: _9561_

### Firewall Event

- Default port for HTTP Endpoint: _9652_

### HTTP Request

- Default port for HTTP Endpoint: _9563_

### NEL Report

- Default port for HTTP Endpoint: _9564_

### Network Analytics

- Default port for HTTP Endpoint: _9565_

### Spectrum Event

- Default port for HTTP Endpoint: _9566_


## Fields and Sample Event

### Audit Logs

This is the `audit` data stream.

{{event "audit"}}

{{fields "audit"}}

### DNS

This is the `dns` data stream.

{{event "dns"}}

{{fields "dns"}}

### Firewall Event

This is the `firewall_event` data stream.

{{event "firewall_event"}}

{{fields "firewall_event"}}

### HTTP Request

This is the `http_request` data stream.

{{event "http_request"}}

{{fields "http_request"}}

### NEL Report

This is the `nel_report` data stream.

{{event "nel_report"}}

{{fields "nel_report"}}

### Network Analytics

This is the `network_analytics` data stream.

{{event "network_analytics"}}

{{fields "network_analytics"}}

### Spectrum Event

This is the `spectrum_event` data stream.

{{event "spectrum_event"}}

{{fields "spectrum_event"}}
