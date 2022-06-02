# Anomali Integration

The Anomali integration supports the following datasets.

- `limo` dataset: Support for Anomali Limo, a freely available Threat Intelligence service
- `threatstream` dataset: Support for Anomali ThreatStream, a commercial Threat Intelligence service.

## Logs

### Anomali Limo

Anomali Limo offers multiple sources called collections. Each collection has a specific ID, which
then fits into the url used in this configuration. A list of different
collections can be found using the default guest/guest credentials at [Limo Collections.](https://limo.anomali.com/api/v1/taxii2/feeds/collections/)

An example if you want to use the feed with ID 42, the URL to configure would end up like this:
`https://limo.anomali.com/api/v1/taxii2/feeds/collections/41/objects`

{{event "limo"}}

{{fields "limo"}}

### Anomali Threatstream

This integration requires additional software, the _Elastic_ _Extension,_
to connect the Anomali ThreatStream with this integration. It's available
at the [ThreatStream download page.](https://ui.threatstream.com/downloads)

Please refer to the documentation included with the Extension for a detailed
explanation on how to configure the Anomali ThreatStream to send indicator
to this integration.

{{event "threatstream"}}

{{fields "threatstream"}}
