# Anomali Integration

The Anomali integration supports the following datasets.

- `limo` dataset: Support for Anomali Limo, a freely available Threat Intelligence service
- `threatstream` dataset: Support for Anomali ThreatStream, a commercial Threat Intelligence service.

## Logs

### Anomali Limo

Anomali Limo offers multiple sources called collections. Each collection has a specific ID, which
then fits into the url used in this configuration. A list of different
collections can be found using the default guest/guest credentials at https://limo.anomali.com/api/v1/taxii2/feeds/collections/[Limo Collections].

An example if you want to use the feed with ID 42, the URL to configure would end up like this:
`https://limo.anomali.com/api/v1/taxii2/feeds/collections/41/objects`

{{event "limo"}}

{{fields "limo"}}

### Anomali Threatstream

To configure the ThreatStream integration you first need to define an output
in the Anomali ThreatStream Integrator using the Elastic SDK provided by Anomali.
It will deliver indicators via HTTP or HTTPS to a elastic-agent instance running this integration.

Configure an Integrator output with the following settings:

* Indicator Filter: `*` (or use any desired filter).
* SDK Executable Command: `/path/to/python /path/to/anomali-sdk/main.py`.
  Adjust the paths to the python executable and the directory where the Elastic SDK
  has been unpacked.
* Metadata in JSON Format: `{"url": "https://elastic-agent:8080/", "server_certificate": "/path/to/cert.pem", "secret": "my secret"}`.
    - `url`: Use the host and port where the integration will be running, and `http` or `https` accordingly.
    - `server_certificate`: If using HTTPS, absolute path to the server certificate. Otherwise don't set
        this field.
    - `secret`: A shared secret string to authenticate messages between the SDK and the integration.


{{event "threatstream"}}

{{fields "threatstream"}}