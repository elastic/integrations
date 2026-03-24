# Jolokia input

The Jolokia input package collects metrics from [Jolokia agents](https://jolokia.org/agent.html) running on a target JMX server or dedicated proxy server.

The metrics are collected by communicating with a Jolokia HTTP/REST endpoint that exposes the JMX metrics over HTTP/REST/JSON.

You can use this input for any service that collects metrics through Jolokia endpoint. Optionally, you can provide custom mappings and custom ingest pipelines through the Kibana UI to get the tailored data.

## Compatibility

The Jolokia module is tested with Jolokia 2.2.9.

## Configuration

### Hosts
To collect metrics from a Jolokia endpoint, configure the hosts setting to point to your Jolokia agent.
For example:
`http://host_address:jolokia_port`

### Period
Defines the interval at which metrics are fetched.
For example, every `1s`, `1m`, `1h`.

### Path
Specifies the endpoint path of the Jolokia service, including any optional query parameters.
- Default: `/jolokia`
- Example with query parameters:: `/jolokia/?ignoreErrors=true&canonicalNaming=false`

### HTTP Method
Specifies the HTTP method used to communicate with the Jolokia endpoint.
- Supported values: `GET`, `POST`

### Authentication and SSL Configuration
To securely communicate with HTTPS-enabled Jolokia endpoints, you can configure `SSL settings` to meet the necessary requirements. For example:

```yaml
ssl.verification_mode: full
ssl.certificate_authorities:
  - /etc/ssl/certs/ca.crt
ssl.certificate: /etc/ssl/certs/client.crt
ssl.key: /etc/ssl/private/client.key
ssl.key_passphrase: your_key_passphrase
ssl.ca_trusted_fingerprint: "AB:CD:EF:..."
bearer_token_file: /path/to/token.txt
username: your_username
password: your_password

```
- `username / password` used for Basic authentication (if required by Jolokia).


### JMX Mappings and attributes
The Jolokia input package can collect metrics from various JMX MBeans by configuring the `mbean` parameter. You can specify which MBeans and attributes to collect as shown in the example below.

```
- mbean: 'java.lang:type=Runtime'
  attributes:
    - attr: Uptime
      field: uptime
- mbean: 'java.lang:type=Memory'
  attributes:
    - attr: HeapMemoryUsage
      field: memory.heap_usage
    - attr: NonHeapMemoryUsage
      field: memory.non_heap_usage
```
