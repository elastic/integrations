# Jolokia input

This input package collects metrics from  [Jolokia agents](https://jolokia.org/agent.html) running on a target JMX server or dedicated proxy server.

The metrics are collected by communicating with a Jolokia HTTP/REST endpoint that exposes the JMX metrics over HTTP/REST/JSON.

The user can use this input for any service that collects metrics through Jolokia endpoint. User has the flexibility to provide custom mappings and custom ingets pipelines through the Kibana UI to get the tailored data. 

## Collect metrics from a Jolokia endpoint

## Configuration options

### Hosts
- To collect metrics from a Jolokia endpoint, configure the hosts setting to point to your Jolokia agent.
example:
- `http://host_address:jolokia_port`

### Period
- Defines the interval at which metrics are fetched.
- e.g. every `1s`, `1m`, `1h`.

### Path
- Specifies the endpoint path of the Jolokia service, including any optional query parameters.
- Default: `/jolokia`
- Example with query parameters:: `/jolokia/?ignoreErrors=true&canonicalNaming=false`

### HTTP Method
- Specifies the HTTP method used to communicate with the Jolokia endpoint.
- Supported values: `GET`, `POST`

### Authentication and SSL Configuration
- To securely communicate with HTTPS-enabled Jolokia endpoints, we can configure `SSL settings` to match requirements.
Example:
```yaml
ssl.verification_mode: full               # Options: none, certificate, full
ssl.certificate_authorities:
  - /etc/ssl/certs/ca.crt                 # Path to trusted CA file(s)
ssl.certificate: /etc/ssl/certs/client.crt  # Client certificate for mTLS
ssl.key: /etc/ssl/private/client.key        # Private key for the client certificate
ssl.key_passphrase: your_key_passphrase     # Optional: if the private key is encrypted
ssl.ca_trusted_fingerprint: "AB:CD:EF:..."  # Optional: pin to a trusted CA fingerprint
bearer_token_file: /path/to/token.txt       # Optional: for token-based auth
username: your_username                     # Optional: for basic auth
password: your_password                     # Optional: for basic auth

```
- `username / password` used for Basic authentication (if required by Jolokia).


### JMX Mappings and attributes
- The Jolokia Input package can collect metrics from various JMX MBeans by configuring the mbean parameter. You can specify which MBeans and attributes to collect using the following format:

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

## Compatibility

The Jolokia module is tested with Jolokia 2.2.9.
