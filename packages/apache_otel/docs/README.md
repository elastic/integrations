# Apache metrics from OpenTelemetry Collector 

The Apache OTEL integration fetches metrics from [Apache](https://httpd.apache.org/) servers. 

Use the Apache OTEL integration to collect performance metrics from your Apache servers. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics when troubleshooting performance issues. Apache server exposes metrics through its [status module](http://httpd.apache.org/docs/current/mod/mod_status.html), `mod_status`. 


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

1. Compatibility and supported versions: This integration is compatible with systems running the upstream OpenTelemetry Collector and Apache server with the `mod_status` module enabled. This integration has been tested with OTEL collector version [v0.129.0](https://github.com/open-telemetry/opentelemetry-collector/tree/v0.129.0), and Apache version 2.4.59. 

2. Permissions required: The collector requires access to the Apache server-status endpoint (for example, http://localhost:80/server-status). When running the collector, make sure you have the appropriate permissions to access this endpoint. If that link doesn't work, you may need to enable mod_status in your Apache configuration file.

3. Apache configuration: You'll need to update the block (either in your status module's config file or main Apache config file) that starts with `<Location /server-status>` to specify which IP addresses should have access to the status page. In the example below, we are allowing access from localhost, as well as the IP address x.x.x.x.
```
<Location /server-status>
    SetHandler server-status
    Require local
    Require ip x.x.x.x
</Location>
```

4. Finding the Apache config: On Debian-based systems, the status module’s configuration file is typically located at `/etc/apache2/mods-enabled/status.conf`. On other UNIX-like platforms (such as Red Hat–based systems or macOS), you’ll usually find the main configuration file at one of the following paths: `/etc/apache2/apache2.conf`, `/etc/httpd/conf/httpd.conf`, or `/etc/apache2/httpd.conf`.

Within the main configuration file, locate the following line and make sure it is uncommented:

```
LoadModule status_module libexec/apache2/mod_status.so
```

## Setup

1. Make sure the `mod_status` module is enabled and the server-status endpoint is accessible.

2. Install and configure the EDOT Collector or upstream Collector to export metrics to Elasticsearch, as shown in the following example:

```
receivers:
  apache:
    endpoint: http://<hostname>/server-status
    collection_interval: 60s
exporters:
  debug:
    verbosity: detailed
  elasticsearch/otel:
    endpoint: https://localhost:9200
    mapping:
      mode: otel 
    metrics_dynamic_index:
      enabled: true
    auth:
      authenticator: basicauth
  
extensions:
  basicauth:
    client_auth:
      username: elastic
      password: xxxxx

service:
  extensions: [basicauth]
  pipelines:
    metrics:
      receivers: [apache]
      exporters: [debug, elasticsearch/otel]
```

Use this configuration to run the collector.

## Metrics reference

### Apache metrics

For a complete list of all available metrics and their detailed descriptions, refer to the [Apache Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/apachereceiver/documentation.md) in the upstream OpenTelemetry Collector repository.






