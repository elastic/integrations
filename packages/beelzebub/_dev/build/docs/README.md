# Beelzebub Integration

Beelzebub is an advanced honeypot framework designed to provide a highly secure environment for detecting and analysing cyber attacks. It offers a low code approach for easy implementation and uses AI LLM's to mimic the behaviour of a high-interaction honeypot.

Beelzebub is available on GitHub via [https://github.com/mariocandela/beelzebub](https://github.com/mariocandela/beelzebub) or via [https://beelzebub-honeypot.com](https://beelzebub-honeypot.com)

This integration provides multiple ingest source options including log files and via HTTP POST.

This allows you to search, observe and visualize the Beelzebub logs through Elasticsearch and Kibana.

This integration was last tested with Beelzebub `v3.3.6`.

Please note that Beelzebub only produces NDJSON log files at this time, to ship logs to this integration via any other method you will require another component, such as [fluentd](https://www.fluentd.org/), to perform this.

For more information, refer to:
1. [GitHub](https://github.com/mariocandela/beelzebub)
2. [Official Beelzebub Project Website](https://beelzebub-honeypot.com)

## Compatability

The package collects log events from file or by receiving HTTP POST requests.

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. Ensure "Display beta integrations" is enabled beneath the category list to the left
3. In "Search for integrations" search bar type **Beelzebub**
4. Click on "Beelzebub" integration from the search results.
5. Click on **Add Beelzebub** button to add the Beelzebub integration.
6. Configure the integration as appropriate

### Configure the Beelzebub integration

1. Choose your ingest method, e.g. file or HTTP. If using HTTP you can enable HTTPS transport by providing an SSL certificate and private key.
2. Choose to store the original event content in `event.original`, or not.
3. Choose to redact passwords, or not.
4. Configure advanced options if desired.

### Configure Beelzebub logging

Example `beelzebub.yaml` configuration.
```
core:
  logging:
    debug: false
    debugReportCaller: false
    logDisableTimestamp: false
    logsPath: ./logs/beelzebub.log
  tracings:
    rabbit-mq:
      enabled: false
      uri: ""
  prometheus:
    path: "/metrics"
    port: ":2112"
  beelzebub-cloud:
    enabled: false
    uri: ""
    auth-token: ""
```

Example `fluentd.conf` to transport logs from local beelzebub.log file via HTTP to an Elastic Agent http_endpoint.

```
# fluentd.conf

<source>
  @type tail
  path /beelzebub/logs/beelzebub.log
  pos_file /fluentd/tmp/beelzebub.pos
  tag app.honeypot
  <parse>
    @type none
  </parse>
</source>

<match app.honeypot>
  @type copy

  # OPTIONAL: copy logs to S3 and/or any other output as required via multiple <store></store> definitions.

  <store>
    @type http
    endpoint "#{ENV['HTTP_URL']}"
    <auth>
      method basic
      username "#{ENV['HTTP_USERNAME']}"
      password "#{ENV['HTTP_PASSWORD']}"
    </auth>
    open_timeout 2
    content_type "application/json"
    <format>
      @type single_value
    </format>
    <buffer>
      flush_interval 10s
    </buffer>
  </store>
</match>

# EOF
```

## Logs

The Beelzebub logs dataset provides logs from Beelzebub instances.

All Beelzebub logs are available in the `beelzebub.logs` field group.

{{fields "logs"}}

{{event "logs"}}

