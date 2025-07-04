# Beelzebub Integration

Beelzebub is an advanced honeypot framework designed to provide a highly secure environment for detecting and analysing cyber attacks. It offers a low code approach for easy implementation and uses AI LLM's to mimic the behaviour of a high-interaction honeypot.

Beelzebub is available on GitHub via [https://github.com/mariocandela/beelzebub](https://github.com/mariocandela/beelzebub) or via [https://beelzebub-honeypot.com](https://beelzebub-honeypot.com)

This integration provides multiple ingest source options including log files and via HTTP POST.

This allows you to search, observe and visualize the Beelzebub logs through Elasticsearch and Kibana.

This integration was last tested with Beelzebub `v3.3.6`.

Please note that Beelzebub only produces NDJSON log files at this time, to ship logs to this integration via any other method you will require another component, such as [Logstash](https://www.elastic.co/logstash), which can perform this by reading the Beelzebub produced log files and transporting the content as it changes to an appropriately configured Elastic Agent input, an ingest location that can be utilised by an appropriately configured Elastic Agent, or directly into Elasticsearch.

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

### Example Beelzebub Logging Configuration

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

## Logs

The Beelzebub logs dataset provides logs from Beelzebub instances.

All Beelzebub logs are available in the `beelzebub.logs` field group.

{{fields "logs"}}

{{event "logs"}}

