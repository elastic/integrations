# Beelzebub Integration

Beelzebub is an advanced honeypot framework designed to provide a highly secure environment for detecting and analyzing cyber attacks. It offers a low code approach for easy implementation and uses AI LLM's to mimic the behavior of a high-interaction honeypot.

Beelzebub is available on GitHub via [https://github.com/mariocandela/beelzebub](https://github.com/mariocandela/beelzebub) or via [https://beelzebub-honeypot.com](https://beelzebub-honeypot.com)

This integration provides multiple ingest source options including log files, HTTP and from S3 or S3-like storage buckets.

This allows you to search, observe and visualize the Beelzebub logs through Elasticsearch and Kibana.

This integration was last tested with Beelzebub `v3.3.6`.

Please note that Beelzebub only produces NDJSON log files at this time, to ship logs to this integration via HTTP or S3 you will require another component, such as [fluentd](https://www.fluentd.org/), to perform this.

For more information, refer to:
1. [GitHub](https://github.com/mariocandela/beelzebub)
2. [Official Beelzebub Project Website](https://beelzebub-honeypot.com)

## Compatability

The package collects log events from file, via HTTP and from S3 or S3-like storage buckets.

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. Ensure "Display beta integrations" is enabled beneath the category list to the left
3. In "Search for integrations" search bar type **Beelzebub**
4. Click on "Beelzebub" integration from the search results.
5. Click on **Add Beelzebub** button to add the Beelzebub integration.
6. Configure the integration as appropriate

### Configure the Beelzebub integration

1. Choose your ingest method, e.g. file, HTTP or S3/S3-like bucket. If using HTTP you can enable HTTPS transport by providing an SSL certificate and private key.
2. Choose to store the original event content in `event.original`, or not.
3. Choose to retain the original fields that have been mapped to ECS fields, or not. 

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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| beelzebub.banner |  | keyword |
| beelzebub.commands |  | unsigned_long |
| beelzebub.event.Body | HTTP request body | text |
| beelzebub.event.Client | Client identifier, e.g. SSH client ID and version | keyword |
| beelzebub.event.Command | Command issued by client | keyword |
| beelzebub.event.CommandOutput | Command response returned to client | text |
| beelzebub.event.DateTime | Date log message created | date |
| beelzebub.event.Description | Description of event | keyword |
| beelzebub.event.Environ | Environment variables | keyword |
| beelzebub.event.HTTPMethod | HTTP request method | keyword |
| beelzebub.event.Headers.\* | HTTP request headers | keyword |
| beelzebub.event.HostHTTPRequest | HTTP host name | keyword |
| beelzebub.event.ID | Unique ID for event | keyword |
| beelzebub.event.Msg | Beelzebub described message | keyword |
| beelzebub.event.Password | Password sent by client | keyword |
| beelzebub.event.Protocol | Protocol used to connect to honeypot | keyword |
| beelzebub.event.RemoteAddr | Remote IP:port pair that the client connection originates from | keyword |
| beelzebub.event.RequestURI | HTTP request URI | keyword |
| beelzebub.event.SourceIp | Remote IP that the client connection originates from | keyword |
| beelzebub.event.SourcePort | Remote port the client connection originates from | keyword |
| beelzebub.event.Status | Beelzebub described status | keyword |
| beelzebub.event.User | Username sent by client | keyword |
| beelzebub.event.UserAgent | HTTP User-Agent header sent by the client | keyword |
| beelzebub.level |  | keyword |
| beelzebub.msg |  | keyword |
| beelzebub.port |  | keyword |
| beelzebub.status |  | keyword |
| beelzebub.time | The time the log event occurred | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.offset | Log offset | long |
| log.source.address | Source for network originated events | keyword |
| user_agent.device.type |  | keyword |


An example event for `logs` looks as following:

```json
{
    "@timestamp": "2025-02-13T01:08:26.000Z",
    "agent": {
        "ephemeral_id": "7e2a993e-c6c2-4778-b8ee-45ceaa0d85cb",
        "id": "30ca00a7-05d6-487c-877f-6e356ec4ba85",
        "name": "elastic-agent-24661",
        "type": "filebeat",
        "version": "8.17.2"
    },
    "beelzebub": {
        "event": {
            "Client": "SSH-2.0-dropbear",
            "DateTime": "2025-02-13T01:08:26Z",
            "Description": "SSH interactive ChatGPT",
            "ID": "1974e109-d6f8-4bb1-934c-180a163e1cb8",
            "Msg": "New SSH attempt",
            "Password": "test",
            "Protocol": "SSH",
            "RemoteAddr": "103.100.225.133:60748",
            "SourceIp": "103.100.225.133",
            "SourcePort": "60748",
            "Status": "Stateless",
            "User": "root"
        },
        "level": "info",
        "msg": "New Event",
        "status": "Stateless",
        "time": "2025-02-13T01:08:26Z"
    },
    "data_stream": {
        "dataset": "beelzebub.logs",
        "namespace": "40452",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "30ca00a7-05d6-487c-877f-6e356ec4ba85",
        "snapshot": false,
        "version": "8.17.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "beelzebub.logs",
        "id": "1974e109-d6f8-4bb1-934c-180a163e1cb8",
        "ingested": "2025-02-15T07:13:30Z",
        "kind": "event",
        "original": "{\"event\":{\"DateTime\":\"2025-02-13T01:08:26Z\",\"RemoteAddr\":\"103.100.225.133:60748\",\"Protocol\":\"SSH\",\"Command\":\"\",\"CommandOutput\":\"\",\"Status\":\"Stateless\",\"Msg\":\"New SSH attempt\",\"ID\":\"1974e109-d6f8-4bb1-934c-180a163e1cb8\",\"Environ\":\"\",\"User\":\"root\",\"Password\":\"test\",\"Client\":\"SSH-2.0-dropbear\",\"Headers\":\"\",\"Cookies\":\"\",\"UserAgent\":\"\",\"HostHTTPRequest\":\"\",\"Body\":\"\",\"HTTPMethod\":\"\",\"RequestURI\":\"\",\"Description\":\"SSH interactive ChatGPT\",\"SourceIp\":\"103.100.225.133\",\"SourcePort\":\"60748\"},\"level\":\"info\",\"msg\":\"New Event\",\"status\":\"Stateless\",\"time\":\"2025-02-13T01:08:26Z\"}",
        "reason": "New SSH attempt",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "44",
            "inode": "100",
            "path": "/tmp/service_logs/beelzebub-logs-ndjson.log"
        },
        "offset": 0
    },
    "source": {
        "as": {
            "number": 64496,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Greenwich",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.47687,
                "lon": -0.00041
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "103.100.225.133",
        "port": 60748
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded"
    ],
    "user_agent": {
        "device": {
            "name": "Other",
            "type": "Other"
        },
        "name": "Other"
    }
}
```

