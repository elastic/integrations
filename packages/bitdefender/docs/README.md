# BitDefender Integration

[BitDefender GravityZone](https://www.bitdefender.com/business/products/security-products.html) supports SIEM integration using "push notifications", which are JSON messages sent via HTTP POST to a HTTP or HTTPS endpoint, which this integration can consume.

This integration additionally provides:
1. Collection of push notification configuration via API polling, which includes the "state" of the push notification service on the BitDefender GravityZone server, e.g. indicating if it is currently enabled or disabled. This is useful as the state may change to disabled (value of 0) for unknown reasons and you may wish to alert on this event.
2. Collection of push notification statistics via API polling, which includes the number of events sent, and counters for errors of different types, which you may wish to use to troubleshoot lost push notification events and for alerting purposes.
3. Support for multiple instances of the integration, which may be needed for MSP/MSSP scenarios where multiple BitDefender GravityZone tenants exist.
4. BitDefender company ID to your own company name/description mapping, in order to determine to which tenant the event relates to in a human friendly way. This is very useful for MSP/MSSP environments or for large organisations with multiple sub-organisations.

This allows you to search, observe and visualize the BitDefender GravityZone events through Elastic, trigger alerts and monitor the BitDefender GravityZone Push Notification service for state and errors.

For more information about BitDefender GravityZone, refer to [BitDefender GravityZone](https://www.bitdefender.com/business/products/security-products.html) and read the  [Public API - Push](https://www.bitdefender.com/business/support/en/77209-135318-push.html) documentation.

## Compatibility

This integration supports BitDefender GravityZone, which is the business oriented product set sold by BitDefender.

BitDefender products for home users are not supported.

The package collects BitDefender GravityZone push notification transported events sent in "qradar" format or "splunk" format.

The "qradar" format appears to be plain Newline Delimited JSON and is the format this integration expects by default, however the ingest pipeline will attempt to detect if "splunk" format events have been received.

The integration can also collect the push notification configuration and statistics by polling the BitDefender GravityZone API.

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In "Search for integrations" search bar type **GravityZone**
3. Click on "BitDefender GravityZone" integration from the search results.
4. Click on **Add BitDefender GravityZone** button to add BitDefender GravityZone integration.

![Example Integration Configuration](../img/bitdefender-integration-configuration-1.png)

![Example Integration Configuration](../img/bitdefender-integration-configuration-2.png)


### Create a BitDefender GravityZone API key that can configure a push notification service

The vendor documentation is available [here](https://www.bitdefender.com/business/support/en/77211-125280-getting-started.html#UUID-e6befdd4-3eb1-4b6e-cc6c-19bdd16847b4_section-idm4640169987334432655171029621). However, at the time of writing this is out of date and the screenshots the vendor provides do not accurately describe what you will need to do.

The API key needed to configure push notifications, and collection push notification configuration state and statistics, is typically configured within the BitDefender GravityZone cloud portal [here](https://cloud.gravityzone.bitdefender.com/)

Bear in mind the API key will be associated to the account you create it from. A named human account may not be desirable, e.g. you may wish to  (probably should) create API keys for functions such as push notifications under a non-human/software service account that will never retire or be made redundant.

Navigate to your account details within the GravityZone portal. If you have sufficient privileges you will see the "API keys" section near the bottom of the page. Click "Add" here.

![Example Configuration 1](../img/bitdefender-gravityzone-api-key-1.png)

Give the API key a description and tick the "Event Push Service API" box at minimum.

NOTE: If you intend to use the API key for other API calls you may need to tick other boxes.

![Example Configuration 2](../img/bitdefender-gravityzone-api-key-2.png)

Click the Key value that is shown in blue.

![Example Configuration 3](../img/bitdefender-gravityzone-api-key-3.png)

Click the clipboard icon to copy the API key to your PC's clipboard.

![Example Configuration 4](../img/bitdefender-gravityzone-api-key-4.png)

### Creating the push notification configuration via BitDefender GravityZone API

The BitDefender documentation for how to do this is [here](https://www.bitdefender.com/business/support/en/77209-135319-setpusheventsettings.html)

You should use the "qradar" format option.

**NOTE**: The `jsonrpc` format that BitDefender's documentation presents as the default and best option, should **NOT** be used, due to limitations in the filebeat "http_endpoint" input and available processors at this point. The [`http_endpoint` input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-http_endpoint.html) can only collect events if the incoming body is either an object or an array of objects at the root. But as `jsonrpc` format sends the array of events bundled inside `params.events` JSON key, the input is currently unable to collect them.

An example using cURL, as the official documentation is unclear at times what to do and how to do it.

```
curl --location --request POST 'https://cloud.gravityzone.bitdefender.com/api/v1.0/jsonrpc/push' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'Authorization: Basic TE9MX05JQ0VfVFJZOgo=' \
--data-raw '{
  "id": 1,
  "jsonrpc": "2.0",
  "method": "setPushEventSettings",
  "params": {
    "status": 1,
    "serviceType": "qradar",
    "serviceSettings": {
      "authorization": "secret value",
      "requireValidSslCertificate": true,
      "url": "https://your.webhook.receiver.domain.tld/bitdefender/push/notification"
    },
    "subscribeToCompanies": [
      "COMPANY IDS HERE IF YOU HAVE A MULTI TENANT ENVIRONMENT",
      "AND YOU WANT TO LIMIT THE SUBSCRIPTION TO ONLY SOME COMPANIES",
      "OTHERWISE DELETE THE ENTIRE subscribeToCompanies NODE TO GET EVERYTHING"
    ],
    "subscribeToEventTypes": {
      "adcloud": true,
      "antiexploit": true,
      "aph": true,
      "av": true,
      "avc": true,
      "dp": true,
      "endpoint-moved-in": true,
      "endpoint-moved-out": true,
      "exchange-malware": true,
      "exchange-user-credentials": true,
      "fw": true,
      "hd": true,
      "hwid-change": true,
      "install": true,
      "modules": true,
      "network-monitor": true,
      "network-sandboxing": true,
      "new-incident": true,
      "ransomware-mitigation": true,
      "registration": true,
      "security-container-update-available": true,
      "supa-update-status": true,
      "sva": true,
      "sva-load": true,
      "task-status": true,
      "troubleshooting-activity": true,
      "uc": true,
      "uninstall": true
    }
  }
}'
```

## Dashboards

There are two dashboards available as part of the integration,

"[BitDefender GravityZone] Push Notifications", which provides a summary of push notifications received within the search window.

![Push Notifications Dashboard](./img/bitdefender-dashboard-push-notifications.png)

"[BitDefender GravityZone] Configuration State & Statistics", which provides graphs and other visualisations related push notification service state and statistics available within the search window.

![Configuration State & Statistics Dashboard](./img/bitdefender-dashboard-push-config-and-stats.png)

## Data Stream

### Log Stream Push Notifications

The BitDefender GravityZone events dataset provides events from BitDefender GravityZone push notifications that have been received.

All BitDefender GravityZone log events are available in the `bitdefender_gravityzone.events` field group.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| bitdefender.event._testEvent_ |  | boolean |
| bitdefender.event.actionTaken |  | keyword |
| bitdefender.event.aph_status |  | integer |
| bitdefender.event.aph_type |  | keyword |
| bitdefender.event.att_ck_id |  | keyword |
| bitdefender.event.attack_entry |  | keyword |
| bitdefender.event.attack_source |  | keyword |
| bitdefender.event.attack_type |  | keyword |
| bitdefender.event.attack_types |  | keyword |
| bitdefender.event.avc_status |  | integer |
| bitdefender.event.block_type |  | keyword |
| bitdefender.event.blocking_rule_name |  | keyword |
| bitdefender.event.categories |  | keyword |
| bitdefender.event.companyId |  | keyword |
| bitdefender.event.company_name |  | keyword |
| bitdefender.event.computerIp |  | keyword |
| bitdefender.event.computerName |  | keyword |
| bitdefender.event.computer_fqdn |  | keyword |
| bitdefender.event.computer_id |  | keyword |
| bitdefender.event.computer_ip |  | keyword |
| bitdefender.event.computer_name |  | keyword |
| bitdefender.event.count |  | long |
| bitdefender.event.cpuUsage |  | float |
| bitdefender.event.created |  | date |
| bitdefender.event.date |  | keyword |
| bitdefender.event.detected_on |  | date |
| bitdefender.event.detectionTime |  | date |
| bitdefender.event.detection_action |  | keyword |
| bitdefender.event.detection_attackTechnique |  | keyword |
| bitdefender.event.detection_cve |  | keyword |
| bitdefender.event.detection_exploitTechnique |  | keyword |
| bitdefender.event.detection_level |  | keyword |
| bitdefender.event.detection_name |  | keyword |
| bitdefender.event.detection_parentPath |  | keyword |
| bitdefender.event.detection_parentPid |  | keyword |
| bitdefender.event.detection_path |  | keyword |
| bitdefender.event.detection_pid |  | keyword |
| bitdefender.event.detection_threatName |  | keyword |
| bitdefender.event.detection_time |  | date |
| bitdefender.event.detection_username |  | keyword |
| bitdefender.event.dlp_status |  | integer |
| bitdefender.event.dp_status |  | integer |
| bitdefender.event.endDate |  | date |
| bitdefender.event.endpointId |  | keyword |
| bitdefender.event.errorCode |  | integer |
| bitdefender.event.errorMessage |  | keyword |
| bitdefender.event.exploit_path |  | keyword |
| bitdefender.event.exploit_type |  | keyword |
| bitdefender.event.failedStorageType |  | integer |
| bitdefender.event.filePaths |  | keyword |
| bitdefender.event.fileSizes |  | keyword |
| bitdefender.event.file_hash_md5 |  | keyword |
| bitdefender.event.file_hash_sha256 |  | keyword |
| bitdefender.event.file_path |  | keyword |
| bitdefender.event.final_status |  | keyword |
| bitdefender.event.firewall_status |  | integer |
| bitdefender.event.fromSupa |  | integer |
| bitdefender.event.hash |  | keyword |
| bitdefender.event.host_name |  | keyword |
| bitdefender.event.hwid |  | keyword |
| bitdefender.event.id |  | long |
| bitdefender.event.incident_id |  | keyword |
| bitdefender.event.isSuccessful |  | integer |
| bitdefender.event.is_container_host |  | integer |
| bitdefender.event.is_fileless_attack |  | integer |
| bitdefender.event.issueType |  | long |
| bitdefender.event.item_count |  | keyword |
| bitdefender.event.jsonrpc.method |  | keyword |
| bitdefender.event.jsonrpc.version |  | keyword |
| bitdefender.event.lastAdReportDate |  | keyword |
| bitdefender.event.last_blocked |  | keyword |
| bitdefender.event.lastupdate |  | keyword |
| bitdefender.event.loadAverage |  | float |
| bitdefender.event.localPath |  | keyword |
| bitdefender.event.local_port |  | keyword |
| bitdefender.event.main_action |  | keyword |
| bitdefender.event.malware.actionTaken |  | keyword |
| bitdefender.event.malware.infectedObject |  | keyword |
| bitdefender.event.malware.malwareName |  | keyword |
| bitdefender.event.malware.malwareType |  | keyword |
| bitdefender.event.malware_name |  | keyword |
| bitdefender.event.malware_status |  | integer |
| bitdefender.event.malware_type |  | keyword |
| bitdefender.event.memoryUsage |  | float |
| bitdefender.event.module |  | keyword |
| bitdefender.event.networkSharePath |  | keyword |
| bitdefender.event.networkUsage |  | float |
| bitdefender.event.network_monitor_status |  | long |
| bitdefender.event.new_hwid |  | keyword |
| bitdefender.event.oldData.features.enabled |  | boolean |
| bitdefender.event.oldData.features.id |  | keyword |
| bitdefender.event.oldData.features.isFunctioning |  | boolean |
| bitdefender.event.oldData.features.registrationStatus |  | keyword |
| bitdefender.event.old_hwid |  | keyword |
| bitdefender.event.overallUsage |  | float |
| bitdefender.event.parent_process_path |  | keyword |
| bitdefender.event.parent_process_pid |  | long |
| bitdefender.event.port |  | long |
| bitdefender.event.powered_off |  | integer |
| bitdefender.event.process_command_line |  | keyword |
| bitdefender.event.process_path |  | keyword |
| bitdefender.event.process_pid |  | long |
| bitdefender.event.product_installed |  | keyword |
| bitdefender.event.product_reboot_required |  | integer |
| bitdefender.event.product_registration |  | keyword |
| bitdefender.event.product_update_available |  | integer |
| bitdefender.event.protocol_id |  | keyword |
| bitdefender.event.pu_status |  | integer |
| bitdefender.event.reason |  | integer |
| bitdefender.event.recipients |  | keyword |
| bitdefender.event.remediationActions |  | keyword |
| bitdefender.event.saveToBitdefenderCloud |  | integer |
| bitdefender.event.scanEngineType |  | integer |
| bitdefender.event.sender |  | keyword |
| bitdefender.event.serverName |  | keyword |
| bitdefender.event.severity |  | keyword |
| bitdefender.event.severityScore |  | integer |
| bitdefender.event.severity_score |  | integer |
| bitdefender.event.signature_update |  | date |
| bitdefender.event.signaturesNumber |  | keyword |
| bitdefender.event.source_ip |  | keyword |
| bitdefender.event.startDate |  | date |
| bitdefender.event.status |  | keyword |
| bitdefender.event.stopReason |  | integer |
| bitdefender.event.subject |  | keyword |
| bitdefender.event.syncerId |  | keyword |
| bitdefender.event.targetName |  | keyword |
| bitdefender.event.target_type |  | keyword |
| bitdefender.event.taskId |  | keyword |
| bitdefender.event.taskName |  | keyword |
| bitdefender.event.taskScanType |  | integer |
| bitdefender.event.taskType |  | keyword |
| bitdefender.event.threatType |  | keyword |
| bitdefender.event.timestamp |  | keyword |
| bitdefender.event.uc_application_status |  | integer |
| bitdefender.event.uc_categ_filtering |  | integer |
| bitdefender.event.uc_type |  | keyword |
| bitdefender.event.uc_web_filtering |  | integer |
| bitdefender.event.updatesigam |  | keyword |
| bitdefender.event.url |  | keyword |
| bitdefender.event.user.id |  | keyword |
| bitdefender.event.user.name |  | keyword |
| bitdefender.event.user.sid |  | keyword |
| bitdefender.event.user.userName |  | keyword |
| bitdefender.event.user.userSid |  | keyword |
| bitdefender.event.userId |  | keyword |
| bitdefender.event.user_sid |  | keyword |
| bitdefender.event.username |  | keyword |
| bitdefender.event.victim_ip |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| destination.nat.as.number |  | long |
| destination.nat.as.organization.name |  | keyword |
| destination.nat.geo.city_name |  | keyword |
| destination.nat.geo.continent_name |  | keyword |
| destination.nat.geo.country_iso_code |  | keyword |
| destination.nat.geo.country_name |  | keyword |
| destination.nat.geo.location |  | geo_point |
| destination.nat.geo.region_iso_code |  | keyword |
| destination.nat.geo.region_name |  | keyword |
| input.type |  | keyword |


An example event for `push_notifications` looks as following:

```json
{
    "@timestamp": "2023-01-27T07:27:33.785Z",
    "agent": {
        "ephemeral_id": "7e1d4d9d-44a4-4ac8-ab34-72e2763c9bf6",
        "id": "f0239f6f-245e-4d57-bada-68e5f564b259",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.1"
    },
    "bitdefender": {
        "event": {
            "_testEvent_": true,
            "companyId": "623c18fb12fb8700396d6375",
            "issueType": 0,
            "lastAdReportDate": "2017-09-14T08:03:49.671Z",
            "module": "adcloud",
            "syncerId": "59b7d9bfa849af3a1465b7e3"
        },
        "id": "test"
    },
    "data_stream": {
        "dataset": "bitdefender.push_notifications",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f0239f6f-245e-4d57-bada-68e5f564b259",
        "snapshot": false,
        "version": "8.5.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "bitdefender.push_notifications",
        "ingested": "2023-01-27T07:27:34Z",
        "kind": "event",
        "module": "adcloud",
        "original": "{\"_testEvent_\":true,\"companyId\":\"623c18fb12fb8700396d6375\",\"issueType\":0,\"lastAdReportDate\":\"2017-09-14T08:03:49.671Z\",\"module\":\"adcloud\",\"syncerId\":\"59b7d9bfa849af3a1465b7e3\"}",
        "provider": "Cloud AD Integration",
        "severity": 0,
        "timezone": "+00:00",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "organization": {
        "id": "623c18fb12fb8700396d6375",
        "name": "test_events"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded"
    ]
}

```

### Log Stream Push Notification Configuration

The BitDefender GravityZone push notification configuration dataset provides configuration state collected from the BitDefender GravityZone API.

This includes the status of the push notification configuration, which may be indicative of the push notification service being disabled. Alerting based on this may be desirable.

All BitDefender GravityZone push notification configuration states are available in the `bitdefender.push.configuration` field group.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| bitdefender.id |  | keyword |
| bitdefender.push.configuration.serviceSettings.requireValidSslCertificate |  | boolean |
| bitdefender.push.configuration.serviceSettings.url |  | keyword |
| bitdefender.push.configuration.serviceType |  | keyword |
| bitdefender.push.configuration.status |  | long |
| bitdefender.push.configuration.subscribeToCompanies |  | keyword |
| bitdefender.push.configuration.subscribeToEventTypes.adcloud |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.antiexploit |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.aph |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.av |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.avc |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.dp |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.endpoint-moved-in |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.endpoint-moved-out |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.exchange-malware |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.exchange-user-credentials |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.fw |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.hd |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.hwid-change |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.install |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.modules |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.network-monitor |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.network-sandboxing |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.new-incident |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.ransomware-mitigation |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.registration |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.security-container-update-available |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.supa-update-status |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.sva |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.sva-load |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.task-status |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.troubleshooting-activity |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.uc |  | boolean |
| bitdefender.push.configuration.subscribeToEventTypes.uninstall |  | boolean |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| input.type |  | keyword |


An example event for `push_configuration` looks as following:

```json
{
    "@timestamp": "2024-07-15T09:30:33.869Z",
    "agent": {
        "ephemeral_id": "d1d677fd-e585-4395-a4ee-8c3c2670cb99",
        "id": "b2122e94-e7cd-4274-9c2e-856609628a36",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.3"
    },
    "bitdefender": {
        "id": "1",
        "push": {
            "configuration": {
                "serviceSettings": {
                    "requireValidSslCertificate": true,
                    "url": "https://your.elastic.agent/bitdefender/push/notification"
                },
                "serviceType": "qradar",
                "status": 1,
                "subscribeToEventTypes": {
                    "adcloud": true,
                    "antiexploit": true,
                    "aph": true,
                    "av": true,
                    "avc": true,
                    "dp": true,
                    "endpoint-moved-in": true,
                    "endpoint-moved-out": true,
                    "exchange-malware": true,
                    "exchange-user-credentials": true,
                    "fw": true,
                    "hd": true,
                    "hwid-change": true,
                    "install": true,
                    "modules": true,
                    "network-monitor": true,
                    "network-sandboxing": true,
                    "new-incident": true,
                    "ransomware-mitigation": true,
                    "registration": true,
                    "security-container-update-available": true,
                    "supa-update-status": true,
                    "sva": true,
                    "sva-load": true,
                    "task-status": true,
                    "troubleshooting-activity": true,
                    "uc": true,
                    "uninstall": true
                }
            }
        }
    },
    "data_stream": {
        "dataset": "bitdefender.push_configuration",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "b2122e94-e7cd-4274-9c2e-856609628a36",
        "snapshot": false,
        "version": "8.14.3"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2024-07-15T09:30:33.869Z",
        "dataset": "bitdefender.push_configuration",
        "ingested": "2024-07-15T09:30:45Z",
        "original": "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"serviceSettings\":{\"requireValidSslCertificate\":true,\"url\":\"https://your.elastic.agent/bitdefender/push/notification\"},\"serviceType\":\"qradar\",\"status\":1,\"subscribeToEventTypes\":{\"adcloud\":true,\"antiexploit\":true,\"aph\":true,\"av\":true,\"avc\":true,\"dp\":true,\"endpoint-moved-in\":true,\"endpoint-moved-out\":true,\"exchange-malware\":true,\"exchange-user-credentials\":true,\"fw\":true,\"hd\":true,\"hwid-change\":true,\"install\":true,\"modules\":true,\"network-monitor\":true,\"network-sandboxing\":true,\"new-incident\":true,\"ransomware-mitigation\":true,\"registration\":true,\"security-container-update-available\":true,\"supa-update-status\":true,\"sva\":true,\"sva-load\":true,\"task-status\":true,\"troubleshooting-activity\":true,\"uc\":true,\"uninstall\":true}}}"
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded"
    ]
}
```

### Log Stream Push Notification Statistics

The BitDefender GravityZone push notification statistics dataset provides statistics collected from the BitDefender GravityZone API.

This includes information about errors and HTTP response codes that the push notification service has received when sending push notifications, which may be indicative of failures to deliver push notifications resulting in missing events. Alerting based on this may be desirable.

All BitDefender GravityZone push notification statistics are available in the `bitdefender.push.stats` field group.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| bitdefender.id |  | keyword |
| bitdefender.push.stats.count.errorMessages |  | long |
| bitdefender.push.stats.count.events |  | long |
| bitdefender.push.stats.count.sentMessages |  | long |
| bitdefender.push.stats.count.testEvents |  | long |
| bitdefender.push.stats.error.configurationError |  | long |
| bitdefender.push.stats.error.connectionError |  | long |
| bitdefender.push.stats.error.serviceError |  | long |
| bitdefender.push.stats.error.statusCode2xx |  | long |
| bitdefender.push.stats.error.statusCode300 |  | long |
| bitdefender.push.stats.error.statusCode400 |  | long |
| bitdefender.push.stats.error.statusCode500 |  | long |
| bitdefender.push.stats.error.timeout |  | long |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| input.type |  | keyword |


An example event for `push_statistics` looks as following:

```json
{
    "@timestamp": "2023-01-27T07:28:05.023Z",
    "agent": {
        "ephemeral_id": "7e1d4d9d-44a4-4ac8-ab34-72e2763c9bf6",
        "id": "f0239f6f-245e-4d57-bada-68e5f564b259",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.1"
    },
    "bitdefender": {
        "id": "test",
        "push": {
            "stats": {
                "count": {
                    "errorMessages": 121,
                    "events": 1415824,
                    "sentMessages": 78368,
                    "testEvents": 0
                },
                "error": {
                    "configurationError": 0,
                    "connectionError": 7,
                    "serviceError": 114,
                    "statusCode2xx": 0,
                    "statusCode300": 0,
                    "statusCode400": 0,
                    "statusCode500": 0,
                    "timeout": 0
                }
            }
        }
    },
    "data_stream": {
        "dataset": "bitdefender.push_statistics",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f0239f6f-245e-4d57-bada-68e5f564b259",
        "snapshot": false,
        "version": "8.5.1"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-01-27T07:28:05.023Z",
        "dataset": "bitdefender.push_statistics",
        "ingested": "2023-01-27T07:28:06Z",
        "original": "{\"id\":\"test\",\"jsonrpc\":\"2.0\",\"result\":{\"count\":{\"errorMessages\":121,\"events\":1415824,\"sentMessages\":78368,\"testEvents\":0},\"error\":{\"configurationError\":0,\"connectionError\":7,\"serviceError\":114,\"statusCode2xx\":0,\"statusCode300\":0,\"statusCode400\":0,\"statusCode500\":0,\"timeout\":0},\"lastUpdateTime\":\"2023-01-27T09:19:22\"}}"
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded"
    ]
}

```
