# BitDefender Integration

## Overview

[BitDefender GravityZone](https://www.bitdefender.com/business/products/security-products.html) supports SIEM integration using "push notifications", which are JSON messages sent via HTTP POST to a HTTP or HTTPS endpoint, which this integration can consume.

This integration additionally provides:
1. Collection of push notification configuration via API polling, which includes the "state" of the push notification service on the BitDefender GravityZone server, e.g. indicating if it is currently enabled or disabled. This is useful as the state may change to disabled (value of 0) for unknown reasons and you may wish to alert on this event.
2. Collection of push notification statistics via API polling, which includes the number of events sent, and counters for errors of different types, which you may wish to use to troubleshoot lost push notification events and for alerting purposes.
3. Support for multiple instances of the integration, which may be needed for MSP/MSSP scenarios where multiple BitDefender GravityZone tenants exist.
4. BitDefender company ID to your own company name/description mapping, in order to determine to which tenant the event relates to in a human friendly way. This is very useful for MSP/MSSP environments or for large organisations with multiple sub-organisations.
5. GravityZone Public API polling for EDR/XDR incidents and individual incident alerts, and endpoint and account entity inventories.

This allows you to search, observe and visualize BitDefender GravityZone events, incidents, and entities through Elastic, trigger alerts, and monitor the BitDefender GravityZone Push Notification service for state and errors.

For more information about BitDefender GravityZone, refer to [BitDefender GravityZone](https://www.bitdefender.com/business/products/security-products.html) and refer to the [Public API - Push](https://www.bitdefender.com/business/support/en/77209-135318-push.html) documentation.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

### Compatibility

This integration supports BitDefender GravityZone, which is the business oriented product set sold by BitDefender.

BitDefender products for home users are not supported.

The package collects BitDefender GravityZone push notification transported events sent in `jsonrpc`, `qradar`, or `splunk` format.

The `jsonrpc` format is recommended default, but the ingest pipeline will attempt to detect if `qradar` or `splunk` format events have been received and process them accordingly.

The integration can also collect the push notification configuration and statistics and poll higher-level security incidents and entity inventories from the BitDefender GravityZone Public API.

Public API polling in this integration targets GravityZone Cloud. GravityZone On-Premises has a different API surface, authentication model, and service-specific paths and is not supported by the Public API polling data streams.

## How do I deploy this integration?

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**.
2. In "Search for integrations" search bar type **GravityZone**.
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

### Create an API key for Public API polling

The Public API polling data streams support either of these authentication types:

- A Service API key, configured with `x_api_key`, from **Accounts → Service API keys**. Enable only the API areas required by the selected data streams. Service API keys are independent of human accounts, expire after at most one year, and do not support the Event Push Service API.
- A Personal API key, configured with `basic`, from the account menu under **API keys**. Personal API keys are required for the existing Push API streams.

Copy the exact Control Center API Access URL from the account menu under **Control Center API**. The URL normally ends in `/api`. GravityZone uses multiple regional instances, including `https://cloudgz.gravityzone.bitdefender.com/api`, `https://cloud.gravityzone.bitdefender.com/api`, and `https://cloudap.gravityzone.bitdefender.com/api`. An API key is valid only on the Control Center instance where it was created. If GravityZone reports an invalid API key, verify the Access URL before replacing the key.

For partner or MSP collection, optionally set the target company ID. The integration places that ID in the method-specific request field required by each API.

If Push and Public API polling require different key types or permissions, create separate integration policies and enable only the relevant data streams in each policy.

The Public API data streams require the corresponding GravityZone API permissions and product licenses:

- Incidents: **Incidents API** and an EDR/XDR-capable subscription.
- Endpoint inventory: **Network API**.
- Account inventory: **Accounts API** and the required user-management rights.

Selecting an API area when creating a key does not grant the corresponding product license or user rights.

GravityZone rate limits vary by API method and tenant. A throttled request returns HTTP `429` and can include a `Retry-After` header. The integration retries throttled requests. Each polling cycle fetches every paginated response page for the enabled stream:

- Incidents runs paginated `getIncidentsList` requests for the window and then resolves full details with `getIncidentsByIds` in batches of up to 10 incident IDs per request.
- Endpoint inventory and account inventory append a full snapshot of the active inventory on every polling interval. Size retention and polling intervals according to your tenant's object counts and API rate limits, or split streams across separate API keys when needed.

### Creating the push notification configuration via BitDefender GravityZone API

The BitDefender documentation for how to do this is [here](https://www.bitdefender.com/business/support/en/77209-135319-setpusheventsettings.html)

You should use the `jsonrpc` format option.

An example using cURL:

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
    "serviceType": "jsonRPC",
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

## Data stream

### Log stream push notifications

The BitDefender GravityZone events dataset provides events from BitDefender GravityZone push notifications that have been received.

All BitDefender GravityZone log events are available in the `bitdefender_gravityzone.events` field group.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| bitdefender.event._testEvent_ |  | boolean |
| bitdefender.event.action |  | keyword |
| bitdefender.event.actionTaken |  | keyword |
| bitdefender.event.aph_status |  | integer |
| bitdefender.event.aph_type |  | keyword |
| bitdefender.event.att_ck_id |  | keyword |
| bitdefender.event.attack_entry |  | keyword |
| bitdefender.event.attack_source |  | keyword |
| bitdefender.event.attack_type |  | keyword |
| bitdefender.event.attack_types |  | keyword |
| bitdefender.event.auto_renew_period |  | long |
| bitdefender.event.avc_status |  | integer |
| bitdefender.event.block_type |  | keyword |
| bitdefender.event.blocked |  | long |
| bitdefender.event.blocking_rule_name |  | keyword |
| bitdefender.event.categories |  | keyword |
| bitdefender.event.cleaned |  | long |
| bitdefender.event.command_line_parameters |  | keyword |
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
| bitdefender.event.deleted |  | long |
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
| bitdefender.event.deviceClass |  | integer |
| bitdefender.event.deviceId |  | keyword |
| bitdefender.event.deviceName |  | keyword |
| bitdefender.event.dlp_status |  | integer |
| bitdefender.event.dp_status |  | integer |
| bitdefender.event.enabled_services |  | keyword |
| bitdefender.event.endDate |  | date |
| bitdefender.event.end_subscription_date |  | date |
| bitdefender.event.endpointId |  | keyword |
| bitdefender.event.errorCode |  | integer |
| bitdefender.event.errorMessage |  | keyword |
| bitdefender.event.exploit_path |  | keyword |
| bitdefender.event.exploit_type |  | keyword |
| bitdefender.event.failedStorageType |  | integer |
| bitdefender.event.filePaths |  | keyword |
| bitdefender.event.fileSizes |  | keyword |
| bitdefender.event.file_hash |  | keyword |
| bitdefender.event.file_hash_md5 |  | keyword |
| bitdefender.event.file_hash_sha256 |  | keyword |
| bitdefender.event.file_name |  | keyword |
| bitdefender.event.file_path |  | keyword |
| bitdefender.event.final_status |  | keyword |
| bitdefender.event.firewall_status |  | integer |
| bitdefender.event.fromSupa |  | integer |
| bitdefender.event.hash |  | keyword |
| bitdefender.event.host_name |  | keyword |
| bitdefender.event.hwid |  | keyword |
| bitdefender.event.id |  | long |
| bitdefender.event.ignored |  | long |
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
| bitdefender.event.license_key |  | keyword |
| bitdefender.event.license_limit |  | long |
| bitdefender.event.license_type |  | keyword |
| bitdefender.event.loadAverage |  | float |
| bitdefender.event.localPath |  | keyword |
| bitdefender.event.local_port |  | keyword |
| bitdefender.event.mailboxes |  | long |
| bitdefender.event.main_action |  | keyword |
| bitdefender.event.malware.actionTaken |  | keyword |
| bitdefender.event.malware.infectedObject |  | keyword |
| bitdefender.event.malware.malwareName |  | keyword |
| bitdefender.event.malware.malwareType |  | keyword |
| bitdefender.event.malware_name |  | keyword |
| bitdefender.event.malware_status |  | integer |
| bitdefender.event.malware_type |  | keyword |
| bitdefender.event.memoryUsage |  | float |
| bitdefender.event.minimal_commitment_usage_endpoints |  | long |
| bitdefender.event.module |  | keyword |
| bitdefender.event.moved_company_id |  | keyword |
| bitdefender.event.moved_company_name |  | keyword |
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
| bitdefender.event.parent_process_id |  | long |
| bitdefender.event.parent_process_path |  | keyword |
| bitdefender.event.parent_process_pid |  | long |
| bitdefender.event.port |  | long |
| bitdefender.event.powered_off |  | integer |
| bitdefender.event.present |  | long |
| bitdefender.event.process_command_line |  | keyword |
| bitdefender.event.process_info_command_line |  | keyword |
| bitdefender.event.process_info_path |  | keyword |
| bitdefender.event.process_path |  | keyword |
| bitdefender.event.process_pid |  | long |
| bitdefender.event.productId |  | long |
| bitdefender.event.product_installed |  | keyword |
| bitdefender.event.product_reboot_required |  | integer |
| bitdefender.event.product_registration |  | keyword |
| bitdefender.event.product_update_available |  | integer |
| bitdefender.event.protocol_id |  | keyword |
| bitdefender.event.pu_status |  | integer |
| bitdefender.event.quarantined |  | long |
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
| bitdefender.event.storage_ip |  | ip |
| bitdefender.event.storage_name |  | keyword |
| bitdefender.event.storage_type |  | keyword |
| bitdefender.event.subject |  | keyword |
| bitdefender.event.svaLoad |  | keyword |
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
| bitdefender.event.vendorId |  | long |
| bitdefender.event.victim_ip |  | keyword |
| bitdefender.id |  | keyword |
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
    "@timestamp": "2024-07-25T10:16:53.355Z",
    "agent": {
        "ephemeral_id": "e80bc3a4-2ee1-435a-8ff1-cf18df9f0fe8",
        "id": "0eb83218-5f40-45bd-8fb3-9423008f7b6f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.3"
    },
    "bitdefender": {
        "event": {
            "aph_type": "phishing",
            "companyId": "59a14b271da197c6108b4567",
            "computer_fqdn": "fc-exchange-01.fc.dom",
            "computer_id": "59b7d9bfa849af3a1465b7e4",
            "computer_ip": "192.168.0.1",
            "computer_name": "FC-EXCHANGE-01",
            "count": 1,
            "id": 150537,
            "jsonrpc": {
                "method": "addEvents",
                "version": "2.0"
            },
            "last_blocked": "2023-09-13T08:49:43.000Z",
            "module": "aph",
            "product_installed": "BEST",
            "status": "aph_blocked",
            "url": "http://example.com/account/support/"
        },
        "id": "test"
    },
    "data_stream": {
        "dataset": "bitdefender.push_notifications",
        "namespace": "29298",
        "type": "logs"
    },
    "destination": {
        "ip": "192.168.0.1"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0eb83218-5f40-45bd-8fb3-9423008f7b6f",
        "snapshot": false,
        "version": "8.14.3"
    },
    "event": {
        "action": "aph_blocked",
        "agent_id_status": "verified",
        "category": [
            "threat",
            "network"
        ],
        "dataset": "bitdefender.push_notifications",
        "id": "150537",
        "ingested": "2024-07-25T10:17:03Z",
        "kind": "alert",
        "module": "aph",
        "original": "{\"event\":{\"aph_type\":\"phishing\",\"companyId\":\"59a14b271da197c6108b4567\",\"computer_fqdn\":\"fc-exchange-01.fc.dom\",\"computer_id\":\"59b7d9bfa849af3a1465b7e4\",\"computer_ip\":\"192.168.0.1\",\"computer_name\":\"FC-EXCHANGE-01\",\"count\":1,\"last_blocked\":\"2023-09-13T08:49:43.000Z\",\"module\":\"aph\",\"product_installed\":\"BEST\",\"status\":\"aph_blocked\",\"url\":\"http://example.com/account/support/\"},\"id\":150537,\"jsonrpc\":{\"method\":\"addEvents\",\"version\":\"2.0\"}}",
        "provider": "Antiphishing",
        "severity": 0,
        "timezone": "+00:00",
        "type": [
            "info",
            "access"
        ]
    },
    "host": {
        "hostname": "fc-exchange-01.fc.dom",
        "id": "59b7d9bfa849af3a1465b7e4",
        "ip": [
            "192.168.0.1"
        ],
        "name": "FC-EXCHANGE-01"
    },
    "input": {
        "type": "http_endpoint"
    },
    "message": "aph_blocked, aph type: phishing",
    "organization": {
        "id": "59a14b271da197c6108b4567"
    },
    "related": {
        "hosts": [
            "FC-EXCHANGE-01"
        ],
        "ip": [
            "192.168.0.1"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded"
    ],
    "url": {
        "domain": "example.com",
        "original": "http://example.com/account/support/",
        "path": "/account/support/",
        "registered_domain": "example.com",
        "scheme": "http",
        "top_level_domain": "com"
    }
}
```

### Log stream push notification configuration

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
    "@timestamp": "2025-08-04T05:45:30.706Z",
    "agent": {
        "ephemeral_id": "6add488a-b2f6-487a-af12-30506202511b",
        "id": "dc1ce160-e35b-4897-a9cb-680439488735",
        "name": "elastic-agent-51646",
        "type": "filebeat",
        "version": "8.18.0"
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
        "namespace": "20813",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "dc1ce160-e35b-4897-a9cb-680439488735",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "bitdefender.push_configuration",
        "ingested": "2025-08-04T05:45:33Z",
        "original": "{\"id\":\"1\",\"jsonrpc\":\"2.0\",\"result\":{\"serviceSettings\":{\"requireValidSslCertificate\":true,\"url\":\"https://your.elastic.agent/bitdefender/push/notification\"},\"serviceType\":\"qradar\",\"status\":1,\"subscribeToEventTypes\":{\"adcloud\":true,\"antiexploit\":true,\"aph\":true,\"av\":true,\"avc\":true,\"dp\":true,\"endpoint-moved-in\":true,\"endpoint-moved-out\":true,\"exchange-malware\":true,\"exchange-user-credentials\":true,\"fw\":true,\"hd\":true,\"hwid-change\":true,\"install\":true,\"modules\":true,\"network-monitor\":true,\"network-sandboxing\":true,\"new-incident\":true,\"ransomware-mitigation\":true,\"registration\":true,\"security-container-update-available\":true,\"supa-update-status\":true,\"sva\":true,\"sva-load\":true,\"task-status\":true,\"troubleshooting-activity\":true,\"uc\":true,\"uninstall\":true}}}"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "forwarded"
    ]
}
```

### Log stream push notification statistics

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
    "@timestamp": "2025-08-04T05:53:31.451Z",
    "agent": {
        "ephemeral_id": "181a8db2-ef15-4ce1-b78b-fe1d67440dd6",
        "id": "088aadd3-85d3-4553-8e87-2428b1e4e35a",
        "name": "elastic-agent-40833",
        "type": "filebeat",
        "version": "8.18.0"
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
        "namespace": "74028",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "088aadd3-85d3-4553-8e87-2428b1e4e35a",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "bitdefender.push_statistics",
        "ingested": "2025-08-04T05:53:34Z",
        "original": "{\"id\":\"test\",\"jsonrpc\":\"2.0\",\"result\":{\"count\":{\"errorMessages\":121,\"events\":1415824,\"sentMessages\":78368,\"testEvents\":0},\"error\":{\"configurationError\":0,\"connectionError\":7,\"serviceError\":114,\"statusCode2xx\":0,\"statusCode300\":0,\"statusCode400\":0,\"statusCode500\":0,\"timeout\":0},\"lastUpdateTime\":\"2023-01-27T09:19:22\"}}"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "forwarded"
    ]
}
```

### Log stream incidents

The incidents dataset collects changed EDR and XDR incidents and retrieves their complete details, including alert graphs, affected entities, MITRE ATT&CK metadata, status, priority, and analyst notes. Each polling cycle pages through `getIncidentsList` and fetches full incident objects with `getIncidentsByIds` in batches of up to 10 IDs. Parent incident documents use a revision-aware document ID derived from `incidentId` and `lastIncidentChange`, so unchanged boundary overlaps collapse onto the same document while status, action, or severity updates are preserved as new revisions in the append-only data stream.

The same poll emits each object in an incident's `details.alerts` array as a separate document in the `bitdefender.incident_alert` dataset. Individual alert documents include compact parent-incident context and alert-level process, file, network, registry, user, host, and related indicator fields. Alert documents use a revision-aware document ID derived from the parent incident ID, alert ID, and parent incident state so unchanged re-polls deduplicate cleanly without dropping later incident status, action, or severity updates. This fan-out does not make additional GravityZone API requests.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| bitdefender.incident.assignee.companyId |  | keyword |
| bitdefender.incident.assignee.companyName |  | keyword |
| bitdefender.incident.assignee.userId |  | keyword |
| bitdefender.incident.assignee.userName |  | keyword |
| bitdefender.incident.attackTypes |  | keyword |
| bitdefender.incident.company.id |  | keyword |
| bitdefender.incident.company.name |  | keyword |
| bitdefender.incident.created |  | date |
| bitdefender.incident.details | Full polymorphic endpoint EDR or organization XDR incident details, including alerts, graph nodes, resources, MITRE ATT&CK metadata, counters, narrative, and reasoning. | flattened |
| bitdefender.incident.id | Stable GravityZone incident identifier. | keyword |
| bitdefender.incident.incidentId | Stable GravityZone incident identifier. | keyword |
| bitdefender.incident.incidentLink |  | keyword |
| bitdefender.incident.incidentNumber | Incident number displayed in GravityZone Control Center. | long |
| bitdefender.incident.incidentType | Incident scope, such as incident or extendedIncident. | keyword |
| bitdefender.incident.lastIncidentChange |  | date |
| bitdefender.incident.lastProcessed |  | date |
| bitdefender.incident.lastUpdated |  | date |
| bitdefender.incident.mainAction |  | keyword |
| bitdefender.incident.notes.created |  | date |
| bitdefender.incident.notes.id |  | keyword |
| bitdefender.incident.notes.text |  | match_only_text |
| bitdefender.incident.notes.userId |  | keyword |
| bitdefender.incident.notes.userName |  | keyword |
| bitdefender.incident.priority |  | keyword |
| bitdefender.incident.severityScore |  | long |
| bitdefender.incident.status |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.reference | Reference URL linking to additional information about this event. This URL links to a static definition of this event. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| organization.id | Unique identifier for the organization. | keyword |
| organization.name | Organization name. | keyword |
| organization.name.text | Multi-field of `organization.name`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.group.name | The name of the group for a set of related intrusion activity that are tracked by a common name in the security community. While not required, you can use a MITRE ATT&CK® group name. | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.technique.id | The id of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name | The name of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name.text | Multi-field of `threat.technique.name`. | match_only_text |
| threat.technique.subtechnique.id | The full id of subtechnique used by this threat. You can use a MITRE ATT&CK® subtechnique, for example. (ex. https://attack.mitre.org/techniques/T1059/001/) | keyword |
| threat.technique.subtechnique.name | The name of subtechnique used by this threat. You can use a MITRE ATT&CK® subtechnique, for example. (ex. https://attack.mitre.org/techniques/T1059/001/) | keyword |
| threat.technique.subtechnique.name.text | Multi-field of `threat.technique.subtechnique.name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id) | keyword |


An example event for `incident` looks as following:

```json
{
    "@timestamp": "2026-11-01T01:01:00.000Z",
    "agent": {
        "ephemeral_id": "854bbbe5-f862-46f9-ae3e-de4d9fafd6d7",
        "id": "521127d5-3940-4007-a706-e3e7218aa1ad",
        "name": "elastic-agent-60839",
        "type": "filebeat",
        "version": "9.5.5"
    },
    "bitdefender": {
        "incident": {
            "company": {
                "id": "5e4d3c2b1a0987654321fedc",
                "name": "Example Corp"
            },
            "details": {
                "detectionName": "Synthetic incident 1"
            },
            "id": "65f04c2e1234567890abc001",
            "incidentId": "65f04c2e1234567890abc001",
            "incidentNumber": 101,
            "incidentType": "incident",
            "lastIncidentChange": "2026-11-01T01:01:00.000Z",
            "priority": "low",
            "severityScore": 31,
            "status": "open"
        }
    },
    "data_stream": {
        "dataset": "bitdefender.incident",
        "namespace": "22933",
        "type": "logs"
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "521127d5-3940-4007-a706-e3e7218aa1ad",
        "snapshot": false,
        "version": "9.5.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "intrusion_detection",
            "malware",
            "threat"
        ],
        "dataset": "bitdefender.incident",
        "id": "65f04c2e1234567890abc001",
        "ingested": "2026-11-13T18:46:36Z",
        "kind": "alert",
        "module": "bitdefender",
        "original": "{\"company\":{\"id\":\"5e4d3c2b1a0987654321fedc\",\"name\":\"Example Corp\"},\"details\":{\"alerts\":[],\"detectionName\":\"Synthetic incident 1\",\"nodes\":[]},\"incidentId\":\"65f04c2e1234567890abc001\",\"incidentNumber\":101,\"incidentType\":\"incident\",\"lastIncidentChange\":\"2026-11-01T01:01:00Z\",\"notes\":[],\"priority\":\"low\",\"severityScore\":31,\"status\":\"open\"}",
        "risk_score": 31,
        "severity": 47,
        "type": [
            "indicator",
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "message": "Synthetic incident 1",
    "observer": {
        "product": "GravityZone",
        "vendor": "Bitdefender"
    },
    "organization": {
        "id": "5e4d3c2b1a0987654321fedc",
        "name": "Example Corp"
    },
    "rule": {
        "name": "Synthetic incident 1"
    },
    "tags": [
        "preserve_original_event",
        "forwarded"
    ]
}
```

### Log stream incident alerts

The incident alerts dataset contains one document for each endpoint EDR or organization XDR alert embedded in an incident. Enable the incidents data stream to collect both the parent incident and these individual alert documents. Use `data_stream.dataset: bitdefender.incident_alert` to search the alert-level events. Alert titles, identifiers, risk scores, and normalized severities are populated for compatibility with the Elastic Security External Alerts rule.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| bitdefender.incident_alert.alert.date | Date and time when the alert was detected. | date |
| bitdefender.incident_alert.alert.detectedBy.class | Class of the detecting technology. | keyword |
| bitdefender.incident_alert.alert.detectedBy.name | Name of the detecting technology. | keyword |
| bitdefender.incident_alert.alert.extra | Polymorphic extra alert attributes. | flattened |
| bitdefender.incident_alert.alert.id | Stable identifier of the individual alert. | keyword |
| bitdefender.incident_alert.alert.name | Name of the alert. | keyword |
| bitdefender.incident_alert.alert.resources | Polymorphic endpoint alert resources. | flattened |
| bitdefender.incident_alert.alert.sensors | Organization sensors that detected the alert. | keyword |
| bitdefender.incident_alert.alert.tactic | Vendor MITRE ATT&CK tactic identifier. | keyword |
| bitdefender.incident_alert.alert.transitions | Polymorphic organization alert transitions and resources. | flattened |
| bitdefender.incident_alert.incident.company.id | Identifier of the company where the incident occurred. | keyword |
| bitdefender.incident_alert.incident.company.name | Name of the company where the incident occurred. | keyword |
| bitdefender.incident_alert.incident.created | Date and time when the parent incident was created. | date |
| bitdefender.incident_alert.incident.details.computerFqdn | FQDN of the endpoint that generated the incident. | keyword |
| bitdefender.incident_alert.incident.details.computerId | Identifier of the endpoint that generated the incident. | keyword |
| bitdefender.incident_alert.incident.details.computerIp | Communication IP address of the endpoint. | ip |
| bitdefender.incident_alert.incident.details.computerMacAddresses | MAC addresses of the endpoint. | keyword |
| bitdefender.incident_alert.incident.details.computerName | Name of the endpoint that generated the incident. | keyword |
| bitdefender.incident_alert.incident.incidentId | Stable identifier of the parent incident. | keyword |
| bitdefender.incident_alert.incident.incidentLink | Link to the parent incident in GravityZone Control Center. | keyword |
| bitdefender.incident_alert.incident.incidentNumber | Incident number displayed in GravityZone Control Center. | long |
| bitdefender.incident_alert.incident.incidentType | Scope of the parent incident. | keyword |
| bitdefender.incident_alert.incident.lastIncidentChange | Date and time of the most recent parent incident change. | date |
| bitdefender.incident_alert.incident.lastProcessed | Date and time when the parent incident was last processed. | date |
| bitdefender.incident_alert.incident.lastUpdated | Date and time when the parent incident was last updated. | date |
| bitdefender.incident_alert.incident.mainAction | Main automatic action taken for the parent incident. | keyword |
| bitdefender.incident_alert.incident.priority | Priority of the parent incident. | keyword |
| bitdefender.incident_alert.incident.severityScore | Severity score of the parent incident. | long |
| bitdefender.incident_alert.incident.status | Investigation status of the parent incident. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.mac | MAC address of the client. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.reference | Reference URL linking to additional information about this event. This URL links to a static definition of this event. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| input.type | Type of Filebeat input. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| organization.id | Unique identifier for the organization. | keyword |
| organization.name | Organization name. | keyword |
| organization.name.text | Multi-field of `organization.name`. | match_only_text |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.parent.command_line.text | Multi-field of `process.parent.command_line`. | match_only_text |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| registry.data.strings | Content when writing string types. Populated as an array when writing string data to the registry. For single string registry types (REG_SZ, REG_EXPAND_SZ), this should be an array with one string. For sequences of string with REG_MULTI_SZ, this array will be variable length. For numeric data, such as REG_DWORD and REG_QWORD, this should be populated with the decimal representation (e.g `"1"`). | wildcard |
| registry.data.type | Standard registry type for encoding contents | keyword |
| registry.path | Full path, including hive, key and value | keyword |
| registry.value | Name of the value written. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| threat.framework | Name of the threat framework used to further categorize and classify the tactic and technique of the reported threat. Framework classification can be provided by detecting systems, evaluated at ingest time, or retrospectively tagged to events. | keyword |
| threat.tactic.id | The id of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


### Log stream endpoints

The endpoint dataset collects bulk network inventory as host and container entity snapshots across all inventory pages on each polling interval. Each poll appends a full snapshot of matching endpoints and containers, including endpoint identity, addresses, operating system, policy, protection modules, management state, last successful scan, and risk posture without per-endpoint detail fan-out. GravityZone returns `firstSeen` without a timezone, so the integration preserves it as a source string and uses the collection time as the entity observation timestamp.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| bitdefender.endpoint.companyId | Identifier of the company that owns the inventory item. | keyword |
| bitdefender.endpoint.details.firstSeen | Raw first-seen time. GravityZone might omit the timezone from this value. | keyword |
| bitdefender.endpoint.details.fqdn | Fully qualified domain name. | keyword |
| bitdefender.endpoint.details.groupId | Identifier of the custom group containing the inventory item. | keyword |
| bitdefender.endpoint.details.ip | Local IP address. | ip |
| bitdefender.endpoint.details.isContainerHost | Whether container host protection is installed. | boolean |
| bitdefender.endpoint.details.isIsolated | Whether the inventory item is isolated from the network. | boolean |
| bitdefender.endpoint.details.isManaged | Whether the inventory item is managed by GravityZone. | boolean |
| bitdefender.endpoint.details.label | Custom label assigned to the inventory item. | keyword |
| bitdefender.endpoint.details.machineType | Machine classification code. | long |
| bitdefender.endpoint.details.macs | Network adapter MAC addresses in vendor-provided formats. | keyword |
| bitdefender.endpoint.details.managedExchangeServer | Whether the endpoint is a protected Exchange server. | boolean |
| bitdefender.endpoint.details.managedRelay | Whether the endpoint has the GravityZone Relay role. | boolean |
| bitdefender.endpoint.details.managedWithBest | Whether Bitdefender Endpoint Security Tools is installed. | boolean |
| bitdefender.endpoint.details.modules.advancedAntiExploit |  | boolean |
| bitdefender.endpoint.details.modules.advancedThreatControl |  | boolean |
| bitdefender.endpoint.details.modules.antimalware |  | boolean |
| bitdefender.endpoint.details.modules.applicationControl |  | boolean |
| bitdefender.endpoint.details.modules.containerProtection |  | boolean |
| bitdefender.endpoint.details.modules.contentControl |  | boolean |
| bitdefender.endpoint.details.modules.deviceControl |  | boolean |
| bitdefender.endpoint.details.modules.edrSensor |  | boolean |
| bitdefender.endpoint.details.modules.encryption |  | boolean |
| bitdefender.endpoint.details.modules.exchange |  | boolean |
| bitdefender.endpoint.details.modules.firewall |  | boolean |
| bitdefender.endpoint.details.modules.hyperDetect |  | boolean |
| bitdefender.endpoint.details.modules.integrityMonitoring |  | boolean |
| bitdefender.endpoint.details.modules.networkAttackDefense |  | boolean |
| bitdefender.endpoint.details.modules.patchManagement |  | boolean |
| bitdefender.endpoint.details.modules.powerUser |  | boolean |
| bitdefender.endpoint.details.modules.relay |  | boolean |
| bitdefender.endpoint.details.modules.remoteEnginesScanning |  | boolean |
| bitdefender.endpoint.details.modules.riskManagement |  | boolean |
| bitdefender.endpoint.details.modules.sandboxAnalyzer |  | boolean |
| bitdefender.endpoint.details.movingInfo.destinationCompanyName | Destination company name for an in-progress transfer. | keyword |
| bitdefender.endpoint.details.movingInfo.state | Inter-company transfer state. | long |
| bitdefender.endpoint.details.operatingSystemVersion | Operating system name and version reported by GravityZone. | keyword |
| bitdefender.endpoint.details.policy.applied | Whether the policy is currently applied. | boolean |
| bitdefender.endpoint.details.policy.id | Identifier of the active security policy. | keyword |
| bitdefender.endpoint.details.policy.name | Name of the active security policy. | keyword |
| bitdefender.endpoint.details.productOutdated | Vendor-provided security agent update status. | boolean |
| bitdefender.endpoint.details.publicIp | Public IP address. | ip |
| bitdefender.endpoint.details.riskScore.appVulnerabilities | Application vulnerability contribution percentage. | keyword |
| bitdefender.endpoint.details.riskScore.humanRisks | Human risk contribution percentage. | keyword |
| bitdefender.endpoint.details.riskScore.impact | Risk impact level. | keyword |
| bitdefender.endpoint.details.riskScore.misconfigurations | Misconfiguration contribution percentage. | keyword |
| bitdefender.endpoint.details.riskScore.value | Overall risk score percentage. | keyword |
| bitdefender.endpoint.details.securityServer | Whether the endpoint is a GravityZone Security Server. | boolean |
| bitdefender.endpoint.details.ssid | Active Directory SID of the endpoint. | keyword |
| bitdefender.endpoint.id | Stable GravityZone network inventory item identifier. | keyword |
| bitdefender.endpoint.lastSuccessfulScan.date | Time of the last successful scan. | date |
| bitdefender.endpoint.lastSuccessfulScan.name | Name of the last successful scan. | keyword |
| bitdefender.endpoint.manageAiSpm | Whether AI Security Posture Management applies to the inventory item. | boolean |
| bitdefender.endpoint.name | Name of the endpoint or container. | keyword |
| bitdefender.endpoint.parentId | Identifier of the immediate parent inventory container. | keyword |
| bitdefender.endpoint.type | Network inventory item type. Values emitted by this stream are 5 (computer), 6 (virtual machine), 7 (EC2 instance), and 16 (container). | long |
| container.id | Unique container id. | keyword |
| container.name | Container name. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| entity.id | A unique identifier for the entity. When multiple identifiers exist, this should be the most stable and commonly used identifier that: 1) persists across the entity's lifecycle, 2) ensures uniqueness within its scope, 3) is commonly used for queries and correlation, and 4) is readily available in most observations (logs/events). For entities with dedicated field sets (for example, host, user), this value should match the corresponding \*.id field. Alternative identifiers (for example, ARNs values in AWS, URLs) can be preserved in the raw field. | keyword |
| entity.last_seen_timestamp | Indicates the date/time when this entity was last "seen," usually based upon the last event/log that is initiated by this entity. | date |
| entity.name | The name of the entity. The keyword field enables exact matches for filtering and aggregations, while the text field enables full-text search. For entities with dedicated field sets (for example, `host`), this field should mirrors the corresponding \*.name value. | keyword |
| entity.name.text | Multi-field of `entity.name`. | match_only_text |
| entity.source | The module or integration that provided this entity data (similar to event.module). | keyword |
| entity.type | A standardized high-level classification of the entity. This provides a normalized way to group similar entities across different providers or systems. Example values: `bucket`, `database`, `container`, `function`, `queue`, `host`, `user`, `application`, `session`, `cloud`, `orchestrator`, etc. If an entity is nested under a top-level namespace like `host` or `cloud`, or similar, its type array should include the matching value — for example, `host` or `cloud`. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.entity.attributes.managed | Indicates whether the entity is managed by an external administration or control system. Typically applicable to Host and Service entities. | boolean |
| host.entity.id | A unique identifier for the entity. When multiple identifiers exist, this should be the most stable and commonly used identifier that: 1) persists across the entity's lifecycle, 2) ensures uniqueness within its scope, 3) is commonly used for queries and correlation, and 4) is readily available in most observations (logs/events). For entities with dedicated field sets (for example, host, user), this value should match the corresponding \*.id field. Alternative identifiers (for example, ARNs values in AWS, URLs) can be preserved in the raw field. | keyword |
| host.entity.last_seen_timestamp | Indicates the date/time when this entity was last "seen," usually based upon the last event/log that is initiated by this entity. | date |
| host.entity.name | The name of the entity. The keyword field enables exact matches for filtering and aggregations, while the text field enables full-text search. For entities with dedicated field sets (for example, `host`), this field should mirrors the corresponding \*.name value. | keyword |
| host.entity.name.text | Multi-field of `host.entity.name`. | match_only_text |
| host.entity.source | The module or integration that provided this entity data (similar to event.module). | keyword |
| host.entity.type | A standardized high-level classification of the entity. This provides a normalized way to group similar entities across different providers or systems. Example values: `bucket`, `database`, `container`, `function`, `queue`, `host`, `user`, `application`, `session`, `cloud`, `orchestrator`, etc. If an entity is nested under a top-level namespace like `host` or `cloud`, or similar, its type array should include the matching value — for example, `host` or `cloud`. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.full.text | Multi-field of `host.os.full`. | match_only_text |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.risk.calculated_level | A risk classification level calculated by an internal system as part of entity analytics and entity risk scoring. | keyword |
| host.risk.calculated_score | A risk classification score calculated by an internal system as part of entity analytics and entity risk scoring. | float |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| organization.id | Unique identifier for the organization. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |


An example event for `endpoint` looks as following:

```json
{
    "@timestamp": "2026-11-02T21:50:21.327Z",
    "agent": {
        "ephemeral_id": "474f45cf-5246-4741-a9be-c424034096f8",
        "id": "9df94d36-6611-4aef-a3c2-b2edd835ca9e",
        "name": "elastic-agent-76679",
        "type": "filebeat",
        "version": "9.5.5"
    },
    "bitdefender": {
        "endpoint": {
            "companyId": "5e4d3c2b1a0987654321fedc",
            "details": {
                "firstSeen": "2026-10-01T10:00:00",
                "fqdn": "example-host-01.example.local",
                "groupId": "65b00000000000000000a001",
                "ip": "192.0.2.21",
                "isIsolated": false,
                "isManaged": true,
                "label": "Example Windows host",
                "machineType": 1,
                "macs": "00:00:5E:00:53:21",
                "managedWithBest": true,
                "modules": {
                    "advancedThreatControl": true,
                    "antimalware": true,
                    "contentControl": true,
                    "deviceControl": true,
                    "edrSensor": true,
                    "firewall": true,
                    "hyperDetect": true,
                    "networkAttackDefense": true,
                    "patchManagement": true
                },
                "operatingSystemVersion": "Windows 11 Enterprise",
                "policy": {
                    "applied": true,
                    "id": "65b00000000000000000c001",
                    "name": "Example endpoint policy"
                },
                "productOutdated": false,
                "publicIp": "198.51.100.21",
                "riskScore": {
                    "appVulnerabilities": "8%",
                    "humanRisks": "2%",
                    "impact": "Low",
                    "misconfigurations": "10%",
                    "value": "20%"
                },
                "ssid": "S-1-5-21-000000000-000000000-000000000-1001"
            },
            "id": "65b000000000000000000001",
            "lastSuccessfulScan": {
                "date": "2026-11-01T06:00:00.000Z",
                "name": "Scheduled scan"
            },
            "name": "example-host-01",
            "parentId": "65b00000000000000000a001",
            "type": 5
        }
    },
    "data_stream": {
        "dataset": "bitdefender.endpoint",
        "namespace": "71712",
        "type": "logs"
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "9df94d36-6611-4aef-a3c2-b2edd835ca9e",
        "snapshot": false,
        "version": "9.5.5"
    },
    "entity": {
        "id": "65b000000000000000000001",
        "last_seen_timestamp": "2026-11-02T21:50:21.327Z",
        "name": "example-host-01",
        "source": "bitdefender_gravityzone",
        "type": [
            "host"
        ]
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "bitdefender.endpoint",
        "ingested": "2026-11-02T21:50:25Z",
        "kind": "asset",
        "module": "bitdefender",
        "original": "{\"companyId\":\"5e4d3c2b1a0987654321fedc\",\"details\":{\"firstSeen\":\"2026-10-01T10:00:00\",\"fqdn\":\"example-host-01.example.local\",\"groupId\":\"65b00000000000000000a001\",\"ip\":\"192.0.2.21\",\"isIsolated\":false,\"isManaged\":true,\"label\":\"Example Windows host\",\"machineType\":1,\"macs\":[\"00:00:5E:00:53:21\"],\"managedWithBest\":true,\"modules\":{\"advancedThreatControl\":true,\"antimalware\":true,\"contentControl\":true,\"deviceControl\":true,\"edrSensor\":true,\"firewall\":true,\"hyperDetect\":true,\"networkAttackDefense\":true,\"patchManagement\":true},\"operatingSystemVersion\":\"Windows 11 Enterprise\",\"policy\":{\"applied\":true,\"id\":\"65b00000000000000000c001\",\"name\":\"Example endpoint policy\"},\"productOutdated\":false,\"publicIp\":\"198.51.100.21\",\"riskScore\":{\"appVulnerabilities\":\"8%\",\"humanRisks\":\"2%\",\"impact\":\"Low\",\"misconfigurations\":\"10%\",\"value\":\"20%\"},\"ssid\":\"S-1-5-21-000000000-000000000-000000000-1001\"},\"id\":\"65b000000000000000000001\",\"lastSuccessfulScan\":{\"date\":\"2026-11-01T06:00:00+00:00\",\"name\":\"Scheduled scan\"},\"name\":\"example-host-01\",\"parentId\":\"65b00000000000000000a001\",\"type\":5}",
        "type": [
            "info"
        ]
    },
    "host": {
        "domain": "example.local",
        "entity": {
            "attributes": {
                "managed": true
            },
            "id": "65b000000000000000000001",
            "last_seen_timestamp": "2026-11-02T21:50:21.327Z",
            "name": "example-host-01",
            "source": "bitdefender_gravityzone",
            "type": [
                "host"
            ]
        },
        "hostname": "example-host-01.example.local",
        "id": "65b000000000000000000001",
        "ip": [
            "192.0.2.21",
            "198.51.100.21"
        ],
        "mac": [
            "00-00-5E-00-53-21"
        ],
        "name": "example-host-01",
        "os": {
            "full": "Windows 11 Enterprise",
            "name": "Windows",
            "platform": "windows",
            "type": "windows"
        },
        "risk": {
            "calculated_level": "Low",
            "calculated_score": 20
        },
        "type": "computer"
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "GravityZone",
        "vendor": "Bitdefender"
    },
    "organization": {
        "id": "5e4d3c2b1a0987654321fedc"
    },
    "related": {
        "hosts": [
            "example-host-01",
            "example-host-01.example.local"
        ],
        "ip": [
            "192.0.2.21",
            "198.51.100.21"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded"
    ]
}
```

### Log stream accounts

The account dataset collects Control Center users as entity snapshots across all pages on each polling interval, including roles, enabled permissions, authentication method, and MFA state. When authenticated with a Personal API key (`basic`), the cycle also calls `getAccountDetails` once to include the key owner's account.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| bitdefender.account.accountLockdown | Whether the account locks after repeated failed sign-in attempts. | boolean |
| bitdefender.account.authenticationMethod | GravityZone account authentication method code. | long |
| bitdefender.account.companyId | Identifier of the company to which the account belongs. | keyword |
| bitdefender.account.companyName | Name of the company to which the account belongs. | keyword |
| bitdefender.account.email | Email address used to sign in to the Control Center account. | keyword |
| bitdefender.account.hasOwnCompanyInTargets | Whether the account can manage its own top-level company. | boolean |
| bitdefender.account.id | Stable GravityZone Control Center account identifier. | keyword |
| bitdefender.account.passwordLifetime | Password expiration policy in days. | long |
| bitdefender.account.phoneNumber.countryCode | Telephone country calling code. | keyword |
| bitdefender.account.phoneNumber.subscriberNumber | Telephone subscriber number. | keyword |
| bitdefender.account.profile.fullName | Full name associated with the account. | keyword |
| bitdefender.account.profile.landingPage | Default Control Center landing page. | keyword |
| bitdefender.account.profile.language | Control Center interface language. | keyword |
| bitdefender.account.profile.timezone | Account timezone. | keyword |
| bitdefender.account.rights.companyManager |  | boolean |
| bitdefender.account.rights.manageCompanies |  | boolean |
| bitdefender.account.rights.manageInventory |  | boolean |
| bitdefender.account.rights.manageMspTrialFeatures |  | boolean |
| bitdefender.account.rights.manageNetworks |  | boolean |
| bitdefender.account.rights.managePoliciesRead |  | boolean |
| bitdefender.account.rights.managePoliciesWrite |  | boolean |
| bitdefender.account.rights.manageRemoteShell |  | boolean |
| bitdefender.account.rights.manageReports |  | boolean |
| bitdefender.account.rights.manageServiceAccounts |  | boolean |
| bitdefender.account.rights.manageUsers |  | boolean |
| bitdefender.account.role | GravityZone account role code. | long |
| bitdefender.account.targetIds | Inventory target identifiers assigned to the account. | keyword |
| bitdefender.account.twoFactorAuthenticationStatus | Whether two-factor authentication is enabled. | boolean |
| bitdefender.account.userName | Account login name returned by GravityZone On-Premises deployments. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| entity.id | A unique identifier for the entity. When multiple identifiers exist, this should be the most stable and commonly used identifier that: 1) persists across the entity's lifecycle, 2) ensures uniqueness within its scope, 3) is commonly used for queries and correlation, and 4) is readily available in most observations (logs/events). For entities with dedicated field sets (for example, host, user), this value should match the corresponding \*.id field. Alternative identifiers (for example, ARNs values in AWS, URLs) can be preserved in the raw field. | keyword |
| entity.last_seen_timestamp | Indicates the date/time when this entity was last "seen," usually based upon the last event/log that is initiated by this entity. | date |
| entity.name | The name of the entity. The keyword field enables exact matches for filtering and aggregations, while the text field enables full-text search. For entities with dedicated field sets (for example, `host`), this field should mirrors the corresponding \*.name value. | keyword |
| entity.name.text | Multi-field of `entity.name`. | match_only_text |
| entity.source | The module or integration that provided this entity data (similar to event.module). | keyword |
| entity.type | A standardized high-level classification of the entity. This provides a normalized way to group similar entities across different providers or systems. Example values: `bucket`, `database`, `container`, `function`, `queue`, `host`, `user`, `application`, `session`, `cloud`, `orchestrator`, etc. If an entity is nested under a top-level namespace like `host` or `cloud`, or similar, its type array should include the matching value — for example, `host` or `cloud`. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| organization.id | Unique identifier for the organization. | keyword |
| organization.name | Organization name. | keyword |
| organization.name.text | Multi-field of `organization.name`. | match_only_text |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.entity.attributes.mfa_enabled | Indicates whether multi-factor authentication is enabled for this entity. Typically applicable to User entities. | boolean |
| user.entity.attributes.permissions | Action-level permissions associated with this entity (not roles or groups). Typically applicable to User, Host, and Service entities. | keyword |
| user.entity.id | A unique identifier for the entity. When multiple identifiers exist, this should be the most stable and commonly used identifier that: 1) persists across the entity's lifecycle, 2) ensures uniqueness within its scope, 3) is commonly used for queries and correlation, and 4) is readily available in most observations (logs/events). For entities with dedicated field sets (for example, host, user), this value should match the corresponding \*.id field. Alternative identifiers (for example, ARNs values in AWS, URLs) can be preserved in the raw field. | keyword |
| user.entity.last_seen_timestamp | Indicates the date/time when this entity was last "seen," usually based upon the last event/log that is initiated by this entity. | date |
| user.entity.name | The name of the entity. The keyword field enables exact matches for filtering and aggregations, while the text field enables full-text search. For entities with dedicated field sets (for example, `host`), this field should mirrors the corresponding \*.name value. | keyword |
| user.entity.name.text | Multi-field of `user.entity.name`. | match_only_text |
| user.entity.source | The module or integration that provided this entity data (similar to event.module). | keyword |
| user.entity.type | A standardized high-level classification of the entity. This provides a normalized way to group similar entities across different providers or systems. Example values: `bucket`, `database`, `container`, `function`, `queue`, `host`, `user`, `application`, `session`, `cloud`, `orchestrator`, etc. If an entity is nested under a top-level namespace like `host` or `cloud`, or similar, its type array should include the matching value — for example, `host` or `cloud`. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.roles | Array of user roles at the time of the event. | keyword |


An example event for `account` looks as following:

```json
{
    "@timestamp": "2026-11-02T21:35:06.445Z",
    "agent": {
        "ephemeral_id": "e5c177b2-16b0-4ad5-a790-bd1a2c6d6faa",
        "id": "3675909e-74c6-4939-94e0-2686e044c3ce",
        "name": "elastic-agent-11206",
        "type": "filebeat",
        "version": "9.5.5"
    },
    "bitdefender": {
        "account": {
            "accountLockdown": false,
            "authenticationMethod": 0,
            "companyId": "5e4d3c2b1a0987654321fedc",
            "companyName": "Example Corp",
            "email": "analyst@example.com",
            "id": "65c000000000000000000011",
            "passwordLifetime": 90,
            "profile": {
                "fullName": "Alex Morgan",
                "landingPage": "dashboardV2",
                "language": "en_US",
                "timezone": "UTC"
            },
            "rights": {
                "companyManager": false,
                "manageCompanies": false,
                "manageInventory": true,
                "manageNetworks": true,
                "managePoliciesRead": true,
                "managePoliciesWrite": true,
                "manageRemoteShell": true,
                "manageReports": true,
                "manageServiceAccounts": false,
                "manageUsers": false
            },
            "role": 2,
            "twoFactorAuthenticationStatus": true
        }
    },
    "data_stream": {
        "dataset": "bitdefender.account",
        "namespace": "70579",
        "type": "logs"
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "3675909e-74c6-4939-94e0-2686e044c3ce",
        "snapshot": false,
        "version": "9.5.5"
    },
    "entity": {
        "id": "65c000000000000000000011",
        "last_seen_timestamp": "2026-11-02T21:35:06.445Z",
        "name": "analyst@example.com",
        "source": "Bitdefender GravityZone",
        "type": [
            "user"
        ]
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "bitdefender.account",
        "ingested": "2026-11-02T21:35:10Z",
        "kind": "asset",
        "module": "bitdefender",
        "original": "{\"accountLockdown\":false,\"authenticationMethod\":0,\"companyId\":\"5e4d3c2b1a0987654321fedc\",\"companyName\":\"Example Corp\",\"email\":\"analyst@example.com\",\"id\":\"65c000000000000000000011\",\"passwordLifetime\":90,\"profile\":{\"fullName\":\"Alex Morgan\",\"landingPage\":\"dashboardV2\",\"language\":\"en_US\",\"timezone\":\"UTC\"},\"rights\":{\"companyManager\":false,\"manageCompanies\":false,\"manageInventory \":true,\"manageNetworks\":true,\"managePoliciesRead\":true,\"managePoliciesWrite\":true,\"manageRemoteShell\":true,\"manageReports\":true,\"manageServiceAccounts\":false,\"manageUsers\":false},\"role\":2,\"twoFactorAuthenticationStatus\":true}",
        "type": [
            "user",
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "GravityZone",
        "vendor": "Bitdefender"
    },
    "organization": {
        "id": "5e4d3c2b1a0987654321fedc",
        "name": "Example Corp"
    },
    "related": {
        "user": [
            "65c000000000000000000011",
            "analyst@example.com",
            "Alex Morgan"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded"
    ],
    "user": {
        "email": "analyst@example.com",
        "entity": {
            "attributes": {
                "mfa_enabled": true,
                "permissions": [
                    "manage_networks",
                    "manage_inventory",
                    "manage_policies_read",
                    "manage_policies_write",
                    "manage_reports",
                    "manage_remote_shell"
                ]
            },
            "id": "65c000000000000000000011",
            "last_seen_timestamp": "2026-11-02T21:35:06.445Z",
            "name": "analyst@example.com",
            "source": "Bitdefender GravityZone",
            "type": [
                "user"
            ]
        },
        "full_name": "Alex Morgan",
        "id": "65c000000000000000000011",
        "name": "analyst@example.com",
        "roles": [
            "network_administrator"
        ]
    }
}
```
