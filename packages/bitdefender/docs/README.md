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
| bitdefender.event.incident_id |  | keyword |
| bitdefender.event.isSuccessful |  | integer |
| bitdefender.event.is_container_host |  | integer |
| bitdefender.event.is_fileless_attack |  | integer |
| bitdefender.event.issueType |  | long |
| bitdefender.event.item_count |  | keyword |
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
| bitdefender.id |  | keyword |
| bitdefender.jsonrpc |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.nat.as.number |  | long |
| destination.nat.as.organization.name |  | keyword |
| destination.nat.geo.city_name |  | keyword |
| destination.nat.geo.continent_name |  | keyword |
| destination.nat.geo.country_iso_code |  | keyword |
| destination.nat.geo.country_name |  | keyword |
| destination.nat.geo.location |  | geo_point |
| destination.nat.geo.region_iso_code |  | keyword |
| destination.nat.geo.region_name |  | keyword |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.port | Port of the destination. | long |
| destination.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.sender.address | Per RFC 5322, specifies the address responsible for the actual transmission of the message. | keyword |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| input.type |  | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| organization.id | Unique identifier for the organization. | keyword |
| organization.name | Organization name. | keyword |
| organization.name.text | Multi-field of `organization.name`. | match_only_text |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.software.name | The name of the software used by this threat to conduct behavior commonly modeled using MITRE ATT&CK®. While not required, you can use a MITRE ATT&CK® software name. | keyword |
| threat.technique.id | The id of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name | The name of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name.text | Multi-field of `threat.technique.name`. | match_only_text |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.kernel | Operating system kernel version as a raw string. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| user_agent.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |


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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| input.type |  | keyword |
| tags | List of keywords used to tag each event. | keyword |


An example event for `push_configuration` looks as following:

```json
{
    "@timestamp": "2023-01-27T07:26:02.619Z",
    "agent": {
        "ephemeral_id": "7e1d4d9d-44a4-4ac8-ab34-72e2763c9bf6",
        "id": "f0239f6f-245e-4d57-bada-68e5f564b259",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.1"
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
        "id": "f0239f6f-245e-4d57-bada-68e5f564b259",
        "snapshot": false,
        "version": "8.5.1"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-01-27T07:26:02.619Z",
        "dataset": "bitdefender.push_configuration",
        "ingested": "2023-01-27T07:26:03Z",
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| input.type |  | keyword |
| tags | List of keywords used to tag each event. | keyword |


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
