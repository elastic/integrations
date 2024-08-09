# AbuseCH integration

This integration is for [AbuseCH](https://urlhaus.abuse.ch/) logs. It includes the following datasets for retrieving indicators from the AbuseCH API:

- `url` dataset: Supports URL based indicators from AbuseCH API.
- `malware` dataset: Supports Malware based indicators from AbuseCH API.
- `malwarebazaar` dataset: Supports indicators from the MalwareBazaar from AbuseCH.
- `threatfox` dataset: Supports indicators from AbuseCH Threat Fox API.

## Expiration of Indicators of Compromise (IOCs)
All AbuseCH datasets now support indicator expiration. For `URL` dataset, a full list of active indicators are ingested every interval. For other datasets namely `Malware`, `MalwareBazaar`, and `ThreatFox`, the indicators are expired after duration `IOC Expiration Duration` configured in the integration setting. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to facilitate only active indicators be available to the end users. Each transform creates a destination index named `logs-ti_abusech_latest.dest_*` which only contains active and unexpired indicators. The indiator match rules and dashboards are updated to list only active indicators.
Destinations indices are aliased to `logs-ti_abusech_latest.<datastream_name>`.

| Source Datastream                  | Destination Index Pattern                        | Destination Alias                       |
|:-----------------------------------|:-------------------------------------------------|-----------------------------------------|
| `logs-ti_abusech.url-*`            | `logs-ti_abusech_latest.dest_url-*`              | `logs-ti_abusech_latest.url`            |
| `logs-ti_abusech.malware-*`        | `logs-ti_abusech_latest.dest_malware-*`          | `logs-ti_abusech_latest.malware`        |
| `logs-ti_abusech.malwarebazaar-*`  | `logs-ti_abusech_latest.dest_malwarebazaar-*`    | `logs-ti_abusech_latest.malwarebazaar`  |
| `logs-ti_abusech.threatfox-*`      | `logs-ti_abusech_latest.dest_threatfox-*`        | `logs-ti_abusech_latest.threatfox`      |

### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_abusech.<datastream_name>-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-ti_abusech.<datastream_name>-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

## Logs

### URL

The AbuseCH URL data_stream retrieves full list of active threat intelligence indicators every interval from the Active Indicators URL database dump `https://urlhaus.abuse.ch/downloads/json/`.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abusech.url.blacklists.spamhaus_dbl | If the indicator is listed on the spamhaus blacklist. | keyword |
| abusech.url.blacklists.surbl | If the indicator is listed on the surbl blacklist. | keyword |
| abusech.url.deleted_at | The timestamp when the indicator is (will be) deleted. | date |
| abusech.url.id | The ID of the indicator. | keyword |
| abusech.url.larted | Indicates whether the malware URL has been reported to the hosting provider (true or false). | boolean |
| abusech.url.last_online | Last timestamp when the URL has been serving malware. | date |
| abusech.url.reporter | The Twitter handle of the reporter that has reported this malware URL (or anonymous). | keyword |
| abusech.url.tags | A list of tags associated with the queried malware URL. | keyword |
| abusech.url.threat | The threat corresponding to this malware URL. | keyword |
| abusech.url.url_status | The current status of the URL. Possible values are: online, offline and unknown. | keyword |
| abusech.url.urlhaus_reference | Link to URLhaus entry. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.interval | User-configured value for `Interval` setting. This is used in calculation of indicator expiration time. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


### Malware

The AbuseCH malware data_stream retrieves threat intelligence indicators from the payload API endpoint `https://urlhaus-api.abuse.ch/v1/payloads/recent/`.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abusech.malware.deleted_at | The indicator expiration timestamp. | date |
| abusech.malware.ioc_expiration_duration | The configured expiration duration. | keyword |
| abusech.malware.signature | Malware family. | keyword |
| abusech.malware.virustotal.link | Link to the Virustotal report. | keyword |
| abusech.malware.virustotal.percent | AV detection in percent. | float |
| abusech.malware.virustotal.result | AV detection ratio. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


### MalwareBazaar

The AbuseCH malwarebazaar data_stream retrieves threat intelligence indicators from the MalwareBazaar API endpoint `https://mb-api.abuse.ch/api/v1/`.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abusech.malwarebazaar.anonymous | Identifies if the sample was submitted anonymously. | long |
| abusech.malwarebazaar.code_sign.algorithm | Algorithm used to generate the public key. | keyword |
| abusech.malwarebazaar.code_sign.cscb_listed | Whether the certificate is present on the Code Signing Certificate Blocklist (CSCB). | boolean |
| abusech.malwarebazaar.code_sign.cscb_reason | Why the certificate is present on the Code Signing Certificate Blocklist (CSCB). | keyword |
| abusech.malwarebazaar.code_sign.issuer_cn | Common name (CN) of issuing certificate authority. | keyword |
| abusech.malwarebazaar.code_sign.serial_number | Unique serial number issued by the certificate authority. | keyword |
| abusech.malwarebazaar.code_sign.subject_cn | Common name (CN) of subject. | keyword |
| abusech.malwarebazaar.code_sign.thumbprint | Hash of certificate. | keyword |
| abusech.malwarebazaar.code_sign.thumbprint_algorithm | Algorithm used to create thumbprint. | keyword |
| abusech.malwarebazaar.code_sign.valid_from | Time at which the certificate is first considered valid. | date |
| abusech.malwarebazaar.code_sign.valid_to | Time at which the certificate is no longer considered valid. | keyword |
| abusech.malwarebazaar.deleted_at | The indicator expiration timestamp. | date |
| abusech.malwarebazaar.dhash_icon | In case the file is a PE executable: dhash of the samples icon. | keyword |
| abusech.malwarebazaar.intelligence.downloads | Number of downloads from MalwareBazaar. | long |
| abusech.malwarebazaar.intelligence.mail.Generic | Malware seen in generic spam traffic. | keyword |
| abusech.malwarebazaar.intelligence.mail.IT | Malware seen in IT spam traffic. | keyword |
| abusech.malwarebazaar.intelligence.uploads | Number of uploads from MalwareBazaar. | long |
| abusech.malwarebazaar.ioc_expiration_duration | The configured expiration duration. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


### Threat Fox

The AbuseCH threatfox data_stream retrieves threat intelligence indicators from the Threat Fox API endpoint `https://threatfox-api.abuse.ch/api/v1/`.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abusech.threatfox.confidence_level | Confidence level between 0-100. | long |
| abusech.threatfox.deleted_at | The indicator expiration timestamp. | date |
| abusech.threatfox.ioc_expiration_duration | The configured expiration duration. | keyword |
| abusech.threatfox.malware | The malware associated with the IOC. | keyword |
| abusech.threatfox.tags | A list of tags associated with the queried malware sample. | keyword |
| abusech.threatfox.threat_type | The type of threat. | keyword |
| abusech.threatfox.threat_type_desc | The threat descsription. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
