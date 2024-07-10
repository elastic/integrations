# Netskope

This integration is for Netskope. It can be used to receive logs sent by [Netskope Cloud Log Shipper](https://docs.netskope.com/en/cloud-exchange-feature-lists.html#UUID-e7c43f4b-8aad-679e-eea0-59ce19f16e29_section-idm4547044691454432680066508785) on respective TCP ports.

The log message is expected to be in JSON format. The data is mapped to
ECS fields where applicable and the remaining fields are written under
`netskope.<data-stream-name>.*`.

## Setup steps

1. Configure this integration with the TCP input in Kibana.
2. For all Netskope Cloud Exchange configurations refer to the [Log Shipper](https://docs.netskope.com/en/cloud-exchange-feature-lists.html#UUID-e7c43f4b-8aad-679e-eea0-59ce19f16e29_section-idm4547044691454432680066508785).
3. In Netskope Cloud Exchange please enable Log Shipper, add your Netskope Tenant.
4. Configure input connectors:
    1. First with all Event types, and
    2. Second with all Alerts type.
    For detailed steps refer to [Configure the Netskope Plugin for Log Shipper](https://docs.netskope.com/en/configure-the-netskope-plugin-for-log-shipper.html).
5. Configure output connectors:
    1. Navigate to Settings -> Plugins.
    2. Add separate output connector **Elastic CLS** for both Alerts and Events and select mapping **"Elastic Default Mappings (Recommended)"** for both.
6. Create business rules:
    1. Navigate to Home Page > Log Shipper > Business Rules.
    2. Create business rules with Netskope Alerts.
    3. Create business rules with Netskope Events.
    For detailed steps refer to [Manage Log Shipper Business Rules](https://docs.netskope.com/en/manage-log-shipper-business-rules.html).
7. Adding SIEM mappings:
    1. Navigate to Home Page > Log Shipper > SIEM Mappings
    2. Add SIEM mapping for events:
        * Add **Rule** put rule created in step 6.
        * Add **Source Configuration** put input created for Events in step 4.
        * Add **Destination Configuration**, put output created for Events in step 5.

> Note: For detailed steps refer to [Configure Log Shipper SIEM Mappings](https://docs.netskope.com/en/configure-log-shipper-siem-mappings.html).
Please make sure to use the given response formats.

## Compatibility

This package has been tested against `Netskope version 95.1.0.645` and `Netskope Cloud Exchange version 3.4.0`.

## Documentation and configuration

### Alerts

Default port: _9020_

### Events

Default port: _9021_

## Fields and Sample event

### Alerts

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| netskope.alerts.Url2Activity | Populated if the activity from the URL matches certain activities. This field applies to Risk Insights only. | keyword |
| netskope.alerts.access_method | Cloud app traffic can be steered to the Netskope cloud using different deployment methods such as Client (Netskope Client), Secure Forwarder etc. Administrators can also upload firewall and/or proxy logs for log analytics. This field shows the actual access method that triggered the event. For log uploads this shows the actual log type such as PAN, Websense, etc. | keyword |
| netskope.alerts.account.id | Account ID (usually is account number as provided by the cloud provider). | keyword |
| netskope.alerts.account.name | Account name - in case of AWS this is the instance name set by user. For others, account name is provided by cloud provider. | keyword |
| netskope.alerts.acked | Whether user acknowledged the alert or not. | boolean |
| netskope.alerts.acting.role | N/A | keyword |
| netskope.alerts.action | Action taken on the event for the policy. | keyword |
| netskope.alerts.activities | N/A | keyword |
| netskope.alerts.activity.name | Description of the user performed activity. | keyword |
| netskope.alerts.activity.status | Displayed when the user is denied access while performing some activity. | keyword |
| netskope.alerts.activity.type | Displayed when only admins can perform the activity in question. | keyword |
| netskope.alerts.agg.window | N/A | long |
| netskope.alerts.aggregated.user | N/A | boolean |
| netskope.alerts.alert.affected.entities | N/A | keyword |
| netskope.alerts.alert.category | N/A | keyword |
| netskope.alerts.alert.description | N/A | keyword |
| netskope.alerts.alert.detection.stage | N/A | keyword |
| netskope.alerts.alert.id | Hash of alert generated from code. | keyword |
| netskope.alerts.alert.name | Name of the alert. | keyword |
| netskope.alerts.alert.notes | N/A | keyword |
| netskope.alerts.alert.query | N/A | keyword |
| netskope.alerts.alert.score | N/A | long |
| netskope.alerts.alert.source | N/A | keyword |
| netskope.alerts.alert.status | N/A | keyword |
| netskope.alerts.alert.type | Shows if it is an application event or a connection event. Application events are recorded to track user events inside a cloud app. Connection events shows the actual HTTP connection. | keyword |
| netskope.alerts.alert.window | N/A | long |
| netskope.alerts.algorithm | N/A | keyword |
| netskope.alerts.anomaly.efficacy | Full anomaly details for debugging. | keyword |
| netskope.alerts.anomaly.fields | Name(s) and values(s) of the anomalous fields, usually there's going to be only one in the list. | keyword |
| netskope.alerts.anomaly.id | N/A | keyword |
| netskope.alerts.anomaly.magnitude | N/A | double |
| netskope.alerts.anomaly.type | Type of UBA alert. | keyword |
| netskope.alerts.app.activity | N/A | keyword |
| netskope.alerts.app.app_name | N/A | keyword |
| netskope.alerts.app.category | N/A | keyword |
| netskope.alerts.app.name | Specific cloud application used by the user (e.g. app = Dropbox). | keyword |
| netskope.alerts.app.region | N/A | keyword |
| netskope.alerts.app.session.id | Unique App/Site Session ID for traffic_type = CloudApp and Web. An app session starts when a user starts using a cloud app/site on and ends once they have been inactive for a certain period of time(15 mins). Use app_session_id to check all the user activities in a single app session. app_session_id is unique for a user, device, browser and domain. | keyword |
| netskope.alerts.app.suite | N/A | keyword |
| netskope.alerts.asn | N/A | long |
| netskope.alerts.asset.id | N/A | keyword |
| netskope.alerts.asset.object.id | N/A | keyword |
| netskope.alerts.attachment | File name. | keyword |
| netskope.alerts.audit.category | The subcategories in an application such as IAM, EC in AWS, login, token, file, etc., in case of Google. | keyword |
| netskope.alerts.audit.type | The sub category in audit according to SaaS / IaaS apps. | keyword |
| netskope.alerts.bin.timestamp | Applicable to only: Shared Credentials, Data Exfiltration, Bulk Anomaly types( Bulk Upload/Download/Delete) and Failed Login Anomaly type. Bin TimeStamp (is a window used that is used for certain types of anomalies - for breaking into several windows per day/hour). | long |
| netskope.alerts.breach.date | Breach date for compromised credentials. | double |
| netskope.alerts.breach.description | N/A | keyword |
| netskope.alerts.breach.id | Breach ID for compromised credentials. | keyword |
| netskope.alerts.breach.media_references | Media references of breach. | keyword |
| netskope.alerts.breach.score | Breach score for compromised credentials. | long |
| netskope.alerts.breach.target_references | Breach target references for compromised credentials. | keyword |
| netskope.alerts.browser.session.id | Browser session ID. If there is an idle timeout of 15 minutes, it will timeout the session. | keyword |
| netskope.alerts.bucket | N/A | keyword |
| netskope.alerts.bypass.traffic | Tells if traffic is bypassed by Netskope. | boolean |
| netskope.alerts.category.id | Matching category ID according to policy. Populated for both cloud and web traffic. | keyword |
| netskope.alerts.category.name | N/A | keyword |
| netskope.alerts.cci | N/A | keyword |
| netskope.alerts.ccl | Cloud Confidence Level. CCL measures the enterprise readiness of the cloud apps taking into consideration those apps security, auditability and business continuity. Each app is assigned one of five cloud confidence levels: excellent, high, medium, low, or poor. Useful for querying if users are accessing a cloud app with a lower CCL. | keyword |
| netskope.alerts.channel | Channel of the user for slack and slack enterprise apps. | keyword |
| netskope.alerts.cloud.provider | N/A | keyword |
| netskope.alerts.compliance.standards | N/A | keyword |
| netskope.alerts.compute.instance | N/A | keyword |
| netskope.alerts.connection.duration | Duration of the connection in milliseconds. Useful for querying long-lived sessions. | long |
| netskope.alerts.connection.endtime | Connection end time. | long |
| netskope.alerts.connection.id | Each connection has a unique ID. Shows the ID for the connection event. | keyword |
| netskope.alerts.connection.starttime | Connection start time. | long |
| netskope.alerts.count | Number of raw log lines/events sessionized or suppressed during the suppressed interval. | long |
| netskope.alerts.created_at | N/A | keyword |
| netskope.alerts.data.type | Content type of upload/download. | keyword |
| netskope.alerts.data.version | N/A | long |
| netskope.alerts.description | N/A | keyword |
| netskope.alerts.destination.geoip_src | Source from where the location of Destination IP was derived. | long |
| netskope.alerts.detected-file-type | N/A | keyword |
| netskope.alerts.detection.engine | Customer exposed detection engine name. | keyword |
| netskope.alerts.detection.type | Same as malware type. Duplicate. | keyword |
| netskope.alerts.device.classification | Designation of device as determined by the Netskope Client as to whether the device is managed or not. | keyword |
| netskope.alerts.device.name | Device type from where the user accessed the cloud app. It could be Macintosh Windows device, iPad etc. | keyword |
| netskope.alerts.dlp.file | File/Object name extracted from the file/object. | keyword |
| netskope.alerts.dlp.fingerprint.classification | Fingerprint classification. | keyword |
| netskope.alerts.dlp.fingerprint.match | Fingerprint classification match file name. | keyword |
| netskope.alerts.dlp.fingerprint.score | Fingerprint classification score. | long |
| netskope.alerts.dlp.fv | N/A | long |
| netskope.alerts.dlp.incident.id | Incident ID associated with sub-file. In the case of main file, this is same as the parent incident ID. | keyword |
| netskope.alerts.dlp.is_unique_count | True or false depending upon if rule is unique counted per rule data. | boolean |
| netskope.alerts.dlp.mail.parent.id | N/A | keyword |
| netskope.alerts.dlp.parent.id | Incident ID associated with main container (or non-container) file that was scanned. | keyword |
| netskope.alerts.dlp.profile | DLP profile name. | keyword |
| netskope.alerts.dlp.rule.count | Count of rule hits. | long |
| netskope.alerts.dlp.rule.name | DLP rule that triggered. | keyword |
| netskope.alerts.dlp.rule.score | DLP rule score for weighted dictionaries. | long |
| netskope.alerts.dlp.rule.severity | Severity of rule. | keyword |
| netskope.alerts.dlp.unique_count | Integer value of number of unique matches seen per rule data. Only present if rule is uniquely counted. | long |
| netskope.alerts.doc.count | N/A | long |
| netskope.alerts.domain | Domain value. This will hold the host header value or SNI or extracted from absolute URI. | keyword |
| netskope.alerts.domain_shared_with | N/A | keyword |
| netskope.alerts.download.app | Applicable to only data exfiltration. Download App (App in the download event). | keyword |
| netskope.alerts.drive.id | N/A | keyword |
| netskope.alerts.dynamic.classification | URLs were categorized by NSURLC machine or not. | keyword |
| netskope.alerts.elastic_key | N/A | keyword |
| netskope.alerts.email.source | N/A | keyword |
| netskope.alerts.encrypt.failure | Reason of failure while encrypting. | keyword |
| netskope.alerts.encryption.service.key | N/A | keyword |
| netskope.alerts.enterprise.id | EnterpriseID in case of Slack for Enterprise. | keyword |
| netskope.alerts.enterprise.name | Enterprise name in case of Slack for Enterprise. | keyword |
| netskope.alerts.entity.list | N/A | keyword |
| netskope.alerts.entity.type | N/A | keyword |
| netskope.alerts.entity.value | N/A | keyword |
| netskope.alerts.event.detail | N/A | keyword |
| netskope.alerts.event.id | N/A | keyword |
| netskope.alerts.event.type | Anomaly type. | keyword |
| netskope.alerts.event_source_channel | N/A | keyword |
| netskope.alerts.exposure | Exposure of a document. | keyword |
| netskope.alerts.external.collaborator.count | Count of external collaborators on a file/folder. Supported for some apps. | long |
| netskope.alerts.external.email | N/A | long |
| netskope.alerts.feature.description | N/A | keyword |
| netskope.alerts.feature.id | N/A | keyword |
| netskope.alerts.feature.name | N/A | keyword |
| netskope.alerts.file.id | Unique identifier of the file. | keyword |
| netskope.alerts.file.lang | Language of the file. | keyword |
| netskope.alerts.file.name | N/A | keyword |
| netskope.alerts.file.password.protected | N/A | keyword |
| netskope.alerts.file.path.orignal | If the file is moved, then keep original path of the file in this field. | keyword |
| netskope.alerts.file.size | Size of the file in bytes. | long |
| netskope.alerts.file.type | File type. | keyword |
| netskope.alerts.flow_status | N/A | keyword |
| netskope.alerts.from.logs | Shows if the event was generated from the Risk Insights log. | keyword |
| netskope.alerts.from.object | Initial name of an object that has been renamed, copied or moved. | keyword |
| netskope.alerts.from.storage | N/A | keyword |
| netskope.alerts.from.user_category | Type of from_user. | keyword |
| netskope.alerts.gateway | N/A | keyword |
| netskope.alerts.graph.id | N/A | keyword |
| netskope.alerts.http_status | N/A | keyword |
| netskope.alerts.http_transaction_count | HTTP transaction count. | long |
| netskope.alerts.iaas.asset.tags | List of tags associated with the asset for which alert is raised. Each tag is a key/value pair. | keyword |
| netskope.alerts.iaas.remediated | N/A | keyword |
| netskope.alerts.iam.session | N/A | keyword |
| netskope.alerts.id | N/A | keyword |
| netskope.alerts.insertion_epoch_timestamp | Insertion timestamp. | long |
| netskope.alerts.instance.id | Unique ID associated with an organization application instance. | keyword |
| netskope.alerts.instance.name | Instance name associated with an organization application instance. | keyword |
| netskope.alerts.instance.type | Instance type. | keyword |
| netskope.alerts.instance_name | Instance associated with an organization application instance. | keyword |
| netskope.alerts.internal.collaborator.count | Count of internal collaborators on a file/folder. Supported for some apps. | long |
| netskope.alerts.ip.protocol | N/A | keyword |
| netskope.alerts.ipblock | IPblock that caused the alert. | keyword |
| netskope.alerts.is_alert | Indicates whether alert is generated or not. Populated as yes for all alerts. | boolean |
| netskope.alerts.is_file_passwd_protected | Tells if the file is password protected. | boolean |
| netskope.alerts.is_malicious | Only exists if some HTTP transaction belonging to the page event resulted in a malsite alert. | boolean |
| netskope.alerts.is_two_factor_auth | N/A | keyword |
| netskope.alerts.is_universal_connector | N/A | keyword |
| netskope.alerts.is_user_generated | Tells whether it is user generated page event. | boolean |
| netskope.alerts.is_web_universal_connector | N/A | boolean |
| netskope.alerts.isp | N/A | keyword |
| netskope.alerts.item.id | N/A | keyword |
| netskope.alerts.justification.reason | Justification reason provided by user. For following policies, justification events are raised. User is displayed a notification popup, user enters justification and can select to proceed or block: useralert policy, dlp block policy, block policy with custom template which contains justification text box. | keyword |
| netskope.alerts.justification.type | Type of justification provided by user when user bypasses the policy block. | keyword |
| netskope.alerts.last.app | Last application (app in the first/older event). Applies to only proximity anomaly alert. | keyword |
| netskope.alerts.last.coordinates | Last location coordinates(latitude, longitude). Applies to only proximity alert. | keyword |
| netskope.alerts.last.country | Last location (Country). Applies to only proximity anomaly alert. | keyword |
| netskope.alerts.last.device | Last device name (Device Name in the first/older event). Applies to only proximity anomaly alert. | keyword |
| netskope.alerts.last.location | Last location (City). Applies to only proximity anomaly alert. | keyword |
| netskope.alerts.last.modified_timestamp | Timestamp when alert is acknowledged. | long |
| netskope.alerts.last.region | Applies to only proximity anomaly alert. | keyword |
| netskope.alerts.last.timestamp | Last timestamp (timestamp in the first/older event). Applies to only proximity anomaly alert. | long |
| netskope.alerts.latency.max | Max latency for a connection in milliseconds. | long |
| netskope.alerts.latency.min | Min latency for a connection in milliseconds. | long |
| netskope.alerts.latency.total | Total latency from proxy to app in milliseconds. | long |
| netskope.alerts.legal_hold.custodian_name | Custodian name of legal hold profile. | keyword |
| netskope.alerts.legal_hold.destination.app | Destination appname of legalhold action. | keyword |
| netskope.alerts.legal_hold.destination.instance | Destination instance of legal hold action. | keyword |
| netskope.alerts.legal_hold.file.id | File ID of legal hold file. | keyword |
| netskope.alerts.legal_hold.file.name | File name of legal hold file. | keyword |
| netskope.alerts.legal_hold.file.name_original | Original filename of legal hold file. | keyword |
| netskope.alerts.legal_hold.file.path | File path of legal hold file. | keyword |
| netskope.alerts.legal_hold.profile_name | Legal hold profile name. | keyword |
| netskope.alerts.legal_hold.shared | Shared type of legal hold file. | keyword |
| netskope.alerts.legal_hold.shared_with | User shared with the legal hold file. | keyword |
| netskope.alerts.legal_hold.version | File version of original file. | keyword |
| netskope.alerts.list.id | N/A | keyword |
| netskope.alerts.local.md5 | md5 hash of file generated by Malware engine. | keyword |
| netskope.alerts.local.sha1 | sha1 hash of file generated by Malware engine. | keyword |
| netskope.alerts.local.sha256 | sha256 hash of file generated by Malware engine. | keyword |
| netskope.alerts.log.file.name | Log file name for Risk Insights. | keyword |
| netskope.alerts.login.type | Salesforce login type. | keyword |
| netskope.alerts.login.url.domain |  | keyword |
| netskope.alerts.login.url.extension |  | keyword |
| netskope.alerts.login.url.fragment |  | keyword |
| netskope.alerts.login.url.full |  | keyword |
| netskope.alerts.login.url.original |  | keyword |
| netskope.alerts.login.url.password |  | keyword |
| netskope.alerts.login.url.path |  | keyword |
| netskope.alerts.login.url.port |  | long |
| netskope.alerts.login.url.query |  | keyword |
| netskope.alerts.login.url.scheme |  | keyword |
| netskope.alerts.login.url.username |  | keyword |
| netskope.alerts.malsite.active | Since how many days malsite is Active. | long |
| netskope.alerts.malsite.as.number | Malsite ASN Number. | keyword |
| netskope.alerts.malsite.category | Category of malsite [ Phishing / Botnet / Malicous URL, etc. ]. | keyword |
| netskope.alerts.malsite.city | Malsite city. | keyword |
| netskope.alerts.malsite.confidence | Malsite confidence score. | long |
| netskope.alerts.malsite.consecutive | How many times that malsite is seen. | long |
| netskope.alerts.malsite.country | Malsite country. | keyword |
| netskope.alerts.malsite.dns.server | DNS server of the malsite URL/Domain/IP. | keyword |
| netskope.alerts.malsite.first_seen | Malsite first seen timestamp. | long |
| netskope.alerts.malsite.hostility | Malsite hostility score. | long |
| netskope.alerts.malsite.id | Malicious Site ID - Hash of threat match value. | keyword |
| netskope.alerts.malsite.ip_host | Malsite IP. | keyword |
| netskope.alerts.malsite.isp | Malsite ISP info. | keyword |
| netskope.alerts.malsite.last.seen | Malsite last seen timestamp. | long |
| netskope.alerts.malsite.latitude | Latitude plot of the Malsite URL/IP/Domain. | double |
| netskope.alerts.malsite.longitude | Longitude plot of the Malsite URL/IP/Domain. | double |
| netskope.alerts.malsite.region | Region of the malsite URL/IP/Domain. | keyword |
| netskope.alerts.malsite.reputation | Reputation score of Malsite IP/Domain/URL. | double |
| netskope.alerts.malsite.severity.level | Severity level of the Malsite ( High / Med / Low). | keyword |
| netskope.alerts.malware.id | md5 hash of the malware name as provided by the scan engine. | keyword |
| netskope.alerts.malware.name | Netskope detection name. | keyword |
| netskope.alerts.malware.profile | tss_profile: profile which user has selected. Data comes from WebUI. Its a json structure. | keyword |
| netskope.alerts.malware.severity | Malware severity. | keyword |
| netskope.alerts.malware.type | Malware Type. | keyword |
| netskope.alerts.managed.app | Whether or not the app in question is managed. | boolean |
| netskope.alerts.management.id | Management ID. | keyword |
| netskope.alerts.matched.username | N/A | keyword |
| netskope.alerts.matrix.columns | N/A | keyword |
| netskope.alerts.matrix.rows | N/A | keyword |
| netskope.alerts.md5 | md5 of the file. | keyword |
| netskope.alerts.md5_list | List of md5 hashes specific to the files that are part of custom sequence policy alert. | keyword |
| netskope.alerts.mime.type | MIME type of the file. | keyword |
| netskope.alerts.ml_detection | N/A | boolean |
| netskope.alerts.modified.date | N/A | long |
| netskope.alerts.modified.timestamp | Timestamp corresponding to the modification time of the entity (file, etc.). | long |
| netskope.alerts.netskope_pop | N/A | keyword |
| netskope.alerts.network.name | N/A | keyword |
| netskope.alerts.network.security.group | N/A | keyword |
| netskope.alerts.new.value | New value for a given file for salesforce.com. | keyword |
| netskope.alerts.nonzero.entries | N/A | long |
| netskope.alerts.nonzero.percentage | N/A | double |
| netskope.alerts.notify.template | N/A | keyword |
| netskope.alerts.ns_activity | Maps app activity to Netskope standard activity. | keyword |
| netskope.alerts.ns_device_uid | Device identifiers on macOS and Windows. | keyword |
| netskope.alerts.numbytes | Total number of bytes that were transmitted for the connection - numbytes = client_bytes + server_bytes. | long |
| netskope.alerts.obfuscate | N/A | boolean |
| netskope.alerts.object.count | Displayed when the activity is Delete. Shows the number of objects being deleted. | long |
| netskope.alerts.object.id | Unique ID associated with an object. | keyword |
| netskope.alerts.object.name | Name of the object which is being acted on. It could be a filename, folder name, report name, document name, etc. | keyword |
| netskope.alerts.object.type | Type of the object which is being acted on. Object type could be a file, folder, report, document, message, etc. | keyword |
| netskope.alerts.old.value | Old value for a given file for salesforce.com. | keyword |
| netskope.alerts.org | Search for events from a specific organization. Organization name is derived from the user ID. | keyword |
| netskope.alerts.organization.unit | Org Units for which the event correlates to. This ties to user information extracted from Active Directory using the Directory Importer/AD Connector application. | keyword |
| netskope.alerts.orig_ty | Event Type of original event. | keyword |
| netskope.alerts.original.file_path | If the file is moved, then keep original path of the file in this field. | keyword |
| netskope.alerts.os_version_hostname | Host and OS Version that caused the alert. Concatenation of 2 fields (hostname and os). | keyword |
| netskope.alerts.other.categories | N/A | keyword |
| netskope.alerts.owner | Owner of the file. | keyword |
| netskope.alerts.page.site | N/A | keyword |
| netskope.alerts.page.url.domain |  | keyword |
| netskope.alerts.page.url.extension |  | keyword |
| netskope.alerts.page.url.fragment |  | keyword |
| netskope.alerts.page.url.full |  | keyword |
| netskope.alerts.page.url.original |  | keyword |
| netskope.alerts.page.url.password |  | keyword |
| netskope.alerts.page.url.path |  | keyword |
| netskope.alerts.page.url.port |  | long |
| netskope.alerts.page.url.query |  | keyword |
| netskope.alerts.page.url.scheme |  | keyword |
| netskope.alerts.page.url.username |  | keyword |
| netskope.alerts.parameters | N/A | keyword |
| netskope.alerts.parent.id | N/A | keyword |
| netskope.alerts.path.id | N/A | keyword |
| netskope.alerts.policy.actions | N/A | keyword |
| netskope.alerts.policy.id | The Netskope internal ID for the policy created by an admin. | keyword |
| netskope.alerts.policy.name | Predefined or Custom policy name. | keyword |
| netskope.alerts.pretty.sourcetype | N/A | keyword |
| netskope.alerts.processing.time | N/A | long |
| netskope.alerts.profile.emails | List of profile emails per policy. | keyword |
| netskope.alerts.profile.id | Anomaly profile ID. | keyword |
| netskope.alerts.quarantine.action.reason | Reason for the action taken for quarantine. | keyword |
| netskope.alerts.quarantine.admin | Quarantine profile custodian email/name. | keyword |
| netskope.alerts.quarantine.app | Quarantine app name. | keyword |
| netskope.alerts.quarantine.failure | Reason of failure. | keyword |
| netskope.alerts.quarantine.file.id | File ID of the quarantined file. | keyword |
| netskope.alerts.quarantine.file.name | File name of the quarantine file. | keyword |
| netskope.alerts.quarantine.instance | Quarantine instance name. | keyword |
| netskope.alerts.quarantine.original.file.name | Original file name which got quarantined. | keyword |
| netskope.alerts.quarantine.original.file.path | Original file path which got quarantined. | keyword |
| netskope.alerts.quarantine.original.shared | Original file shared user details. | keyword |
| netskope.alerts.quarantine.original.version | Original version of file which got quarantined. | keyword |
| netskope.alerts.quarantine.profile.id | Quarantine profile ID. | keyword |
| netskope.alerts.quarantine.profile.name | Quarantine profile name of policy for quarantine action. | keyword |
| netskope.alerts.quarantine.shared.with | N/A | keyword |
| netskope.alerts.referer.domain |  | keyword |
| netskope.alerts.referer.extension |  | keyword |
| netskope.alerts.referer.fragment |  | keyword |
| netskope.alerts.referer.full |  | keyword |
| netskope.alerts.referer.original |  | keyword |
| netskope.alerts.referer.password |  | keyword |
| netskope.alerts.referer.path |  | keyword |
| netskope.alerts.referer.port |  | long |
| netskope.alerts.referer.query |  | keyword |
| netskope.alerts.referer.scheme |  | keyword |
| netskope.alerts.referer.username |  | keyword |
| netskope.alerts.region.id | Region ID (as provided by the cloud provider). | keyword |
| netskope.alerts.region.name | N/A | keyword |
| netskope.alerts.reladb | N/A | keyword |
| netskope.alerts.repo | N/A | keyword |
| netskope.alerts.request.cnt | Total number of HTTP requests (equal to number of transaction events for this page event) sent from client to server over one underlying TCP connection. | long |
| netskope.alerts.request.id | Unique request ID for the event. | keyword |
| netskope.alerts.resource.category | Category of resource as defined in DOM. | keyword |
| netskope.alerts.resource.group | N/A | keyword |
| netskope.alerts.resources | N/A | keyword |
| netskope.alerts.response.cnt | Total number of HTTP responses (equal to number of transaction events for this page event) from server to client. | long |
| netskope.alerts.response.content.length | N/A | long |
| netskope.alerts.response.content.type | N/A | keyword |
| netskope.alerts.retro.scan.name | Retro scan name. | keyword |
| netskope.alerts.risk_level.id | This field is set by both role-based access (RBA) and MLAD. | keyword |
| netskope.alerts.risk_level.tag | Corresponding field to risk_level_id. Name. | keyword |
| netskope.alerts.role | Roles for Box. | keyword |
| netskope.alerts.rule.id | N/A | keyword |
| netskope.alerts.sa.profile.id | CSA profile ID. | keyword |
| netskope.alerts.sa.profile.name | CSA profile name. | keyword |
| netskope.alerts.sa.rule.id | CSA rule ID. | keyword |
| netskope.alerts.sa.rule.name | CSA rule name. | keyword |
| netskope.alerts.sa.rule.remediation | N/A | keyword |
| netskope.alerts.sa.rule.severity | Rule severity. | keyword |
| netskope.alerts.scan.time | Time when the scan is done. | long |
| netskope.alerts.scan.type | Generated during retroactive scan or new ongoing activity. | keyword |
| netskope.alerts.scanner_result | N/A | keyword |
| netskope.alerts.scopes | List of permissions for google apps. | keyword |
| netskope.alerts.serial | N/A | keyword |
| netskope.alerts.server.bytes | Total number of downloaded from server to client. | long |
| netskope.alerts.session.id | Populated by Risk Insights. | keyword |
| netskope.alerts.severity.id | Severity ID used by watchlist and malware alerts. | keyword |
| netskope.alerts.severity.level | Severity used by watchlist and malware alerts. | keyword |
| netskope.alerts.severity.level_id | If the Severity Level ID is 1, it means that URL / IP /Domain is detected from Internal threat feed and if Severity Level ID is 2, then it means the detection happened based on the Zvelo DB Malsite Category. | long |
| netskope.alerts.sfwder | N/A | keyword |
| netskope.alerts.shared.credential.user | Applicable to only shared credentials. User with whom the credentials are shared with. | keyword |
| netskope.alerts.shared.domains | List of domains of users the document is shared with. | keyword |
| netskope.alerts.shared.is_shared | If the file is shared or not. | boolean |
| netskope.alerts.shared.type | Shared Type. | keyword |
| netskope.alerts.shared.with | Array of emails with whom a document is shared with. | keyword |
| netskope.alerts.shared_type | N/A | keyword |
| netskope.alerts.site | For traffic_type = CloudApp, site = app and for traffic_type = Web, it will be the second level domain name + top-level domain name. For example, in "www.cnn.com", it is "cnn.com". | keyword |
| netskope.alerts.slc_latitude | N/A | keyword |
| netskope.alerts.slc_longitude | N/A | keyword |
| netskope.alerts.source.geoip_src | Source from where the location of Source IP was derived. | long |
| netskope.alerts.source.time | N/A | keyword |
| netskope.alerts.srcip2 | N/A | keyword |
| netskope.alerts.ssl.decrypt.policy | Applicable to only bypass events. There are 2 ways to create rules for bypass: Bypass due to Exception Configuration Bypass due to SSL Decrypt Policy The existing flag bypass_traffic only gives information that a flow has been bypassed, but does not tell exactly which policy was responsible for it. ssl_decrypt_policy field will provide this extra information. In addition, policy field will be also set for every Bypass event. | keyword |
| netskope.alerts.start_time | Start time for alert time period. | long |
| netskope.alerts.statistics | This field & summary field go together. This field will either tell count or size of files. File size is in bytes. | long |
| netskope.alerts.storage_service_bucket | N/A | keyword |
| netskope.alerts.sub.type | Workplace by Facebook post sub category (files, comments, status etc). | keyword |
| netskope.alerts.summary | Tells whether anomaly was measured from count or size of files. | keyword |
| netskope.alerts.suppression.end.time | When events are suppressed (like collaboration apps), then the suppression end time will be set and only one event will be send with suppression start time and end time and count of occurrence. | long |
| netskope.alerts.suppression.key | To limit the number of events. Example: Suppress block event for browse. | keyword |
| netskope.alerts.suppression.start.time | When events are suppressed (like collaboration apps), then the suppression end time will be set and only one event will be send with suppression start time and end time and count of occurrence. | long |
| netskope.alerts.target.entity.key | N/A | keyword |
| netskope.alerts.target.entity.type | N/A | keyword |
| netskope.alerts.target.entity.value | N/A | keyword |
| netskope.alerts.team | Slack team name. | keyword |
| netskope.alerts.telemetry.app | Typically SaaS app web sites use web analytics code within the pages to gather analytic data. When a SaaS app action or page is shown, there is subsequent traffic generated to tracking apps such as doubleclick.net, Optimizely, etc. These tracking apps are listed if applicable in the Telemetry App field. | keyword |
| netskope.alerts.temp.user | N/A | keyword |
| netskope.alerts.tenant.id | Tenant id. | keyword |
| netskope.alerts.threat.match.field | Threat match field, either from domain or URL or IP. | keyword |
| netskope.alerts.threat.match.value | N/A | keyword |
| netskope.alerts.threat.source.id | Threat source id: 1 - NetskopeThreatIntel, 2 - Zvelodb. | keyword |
| netskope.alerts.threshold.time | Applicable to: Shared Credentials, Data Exfiltration, Bulk Anomaly types( Bulk Upload/ Download/ Delete) and Failed Login Anomaly type. Threshold Time. | long |
| netskope.alerts.threshold.value | Threshold (Count at which the anomaly should trigger). Applicable to Bulk Anomaly types( Bulk Upload/ Download/ Delete) and Failed Login Anomaly type. | long |
| netskope.alerts.title | Title of the file. | keyword |
| netskope.alerts.to.object | Changed name of an object that has been renamed, copied, or moved. | keyword |
| netskope.alerts.to.storage | N/A | keyword |
| netskope.alerts.to.user | Used when a file is moved from user A to user B. Shows the email address of user B. | keyword |
| netskope.alerts.to.user_category | Type of user to which move is done. | keyword |
| netskope.alerts.total.collaborator.count | Count of collaborators on a file/folder. Supported for some apps. | long |
| netskope.alerts.traffic.type | Type of the traffic: CloudApp or Web. CloudApp indicates CASB and web indicates HTTP traffic. Web traffic is only captured for inline access method. It is currently not captured for Risk Insights. | keyword |
| netskope.alerts.transaction.id | Unique ID for a given request/response. | keyword |
| netskope.alerts.transformation | N/A | keyword |
| netskope.alerts.tss.mode | Malware scanning mode, specifies whether it's Real-time Protection or API Data Protection. | keyword |
| netskope.alerts.tss.version | N/A | long |
| netskope.alerts.tunnel.id | Shows the Client installation ID. Only available for the Client steering configuration. | keyword |
| netskope.alerts.type | Type of the alert. | keyword |
| netskope.alerts.uba_ap1 | N/A | keyword |
| netskope.alerts.uba_ap2 | N/A | keyword |
| netskope.alerts.uba_inst1 | N/A | keyword |
| netskope.alerts.uba_inst2 | N/A | keyword |
| netskope.alerts.updated | N/A | long |
| netskope.alerts.url.domain |  | keyword |
| netskope.alerts.url.extension |  | keyword |
| netskope.alerts.url.fragment |  | keyword |
| netskope.alerts.url.full |  | keyword |
| netskope.alerts.url.original |  | keyword |
| netskope.alerts.url.password |  | keyword |
| netskope.alerts.url.path |  | keyword |
| netskope.alerts.url.port |  | long |
| netskope.alerts.url.query |  | keyword |
| netskope.alerts.url.scheme |  | keyword |
| netskope.alerts.url.username |  | keyword |
| netskope.alerts.user.category | Type of user in an enterprise - external / internal. | keyword |
| netskope.alerts.user.geo.city_name | City name. | keyword |
| netskope.alerts.user.geo.continent_name | Name of the continent. | keyword |
| netskope.alerts.user.geo.country_iso_code | Country ISO code. | keyword |
| netskope.alerts.user.geo.country_name | Country name. | keyword |
| netskope.alerts.user.geo.location | Longitude and latitude. | geo_point |
| netskope.alerts.user.geo.region_iso_code | Region ISO code. | keyword |
| netskope.alerts.user.geo.region_name | Region name. | keyword |
| netskope.alerts.user.group | N/A | keyword |
| netskope.alerts.user.ip | IP address of User. | keyword |
| netskope.alerts.value | N/A | double |
| netskope.alerts.violating_user.name | User who caused a violation. Populated for Workplace by Facebook. | keyword |
| netskope.alerts.violating_user.type | Category of the user who caused a violation. Populated for Workplace by Facebook. | keyword |
| netskope.alerts.web.url.domain |  | keyword |
| netskope.alerts.web.url.extension |  | keyword |
| netskope.alerts.web.url.fragment |  | keyword |
| netskope.alerts.web.url.full |  | keyword |
| netskope.alerts.web.url.original |  | keyword |
| netskope.alerts.web.url.password |  | keyword |
| netskope.alerts.web.url.path |  | keyword |
| netskope.alerts.web.url.port |  | long |
| netskope.alerts.web.url.query |  | keyword |
| netskope.alerts.web.url.scheme |  | keyword |
| netskope.alerts.web.url.username |  | keyword |
| netskope.alerts.workspace.id | Workspace ID in case of Slack for Enterprise. | keyword |
| netskope.alerts.workspace.name | Workspace name in case of Slack for Enterprise. | keyword |
| netskope.alerts.zip.password | Zip the malicious file and put pwd to it and send it back to caller. | keyword |


An example event for `alerts` looks as following:

```json
{
    "@timestamp": "2021-12-23T16:27:09.000Z",
    "agent": {
        "ephemeral_id": "275c19c7-0f2c-467b-850f-c153e4a77147",
        "id": "7b99f48c-6c10-4dad-86c4-ee578beef412",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "netskope.alerts",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "81.2.69.143",
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.143"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7b99f48c-6c10-4dad-86c4-ee578beef412",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "id": "f621f259f5fbde850ad5593a",
        "ingested": "2024-03-29T07:17:15Z"
    },
    "file": {
        "hash": {
            "md5": "4bb5d9501bf7685ecaed55e3eda9ca01"
        },
        "mime_type": [
            "application\\\\/vnd.apps.document"
        ],
        "path": "\\\\/My Drive\\\\/Clickhouse\\\\/Tenant Migration across MPs",
        "size": 196869
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.224.6:60788"
        }
    },
    "netskope": {
        "alerts": {
            "access_method": "API Connector",
            "acked": false,
            "action": "block",
            "activity": {
                "name": "Login Successful"
            },
            "alert": {
                "name": "policy-alert",
                "type": "nspolicy"
            },
            "app": {
                "category": "Cloud Storage",
                "name": "SomeApp"
            },
            "category": {
                "name": "Cloud Storage"
            },
            "cci": "81",
            "ccl": "high",
            "count": 1,
            "destination": {
                "geoip_src": 2
            },
            "device": {
                "name": "Other"
            },
            "exposure": "organization_wide_link",
            "file": {
                "lang": "ENGLISH"
            },
            "insertion_epoch_timestamp": 1640277131,
            "instance": {
                "id": "example.com",
                "name": "example.com"
            },
            "is_alert": true,
            "modified": {
                "timestamp": 1613760236
            },
            "object": {
                "id": "GxyjNjJxKg14W3Mb57aLY9_klcxToPEyqIoNAcF82rGg",
                "name": "HjBuUvDLWgpudzQr",
                "type": "File"
            },
            "organization": {
                "unit": "example.local\\\\/example\\\\/Active Users"
            },
            "owner": "foobar",
            "policy": {
                "name": "Some Policy"
            },
            "request": {
                "id": "9262245914980288500"
            },
            "scan": {
                "type": "Ongoing"
            },
            "shared": {
                "with": "none"
            },
            "site": "Example",
            "source": {
                "geoip_src": 2
            },
            "suppression": {
                "key": "Tenant Migration across MPs"
            },
            "traffic": {
                "type": "CloudApp"
            },
            "type": "policy",
            "url": {
                "extension": "com\\\\/open",
                "original": "http:\\\\/\\\\/www.example.com\\\\/open?id=WLb5Mc7aPGx914gEyYNjJxTo32yjF8xKAcqIoN_klrGg",
                "path": "\\\\/\\\\/www.example.com\\\\/open",
                "query": "id=WLb5Mc7aPGx914gEyYNjJxTo32yjF8xKAcqIoN_klrGg",
                "scheme": "http"
            }
        }
    },
    "related": {
        "ip": [
            "81.2.69.143"
        ]
    },
    "source": {
        "address": "81.2.69.143",
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.143"
    },
    "tags": [
        "forwarded",
        "netskope-alerts"
    ],
    "user": {
        "email": [
            "test@example.com"
        ]
    },
    "user_agent": {
        "name": "unknown",
        "os": {
            "name": "unknown"
        }
    }
}
```

### Events

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| netskope.events.access_method | Cloud app traffic can be steered to the Netskope cloud using different deployment methods such as Client (Netskope Client), Secure Forwarder etc. Administrators can also upload firewall and/or proxy logs for log analytics. This field shows the actual access method that triggered the event. For log uploads this shows the actual log type such as PAN, Websense, etc. | keyword |
| netskope.events.ack | Whether user acknowledged the alert or not. | boolean |
| netskope.events.activity.name | Description of the user performed activity. | keyword |
| netskope.events.activity.status | Displayed when the user is denied access while performing some activity. | keyword |
| netskope.events.activity.type | Displayed when only admins can perform the activity in question. | keyword |
| netskope.events.alarm.description | N/A | keyword |
| netskope.events.alarm.name | N/A | keyword |
| netskope.events.alert.is_present | Indicates whether alert is generated or not. Populated as yes for all alerts. | boolean |
| netskope.events.alert.name | Name of the alert. | keyword |
| netskope.events.alert.type | Type of the alert. | keyword |
| netskope.events.app.activity | N/A | keyword |
| netskope.events.app.category | N/A | keyword |
| netskope.events.app.name | Specific cloud application used by the user (e.g. app = Dropbox). | keyword |
| netskope.events.app.region | N/A | keyword |
| netskope.events.app.session.id | Unique App/Site Session ID for traffic_type = CloudApp and Web. An app session starts when a user starts using a cloud app/site on and ends once they have been inactive for a certain period of time(15 mins). Use app_session_id to check all the user activities in a single app session. app_session_id is unique for a user, device, browser and domain. | keyword |
| netskope.events.attachment | File name. | keyword |
| netskope.events.audit.category | The subcategories in an application such as IAM, EC in AWS, login, token, file, etc., in case of Google. | keyword |
| netskope.events.audit.log.event | N/A | keyword |
| netskope.events.audit.type | The sub category in audit according to SaaS / IaaS apps. | keyword |
| netskope.events.browser.session.id | Browser session ID. If there is an idle timeout of 15 minutes, it will timeout the session. | keyword |
| netskope.events.bucket | N/A | keyword |
| netskope.events.category.id | Matching category ID according to policy. Populated for both cloud and web traffic. | keyword |
| netskope.events.category.name | N/A | keyword |
| netskope.events.cci | N/A | keyword |
| netskope.events.ccl | Cloud Confidence Level. CCL measures the enterprise readiness of the cloud apps taking into consideration those apps security, auditability and business continuity. Each app is assigned one of five cloud confidence levels: excellent, high, medium, low, or poor. Useful for querying if users are accessing a cloud app with a lower CCL. | keyword |
| netskope.events.channel | Channel of the user for slack and slack enterprise apps. | keyword |
| netskope.events.client.bytes | Total number of bytes uploaded from client to server. | long |
| netskope.events.client.packets | N/A | long |
| netskope.events.connection.duration | Duration of the connection in milliseconds. Useful for querying long-lived sessions. | long |
| netskope.events.connection.end_time | Connection end time. | long |
| netskope.events.connection.id | Each connection has a unique ID. Shows the ID for the connection event. | keyword |
| netskope.events.connection.start_time | Connection start time. | long |
| netskope.events.count | Number of raw log lines/events sessionized or suppressed during the suppressed interval. | long |
| netskope.events.description | N/A | keyword |
| netskope.events.destination.geoip.source | Source from where the location of Destination IP was derived. | long |
| netskope.events.detail | N/A | keyword |
| netskope.events.detection.engine | Customer exposed detection engine name. | keyword |
| netskope.events.detection.type | Same as malware type. Duplicate. | keyword |
| netskope.events.device.classification | Designation of device as determined by the Netskope Client as to whether the device is managed or not. | keyword |
| netskope.events.device.name | N/A | keyword |
| netskope.events.device.type | Device type from where the user accessed the cloud app. It could be Macintosh Windows device, iPad etc. | keyword |
| netskope.events.dlp.count | Count of rule hits. | long |
| netskope.events.dlp.file | File/Object name extracted from the file/object. | keyword |
| netskope.events.dlp.fingerprint.classificaiton | Fingerprint classification. | keyword |
| netskope.events.dlp.fingerprint.match | Fingerprint classification match file name. | keyword |
| netskope.events.dlp.fingerprint.score | Fingerprint classification score. | long |
| netskope.events.dlp.fv | N/A | long |
| netskope.events.dlp.incident.id | Incident ID associated with sub-file. In the case of main file, this is same as the parent incident ID. | keyword |
| netskope.events.dlp.is_unique_count | True or false depending upon if rule is unique counted per rule data. | boolean |
| netskope.events.dlp.mail.parent_id | N/A | keyword |
| netskope.events.dlp.parent.id | Incident ID associated with main container (or non-container) file that was scanned. | keyword |
| netskope.events.dlp.profile | DLP profile name. | keyword |
| netskope.events.dlp.score | DLP rule score for weighted dictionaries. | long |
| netskope.events.dlp.severity | Severity of rule. | keyword |
| netskope.events.dlp.unique_count | Integer value of number of unique matches seen per rule data. Only present if rule is uniquely counted. | long |
| netskope.events.domain | Domain value. This will hold the host header value or SNI or extracted from absolute URI. | keyword |
| netskope.events.domain_shared_with | N/A | long |
| netskope.events.drive.id | N/A | keyword |
| netskope.events.encrypt.failure | Reason of failure while encrypting. | keyword |
| netskope.events.end_time | N/A | keyword |
| netskope.events.enterprise.id | EnterpriseID in case of Slack for Enterprise. | keyword |
| netskope.events.enterprise.name | Enterprise name in case of Slack for Enterprise. | keyword |
| netskope.events.event.type | Anomaly type. | keyword |
| netskope.events.event_type | N/A | keyword |
| netskope.events.exposure | Exposure of a document. | keyword |
| netskope.events.external_collaborator_count | Count of external collaborators on a file/folder. Supported for some apps. | long |
| netskope.events.file.id | Unique identifier of the file. | keyword |
| netskope.events.file.is_password_protected | N/A | keyword |
| netskope.events.file.lang | Language of the file. | keyword |
| netskope.events.from.logs | Shows if the event was generated from the Risk Insights log. | keyword |
| netskope.events.from.object | Initial name of an object that has been renamed, copied or moved. | keyword |
| netskope.events.from.storage | N/A | keyword |
| netskope.events.from.user_category | Type of from_user. | keyword |
| netskope.events.gateway | N/A | keyword |
| netskope.events.graph.id | N/A | keyword |
| netskope.events.http_status | N/A | keyword |
| netskope.events.http_transaction_count | HTTP transaction count. | long |
| netskope.events.iaas_asset_tags | List of tags associated with the asset for which alert is raised. Each tag is a key/value pair. | keyword |
| netskope.events.id | N/A | keyword |
| netskope.events.insertion.timestamp | Insertion timestamp. | long |
| netskope.events.instance.id | Unique ID associated with an organization application instance. | keyword |
| netskope.events.instance.name | Instance name associated with an organization application instance. | keyword |
| netskope.events.instance.type | Instance type. | keyword |
| netskope.events.instance_name | Instance associated with an organization application instance. | keyword |
| netskope.events.internal_collaborator_count | Count of internal collaborators on a file/folder. Supported for some apps. | long |
| netskope.events.ip.protocol | N/A | keyword |
| netskope.events.is_bypass_traffic | Tells if traffic is bypassed by Netskope. | boolean |
| netskope.events.is_malicious | Only exists if some HTTP transaction belonging to the page event resulted in a malsite alert. | boolean |
| netskope.events.item.id | N/A | keyword |
| netskope.events.justification.reason | Justification reason provided by user. For following policies, justification events are raised. User is displayed a notification popup, user enters justification and can select to proceed or block: useralert policy, dlp block policy, block policy with custom template which contains justification text box. | keyword |
| netskope.events.justification.type | Type of justification provided by user when user bypasses the policy block. | keyword |
| netskope.events.last.app | Last application (app in the first/older event). Applies to only proximity anomaly alert. | keyword |
| netskope.events.last.country | Last location (Country). Applies to only proximity anomaly alert. | keyword |
| netskope.events.last.device | Last device name (Device Name in the first/older event). Applies to only proximity anomaly alert. | keyword |
| netskope.events.last.location | Last location (City). Applies to only proximity anomaly alert. | keyword |
| netskope.events.last.region | Applies to only proximity anomaly alert. | keyword |
| netskope.events.last.timestamp | Last timestamp (timestamp in the first/older event). Applies to only proximity anomaly alert. | long |
| netskope.events.latency.max | Max latency for a connection in milliseconds. | long |
| netskope.events.latency.min | Min latency for a connection in milliseconds. | long |
| netskope.events.latency.total | Total latency from proxy to app in milliseconds. | long |
| netskope.events.legal_hold_profile_name | Legal hold profile name. | keyword |
| netskope.events.lh.custodian.name | Custodian name of legal hold profile. | keyword |
| netskope.events.lh.destination.app | Destination appname of legalhold action. | keyword |
| netskope.events.lh.destination.instance | Destination instance of legal hold action. | keyword |
| netskope.events.lh.file_id | File ID of legal hold file. | keyword |
| netskope.events.lh.filename | File name of legal hold file. | keyword |
| netskope.events.lh.filename_original | Original filename of legal hold file. | keyword |
| netskope.events.lh.filepath | File path of legal hold file. | keyword |
| netskope.events.lh.shared | Shared type of legal hold file. | keyword |
| netskope.events.lh.shared_with | User shared with the legal hold file. | keyword |
| netskope.events.lh.version | File version of original file. | keyword |
| netskope.events.list.id | N/A | keyword |
| netskope.events.log_file.name | Log file name for Risk Insights. | keyword |
| netskope.events.login.type | Salesforce login type. | keyword |
| netskope.events.login.url.domain |  | keyword |
| netskope.events.login.url.extension |  | keyword |
| netskope.events.login.url.fragment |  | keyword |
| netskope.events.login.url.full |  | keyword |
| netskope.events.login.url.original |  | keyword |
| netskope.events.login.url.password |  | keyword |
| netskope.events.login.url.path |  | keyword |
| netskope.events.login.url.port |  | long |
| netskope.events.login.url.query |  | keyword |
| netskope.events.login.url.scheme |  | keyword |
| netskope.events.login.url.username |  | keyword |
| netskope.events.malsite_category | Category of malsite [ Phishing / Botnet / Malicous URL, etc. ]. | keyword |
| netskope.events.malware.id | md5 hash of the malware name as provided by the scan engine. | keyword |
| netskope.events.malware.name | Netskope detection name. | keyword |
| netskope.events.malware.profile | tss_profile: profile which user has selected. Data comes from WebUI. Its a json structure. | keyword |
| netskope.events.malware.severity | Malware severity. | keyword |
| netskope.events.malware.type | Malware Type. | keyword |
| netskope.events.managed_app | Whether or not the app in question is managed. | boolean |
| netskope.events.management.id | Management ID. | keyword |
| netskope.events.metric_value | N/A | long |
| netskope.events.modified_at | Timestamp corresponding to the modification time of the entity (file, etc.). | date |
| netskope.events.netskope_pop | N/A | keyword |
| netskope.events.network | N/A | keyword |
| netskope.events.new_value | New value for a given file for salesforce.com. | keyword |
| netskope.events.notify_template | N/A | keyword |
| netskope.events.ns.activity | Maps app activity to Netskope standard activity. | keyword |
| netskope.events.ns.device_uid | Device identifiers on macOS and Windows. | keyword |
| netskope.events.num_sessions | N/A | long |
| netskope.events.numbytes | Total number of bytes that were transmitted for the connection - numbytes = client_bytes + server_bytes. | long |
| netskope.events.obfuscate | N/A | boolean |
| netskope.events.object.count | Displayed when the activity is Delete. Shows the number of objects being deleted. | long |
| netskope.events.object.id | Unique ID associated with an object. | keyword |
| netskope.events.object.name | Name of the object which is being acted on. It could be a filename, folder name, report name, document name, etc. | keyword |
| netskope.events.object.type | Type of the object which is being acted on. Object type could be a file, folder, report, document, message, etc. | keyword |
| netskope.events.old_value | Old value for a given file for salesforce.com. | keyword |
| netskope.events.org | Search for events from a specific organization. Organization name is derived from the user ID. | keyword |
| netskope.events.organization_unit | Org Units for which the event correlates to. This ties to user information extracted from Active Directory using the Directory Importer/AD Connector application. | keyword |
| netskope.events.orig_ty | Event Type of original event. | keyword |
| netskope.events.original_file_path | If the file is moved, then keep original path of the file in this field. | keyword |
| netskope.events.other.categories | N/A | keyword |
| netskope.events.owner | Owner of the file. | keyword |
| netskope.events.page | The URL of the originating page. | keyword |
| netskope.events.page_site | N/A | keyword |
| netskope.events.parent.id | N/A | keyword |
| netskope.events.path_id | Path ID of the file in the application. | long |
| netskope.events.policy.id | The Netskope internal ID for the policy created by an admin. | keyword |
| netskope.events.policy.name | Name of the policy configured by an admin. | keyword |
| netskope.events.profile.emails | List of profile emails per policy. | keyword |
| netskope.events.profile.id | Anomaly profile ID. | keyword |
| netskope.events.publisher_cn | N/A | keyword |
| netskope.events.qar | N/A | keyword |
| netskope.events.quarantine.action.reason | Reason for the action taken for quarantine. | keyword |
| netskope.events.quarantine.admin | Quarantine profile custodian email/name. | keyword |
| netskope.events.quarantine.app | Quarantine app name. | keyword |
| netskope.events.quarantine.app_name | N/A | keyword |
| netskope.events.quarantine.failure | Reason of failure. | keyword |
| netskope.events.quarantine.file.id | File ID of the quarantined file. | keyword |
| netskope.events.quarantine.file.name | File name of the quarantine file. | keyword |
| netskope.events.quarantine.instance | Quarantine instance name. | keyword |
| netskope.events.quarantine.original.file.name | Original file name which got quarantined. | keyword |
| netskope.events.quarantine.original.file.path | Original file path which got quarantined. | keyword |
| netskope.events.quarantine.original.shared | Original file shared user details. | keyword |
| netskope.events.quarantine.original.version | Original version of file which got quarantined. | keyword |
| netskope.events.quarantine.profile.id | Quarantine profile ID. | keyword |
| netskope.events.quarantine.profile.name | Quarantine profile name of policy for quarantine action. | keyword |
| netskope.events.quarantine.shared_with | N/A | keyword |
| netskope.events.referer.domain |  | keyword |
| netskope.events.referer.extension |  | keyword |
| netskope.events.referer.fragment |  | keyword |
| netskope.events.referer.full |  | keyword |
| netskope.events.referer.original |  | keyword |
| netskope.events.referer.password |  | keyword |
| netskope.events.referer.path |  | keyword |
| netskope.events.referer.port |  | long |
| netskope.events.referer.query |  | keyword |
| netskope.events.referer.scheme |  | keyword |
| netskope.events.referer.username |  | keyword |
| netskope.events.repo | N/A | keyword |
| netskope.events.request.count | Total number of HTTP requests (equal to number of transaction events for this page event) sent from client to server over one underlying TCP connection. | long |
| netskope.events.request.id | Unique request ID for the event. | keyword |
| netskope.events.response.content.length | N/A | long |
| netskope.events.response.content.type | N/A | keyword |
| netskope.events.response.count | Total number of HTTP responses (equal to number of transaction events for this page event) from server to client. | long |
| netskope.events.retro_scan_name | Retro scan name. | keyword |
| netskope.events.risk_level | Corresponding field to risk_level_id. Name. | keyword |
| netskope.events.risk_level_id | This field is set by both role-based access (RBA) and MLAD. | keyword |
| netskope.events.role | Roles for Box. | keyword |
| netskope.events.run_id | Run ID. | long |
| netskope.events.sa.profile.id | CSA profile ID. | keyword |
| netskope.events.sa.profile.name | CSA profile name. | keyword |
| netskope.events.sa.rule.severity | Rule severity. | keyword |
| netskope.events.scan.time | Time when the scan is done. | long |
| netskope.events.scan.type | Generated during retroactive scan or new ongoing activity. | keyword |
| netskope.events.scopes | List of permissions for google apps. | keyword |
| netskope.events.serial | N/A | keyword |
| netskope.events.server.bytes | Total number of downloaded from server to client. | long |
| netskope.events.server.packets | N/A | long |
| netskope.events.session.duration | N/A | long |
| netskope.events.session.id | Session ID for Dropbox application. | keyword |
| netskope.events.session.packets | N/A | long |
| netskope.events.severity.id | Severity ID used by watchlist and malware alerts. | keyword |
| netskope.events.severity.level | Severity used by watchlist and malware alerts. | keyword |
| netskope.events.severity.type | Severity type used by watchlist and malware alerts | keyword |
| netskope.events.sfwder | N/A | keyword |
| netskope.events.shared.domains | List of domains of users the document is shared with. | keyword |
| netskope.events.shared.is_shared | If the file is shared or not. | boolean |
| netskope.events.shared.type | Shared Type. | keyword |
| netskope.events.shared.with | Array of emails with whom a document is shared with. | keyword |
| netskope.events.site | For traffic_type = CloudApp, site = app and for traffic_type = Web, it will be the second level domain name + top-level domain name. For example, in "www.cnn.com", it is "cnn.com". | keyword |
| netskope.events.slc.geo.location | Longitude and latitude. | geo_point |
| netskope.events.source.geoip_src | Source from where the location of Source IP was derived. | long |
| netskope.events.ssl_decrypt_policy | Applicable to only bypass events. There are 2 ways to create rules for bypass: Bypass due to Exception Configuration, Bypass due to SSL Decrypt Policy.The existing flag bypass_traffic only gives information that a flow has been bypassed, but does not tell exactly which policy was responsible for it. ssl_decrypt_policy field will provide this extra information. In addition, policy field will be also set for every Bypass event. | keyword |
| netskope.events.start_time | N/A | keyword |
| netskope.events.sub_type | Workplace by Facebook post sub category (files, comments, status etc). | keyword |
| netskope.events.supporting_data | N/A | keyword |
| netskope.events.suppression.end_time | When events are suppressed (like collaboration apps), then the suppression end time will be set and only one event will be send with suppression start time and end time and count of occurrence. | long |
| netskope.events.suppression.key | To limit the number of events. Example: Suppress block event for browse. | keyword |
| netskope.events.suppression.start_time | When events are suppressed (like collaboration apps), then the suppression end time will be set and only one event will be send with suppression start time and end time and count of occurrence. | long |
| netskope.events.team | Slack team name. | keyword |
| netskope.events.telemetry_app | Typically SaaS app web sites use web analytics code within the pages to gather analytic data. When a SaaS app action or page is shown, there is subsequent traffic generated to tracking apps such as doubleclick.net, Optimizely, etc. These tracking apps are listed if applicable in the Telemetry App field. | keyword |
| netskope.events.temp_user | N/A | keyword |
| netskope.events.tenant.id | Tenant id. | keyword |
| netskope.events.threat.match_field | Threat match field, either from domain or URL or IP. | keyword |
| netskope.events.threat.source.id | Threat source id: 1 - NetskopeThreatIntel, 2 - Zvelodb. | keyword |
| netskope.events.threshold | Threshold (Count at which the anomaly should trigger). Applicable to Bulk Anomaly types( Bulk Upload/ Download/ Delete) and Failed Login Anomaly type. | long |
| netskope.events.tnetwork_session_id | N/A | keyword |
| netskope.events.to.object | Changed name of an object that has been renamed, copied, or moved. | keyword |
| netskope.events.to.storage | N/A | keyword |
| netskope.events.to.user | Used when a file is moved from user A to user B. Shows the email address of user B. | keyword |
| netskope.events.to.user_category | Type of user to which move is done. | keyword |
| netskope.events.total.collaborator_count | Count of collaborators on a file/folder. Supported for some apps. | long |
| netskope.events.total_packets | N/A | long |
| netskope.events.traffic.type | Type of the traffic: CloudApp or Web. CloudApp indicates CASB and web indicates HTTP traffic. Web traffic is only captured for inline access method. It is currently not captured for Risk Insights. | keyword |
| netskope.events.transaction.id | Unique ID for a given request/response. | keyword |
| netskope.events.tss_mode | Malware scanning mode, specifies whether it's Real-time Protection or API Data Protection. | keyword |
| netskope.events.tunnel.id | Shows the Client installation ID. Only available for the Client steering configuration. | keyword |
| netskope.events.tunnel.type | N/A | keyword |
| netskope.events.tunnel.up_time | N/A | long |
| netskope.events.two_factor_auth | N/A | keyword |
| netskope.events.type | Shows if it is an application event or a connection event. Application events are recorded to track user events inside a cloud app. Connection events shows the actual HTTP connection. | keyword |
| netskope.events.universal_connector | N/A | keyword |
| netskope.events.url.domain |  | keyword |
| netskope.events.url.extension |  | keyword |
| netskope.events.url.fragment |  | keyword |
| netskope.events.url.full |  | keyword |
| netskope.events.url.original |  | keyword |
| netskope.events.url.password |  | keyword |
| netskope.events.url.path |  | keyword |
| netskope.events.url.port |  | long |
| netskope.events.url.query |  | keyword |
| netskope.events.url.scheme |  | keyword |
| netskope.events.url.username |  | keyword |
| netskope.events.url_to_activity | Populated if the activity from the URL matches certain activities. This field applies to Risk Insights only. | keyword |
| netskope.events.user.category | Type of user in an enterprise - external / internal. | keyword |
| netskope.events.user.generated | Tells whether it is user generated page event. | boolean |
| netskope.events.user.geo.city_name | N/A | keyword |
| netskope.events.user.geo.continent_name | N/A | keyword |
| netskope.events.user.geo.country_iso_code | N/A | keyword |
| netskope.events.user.geo.country_name | N/A | keyword |
| netskope.events.user.geo.location | Longitude and latitude. | geo_point |
| netskope.events.user.geo.region_iso_code | N/A | keyword |
| netskope.events.user.geo.region_name | N/A | keyword |
| netskope.events.user.group | N/A | keyword |
| netskope.events.user.ip | IP address of User. | keyword |
| netskope.events.user.is_aggregated | N/A | boolean |
| netskope.events.violating.user.name | User who caused a vioaltion. Populated for Workplace by Facebook. | keyword |
| netskope.events.violating.user.type | Category of the user who caused a violation. Populated for Workplace by Facebook. | keyword |
| netskope.events.web.url.domain |  | keyword |
| netskope.events.web.url.extension |  | keyword |
| netskope.events.web.url.fragment |  | keyword |
| netskope.events.web.url.full |  | keyword |
| netskope.events.web.url.original |  | keyword |
| netskope.events.web.url.password |  | keyword |
| netskope.events.web.url.path |  | keyword |
| netskope.events.web.url.port |  | long |
| netskope.events.web.url.query |  | keyword |
| netskope.events.web.url.scheme |  | keyword |
| netskope.events.web.url.username |  | keyword |
| netskope.events.web_universal_connector | N/A | keyword |
| netskope.events.workspace.id | Workspace ID in case of Slack for Enterprise. | keyword |
| netskope.events.workspace.name | Workspace name in case of Slack for Enterprise. | keyword |
| netskope.events.zip_password | Zip the malacious file and put pwd to it and send it back to caller. | keyword |


An example event for `events` looks as following:

```json
{
    "@timestamp": "2021-12-24T00:29:56.000Z",
    "agent": {
        "ephemeral_id": "c286de6a-2b0b-406e-89e6-ee0d2b13bd2d",
        "id": "7b99f48c-6c10-4dad-86c4-ee578beef412",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "netskope.events",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7b99f48c-6c10-4dad-86c4-ee578beef412",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "netskope.events",
        "ingested": "2024-03-29T07:18:17Z"
    },
    "event.id": "613ee55ec9d868fc47654a73",
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.224.6:57252"
        }
    },
    "netskope": {
        "events": {
            "alarm": {
                "description": "Events from device not received in the last 24 hours",
                "name": "No_events_from_device"
            },
            "device": {
                "name": "device-1"
            },
            "event_type": "infrastructure",
            "metric_value": 43831789,
            "serial": "FFFFFFFFFFFFFFFF",
            "severity": {
                "level": "high"
            },
            "supporting_data": "abc"
        }
    },
    "tags": [
        "forwarded",
        "netskope-events"
    ]
}
```