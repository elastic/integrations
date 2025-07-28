# Netskope

This integration is for Netskope. It can be used to receive logs sent by [Netskope Cloud Log Shipper](https://docs.netskope.com/en/cloud-exchange-feature-lists.html#UUID-e7c43f4b-8aad-679e-eea0-59ce19f16e29_section-idm4547044691454432680066508785) and [Netskope Log Streaming](https://docs.netskope.com/en/log-streaming/). To receive log from Netskope Cloud Log Shipper use the TCP input, and for Netskope Log Streaming use any of the Cloud based inputs (AWS, GCS, or Azure Blob Storage).



The log message is expected to be in JSON format. The data is mapped to
ECS fields where applicable and the remaining fields are written under
`netskope.<data-stream-name>.*`.

## Setup steps

### For receiving log from Netskope Cloud Shipper
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

### For receiving log from Netskope Log Streaming
1. To configure Log streaming please refer to the [Log Streaming Configuration](https://docs.netskope.com/en/configuring-streams). Ensure that compression is set to GZIP when configuring the stream as other compression types are not supported.


#### Collect data from an AWS S3 bucket

Considering you already have an AWS S3 bucket setup, to configure it with Netskope, follow [these steps](https://docs.netskope.com/en/stream-logs-to-amazon-s3) to enable the log streaming.

#### Collect data from Azure Blob Storage

1. If you already have an Azure storage container setup, configure it with Netskope via log streaming.
2. Enable the Netskope log streaming by following [these instructions](https://docs.netskope.com/en/stream-logs-to-azure-blob).
3. Configure the integration using either Service Account Credentials or Microsoft Entra ID RBAC with OAuth2 options. For OAuth2 (Entra ID RBAC), you will need the Client ID, Client Secret, and Tenant ID. For Service Account Credentials, you will need either the Service Account Key or the URI to access the data.


- How to setup the `auth.oauth2` credentials can be found in the Azure documentation [here]( https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
- For more details about the Azure Blob Storage input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-blob-storage.html).

Note:
- The service principal must be granted the appropriate permissions to read blobs. Ensure that the necessary role assignments are in place for the service principal to access the storage resources. For more information, please refer to the [Azure Role-Based Access Control (RBAC) documentation](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/storage).
- We recommend assigning either the **Storage Blob Data Reader** or **Storage Blob Data Owner** role. The **Storage Blob Data Reader** role provides read-only access to blob data and is aligned with the principle of least privilege, making it suitable for most use cases. The **Storage Blob Data Owner** role grants full administrative access — including read, write, and delete permissions — and should be used only when such elevated access is explicitly required.

#### Collect data from a GCS bucket

1. If you already have a GCS bucket setup, configure it with Netskope via log streaming.
2. Enable the Netskope log streaming by following [these instructions](https://docs.netskope.com/en/stream-logs-to-gcp-cloud-storage).
3. Configure the integration with your GCS project ID, Bucket name and Service Account Key/Service Account Credentials File.

For more details about the GCS input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-gcs.html).

#### The GCS credentials key file:

Once you have added a key to GCP service account, you will get a JSON key file that can only be downloaded once.
If you're new to GCS bucket creation, follow these steps:

1. Make sure you have a service account available, if not follow the steps below:
   - Navigate to 'APIs & Services' > 'Credentials'
   - Click on 'Create credentials' > 'Service account'
2. Once the service account is created, you can navigate to the 'Keys' section and attach/generate your service account key.
3. Make sure to download the JSON key file once prompted.
4. Use this JSON key file either inline (JSON string object), or by specifying the path to the file on the host machine, where the agent is running.

A sample JSON Credentials file looks as follows:
```json
{
  "type": "dummy_service_account",
  "project_id": "dummy-project",
  "private_key_id": "dummy-private-key-id",
  "private_key": "-----BEGIN PRIVATE KEY-----\nDummyPrivateKey\n-----END PRIVATE KEY-----\n",
  "client_email": "dummy-service-account@example.com",
  "client_id": "12345678901234567890",
  "auth_uri": "https://dummy-auth-uri.com",
  "token_uri": "https://dummy-token-uri.com",
  "auth_provider_x509_cert_url": "https://dummy-auth-provider-cert-url.com",
  "client_x509_cert_url": "https://dummy-client-cert-url.com",
  "universe_domain": "dummy-universe-domain.com"
}
```


#### Collect data from AWS SQS

1. If you have already set up a connection to push data into the AWS bucket; if not, refer to the section above.

2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" mentioned in the [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
   - While creating an access policy, use the bucket name configured to create a connection for AWS S3 in Netskope.
3. Configure event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
   - While creating `event notification` select the event type as s3:ObjectCreated:*, destination type SQS Queue, and select the queue name created in Step 2.

For more details about the AWS-S3 input settings, check this [documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

### Enable the integration in Elastic

1. In Kibana go to **Management** > **Integrations**.
2. In "Search for integrations" top bar, search for `Netskope`.
3. Select the **Netskope** integration from the search results.
4. Select "Add Netskope" to add the integration.
5. While adding the integration, there are different options to collect logs; 
    
    To collect logs via AWS S3 when adding the integration, you must provide the following details::
    - Collect logs via S3 Bucket toggled on
    - Access Key ID
    - Secret Access Key
    - Bucket ARN
    - Session Token

    To collect logs via AWS SQS when adding the integration, you must provide the following details:
    - Collect logs via S3 Bucket toggled off
    - Queue URL
    - Secret Access Key
    - Access Key ID

    To collect logs via GCS when adding the integration, you must provide the following details:
    - Project ID
    - Buckets
    - Service Account Key/Service Account Credentials File

    To collect logs via Azure Blob Storage when adding the integration, you must provide the following details:

    - For OAuth2 (Microsoft Entra ID RBAC):
        - Toggle on **Collect logs using OAuth2 authentication**
        - Account Name
        - Client ID
        - Client Secret
        - Tenant ID
        - Container Details.

    - For Service Account Credentials:
        - Service Account Key or the URI
        - Account Name
        - Container Details
        

    To collect logs via TCP when adding the integration, you must provide the following details:
    - Listen Address
    - Listen Port
6. Save the integration.

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
| netskope.alerts.breach.date | Breach date for compromised credentials. | date |
| netskope.alerts.breach.description | Breach description for compromised credentials. | keyword |
| netskope.alerts.breach.description.text | Multi-field of `netskope.alerts.breach.description`. | match_only_text |
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

### Alerts V2

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| aws.s3.bucket.arn | The AWS S3 bucket ARN. | keyword |
| aws.s3.bucket.name | The AWS S3 bucket name. | keyword |
| aws.s3.object.key | The AWS S3 Object key. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| netskope.alert_v2._id | Unique id - hexadecimal string. | keyword |
| netskope.alert_v2.access_method | Cloud app traffic can be steered to the Netskope cloud using different deployment methods such as Client (Netskope Client), Secure Forwarder etc. Administrators can also upload firewall and/or proxy logs for log analytics. This field shows the actual access method that triggered the event.For log uploads this shows the actual log type such as PAN, Websense, etc. | keyword |
| netskope.alert_v2.account_id | Account ID is an account number as provided by the cloud provider AWS, GCP and AZURE etc. | keyword |
| netskope.alert_v2.account_name | Account name - in case of AWS this is the instance name set by user. For others, account name is provided by the cloud provider. | keyword |
| netskope.alert_v2.acked | Whether user has acknowledged the alert or not. | boolean |
| netskope.alert_v2.act_user | Acting User is the user responsible for the configured policy violation. | keyword |
| netskope.alert_v2.action | Action taken on the event for the policy. | keyword |
| netskope.alert_v2.activity | Description of the user performed activity. | keyword |
| netskope.alert_v2.alert | Indicates whether alert is generated or not and its populated as yes for all alerts. | keyword |
| netskope.alert_v2.alert_id | Indicates the alert is raised and the carries the id of the alert raised. | keyword |
| netskope.alert_v2.alert_name | Indicates the alert is raised and the carries the name of the alert raised. | keyword |
| netskope.alert_v2.alert_source | Indicates the alert is raised and the carries the Netskope solution name as source of the alert raised. | keyword |
| netskope.alert_v2.alert_type | Indicates the alert is raised and the carries the type of the alert raised. | keyword |
| netskope.alert_v2.app | Specific cloud application used by the user. | keyword |
| netskope.alert_v2.app_session_id | Unique App/Site Session ID for traffic_type = CloudApp and Web. An app session starts when a user starts using a cloud app/site on and ends once they have been inactive for a certain period of time(15 minutes). Use app_session_id to check all the user activities in a single app session. app_session_id is unique for a user, device, browser and domain. | keyword |
| netskope.alert_v2.appcategory | The application category. | keyword |
| netskope.alert_v2.appsuite | The SAAS application suite ( Ex : Microsoft Office / Google Docs  etc ). | keyword |
| netskope.alert_v2.audit_type | The sub category in audit according to SaaS / IaaS apps. | keyword |
| netskope.alert_v2.bcc | Breach target references for compromised credentials or BCC users information in the case of SMTP DLP incident. | keyword |
| netskope.alert_v2.breach_date | Breach Metric date for compromised credentials. | date |
| netskope.alert_v2.breach_id | Breach description for compromised credentials. | keyword |
| netskope.alert_v2.breach_score | Breach score for compromised credentials. | long |
| netskope.alert_v2.browser | Shows the actual browser from where the cloud app was accessed.A native browser refers to Safari (iOS), Chrome (Android), or the default browser on the user's laptop. | keyword |
| netskope.alert_v2.browser_session_id | Browser Session Id. | keyword |
| netskope.alert_v2.cc | SMTP Proxy will parse the cc field in the email and send them to DLP in the event object. The cc recipients from the e-mail header, up to 1KB. | keyword |
| netskope.alert_v2.cci | Cloud confidence Index value as Integer. | long |
| netskope.alert_v2.ccl | Cloud Confidence Level. CCL measures the enterprise readiness of the cloud apps taking into consideration those apps security, auditability and business continuity.Each app is assigned one of five cloud confidence levels: excellent, high, medium, low, or poor. Useful for querying if users are accessing a cloud app with a lower CCL. | keyword |
| netskope.alert_v2.client_bytes | Total number of bytes uploaded from client to server. | long |
| netskope.alert_v2.client_packets | Total number of packets uploaded from client to server. | long |
| netskope.alert_v2.computer_name | Computer name of the end point. | keyword |
| netskope.alert_v2.conn_duration | Duration of the connection in milliseconds. Useful for querying long-lived sessions. | long |
| netskope.alert_v2.conn_endtime | Connection end time. | date |
| netskope.alert_v2.conn_starttime | Connection start time. | date |
| netskope.alert_v2.connection_id | Each connection has a unique ID. Shows the ID for the connection event. | keyword |
| netskope.alert_v2.connection_type | EndPoint DLP connection mode. | keyword |
| netskope.alert_v2.custom_attr.usr_display_name | User display name from custom attributes. | keyword |
| netskope.alert_v2.custom_attr.usr_status | User status from custom attributes. | keyword |
| netskope.alert_v2.custom_attr.usr_title | User title from custom attributes. | keyword |
| netskope.alert_v2.custom_attr.usr_udf_businesssegmentlevel2 | Business segment level 2 from custom attributes. | keyword |
| netskope.alert_v2.custom_attr.usr_udf_businesssegmentlevel3 | Business segment level 3 from custom attributes. | keyword |
| netskope.alert_v2.custom_attr.usr_udf_companyname | Company name from custom attributes. | keyword |
| netskope.alert_v2.custom_attr.usr_udf_employeeid | Employee ID from custom attributes. | keyword |
| netskope.alert_v2.custom_attr.usr_udf_primarydomain | Primary domain from custom attributes. | keyword |
| netskope.alert_v2.custom_attr.usr_udf_supervisorname | Supervisor name from custom attributes. | keyword |
| netskope.alert_v2.destination_file_directory | The directory and filename of the destination file on the endpoint. | keyword |
| netskope.alert_v2.destination_file_name | Endpoint DLP destination file name. | keyword |
| netskope.alert_v2.destination_file_path | Endpoint DLP destination file path. | keyword |
| netskope.alert_v2.detection_engine | Threat Detection engine name. | keyword |
| netskope.alert_v2.device | Device type from where the user accessed the cloud app. It could be Macintosh Windows device, iPad etc. | keyword |
| netskope.alert_v2.device_classification | Designation of device as determined by the Netskope Client as to whether the device is managed or not. | keyword |
| netskope.alert_v2.device_sn | Device serial number. | keyword |
| netskope.alert_v2.device_type | Device type. | keyword |
| netskope.alert_v2.dlp_file | File/Object name extracted from the file/object. | keyword |
| netskope.alert_v2.dlp_fingerprint_classification | Fingerprint classification. | keyword |
| netskope.alert_v2.dlp_fingerprint_match | Fingerprint classification match file name. | keyword |
| netskope.alert_v2.dlp_fingerprint_score | Fingerprint classification score | long |
| netskope.alert_v2.dlp_incident_id | Incident ID associated with sub-file in DLP scans. In the case of main file, this is same as the parent incident ID. | keyword |
| netskope.alert_v2.dlp_is_unique_count | True or false depending upon if rule is unique counted per rule data. | boolean |
| netskope.alert_v2.dlp_parent_id | Incident ID associated with main container (or non-container) file that was scanned. | keyword |
| netskope.alert_v2.dlp_profile | DLP profile name. | keyword |
| netskope.alert_v2.dlp_profile_name | DLP profile name. | keyword |
| netskope.alert_v2.dlp_rule | DLP rule that triggered the scans. | keyword |
| netskope.alert_v2.dlp_rule_count | Count of dlp rule hits. | long |
| netskope.alert_v2.dlp_rule_score | DLP rule score for weighted dictionaries. | long |
| netskope.alert_v2.dlp_rule_severity | Severity of DLP rule. | keyword |
| netskope.alert_v2.dlp_unique_count | Integer value of number of unique matches seen per rule data. Only present if rule is uniquely counted. | long |
| netskope.alert_v2.dns_profile | DNS profiles allow you to control, inspect, and log all or blocked DNS traffic. When configuring a DNS profile, you can configure the actions taken for specific domain categories and choose to allow or block specific domains. This field contains the configuration file name. | keyword |
| netskope.alert_v2.domain | Domain value. This will hold the host header value or SNI or extracted from absolute URI. | keyword |
| netskope.alert_v2.domain_ip | Domain IP address. | ip |
| netskope.alert_v2.driver | Driver name used by endpoint device. | keyword |
| netskope.alert_v2.dst_country | Application's two-letter country code as determined by the Maxmind or IP2Location Geo Database. | keyword |
| netskope.alert_v2.dst_geoip_src | Source from where the location of Destination IP was derived. | long |
| netskope.alert_v2.dst_latitude | Latitude of the Application as determined by the Maxmind or IP2Location Geo Database. | double |
| netskope.alert_v2.dst_latitude_keyword |  | keyword |
| netskope.alert_v2.dst_location | Application's city as determined by the Maxmind or IP2Location Geo database. | keyword |
| netskope.alert_v2.dst_longitude | Longitude of the Application as determined by the Maxmind or IP2Location Geo Database. | double |
| netskope.alert_v2.dst_longitude_keyword |  | keyword |
| netskope.alert_v2.dst_region | Application's state or region as determined by the Maxmind or IP2Location Geo Database. | keyword |
| netskope.alert_v2.dst_timezone | Destination timezone. | keyword |
| netskope.alert_v2.dst_zipcode | Application's zip code as determined by the Maxmind or IP2Location Geo Database. | keyword |
| netskope.alert_v2.dsthost | Destination host. | keyword |
| netskope.alert_v2.dstip | IP address where the destination app is hosted. | ip |
| netskope.alert_v2.dstport | Destination port. | long |
| netskope.alert_v2.email_title | Email subject. | keyword |
| netskope.alert_v2.end_time | When events are suppressed (like collaboration apps), then the suppression end time will be set and only one event will be send with suppression start time and end time and count of occurrence. | date |
| netskope.alert_v2.event_uuid | Unique ID to recognize applation event activities. | keyword |
| netskope.alert_v2.executable_hash | Flag to indicate if executable_hash is signed or not. | keyword |
| netskope.alert_v2.executable_signed | Flag to indicate if executable_hash is signed or not. | boolean |
| netskope.alert_v2.file_category | Type of file category. | keyword |
| netskope.alert_v2.file_cls_encrypted | Its a boolean value representing  whether its CLS encrypted or not. | boolean |
| netskope.alert_v2.file_exposure | File sharing exposure value for SaaS apps. | keyword |
| netskope.alert_v2.file_id | Unique file id to recognize the file. | keyword |
| netskope.alert_v2.file_origin | File origin source location. | keyword |
| netskope.alert_v2.file_path | Path of the file in the application. | keyword |
| netskope.alert_v2.file_size | Size of the file in bytes. | long |
| netskope.alert_v2.file_type | File type as detected by Netskope Solutions. | keyword |
| netskope.alert_v2.filename | Filename found during Malware threat detection. | keyword |
| netskope.alert_v2.from_user | Email address used to login to the SAAS app. | keyword |
| netskope.alert_v2.hostname | User's Host name. | keyword |
| netskope.alert_v2.iaas_remediated | value representing whether IAAS alerts remediated or not. | boolean |
| netskope.alert_v2.iaas_remediated_by | IAAS/CSA scan alerts can be remediated by taking remediation steps. This field captures the admin's email address who applied the remediation steps. | keyword |
| netskope.alert_v2.iaas_remediated_on | IAAS/CSA scan alerts can be remediated by taking remediation steps. This field captures the time in epoch format when remediation steps were taken. | long |
| netskope.alert_v2.iaas_remediation_action | IAAS/CSA scan alerts can be remediated by taking remediation steps. This field captures the action taken. | keyword |
| netskope.alert_v2.incident_id | Unique Incident ID associated with main container (or non-container) file that was scanned. | keyword |
| netskope.alert_v2.instance | Instance associated with an organization application instance. | keyword |
| netskope.alert_v2.instance_id | Unique ID associated with an organization application instance. | keyword |
| netskope.alert_v2.instance_name | App instances are configured while configuring policies. instance_name is the custom name chose by admin. | keyword |
| netskope.alert_v2.ip_protocol | Assigned Internet Protocol Number. | keyword |
| netskope.alert_v2.loc | Short name for location. | keyword |
| netskope.alert_v2.local_md5 | MD5 of the sample which was calculated by Netskope's FastScan (TSS) service. | keyword |
| netskope.alert_v2.local_sha1 | SHA1 of the sample which was calculated by Netskope's fastscan (TSS) service. | keyword |
| netskope.alert_v2.local_sha256 | SHA256 of the sample which was calculated by Netskope's fastscan (TSS) service. | keyword |
| netskope.alert_v2.location | A string that specifies the physical location of the printer (for example, Bldg. 38, Room 1164). | keyword |
| netskope.alert_v2.mal_id | Unique id assigned to recognize the malware. | keyword |
| netskope.alert_v2.mal_type | Type of malware detected. | keyword |
| netskope.alert_v2.malware_id | Unique id assigned to recognize the malware. | keyword |
| netskope.alert_v2.malware_severity | Malware Severity category. | keyword |
| netskope.alert_v2.malware_type | Type of malware detected. | keyword |
| netskope.alert_v2.managed_app | Whether or not the app in question is managed. | keyword |
| netskope.alert_v2.managementID | Field value is attached to Devices Host Info Object. | keyword |
| netskope.alert_v2.md5 | MD5 value of the file content. | keyword |
| netskope.alert_v2.message_id | Unique message id used internally by NSProxy. | keyword |
| netskope.alert_v2.mime_type | A media type (also known as a Multipurpose Internet Mail Extensions or MIME type) indicates the nature and format of a document, file, or assortment of bytes. | keyword |
| netskope.alert_v2.modified_date | File modification date found during malware detection. Timestamp in epoch format. | date |
| netskope.alert_v2.netskope_pop | Netskope Data Plane name. | keyword |
| netskope.alert_v2.network_session_id | Network session ID used by NPA services. | keyword |
| netskope.alert_v2.nsdeviceuid | Device ID attached to Devices Host Info Object. | keyword |
| netskope.alert_v2.numbytes | Total number of bytes that were transmitted for the connection - numbytes = client_bytes + server_bytes. | long |
| netskope.alert_v2.oauth | Oauth is a standard that allows applications to access a user's data without the user needing to share their password. This field holds value if it was used or not. | keyword |
| netskope.alert_v2.object | Name of the object which is being acted on. It could be a filename, folder name, report name, document name, etc.Incident object name and the value of the field represents the object details of the incident triggered. | keyword |
| netskope.alert_v2.object_id | Unique ID associated with an object. | keyword |
| netskope.alert_v2.object_type | Type of the object which is being acted on. Object type could be a file, folder, report, document, message, etc. | keyword |
| netskope.alert_v2.org | Search for events from a specific organization. Organization name is derived from the user ID. | keyword |
| netskope.alert_v2.organization_unit | Org Units for which the event correlates to. This ties to user information extracted from Active Directory using the Directory Importer/AD Connector application. | keyword |
| netskope.alert_v2.os | Operating system of the host who generated the event. | keyword |
| netskope.alert_v2.os_details | Detailed OS version string. | keyword |
| netskope.alert_v2.os_family | Operating system type of the end user's device. | keyword |
| netskope.alert_v2.os_user_name | Username on the local machine that performs action. | keyword |
| netskope.alert_v2.os_version | OS version of the host. | keyword |
| netskope.alert_v2.owner | Owner or the user information of the file object in DLP. | keyword |
| netskope.alert_v2.owner_pdl | File's owner Preferred Data Location derived from owner uid(OneDrive) and site URL(SharePoint). | keyword |
| netskope.alert_v2.page | The URL of the originating page. | keyword |
| netskope.alert_v2.parent_id | Parent ID ( event_id ) of an alert. | keyword |
| netskope.alert_v2.pid | Process ID that is doing file processing ex:- A process that trigger the evaluation. | keyword |
| netskope.alert_v2.policy | Name of the policy configured by an admin. | keyword |
| netskope.alert_v2.policy_action | Endpoint DLP Policy action planned according to the policy. User can override the planned action or actual enforcement action might not be implemented. | keyword |
| netskope.alert_v2.policy_name | Endpoint DLP Name of matching policy. | keyword |
| netskope.alert_v2.policy_name_enforced | Actual action taken by Endpoint DLP Policy. | keyword |
| netskope.alert_v2.policy_version | Endpoint DLP Policy name configured version number. | keyword |
| netskope.alert_v2.pop_id | Netskope MPs/DPs unique id. | keyword |
| netskope.alert_v2.port | A string that identifies the port(s) used to transmit data to the printer. If a printer is connected to more than one port, the names of each port must be separated by commas (for example, LPT1:,LPT2:,LPT3:). | keyword |
| netskope.alert_v2.process_cert_subject | the subject of the certificate that signed the process. | keyword |
| netskope.alert_v2.process_name | Endpoint process Name For example:- native application for Printer on User's Laptop. | keyword |
| netskope.alert_v2.process_path | The path to the process that performed the action on the endpoint. | keyword |
| netskope.alert_v2.product_id | It's Part of USB specification. Used to identify a USB device. | keyword |
| netskope.alert_v2.publisher_cn | The publisher CName. | keyword |
| netskope.alert_v2.quarantine_action_reason | Reason for the action taken for quarantine. | keyword |
| netskope.alert_v2.record_type | Indicate the event type of the record. | keyword |
| netskope.alert_v2.redirect_url | URL name where traffic is redirected based on the applied Policy. | keyword |
| netskope.alert_v2.referer | Referer URL associated with an activity in a cloud app.Referer URL of the application(with http) that the user visited as provided by the log or data plane traffic. | keyword |
| netskope.alert_v2.region_id | Region ID as provided by the cloud provider AWS, GCP and Azure etc. | keyword |
| netskope.alert_v2.region_name | Region Name as provided by the cloud provider AWS, GCP and Azure etc. | keyword |
| netskope.alert_v2.related_malware | This field contains the malware information attached to UEBA anomaly detection. | keyword |
| netskope.alert_v2.req_cnt | Total number of HTTP requests (equal to number of transaction events for this page event) sent from client to server over one underlying TCP connection. | long |
| netskope.alert_v2.request_id | Unique id attached to proxy activity events and dlp activity events. | keyword |
| netskope.alert_v2.resource_category | IAAS assets resource category of the Cloud providers AWS, GCP and Azure etc. For Example Amazon EC2, Amazon ECS are categorized as Compute whereas Amazon RDS and DynamoDB are categorized as database. | keyword |
| netskope.alert_v2.resource_group | Cloud providers AWS, GCP and Azure have entities called resource groups that organize resources such as VMs, storage, and virtual networking devices etc. | keyword |
| netskope.alert_v2.resp_cnt | Total number of HTTP responses (equal to number of transaction events for this page event) from server to client. | long |
| netskope.alert_v2.risk_level_id | This field is set by both RBA and MLAD anomaly engines for every anomaly that's detected. MLAD always sets individual anomalies risk-level to 0 (low). RBA has different rules. | keyword |
| netskope.alert_v2.sa_profile_name | IAAS/CSA profile Name as provided by cloud providers AWS, GCP and Azure etc. | keyword |
| netskope.alert_v2.sa_rule_name | IAAS/CSA rule name configured for scans to run on data stored in cloud providers AWS, GCP and Azure data. | keyword |
| netskope.alert_v2.sa_rule_severity | IAAS/CSA rule severity as captured by backend policy engines. | keyword |
| netskope.alert_v2.sanctioned_instance | A sanctioned instance is a company owned account in an external application. A value of yes indicates that the company has granted    access for the specific SaaS / IaaS account to Netskope. A value of no    represents a personal user account or an enterprise account not    authorized by the enterprise Administrator. | keyword |
| netskope.alert_v2.sender | Sender email information related to introspection's support for MS Teams app. | keyword |
| netskope.alert_v2.server_bytes | Total number of downloaded bytes from server to client. | long |
| netskope.alert_v2.server_packets | Total number of server packet from server to client. | long |
| netskope.alert_v2.session_duration | Session duration of a session. | long |
| netskope.alert_v2.severity | Severity used by watchlist and malware alerts. Severity of the incident. | keyword |
| netskope.alert_v2.severity_id | Malware severity category ids. These ids are mapped with severity category values like high, low, medium etc. | keyword |
| netskope.alert_v2.severity_level | Severity level of the Malsite ( High / Med / Low). | keyword |
| netskope.alert_v2.sha256 | Sha256 value of a file. | keyword |
| netskope.alert_v2.sharedType | Object shared type detected for the DLP incidents. | keyword |
| netskope.alert_v2.shared_credential_user | Denotes the value of the credential being shared by multiple users. | keyword |
| netskope.alert_v2.shared_domains | List of domains of users the document is shared with. | keyword |
| netskope.alert_v2.shared_with | Email ids with whom a document is shared with. | keyword |
| netskope.alert_v2.site | For traffic_type = CloudApp, site = app and for traffic_type = Web, it will be the second level domain name + top-level domain name. For example, in www.cnn.com, it is cnn.com. | keyword |
| netskope.alert_v2.smtp_status | Customers can configure Netskope SMTP Proxy with Microsoft O365 Exchange, all outgoing emails from Microsoft O365 Exchange are sent to Netskope SMTP Proxy for policy evaluation and will send Back to Exchange  for mail delivery. This field denotes the status code for ex:- SMTP status 250 shows successful delivery of mail. | keyword |
| netskope.alert_v2.src_country | User's country's two-letter Country Code as determined by the Maxmind or IP2Location Geo Database. | keyword |
| netskope.alert_v2.src_geoip_src | Source from where the location of Source IP was derived. | long |
| netskope.alert_v2.src_latitude | Latitude of the user as determined by the Maxmind or IP2Location Geo database. | double |
| netskope.alert_v2.src_latitude_keyword |  | keyword |
| netskope.alert_v2.src_location | User's city as determined by the Maxmind or IP2Location Geo Database. | keyword |
| netskope.alert_v2.src_longitude | Longitude of the user as determined by the Maxmind or IP2Location Geo database. | double |
| netskope.alert_v2.src_longitude_keyword |  | keyword |
| netskope.alert_v2.src_region | Source state or region as determined by the Maxmind or IP2Location Geo database. | keyword |
| netskope.alert_v2.src_timezone | Source timezone for the location at which the event is created. Shows the long format timezone designation. | keyword |
| netskope.alert_v2.src_zipcode | Source zip code for the location at which the event is created as determined by the Maxmind or IP2Location Geo Database. | keyword |
| netskope.alert_v2.srcip | IP address of source/user where event is created. | ip |
| netskope.alert_v2.srcport | Port used by the source/user where event is created. It is used by NPA applications. | long |
| netskope.alert_v2.start_time | Capture NPA user's session start time. | date |
| netskope.alert_v2.subject | value present in the email subject captured during DLP email scans. | keyword |
| netskope.alert_v2.suppression_count | Number of events suppressed. | keyword |
| netskope.alert_v2.telemetry_app | Typically SaaS app web sites use web analytics code within the pages to gather analytic data.When a SaaS app action or page is shown, there is subsequent traffic generated to tracking apps such as doubleclick.net, Optimizely, etc. These tracking apps are listed if applicable in theTelemetry App field. | keyword |
| netskope.alert_v2.threat_type | Type of threat detected. | keyword |
| netskope.alert_v2.timestamp | Timestamp when the event/alert happened. Event timestamp in Unix epoch format. | date |
| netskope.alert_v2.to_user | Used when a file is moved from user A to user B. Shows the email address of user B. | keyword |
| netskope.alert_v2.total_packets | Total value of Server Packets + Client Packets. | long |
| netskope.alert_v2.traffic_type | Type of the traffic: CloudApp or Web. CloudApp indicates CASB and web indicates HTTP traffic. Web traffic is only captured for inline access method. It is currently not captured for Risk Insights. | keyword |
| netskope.alert_v2.transaction_id | Unique ID for a given request/response. | keyword |
| netskope.alert_v2.tss_license | Indicates if malware license is enabled for the tenant or not. | keyword |
| netskope.alert_v2.tss_mode | Malware scanning mode, specifies whether it's Real-time Protection or API Data Protection. | keyword |
| netskope.alert_v2.tunnel_id | Shows the Client installation ID. Only available for the Client steering configuration. | keyword |
| netskope.alert_v2.two_factor_auth | Two factor authentication is enabled or not. | keyword |
| netskope.alert_v2.type | Shows if it is an application event or a connection event. Application events are recorded to track user events inside a cloud app. Connection events shows the actual HTTP connection. | keyword |
| netskope.alert_v2.unc_path | The Universal Naming Convention path of the network file share, or printer. | keyword |
| netskope.alert_v2.ur_normalized | All lower case user email. | keyword |
| netskope.alert_v2.url | URL of the application that the user visited as provided by the log or data plane traffic. | wildcard |
| netskope.alert_v2.user | User email. | keyword |
| netskope.alert_v2.user_confidence_index | UCI (User Confidence Index) is one of the ways that UEBA describes how risky the user’s behavior is. The lower UCI is, the more risky the user behavior is. The UCI starts from an initial value and is deducted an amount when the user’s behavior is detected to be anomaly by UEBA engine. The user’s UCI is daily-based, i.e. UEBA engine will create the new UCI with an initial score for users when an UTC day starts. Each user is supposed to start from 1000, but his/her previous day performance will rollover to current day and therefore impact the initial UCI. | long |
| netskope.alert_v2.user_confidence_level | UCI (User Confidence Index) is one of the ways that UEBA describes how risky the user’s behavior is. User confidence level field holds risk level values. | keyword |
| netskope.alert_v2.user_id | User email. | keyword |
| netskope.alert_v2.useragent | The User-Agent request header value. | keyword |
| netskope.alert_v2.usergroup | Custom attributes added by customer using ADImporter. | keyword |
| netskope.alert_v2.userip | IP address of User. | ip |
| netskope.alert_v2.userkey | User ID or email. | keyword |
| netskope.alert_v2.vendor_id | Netskope's Vendor id. | keyword |
| netskope.alert_v2.watchlist_name | Name given by admins while creating watchlist by selecting different filters on webUI. | keyword |
| netskope.alert_v2.web_url | Endpoint configured by customer to fetch Filemeta scan etc. | keyword |


An example event for `alerts_v2` looks as following:

```json
{
    "@timestamp": "2025-05-13T11:02:02.000Z",
    "agent": {
        "ephemeral_id": "1caa7082-bf2e-4fc9-bdac-3673d20f986f",
        "id": "d5fe41dd-4f7d-4b58-b383-eb8ba0a48f0c",
        "name": "elastic-agent-55769",
        "type": "filebeat",
        "version": "8.17.8"
    },
    "aws": {
        "s3": {
            "bucket": {
                "arn": "arn:aws:s3:::elastic-package-netskope-alert-v2-bucket-59128",
                "name": "elastic-package-netskope-alert-v2-bucket-59128"
            },
            "object": {
                "key": "test-alerts-v2.csv.gz"
            }
        }
    },
    "cloud": {
        "region": "us-east-1"
    },
    "data_stream": {
        "dataset": "netskope.alerts_v2",
        "namespace": "89449",
        "type": "logs"
    },
    "destination": {
        "geo": {
            "city_name": "Stockholm",
            "country_iso_code": "SE",
            "postal_code": "100 04",
            "region_name": "Stockholm County",
            "timezone": "Europe/Stockholm"
        },
        "ip": "81.2.69.142",
        "port": 443
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d5fe41dd-4f7d-4b58-b383-eb8ba0a48f0c",
        "snapshot": false,
        "version": "8.17.8"
    },
    "event": {
        "action": "alert",
        "agent_id_status": "verified",
        "dataset": "netskope.alerts_v2",
        "id": "eb8fc9903c2fbb6aa05537ff",
        "ingested": "2025-07-17T11:04:37Z",
        "kind": "alert",
        "original": "{\"_id\":\"eb8fc9903c2fbb6aa05537ff\",\"access_method\":\"Client\",\"account_id\":\"-\",\"account_name\":\"-\",\"acked\":\"false\",\"act_user\":\"-\",\"acting_user\":\"-\",\"action\":\"alert\",\"activity\":\"Edit\",\"alert\":\"yes\",\"alert_id\":\"-\",\"alert_name\":\"Web Access Allow\",\"alert_source\":\"-\",\"alert_type\":\"policy\",\"app\":\"Amazon Systems Manager\",\"app-gdpr-level\":\"-\",\"app_session_id\":\"2241753685910532990\",\"appact\":\"-\",\"appcategory\":\"IT Service/Application Management\",\"appsuite\":\"Amazon\",\"assignee\":\"-\",\"audit_type\":\"-\",\"bcc\":\"-\",\"breach_date\":\"-\",\"breach_id\":\"-\",\"breach_score\":\"-\",\"browser\":\"Native\",\"browser_session_id\":\"4940241048203471891\",\"cc\":\"-\",\"cci\":\"92\",\"ccl\":\"excellent\",\"client_bytes\":\"-\",\"client_packets\":\"-\",\"cloud_provider\":\"-\",\"computer_name\":\"-\",\"conn_duration\":\"-\",\"conn_endtime\":\"-\",\"conn_starttime\":\"-\",\"connection_id\":\"2631086121425559188\",\"connection_type\":\"-\",\"custom_attr\":\"-\",\"destination_file_directory\":\"-\",\"destination_file_name\":\"-\",\"destination_file_path\":\"-\",\"detection_engine\":\"-\",\"device\":\"Windows Device\",\"device_classification\":\"unmanaged\",\"device_sn\":\"-\",\"device_type\":\"-\",\"dinsid\":\"-\",\"dlp_file\":\"-\",\"dlp_fingerprint_classification\":\"-\",\"dlp_fingerprint_match\":\"-\",\"dlp_fingerprint_score\":\"-\",\"dlp_incident_id\":\"-\",\"dlp_is_unique_count\":\"-\",\"dlp_match_info\":\"-\",\"dlp_parent_id\":\"-\",\"dlp_profile\":\"-\",\"dlp_profile_name\":\"-\",\"dlp_rule\":\"-\",\"dlp_rule_count\":\"-\",\"dlp_rule_score\":\"-\",\"dlp_rule_severity\":\"-\",\"dlp_unique_count\":\"-\",\"dns_profile\":\"-\",\"domain\":\"ssm.eu-north-1.amazonaws.com\",\"domain_ip\":\"-\",\"driver\":\"-\",\"dst_country\":\"SE\",\"dst_geoip_src\":\"-\",\"dst_latitude\":\"18.0717|59.328699999999998\",\"dst_location\":\"Stockholm\",\"dst_longitude\":\"18.0717|59.328699999999998\",\"dst_region\":\"Stockholm County\",\"dst_timezone\":\"Europe/Stockholm\",\"dst_zipcode\":\"100 04\",\"dsthost\":\"-\",\"dstip\":\"81.2.69.142\",\"dstport\":\"443\",\"eeml\":\"-\",\"email_from_user\":\"-\",\"email_modified\":\"-\",\"email_title\":\"-\",\"email_user\":\"-\",\"encryption_status\":\"-\",\"end_time\":\"-\",\"event_uuid\":\"-\",\"executable_hash\":\"-\",\"executable_signed\":\"-\",\"file_category\":\"-\",\"file_cls_encrypted\":\"-\",\"file_exposure\":\"-\",\"file_id\":\"-\",\"file_md5\":\"-\",\"file_origin\":\"-\",\"file_owner\":\"-\",\"file_path\":\"-\",\"file_pdl\":\"-\",\"file_size\":\"-\",\"file_type\":\"-\",\"filename\":\"-\",\"filepath\":\"-\",\"fllg\":\"-\",\"flpp\":\"-\",\"from_user\":\"-\",\"hostname\":\"Test-IDMHT6TII\",\"iaas_remediated\":\"-\",\"iaas_remediated_by\":\"-\",\"iaas_remediated_on\":\"-\",\"iaas_remediation_action\":\"-\",\"incident_id\":\"5254981775376249392\",\"inline_dlp_match_info\":\"-\",\"instance\":\"-\",\"instance_id\":\"202533540828\",\"instance_name\":\"-\",\"ip_protocol\":\"-\",\"latest_incident_id\":\"-\",\"loc\":\"-\",\"local_md5\":\"-\",\"local_sha1\":\"-\",\"local_sha256\":\"-\",\"local_source_time\":\"-\",\"location\":\"-\",\"mal_id\":\"-\",\"mal_sev\":\"-\",\"mal_type\":\"-\",\"malware_id\":\"-\",\"malware_severity\":\"-\",\"malware_type\":\"-\",\"managed_app\":\"no\",\"managementID\":\"-\",\"md5\":\"-\",\"message_id\":\"-\",\"mime_type\":\"-\",\"modified_date\":\"-\",\"netskope_pop\":\"SE-STO1\",\"network_session_id\":\"-\",\"nsdeviceuid\":\"-\",\"num_users\":\"-\",\"numbytes\":\"-\",\"oauth\":\"-\",\"object\":\"-\",\"object_id\":\"-\",\"object_type\":\"-\",\"org\":\"-\",\"organization_unit\":\"-\",\"os\":\"Windows 11\",\"os_details\":\"-\",\"os_family\":\"Windows\",\"os_user_name\":\"-\",\"os_version\":\"Windows NT 11.0\",\"owner\":\"-\",\"owner_pdl\":\"-\",\"page\":\"ssm.eu-north-1.amazonaws.com\",\"parent_id\":\"-\",\"pid\":\"-\",\"policy\":\"Web Access Allow\",\"policy_action\":\"-\",\"policy_name\":\"-\",\"policy_name_enforced\":\"-\",\"policy_version\":\"-\",\"pop_id\":\"-\",\"port\":\"443\",\"process_cert_subject\":\"-\",\"process_name\":\"-\",\"process_path\":\"-\",\"product_id\":\"-\",\"publisher_cn\":\"-\",\"record_type\":\"alert\",\"redirect_url\":\"-\",\"referer\":\"-\",\"region_id\":\"-\",\"region_name\":\"-\",\"req\":\"-\",\"req_cnt\":\"-\",\"request_id\":\"5254981775376249392\",\"resource_category\":\"-\",\"resource_group\":\"-\",\"resp\":\"-\",\"resp_cnt\":\"-\",\"response_time\":\"-\",\"risk_level_id\":\"-\",\"risk_score\":\"-\",\"sa_profile_name\":\"-\",\"sa_rule_compliance\":\"-\",\"sa_rule_name\":\"-\",\"sa_rule_severity\":\"-\",\"sanctioned_instance\":\"-\",\"sender\":\"-\",\"server_bytes\":\"-\",\"server_packets\":\"-\",\"serverity\":\"-\",\"session_duration\":\"-\",\"session_number_unique\":\"-\",\"severity\":\"-\",\"severity_id\":\"-\",\"severity_level\":\"-\",\"sha256\":\"-\",\"sharedType\":\"-\",\"shared_credential_user\":\"-\",\"shared_domains\":\"-\",\"shared_with\":\"-\",\"site\":\"Amazon Systems Manager\",\"smtp_status\":\"-\",\"smtp_to\":\"-\",\"spet\":\"-\",\"spst\":\"-\",\"src_country\":\"SE\",\"src_geoip_src\":\"-\",\"src_latitude\":\"18.0717|59.328699999999998\",\"src_location\":\"Stockholm\",\"src_longitude\":\"18.0717|59.328699999999998\",\"src_network\":\"-\",\"src_region\":\"Stockholm County\",\"src_timezone\":\"Europe/Stockholm\",\"src_zipcode\":\"100 04\",\"srcip\":\"81.2.69.142\",\"srcport\":\"-\",\"start_time\":\"-\",\"status\":\"-\",\"subject\":\"-\",\"subtype\":\"-\",\"suppression_count\":\"-\",\"tags\":\"-\",\"telemetry_app\":\"-\",\"thr\":\"-\",\"threat_type\":\"-\",\"timestamp\":\"1747134122\",\"to_user\":\"-\",\"total_packets\":\"-\",\"traffic_type\":\"CloudApp\",\"transaction_id\":\"5254981775376249392\",\"tss_license\":\"-\",\"tss_mode\":\"-\",\"tunnel_id\":\"-\",\"tur\":\"-\",\"two_factor_auth\":\"-\",\"type\":\"nspolicy\",\"unc_path\":\"-\",\"ur_normalized\":\"test@gmail.com\",\"url\":\"ssm.eu-north-1.amazonaws.com/\",\"user\":\"test@gmail.com\",\"user_confidence_index\":\"-\",\"user_confidence_level\":\"-\",\"user_id\":\"-\",\"useragent\":\"aws-sdk-go/1.55.5 (go1.23.7; windows; amd64) amazon-ssm-agent/3.3.2299.0\",\"usergroup\":\"-\",\"userip\":\"81.2.69.142\",\"userkey\":\"test@gmail.com\",\"vendor_id\":\"-\",\"violation\":\"-\",\"watchlist_name\":\"-\",\"web_url\":\"-\"}"
    },
    "host": {
        "domain": "ssm.eu-north-1.amazonaws.com",
        "name": "Test-IDMHT6TII",
        "os": {
            "family": "Windows",
            "full": "Windows 11",
            "version": "Windows NT 11.0"
        }
    },
    "input": {
        "type": "aws-s3"
    },
    "log": {
        "file": {
            "path": "https://elastic-package-netskope-alert-v2-bucket-59128.s3.us-east-1.amazonaws.com/test-alerts-v2.csv.gz"
        },
        "offset": 4504
    },
    "netskope": {
        "alert_v2": {
            "access_method": "Client",
            "acked": false,
            "activity": "Edit",
            "alert": "yes",
            "alert_type": "policy",
            "app_session_id": "2241753685910532990",
            "appcategory": "IT Service/Application Management",
            "appsuite": "Amazon",
            "browser": "Native",
            "browser_session_id": "4940241048203471891",
            "cci": 92,
            "ccl": "excellent",
            "connection_id": "2631086121425559188",
            "device": "Windows Device",
            "device_classification": "unmanaged",
            "dst_latitude_keyword": "18.0717|59.328699999999998",
            "dst_longitude_keyword": "18.0717|59.328699999999998",
            "incident_id": "5254981775376249392",
            "instance_id": "202533540828",
            "managed_app": "no",
            "netskope_pop": "SE-STO1",
            "page": "ssm.eu-north-1.amazonaws.com",
            "policy": "Web Access Allow",
            "port": "443",
            "record_type": "alert",
            "request_id": "5254981775376249392",
            "site": "Amazon Systems Manager",
            "src_latitude_keyword": "18.0717|59.328699999999998",
            "src_longitude_keyword": "18.0717|59.328699999999998",
            "traffic_type": "CloudApp",
            "transaction_id": "5254981775376249392",
            "type": "nspolicy",
            "ur_normalized": "test@gmail.com",
            "userip": "81.2.69.142",
            "userkey": "test@gmail.com"
        }
    },
    "network": {
        "application": "amazon systems manager"
    },
    "related": {
        "hosts": [
            "ssm.eu-north-1.amazonaws.com",
            "Test-IDMHT6TII"
        ],
        "ip": [
            "81.2.69.142"
        ],
        "user": [
            "test@gmail.com"
        ]
    },
    "rule": {
        "name": "Web Access Allow"
    },
    "source": {
        "geo": {
            "city_name": "Stockholm",
            "country_iso_code": "SE",
            "postal_code": "100 04",
            "region_name": "Stockholm County",
            "timezone": "Europe/Stockholm"
        },
        "ip": "81.2.69.142"
    },
    "tags": [
        "collect_sqs_logs",
        "preserve_original_event",
        "forwarded",
        "netskope-alerts"
    ],
    "url": {
        "original": "ssm.eu-north-1.amazonaws.com/"
    },
    "user": {
        "email": "test@gmail.com"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "aws-sdk-go",
        "original": "aws-sdk-go/1.55.5 (go1.23.7; windows; amd64) amazon-ssm-agent/3.3.2299.0",
        "version": "1.55.5"
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

### Events V2

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| aws.s3.bucket.arn | The AWS S3 bucket ARN. | keyword |
| aws.s3.bucket.name | The AWS S3 bucket name. | keyword |
| aws.s3.object.key | The AWS S3 Object key. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| netskope.events_v2._id | Unique id - hexadecimal string. | keyword |
| netskope.events_v2.access_method | Cloud app traffic can be steered to the Netskope cloud using different deployment methods such as Client (Netskope Client), Secure Forwarder etc. Administrators can also upload firewall and/or proxy logs for log analytics. This field shows the actual access method that triggered the event.For log uploads this shows the actual log type such as PAN, Websense, etc. | keyword |
| netskope.events_v2.acting_user | Acting User is the user responsible for the violation. | keyword |
| netskope.events_v2.action | Action taken on the event for the policy. | keyword |
| netskope.events_v2.activity | Description of the user performed activity. | keyword |
| netskope.events_v2.alert | Indicates whether alert is generated or not and its populated as yes for all alerts. | keyword |
| netskope.events_v2.alert_name | Indicates the alert is raised and the carries the name of the alert raised. | keyword |
| netskope.events_v2.alert_type | Indicates the alert is raised and the carries the type of the alert raised. | keyword |
| netskope.events_v2.app | Specific cloud application used by the user. | keyword |
| netskope.events_v2.app_session_id | Unique App/Site Session ID for traffic_type = CloudApp and Web. An app session starts when a user starts using a cloud app/site on and ends once they have been inactive for a certain period of time(15 minutes). Use app_session_id to check all the user activities in a single app session. app_session_id is unique for a user, device, browser and domain. | keyword |
| netskope.events_v2.appact | UBA service detect app activities performed by the end user like Download, Upload etc. | keyword |
| netskope.events_v2.appcategory | The application category. | keyword |
| netskope.events_v2.appsuite | The SAAS application suite ( Ex : Microsoft Office / Google Docs  etc ). | keyword |
| netskope.events_v2.assignee | Represents the username to whom the incident is assigned to. | keyword |
| netskope.events_v2.audit_type | The sub category in audit according to SaaS / IaaS apps. | keyword |
| netskope.events_v2.bcc | Breach target references for compromised credentials or BCC users information in the case of SMTP DLP incident. | keyword |
| netskope.events_v2.browser | Shows the actual browser from where the cloud app was accessed.A native browser refers to Safari (iOS), Chrome (Android), or the default browser on the user's laptop. | keyword |
| netskope.events_v2.browser_session_id | Browser Session Id. | keyword |
| netskope.events_v2.cc | SMTP Proxy will parse the cc field in the email and send them to DLP in the event object. The cc recipients from the e-mail header, up to 1KB. | keyword |
| netskope.events_v2.cci | Cloud confidence Index value as Integer. | long |
| netskope.events_v2.ccl | Cloud Confidence Level. CCL measures the enterprise readiness of the cloud apps taking into consideration those apps security, auditability and business continuity.Each app is assigned one of five cloud confidence levels: excellent, high, medium, low, or poor. Useful for querying if users are accessing a cloud app with a lower CCL. | keyword |
| netskope.events_v2.client_bytes | Total number of bytes uploaded from client to server. | long |
| netskope.events_v2.client_packets | Total number of packets uploaded from client to server. | long |
| netskope.events_v2.computer_name | Computer name of the end point. | keyword |
| netskope.events_v2.conn_duration | Duration of the connection in milliseconds. Useful for querying long-lived sessions. | long |
| netskope.events_v2.conn_endtime | Connection end time. | date |
| netskope.events_v2.conn_starttime | Connection start time. | date |
| netskope.events_v2.connection_id | Each connection has a unique ID. Shows the ID for the connection event. | keyword |
| netskope.events_v2.connection_type | EndPoint DLP connection mode. | keyword |
| netskope.events_v2.destination_file_directory | The directory and filename of the destination file on the endpoint. | keyword |
| netskope.events_v2.destination_file_name | Endpoint DLP destination file name. | keyword |
| netskope.events_v2.destination_file_path | Endpoint DLP destination file path. | keyword |
| netskope.events_v2.device | Device type from where the user accessed the cloud app. It could be Macintosh Windows device, iPad etc. | keyword |
| netskope.events_v2.device_classification | Designation of device as determined by the Netskope Client as to whether the device is managed or not. | keyword |
| netskope.events_v2.device_sn | Device serial number. | keyword |
| netskope.events_v2.device_type | Device type. | keyword |
| netskope.events_v2.dlp_file | File/Object name extracted from the file/object. | keyword |
| netskope.events_v2.dlp_incident_id | Incident ID associated with sub-file in DLP scans. In the case of main file, this is same as the parent incident ID. | keyword |
| netskope.events_v2.dlp_is_unique_count | True or false depending upon if rule is unique counted per rule data. | boolean |
| netskope.events_v2.dlp_match_info | DLP match info carries the details about DLP profile and rule info along with the violation count information. | keyword |
| netskope.events_v2.dlp_parent_id | Incident ID associated with main container (or non-container) file that was scanned. | keyword |
| netskope.events_v2.dlp_profile | DLP profile name. | keyword |
| netskope.events_v2.dlp_profile_name | DLP profile name. | keyword |
| netskope.events_v2.dlp_rule | DLP rule that triggered the scans. | keyword |
| netskope.events_v2.dlp_rule_count | Count of dlp rule hits. | long |
| netskope.events_v2.dlp_rule_severity | Severity of DLP rule. | keyword |
| netskope.events_v2.dlp_unique_count | Integer value of number of unique matches seen per rule data. Only present if rule is uniquely counted. | long |
| netskope.events_v2.dns_profile | DNS profiles allow you to control, inspect, and log all or blocked DNS traffic. When configuring a DNS profile, you can configure the actions taken for specific domain categories and choose to allow or block specific domains. This field contains the configuration file name. | keyword |
| netskope.events_v2.domain | Domain value. This will hold the host header value or SNI or extracted from absolute URI. | keyword |
| netskope.events_v2.domain_ip | Domain IP address. | ip |
| netskope.events_v2.driver | Driver name used by endpoint device. | keyword |
| netskope.events_v2.dst_country | Application's two-letter country code as determined by the Maxmind or IP2Location Geo Database. | keyword |
| netskope.events_v2.dst_geoip_src | Source from where the location of Destination IP was derived. | long |
| netskope.events_v2.dst_latitude | Latitude of the Application as determined by the Maxmind or IP2Location Geo Database. | double |
| netskope.events_v2.dst_latitude_keyword |  | keyword |
| netskope.events_v2.dst_location | Application's city as determined by the Maxmind or IP2Location Geo database. | keyword |
| netskope.events_v2.dst_longitude | Longitude of the Application as determined by the Maxmind or IP2Location Geo Database. | double |
| netskope.events_v2.dst_longitude_keyword |  | keyword |
| netskope.events_v2.dst_region | Application's state or region as determined by the Maxmind or IP2Location Geo Database. | keyword |
| netskope.events_v2.dst_timezone | Destination timezone. | keyword |
| netskope.events_v2.dst_zipcode | Application's zip code as determined by the Maxmind or IP2Location Geo Database. | keyword |
| netskope.events_v2.dsthost | Destination host. | keyword |
| netskope.events_v2.dstip | IP address where the destination app is hosted. | ip |
| netskope.events_v2.dstport | Destination port. | long |
| netskope.events_v2.end_time | When events are suppressed (like collaboration apps), then the suppression end time will be set and only one event will be send with suppression start time and end time and count of occurrence. | date |
| netskope.events_v2.executable_hash | Flag to indicate if executable_hash is signed or not. | keyword |
| netskope.events_v2.executable_signed | Flag to indicate if executable_hash is signed or not. | boolean |
| netskope.events_v2.file_origin | File origin source location. | keyword |
| netskope.events_v2.file_path | Path of the file in the application. | keyword |
| netskope.events_v2.file_size | Size of the file in bytes. | long |
| netskope.events_v2.file_type | File type as detected by Netskope Solutions. | keyword |
| netskope.events_v2.from_user | Email address used to login to the SAAS app. | keyword |
| netskope.events_v2.hostname | User's Host name. | keyword |
| netskope.events_v2.incident_id | Unique Incident ID associated with main container (or non-container) file that was scanned. | keyword |
| netskope.events_v2.inline_dlp_match_info | Inline DLP match info carries the details about DLP profile and rule info along with the violation count information. | keyword |
| netskope.events_v2.instance | Instance associated with an organization application instance. | keyword |
| netskope.events_v2.instance_id | Unique ID associated with an organization application instance. | keyword |
| netskope.events_v2.ip_protocol | Assigned Internet Protocol Number. | keyword |
| netskope.events_v2.latest_incident_id | Latest incident ID captured by DLP backend services. | keyword |
| netskope.events_v2.location | A string that specifies the physical location of the printer (for example, Bldg. 38, Room 1164). | keyword |
| netskope.events_v2.managed_app | Whether or not the app in question is managed. | keyword |
| netskope.events_v2.managementID | Field value is attached to Devices Host Info Object. | keyword |
| netskope.events_v2.md5 | MD5 value of the file content. | keyword |
| netskope.events_v2.mime_type | A media type (also known as a Multipurpose Internet Mail Extensions or MIME type) indicates the nature and format of a document, file, or assortment of bytes. | keyword |
| netskope.events_v2.netskope_pop | Netskope Data Plane name. | keyword |
| netskope.events_v2.network_session_id | Network session ID used by NPA services. | keyword |
| netskope.events_v2.nsdeviceuid | Device ID attached to Devices Host Info Object. | keyword |
| netskope.events_v2.numbytes | Total number of bytes that were transmitted for the connection - numbytes = client_bytes + server_bytes. | long |
| netskope.events_v2.oauth | Oauth is a standard that allows applications to access a user's data without the user needing to share their password. This field holds value if it was used or not. | keyword |
| netskope.events_v2.object | Name of the object which is being acted on. It could be a filename, folder name, report name, document name, etc.Incident object name and the value of the field represents the object details of the incident triggered. | keyword |
| netskope.events_v2.object_id | Unique ID associated with an object. | keyword |
| netskope.events_v2.object_type | Type of the object which is being acted on. Object type could be a file, folder, report, document, message, etc. | keyword |
| netskope.events_v2.org | Search for events from a specific organization. Organization name is derived from the user ID. | keyword |
| netskope.events_v2.organization_unit | Org Units for which the event correlates to. This ties to user information extracted from Active Directory using the Directory Importer/AD Connector application. | keyword |
| netskope.events_v2.os | Operating system of the host who generated the event. | keyword |
| netskope.events_v2.os_details | Detailed OS version string. | keyword |
| netskope.events_v2.os_family | Operating system type of the end user's device. | keyword |
| netskope.events_v2.os_user_name | Username on the local machine that performs action. | keyword |
| netskope.events_v2.os_version | OS version of the host. | keyword |
| netskope.events_v2.owner | Owner or the user information of the file object in DLP. | keyword |
| netskope.events_v2.owner_pdl | File's owner Preferred Data Location derived from owner uid(OneDrive) and site URL(SharePoint). | keyword |
| netskope.events_v2.page | The URL of the originating page. | keyword |
| netskope.events_v2.parent_id | Parent ID ( event_id ) of an alert. | keyword |
| netskope.events_v2.pid | Process ID that is doing file processing ex: A process that trigger the evaluation. | long |
| netskope.events_v2.policy | Name of the policy configured by an admin. | keyword |
| netskope.events_v2.policy_action | Endpoint DLP Policy action planned according to the policy. User can override the planned action or actual enforcement action might not be implemented. | keyword |
| netskope.events_v2.policy_name | Endpoint DLP Name of matching policy. | keyword |
| netskope.events_v2.policy_name_enforced | Actual policy name used by Endpoint DLP Policy. | keyword |
| netskope.events_v2.policy_version | Endpoint DLP Policy name configured version number. | keyword |
| netskope.events_v2.pop_id | Netskope MPs/DPs unique id. | keyword |
| netskope.events_v2.port | A string that identifies the port(s) used to transmit data to the printer. If a printer is connected to more than one port, the names of each port must be separated by commas (for example, LPT1:,LPT2:,LPT3:). | keyword |
| netskope.events_v2.process_cert_subject | the subject of the certificate that signed the process. | keyword |
| netskope.events_v2.process_name | Endpoint process Name For example: native application for Printer on User's Laptop. | keyword |
| netskope.events_v2.process_path | The path to the process that performed the action on the endpoint. | keyword |
| netskope.events_v2.product_id | It's Part of USB specification. Used to identify a USB device. | keyword |
| netskope.events_v2.publisher_cn | The publisher CName. | keyword |
| netskope.events_v2.record_type | Indicate the event type of the record. | keyword |
| netskope.events_v2.referer | Referer URL associated with an activity in a cloud app.Referer URL of the application(with http) that the user visited as provided by the log or data plane traffic. | keyword |
| netskope.events_v2.req_cnt | Total number of HTTP requests (equal to number of transaction events for this page event) sent from client to server over one underlying TCP connection. | long |
| netskope.events_v2.request_id | Unique id attached to proxy activity events and dlp activity events. | keyword |
| netskope.events_v2.resp_cnt | Total number of HTTP responses (equal to number of transaction events for this page event) from server to client. | long |
| netskope.events_v2.response_time | Response time in milliseconds from the server/app as captured by NPA solution. | long |
| netskope.events_v2.sanctioned_instance | A sanctioned instance is a company owned account in an external application. A value of yes indicates that the company has granted    access for the specific SaaS / IaaS account to Netskope. A value of no    represents a personal user account or an enterprise account not    authorized by the enterprise Administrator. | keyword |
| netskope.events_v2.server_bytes | Total number of downloaded bytes from server to client. | long |
| netskope.events_v2.server_packets | Total number of server packet from server to client. | long |
| netskope.events_v2.session_duration | Session duration of a session. | long |
| netskope.events_v2.severity | Severity used by watchlist and malware alerts. Severity of the incident. | keyword |
| netskope.events_v2.sha256 | Sha256 value of a file. | keyword |
| netskope.events_v2.shared_with | Email ids with whom a document is shared with. | keyword |
| netskope.events_v2.site | For traffic_type = CloudApp, site = app and for traffic_type = Web, it will be the second level domain name + top-level domain name. For example, in www.cnn.com, it is cnn.com. | keyword |
| netskope.events_v2.smtp_to | SMTP Proxy will parse the smtp_to field in the email and send them to DLP in the event object. List contains the The recipients from the SMTP envelope. | keyword |
| netskope.events_v2.src_country | User's country's two-letter Country Code as determined by the Maxmind or IP2Location Geo Database. | keyword |
| netskope.events_v2.src_geoip_src | Source from where the location of Source IP was derived. | long |
| netskope.events_v2.src_latitude | Latitude of the user as determined by the Maxmind or IP2Location Geo database. | double |
| netskope.events_v2.src_latitude_keyword |  | keyword |
| netskope.events_v2.src_location | User's city as determined by the Maxmind or IP2Location Geo Database. | keyword |
| netskope.events_v2.src_longitude | Longitude of the user as determined by the Maxmind or IP2Location Geo database. | double |
| netskope.events_v2.src_longitude_keyword |  | keyword |
| netskope.events_v2.src_region | Source state or region as determined by the Maxmind or IP2Location Geo database. | keyword |
| netskope.events_v2.src_timezone | Source timezone for the location at which the event is created. Shows the long format timezone designation. | keyword |
| netskope.events_v2.src_zipcode | Source zip code for the location at which the event is created as determined by the Maxmind or IP2Location Geo Database. | keyword |
| netskope.events_v2.srcip | IP address of source/user where event is created. | ip |
| netskope.events_v2.srcport | Port used by the source/user where event is created. It is used by NPA applications. | long |
| netskope.events_v2.start_time | Capture NPA user's session start time. | date |
| netskope.events_v2.status | Specific status name used by the enduser for DLP incidents. | keyword |
| netskope.events_v2.telemetry_app | Typically SaaS app web sites use web analytics code within the pages to gather analytic data.When a SaaS app action or page is shown, there is subsequent traffic generated to tracking apps such as doubleclick.net, Optimizely, etc. These tracking apps are listed if applicable in theTelemetry App field. | keyword |
| netskope.events_v2.threat_type | Type of threat detected. | keyword |
| netskope.events_v2.timestamp | Timestamp when the event/alert happened. Event timestamp in Unix epoch format. | date |
| netskope.events_v2.to_user | Used when a file is moved from user A to user B. Shows the email address of user B. | keyword |
| netskope.events_v2.total_packets | Total value of Server Packets + Client Packets. | long |
| netskope.events_v2.traffic_type | Type of the traffic: CloudApp or Web. CloudApp indicates CASB and web indicates HTTP traffic. Web traffic is only captured for inline access method. It is currently not captured for Risk Insights. | keyword |
| netskope.events_v2.transaction_id | Unique ID for a given request/response. | keyword |
| netskope.events_v2.tss_mode | Malware scanning mode, specifies whether it's Real-time Protection or API Data Protection. | keyword |
| netskope.events_v2.tunnel_id | Shows the Client installation ID. Only available for the Client steering configuration. | keyword |
| netskope.events_v2.type | Shows if it is an application event or a connection event. Application events are recorded to track user events inside a cloud app. Connection events shows the actual HTTP connection. | keyword |
| netskope.events_v2.unc_path | The Universal Naming Convention path of the network file share, or printer. | keyword |
| netskope.events_v2.ur_normalized | All lower case user email. | keyword |
| netskope.events_v2.url | URL of the application that the user visited as provided by the log or data plane traffic. | wildcard |
| netskope.events_v2.user | User email. | keyword |
| netskope.events_v2.user_confidence_index | UCI (User Confidence Index) is one of the ways that UEBA describes how risky the user\u2019s behavior is. The lower UCI is, the more risky the user behavior is. The UCI starts from an initial value and is deducted an amount when the user\u2019s behavior is detected to be anomaly by UEBA engine. The user\u2019s UCI is daily-based, i.e. UEBA engine will create the new UCI with an initial score for users when an UTC day starts. Each user is supposed to start from 1000, but his/her previous day performance will rollover to current day and therefore impact the initial UCI. | long |
| netskope.events_v2.user_confidence_level | UCI (User Confidence Index) is one of the ways that UEBA describes how risky the user\u2019s behavior is. User confidence level field holds risk level values. | keyword |
| netskope.events_v2.user_id | User email. | keyword |
| netskope.events_v2.useragent | The User-Agent request header value. | keyword |
| netskope.events_v2.userip | IP address of User. | ip |
| netskope.events_v2.userkey | User ID or email. | keyword |
| netskope.events_v2.vendor_id | Netskope's Vendor id. | keyword |


An example event for `events_v2` looks as following:

```json
{
    "@timestamp": "2025-05-13T10:43:50.000Z",
    "agent": {
        "ephemeral_id": "04b261d7-d51e-485c-aed5-039119a22e80",
        "id": "e8f06fce-767e-4024-bea3-813ec054f48d",
        "name": "elastic-agent-69616",
        "type": "filebeat",
        "version": "8.17.8"
    },
    "aws": {
        "s3": {
            "bucket": {
                "arn": "arn:aws:s3:::elastic-package-netskope-bucket-91880",
                "name": "elastic-package-netskope-bucket-91880"
            },
            "object": {
                "key": "events.csv.gz"
            }
        }
    },
    "client": {
        "bytes": 961033
    },
    "cloud": {
        "region": "us-east-1"
    },
    "data_stream": {
        "dataset": "netskope.events_v2",
        "namespace": "42670",
        "type": "logs"
    },
    "destination": {
        "bytes": 387197,
        "geo": {
            "city_name": "Chennai",
            "country_iso_code": "IN",
            "region_name": "Tamil Nadu",
            "timezone": "Asia/Kolkata"
        },
        "ip": "142.250.77.133",
        "port": 443
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e8f06fce-767e-4024-bea3-813ec054f48d",
        "snapshot": false,
        "version": "8.17.8"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "netskope.events_v2",
        "id": "c96659f7292a31d76576becd",
        "ingested": "2025-07-18T10:39:59Z",
        "kind": "event",
        "original": "{\"_id\":\"c96659f7292a31d76576becd\",\"access_method\":\"Client\",\"account_id\":\"-\",\"account_name\":\"-\",\"acked\":\"-\",\"act_user\":\"-\",\"acting_user\":\"-\",\"action\":\"-\",\"activity\":\"-\",\"alert\":\"-\",\"alert_id\":\"-\",\"alert_name\":\"-\",\"alert_source\":\"-\",\"alert_type\":\"-\",\"app\":\"Google Gmail\",\"app-gdpr-level\":\"-\",\"app_session_id\":\"438388819325815355\",\"appact\":\"-\",\"appcategory\":\"Webmail\",\"appsuite\":\"-\",\"assignee\":\"-\",\"audit_type\":\"-\",\"bcc\":\"-\",\"breach_date\":\"-\",\"breach_id\":\"-\",\"breach_score\":\"-\",\"browser\":\"Chrome\",\"browser_session_id\":\"5006467906912901882\",\"cc\":\"-\",\"cci\":\"86\",\"ccl\":\"high\",\"client_bytes\":\"961033\",\"client_packets\":\"-\",\"cloud_provider\":\"-\",\"computer_name\":\"-\",\"conn_duration\":\"986\",\"conn_endtime\":\"1747134016\",\"conn_starttime\":\"1747133030\",\"connection_id\":\"8335488044687090606\",\"connection_type\":\"-\",\"custom_attr\":\"-\",\"destination_file_directory\":\"-\",\"destination_file_name\":\"-\",\"destination_file_path\":\"-\",\"detection_engine\":\"-\",\"device\":\"Windows Device\",\"device_classification\":\"-\",\"device_sn\":\"-\",\"device_type\":\"-\",\"dinsid\":\"-\",\"dlp_file\":\"-\",\"dlp_fingerprint_classification\":\"-\",\"dlp_fingerprint_match\":\"-\",\"dlp_fingerprint_score\":\"-\",\"dlp_incident_id\":\"-\",\"dlp_is_unique_count\":\"-\",\"dlp_match_info\":\"-\",\"dlp_parent_id\":\"-\",\"dlp_profile\":\"-\",\"dlp_profile_name\":\"-\",\"dlp_rule\":\"-\",\"dlp_rule_count\":\"-\",\"dlp_rule_score\":\"-\",\"dlp_rule_severity\":\"-\",\"dlp_unique_count\":\"-\",\"dns_profile\":\"-\",\"domain\":\"mail.google.com\",\"domain_ip\":\"-\",\"driver\":\"-\",\"dst_country\":\"IN\",\"dst_geoip_src\":\"-\",\"dst_latitude\":\"80.278480529785156|13.087898254394531\",\"dst_location\":\"Chennai\",\"dst_longitude\":\"80.278480529785156|13.087898254394531\",\"dst_region\":\"Tamil Nadu\",\"dst_timezone\":\"Asia/Kolkata\",\"dst_zipcode\":\"N/A\",\"dsthost\":\"-\",\"dstip\":\"142.250.77.133\",\"dstport\":\"443\",\"eeml\":\"-\",\"email_from_user\":\"-\",\"email_modified\":\"-\",\"email_title\":\"-\",\"email_user\":\"-\",\"encryption_status\":\"-\",\"end_time\":\"-\",\"event_uuid\":\"-\",\"executable_hash\":\"-\",\"executable_signed\":\"-\",\"file_category\":\"-\",\"file_cls_encrypted\":\"-\",\"file_exposure\":\"-\",\"file_id\":\"-\",\"file_md5\":\"-\",\"file_origin\":\"-\",\"file_owner\":\"-\",\"file_path\":\"-\",\"file_pdl\":\"-\",\"file_size\":\"-\",\"file_type\":\"-\",\"filename\":\"-\",\"filepath\":\"-\",\"fllg\":\"-\",\"flpp\":\"-\",\"from_user\":\"-\",\"hostname\":\"Test\",\"iaas_remediated\":\"-\",\"iaas_remediated_by\":\"-\",\"iaas_remediated_on\":\"-\",\"iaas_remediation_action\":\"-\",\"incident_id\":\"-\",\"inline_dlp_match_info\":\"-\",\"instance\":\"-\",\"instance_id\":\"-\",\"instance_name\":\"-\",\"ip_protocol\":\"-\",\"latest_incident_id\":\"-\",\"loc\":\"-\",\"local_md5\":\"-\",\"local_sha1\":\"-\",\"local_sha256\":\"-\",\"local_source_time\":\"-\",\"location\":\"-\",\"mal_id\":\"-\",\"mal_sev\":\"-\",\"mal_type\":\"-\",\"malware_id\":\"-\",\"malware_severity\":\"-\",\"malware_type\":\"-\",\"managed_app\":\"-\",\"managementID\":\"-\",\"md5\":\"-\",\"message_id\":\"-\",\"mime_type\":\"-\",\"modified_date\":\"-\",\"netskope_pop\":\"IN-MAA2\",\"network_session_id\":\"-\",\"nsdeviceuid\":\"-\",\"num_users\":\"-\",\"numbytes\":\"1348230\",\"oauth\":\"-\",\"object\":\"-\",\"object_id\":\"-\",\"object_type\":\"-\",\"org\":\"-\",\"organization_unit\":\"-\",\"os\":\"Windows 11\",\"os_details\":\"-\",\"os_family\":\"Windows\",\"os_user_name\":\"-\",\"os_version\":\"Windows NT 11.0\",\"owner\":\"-\",\"owner_pdl\":\"-\",\"page\":\"mail.google.com\",\"parent_id\":\"-\",\"pid\":\"-\",\"policy\":\"-\",\"policy_action\":\"-\",\"policy_name\":\"-\",\"policy_name_enforced\":\"-\",\"policy_version\":\"-\",\"pop_id\":\"-\",\"port\":\"-\",\"process_cert_subject\":\"-\",\"process_name\":\"-\",\"process_path\":\"-\",\"product_id\":\"-\",\"publisher_cn\":\"-\",\"record_type\":\"page\",\"redirect_url\":\"-\",\"referer\":\"-\",\"region_id\":\"-\",\"region_name\":\"-\",\"req\":\"-\",\"req_cnt\":\"173\",\"request_id\":\"-\",\"resource_category\":\"-\",\"resource_group\":\"-\",\"resp\":\"-\",\"resp_cnt\":\"173\",\"response_time\":\"-\",\"risk_level_id\":\"-\",\"risk_score\":\"-\",\"sa_profile_name\":\"-\",\"sa_rule_compliance\":\"-\",\"sa_rule_name\":\"-\",\"sa_rule_severity\":\"-\",\"sanctioned_instance\":\"-\",\"sender\":\"-\",\"server_bytes\":\"387197\",\"server_packets\":\"-\",\"serverity\":\"-\",\"session_duration\":\"-\",\"session_number_unique\":\"-\",\"severity\":\"-\",\"severity_id\":\"-\",\"severity_level\":\"-\",\"sha256\":\"-\",\"sharedType\":\"-\",\"shared_credential_user\":\"-\",\"shared_domains\":\"-\",\"shared_with\":\"-\",\"site\":\"Google Gmail\",\"smtp_status\":\"-\",\"smtp_to\":\"-\",\"spet\":\"-\",\"spst\":\"-\",\"src_country\":\"IN\",\"src_geoip_src\":\"-\",\"src_latitude\":\"77.590999999999994|12.975300000000001\",\"src_location\":\"Bengaluru\",\"src_longitude\":\"77.590999999999994|12.975300000000001\",\"src_network\":\"-\",\"src_region\":\"Karnataka\",\"src_timezone\":\"Asia/Kolkata\",\"src_zipcode\":\"562130\",\"srcip\":\"175.16.199.0\",\"srcport\":\"-\",\"start_time\":\"-\",\"status\":\"-\",\"subject\":\"-\",\"subtype\":\"-\",\"suppression_count\":\"-\",\"tags\":\"-\",\"telemetry_app\":\"-\",\"thr\":\"-\",\"threat_type\":\"-\",\"timestamp\":\"1747133030\",\"to_user\":\"-\",\"total_packets\":\"-\",\"traffic_type\":\"CloudApp\",\"transaction_id\":\"-\",\"tss_license\":\"-\",\"tss_mode\":\"-\",\"tunnel_id\":\"-\",\"tur\":\"-\",\"two_factor_auth\":\"-\",\"type\":\"connection\",\"unc_path\":\"-\",\"ur_normalized\":\"test@gmail.com\",\"url\":\"mail.google.com\",\"user\":\"test@gmail.com\",\"user_confidence_index\":\"-\",\"user_confidence_level\":\"-\",\"user_id\":\"-\",\"useragent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36\",\"usergroup\":\"-\",\"userip\":\"192.168.1.11\",\"userkey\":\"test@gmail.com\",\"vendor_id\":\"-\",\"violation\":\"-\",\"watchlist_name\":\"-\",\"web_url\":\"-\"}",
        "outcome": "unknown",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "Test",
        "os": {
            "family": "Windows",
            "full": "Windows 11",
            "version": "NT 11.0"
        }
    },
    "input": {
        "type": "aws-s3"
    },
    "log": {
        "file": {
            "path": "https://elastic-package-netskope-bucket-91880.s3.us-east-1.amazonaws.com/events.csv.gz"
        },
        "offset": 3962
    },
    "netskope": {
        "events_v2": {
            "access_method": "Client",
            "app_session_id": "438388819325815355",
            "appcategory": "Webmail",
            "browser": "Chrome",
            "browser_session_id": "5006467906912901882",
            "cci": 86,
            "ccl": "high",
            "conn_duration": 986,
            "conn_endtime": "2025-05-13T11:00:16.000Z",
            "conn_starttime": "2025-05-13T10:43:50.000Z",
            "connection_id": "8335488044687090606",
            "device": "Windows Device",
            "domain": "mail.google.com",
            "dst_latitude_keyword": "80.278480529785156|13.087898254394531",
            "dst_longitude_keyword": "80.278480529785156|13.087898254394531",
            "netskope_pop": "IN-MAA2",
            "page": "mail.google.com",
            "record_type": "page",
            "req_cnt": 173,
            "resp_cnt": 173,
            "site": "Google Gmail",
            "src_country": "IN",
            "src_latitude_keyword": "77.590999999999994|12.975300000000001",
            "src_location": "Bengaluru",
            "src_longitude_keyword": "77.590999999999994|12.975300000000001",
            "src_region": "Karnataka",
            "src_timezone": "Asia/Kolkata",
            "src_zipcode": "562130",
            "srcip": "175.16.199.0",
            "traffic_type": "CloudApp",
            "type": "connection",
            "ur_normalized": "test@gmail.com",
            "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
            "userip": "192.168.1.11",
            "userkey": "test@gmail.com"
        }
    },
    "network": {
        "application": "google gmail",
        "bytes": 1348230
    },
    "related": {
        "hosts": [
            "Test",
            "mail.google.com"
        ],
        "ip": [
            "142.250.77.133",
            "192.168.1.11"
        ],
        "user": [
            "test",
            "test@gmail.com"
        ]
    },
    "server": {
        "bytes": 387197
    },
    "source": {
        "bytes": 961033,
        "geo": {
            "country_iso_code": "IN",
            "postal_code": "562130",
            "region_name": "Karnataka"
        },
        "ip": "175.16.199.0"
    },
    "tags": [
        "collect_sqs_logs",
        "preserve_original_event",
        "forwarded",
        "netskope-event"
    ],
    "url": {
        "original": "mail.google.com"
    },
    "user": {
        "domain": "gmail.com",
        "email": "test@gmail.com",
        "name": "test"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "os": {
            "full": "Windows 10",
            "name": "Windows",
            "version": "10"
        },
        "version": "136.0.0.0"
    }
}
```

### Transaction

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| aws.s3.bucket.arn | The AWS S3 bucket ARN. | keyword |
| aws.s3.bucket.name | The AWS S3 bucket name. | keyword |
| aws.s3.object.key | The AWS S3 Object key. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| netskope.transaction.bytes | Sum of client bytes plus server bytes. | long |
| netskope.transaction.c_ip | Client IP as seen by the Netskope proxy. This will be the machine IP if available, IPv4 address. | ip |
| netskope.transaction.cs_bytes | Bytes received from the client. | long |
| netskope.transaction.cs_content_type | The content-type header in the HTTP request. | keyword |
| netskope.transaction.cs_dns | The destination domain requested. | keyword |
| netskope.transaction.cs_host | The value in the host header from the request. | keyword |
| netskope.transaction.cs_method | The HTTP method (e.g. GET, POST). | keyword |
| netskope.transaction.cs_referer | The value of the referrer header. | keyword |
| netskope.transaction.cs_uri | Path information plus query string. | keyword |
| netskope.transaction.cs_uri_port | Port specified in the request header. | long |
| netskope.transaction.cs_uri_query | The query string portion of the HTTP request. | keyword |
| netskope.transaction.cs_uri_scheme | The protocol used. | keyword |
| netskope.transaction.cs_user_agent | The user-agent header in the HTTP request. | keyword |
| netskope.transaction.cs_username | The client’s username. | keyword |
| netskope.transaction.date | Date of generation, YY-MM-DD format. NOTE: Human readable string for the “x-cs-timestamp” field. | date |
| netskope.transaction.rs_status | The HTTP status code received from the remote server. | long |
| netskope.transaction.s_ip | The server IPv4 address. NOTE: During SSL bypass, the s-ip field displays as Unavailable when it’s neither IPv4 or IPv6. | ip |
| netskope.transaction.sc_bytes | Bytes received from the server. | long |
| netskope.transaction.sc_content_type | The content-type header from the response. | keyword |
| netskope.transaction.sc_status | The HTTP status code received from the server. | long |
| netskope.transaction.time | Time of generation in HH:MM-SEC format in GMT. NOTE: Human readable string for the “x-cs-timestamp” field. | keyword |
| netskope.transaction.time_taken | Delta (integer value in ms) when the request processing started and the full response was received. | keyword |
| netskope.transaction.x_c_browser | Client’s browser. | keyword |
| netskope.transaction.x_c_browser_version | Client’s browser version. | keyword |
| netskope.transaction.x_c_country | Country of the client (user). | keyword |
| netskope.transaction.x_c_device | Client’s device type. | keyword |
| netskope.transaction.x_c_latitude | Latitude of the client. | double |
| netskope.transaction.x_c_local_time | The local time of the client calculated from geolocation of the device IP. | date |
| netskope.transaction.x_c_location | Location of the client. | keyword |
| netskope.transaction.x_c_longitude | Longitude of the client. | double |
| netskope.transaction.x_c_os | Operating system of the client. | keyword |
| netskope.transaction.x_c_region | Region of the client. | keyword |
| netskope.transaction.x_c_zipcode | Zip code of the client. | keyword |
| netskope.transaction.x_category | Primary category name applicable for the url in this transaction. | keyword |
| netskope.transaction.x_category_id | Primary category ID applicable for the url in this transaction, e.g. category ID is 7 for the Cloud Storage category. | keyword |
| netskope.transaction.x_client_ssl_err | Description of SSL error between client (browser) and proxy. | keyword |
| netskope.transaction.x_cs_access_method | Steering method used to access the Netskope cloud. | keyword |
| netskope.transaction.x_cs_app | Cloud application name. | keyword |
| netskope.transaction.x_cs_app_activity | The cloud application activity identified by the proxy. | keyword |
| netskope.transaction.x_cs_app_category | Cloud application category from the CCI database. | keyword |
| netskope.transaction.x_cs_app_cci | Cloud Confidence Index of the Cloud application from the CCI database. | long |
| netskope.transaction.x_cs_app_ccl | Cloud Confidence Level of the Cloud application from the CCI database. | keyword |
| netskope.transaction.x_cs_app_from_user | The user identity detected in the cloud application. | keyword |
| netskope.transaction.x_cs_app_instance_id | The cloud application instance ID identified by the proxy. | keyword |
| netskope.transaction.x_cs_app_instance_name | Reserved for future use. | keyword |
| netskope.transaction.x_cs_app_instance_tag | Reserved for future use. | keyword |
| netskope.transaction.x_cs_app_object_id | The ID of the object transferred to/from the cloud application. | keyword |
| netskope.transaction.x_cs_app_object_name | The name of the object transferred to/from the cloud application. | keyword |
| netskope.transaction.x_cs_app_object_type | The type of the object transferred to/from the cloud application. | keyword |
| netskope.transaction.x_cs_app_suite | The cloud application suite name. | keyword |
| netskope.transaction.x_cs_app_tags | Cloud application tags from the CCI database. | keyword |
| netskope.transaction.x_cs_app_to_user | The recipients of a share/send activity detected in the cloud application. | keyword |
| netskope.transaction.x_cs_connect_host | The host value received in the Client to Proxy HTTP CONNECT request. This field is empty if there is no CONNECT. | keyword |
| netskope.transaction.x_cs_connect_port | The port value received in the Client to Proxy HTTP CONNECT request. This field is empty if there is no CONNECT. | keyword |
| netskope.transaction.x_cs_connect_user_agent | The User-Agent header value received in the Client to Proxy HTTP CONNECT request. This field is empty if there is no CONNECT or the field is missing. | keyword |
| netskope.transaction.x_cs_domain_fronted_sni | The SNI of the SSL connection where Netskope detected domain fronting. In other words, the SNI and Host header were mismatched. SSL inspection must be enabled to see this field. | keyword |
| netskope.transaction.x_cs_dst_ip | The destination IP of the client to proxy session. | ip |
| netskope.transaction.x_cs_dst_port | The destination port of the client to proxy session. | long |
| netskope.transaction.x_cs_http_version | The version of the HTTP protocol of the request. | keyword |
| netskope.transaction.x_cs_ip_connect_xff | X-Forwarded-For header value received in the Client to Proxy HTTP CONNECT request. This field is empty if there is no CONNECT or if the field is missing. | ip |
| netskope.transaction.x_cs_ip_xff | X-Forwarded-For header value received in the Client to Proxy GET request. This field is empty if there is no header or if GET is not decrypted. | ip |
| netskope.transaction.x_cs_page_id | Identifier associated with the page event object. | keyword |
| netskope.transaction.x_cs_session_id | A session for the current user which consists of: user, device, OS, app, browser. | keyword |
| netskope.transaction.x_cs_site | Destination site. | keyword |
| netskope.transaction.x_cs_sni | The hostname that the client is attempting to connect to using the SNI extension in the TLS handshake. | keyword |
| netskope.transaction.x_cs_src_ip | The source IP of the client to proxy session. | ip |
| netskope.transaction.x_cs_src_ip_egress | The public IP used to contact the NewEdge data plane on the traffic coming from the Client device. | ip |
| netskope.transaction.x_cs_src_port | The source port of the client to proxy session. | long |
| netskope.transaction.x_cs_ssl_cipher | The SSL Cipher negotiated between the Client device and the NewEdge data plane for the HTTPS request. | keyword |
| netskope.transaction.x_cs_ssl_engine_action | Indicates the result of the SSL Engine behavior after certificate evaluation and SSL/TLS negotiation. Possible values include: allow, block, or bypass. | keyword |
| netskope.transaction.x_cs_ssl_engine_action_reason | Provides details of the SSL Engine action. | keyword |
| netskope.transaction.x_cs_ssl_fronting_error | Indicates if the server certificate received from the destination server has a mismatch between the SNI and the hostname of the encrypted HTTP request. | keyword |
| netskope.transaction.x_cs_ssl_handshake_error | Indicates if the SSL Engine encountered a problem when establishing the SSL/TLS negotiation. For more information, refer to the x-server-ssl-err and x-client-ssl-err fields. | keyword |
| netskope.transaction.x_cs_ssl_ja3 | Fingerprints the way the Client communicates over TLS. | keyword |
| netskope.transaction.x_cs_ssl_version | The SSL Version negotiated between the Client device and the NewEdge data plane for the HTTPS request. | keyword |
| netskope.transaction.x_cs_timestamp | Date of the request as epoch time. NOTE: This field is the epoch version of the “date” and “time” fields. | date |
| netskope.transaction.x_cs_traffic_type | Type of traffic could be “Web” or “CloudApp”. NOTE: During SSL bypass, x-cs-traffic-type always displays as Unavailable. | keyword |
| netskope.transaction.x_cs_tunnel_id | VPN tunnel ID. | keyword |
| netskope.transaction.x_cs_uri_path | Path of the URI from the received HTTP request. | keyword |
| netskope.transaction.x_cs_url | The full URL of the request received, includes scheme, host, port, path and query. | keyword |
| netskope.transaction.x_cs_userip | The client IP address. If the client IP address is not found, the field is left blank. | ip |
| netskope.transaction.x_error | The error encountered when processing the transaction. | keyword |
| netskope.transaction.x_other_category | Secondary categories applicable for the url in this transaction. | keyword |
| netskope.transaction.x_other_category_id | IDs of secondary categories applicable for the url in this transaction, e.g. category ID is 537 for the News & Media; Entertainment category. | keyword |
| netskope.transaction.x_policy_action | The action performed by the proxy on the transaction after the Real-time policy engine analysis (e.g. allow, block, bypass, alert, user alert). | keyword |
| netskope.transaction.x_policy_dst_host | The hostname computed by the Real-time policy engine. The source for the hostname is provided in the x-policy-dst-host-source field. | keyword |
| netskope.transaction.x_policy_dst_host_source | The source for the hostname value computed by the Real-time policy engine (e.g. OriginalDestDomain, Sni, Uri, HttpHostHeader). | keyword |
| netskope.transaction.x_policy_dst_ip | The destination IP computed by the Real-time policy engine, from DNS resolution. | keyword |
| netskope.transaction.x_policy_justification_reason | The justification provided by the end user in case of “useralert” action. | keyword |
| netskope.transaction.x_policy_justification_type | The justification type selected by the end user in case of “useralert” action. | keyword |
| netskope.transaction.x_policy_name | The Real-time policy name that triggered the action. | keyword |
| netskope.transaction.x_policy_src_ip | The source IP computed by the Real-time policy engine from the source IP or XFF header. | keyword |
| netskope.transaction.x_r_cert_enddate | The end date/time of the server certificate received from the destination server. | date |
| netskope.transaction.x_r_cert_expired | Indicates if the server certificate received from the destination server is expired or not yet valid. | keyword |
| netskope.transaction.x_r_cert_incomplete_chain | Indicates if the server certificate received from destination server has an incomplete issuer chain. | keyword |
| netskope.transaction.x_r_cert_issuer_cn | The issuer CN attribute of the server certificate received from destination server. | keyword |
| netskope.transaction.x_r_cert_mismatch | Indicates if the server certificate received from the destination server has a mismatch between the SNI and the CN/SAN. | keyword |
| netskope.transaction.x_r_cert_revocation_check | Reserved for future use. | keyword |
| netskope.transaction.x_r_cert_revoked | Indicates if the server certificate received from the destination server is revoked. | keyword |
| netskope.transaction.x_r_cert_self_signed | Indicates if the server certificate received from  the destination server is self-signed. | keyword |
| netskope.transaction.x_r_cert_startdate | The start date/time of the server certificate received from the destination server. | date |
| netskope.transaction.x_r_cert_subject_cn | The CN attribute of the server certificate received from the destination server. | keyword |
| netskope.transaction.x_r_cert_untrusted_root | Indicates if the server certificate received from the destination server is signed by a trusted issuer. | keyword |
| netskope.transaction.x_r_cert_valid | Overall result of the evaluation of the validity of the server certificate received from destination server. This field doesn’t reflect the action of the SSL Engine. | keyword |
| netskope.transaction.x_request_id | Request ID needed to correlate DLP and TSS incidents with transaction events. | keyword |
| netskope.transaction.x_rs_file_category | The category of the object transferred to/from the remote server. | keyword |
| netskope.transaction.x_rs_file_language | Reserved for future use. | keyword |
| netskope.transaction.x_rs_file_md5 | The MD5 Hash of the object transferred to/from the remote server. | keyword |
| netskope.transaction.x_rs_file_sha256 | Reserved for future use. | keyword |
| netskope.transaction.x_rs_file_size | Reserved for future use. | keyword |
| netskope.transaction.x_rs_file_type | The type of the object transferred to/from the remote server. | keyword |
| netskope.transaction.x_s_country | Destination country. | keyword |
| netskope.transaction.x_s_custom_signing_ca_error | Indicates that the SSL Engine failed to intercept with a Custom signing CA. | keyword |
| netskope.transaction.x_s_dp_name | The dataplane name processing the request. | keyword |
| netskope.transaction.x_s_latitude | Destination latitude. | double |
| netskope.transaction.x_s_location | Destination location (e.g. city). | keyword |
| netskope.transaction.x_s_longitude | Destination longitude. | double |
| netskope.transaction.x_s_region | Destination region (e.g. state). | keyword |
| netskope.transaction.x_s_zipcode | Destination zip code. | keyword |
| netskope.transaction.x_sc_notification_name | The name of the user notification displayed to the end user in case of action “block” or “useralert”. | keyword |
| netskope.transaction.x_server_ssl_err | Description of SSL error between proxy and content servers. | keyword |
| netskope.transaction.x_sr_dst_ip | The destination IP of the proxy to remote server session. | ip |
| netskope.transaction.x_sr_dst_port | The destination port of the proxy to remote server session. | long |
| netskope.transaction.x_sr_headers_name | List of custom headers inserted. | keyword |
| netskope.transaction.x_sr_headers_value | List of custom header values inserted. | keyword |
| netskope.transaction.x_sr_src_ip | The source IP of the proxy to remote server session. This field is blank if dedicated IPs are used. | ip |
| netskope.transaction.x_sr_src_port | The source port of the proxy to remote server session. This field is blank if dedicated IPs are used. | long |
| netskope.transaction.x_sr_ssl_cipher | The SSL Cipher negotiated between the NewEdge data plane and the Destination Server for the HTTPS request. | keyword |
| netskope.transaction.x_sr_ssl_client_certificate_error | Indicates that the destination server requested a Client certificate during SSL/TLS negotiation. | keyword |
| netskope.transaction.x_sr_ssl_engine_action | Indicates the result of the SSL Engine behavior after certificate evaluation and SSL/TLS Negotiation. Possible values include: allow, block, or bypass. | keyword |
| netskope.transaction.x_sr_ssl_engine_action_reason | Provides details of the SSL Engine action. | keyword |
| netskope.transaction.x_sr_ssl_handshake_error | Indicates if the SSL Engine encountered a problem to establish SSL/TLS negotiation. For more information, refer to the x-server-ssl-err and x-client-ssl-err fields for more information. | keyword |
| netskope.transaction.x_sr_ssl_ja3s | Fingerprints the way the server responds to the TLS. | keyword |
| netskope.transaction.x_sr_ssl_malformed_ssl | Indicates that the SSL Engine encountered a malformed SSL packet during SSL/TLS negotiation. | keyword |
| netskope.transaction.x_sr_ssl_version | The SSL Version negotiated between the NewEdge data plane and the Destination Server for the HTTPS request. | keyword |
| netskope.transaction.x_ssl_bypass | Indicates if the request was SSL bypassed. | keyword |
| netskope.transaction.x_ssl_bypass_reason | Inidacates if the request was SSL bypassed, this field provides the reason. | keyword |
| netskope.transaction.x_ssl_policy_action | Action of the SSL Decryption Policy that matched the request. Possible values include, Decrypt or DoNotDecrypt. | keyword |
| netskope.transaction.x_ssl_policy_categories | Destination Hostname Categories computed by the SSL Policy Engine to evaluate the SSL Decryption Policies. | keyword |
| netskope.transaction.x_ssl_policy_dst_host | The Destination Hostname computed by the SSL Policy Engine to evaluate the SSL Decryption Policies. | keyword |
| netskope.transaction.x_ssl_policy_dst_host_source | Describes how the Destination Hostname was computed by the SSL Policy Engine. Possible values include from SNI or original host. | keyword |
| netskope.transaction.x_ssl_policy_dst_ip | The Destination IP computed by the SSL Policy Engine to evaluate the SSL Decryption Policies. | ip |
| netskope.transaction.x_ssl_policy_name | Name of the SSL Decryption Policy that matched the request. | keyword |
| netskope.transaction.x_ssl_policy_src_ip | The Source IP computed by the SSL Policy Engine to evaluate the SSL Decryption Policies. | ip |
| netskope.transaction.x_transaction_id | Transaction ID needed to correlate application events with transaction events. | keyword |
| netskope.transaction.x_type | The type of log message, which can be “http_transaction” or “WebSocket”.  NOTE: When parsing an HTTP Upgrade response, Netskope uses the Upgrade header to determine if the traffic is WebSocket. | keyword |


An example event for `transaction` looks as following:

```json
{
    "@timestamp": "2024-08-05T16:24:19.000Z",
    "agent": {
        "ephemeral_id": "911359cf-7c9a-4c12-86f2-eb640eea28e4",
        "id": "4b7f7354-8f22-4cc4-a80b-27d8002da0b1",
        "name": "elastic-agent-62562",
        "type": "filebeat",
        "version": "8.17.8"
    },
    "aws": {
        "s3": {
            "bucket": {
                "arn": "arn:aws:s3:::elastic-package-netskope-bucket-82016",
                "name": "elastic-package-netskope-bucket-82016"
            },
            "object": {
                "key": "trxn.csv.gz"
            }
        }
    },
    "client": {
        "geo": {
            "city_name": "The Dalles",
            "country_name": "US",
            "location": {
                "coordinates": [
                    -121.1807000823319,
                    45.60559996403754
                ],
                "type": "Point"
            },
            "postal_code": "97058",
            "region_name": "Oregon"
        },
        "ip": "10.70.0.19"
    },
    "cloud": {
        "region": "us-east-1"
    },
    "data_stream": {
        "dataset": "netskope.transaction",
        "namespace": "54132",
        "type": "logs"
    },
    "destination": {
        "bytes": 0,
        "domain": "us-west1-b-osconfig.googleapis.com",
        "ip": "142.250.99.95",
        "port": 443
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "4b7f7354-8f22-4cc4-a80b-27d8002da0b1",
        "snapshot": false,
        "version": "8.17.8"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "netskope.transaction",
        "id": "2035489204758272484",
        "ingested": "2025-07-18T10:11:29Z",
        "kind": "event",
        "module": "netskope",
        "original": "{\"bytes\":\"18\",\"c-ip\":\"10.70.0.19\",\"cs-bytes\":\"18\",\"cs-content-type\":\"-\",\"cs-dns\":\"-\",\"cs-host\":\"us-west1-b-osconfig.googleapis.com\",\"cs-method\":\"PRI\",\"cs-referer\":\"-\",\"cs-uri\":\"*\",\"cs-uri-port\":\"443\",\"cs-uri-query\":\"-\",\"cs-uri-scheme\":\"-\",\"cs-user-agent\":\"-\",\"cs-username\":\"nadav@skyformation.onmicrosoft.com\",\"date\":\"2024-08-05\",\"rs-status\":\"-\",\"s-ip\":\"-\",\"sc-bytes\":\"0\",\"sc-content-type\":\"-\",\"sc-status\":\"-\",\"time\":\"16:24:19\",\"time-taken\":\"-\",\"x-c-browser\":\"-\",\"x-c-browser-version\":\"-\",\"x-c-country\":\"US\",\"x-c-device\":\"-\",\"x-c-latitude\":\"45.605600\",\"x-c-local-time\":\"NotChecked\",\"x-c-location\":\"The Dalles\",\"x-c-longitude\":\"-121.180700\",\"x-c-os\":\"-\",\"x-c-region\":\"Oregon\",\"x-c-zipcode\":\"97058\",\"x-category\":\"Technology\",\"x-category-id\":\"564\",\"x-client-ssl-err\":\"-\",\"x-cs-access-method\":\"Client\",\"x-cs-app\":\"-\",\"x-cs-app-activity\":\"-\",\"x-cs-app-category\":\"-\",\"x-cs-app-cci\":\"-\",\"x-cs-app-ccl\":\"-\",\"x-cs-app-from-user\":\"-\",\"x-cs-app-instance-id\":\"-\",\"x-cs-app-instance-name\":\"-\",\"x-cs-app-instance-tag\":\"-\",\"x-cs-app-object-id\":\"-\",\"x-cs-app-object-name\":\"-\",\"x-cs-app-object-type\":\"-\",\"x-cs-app-suite\":\"-\",\"x-cs-app-tags\":\"-\",\"x-cs-app-to-user\":\"-\",\"x-cs-connect-host\":\"-\",\"x-cs-connect-port\":\"-\",\"x-cs-connect-user-agent\":\"-\",\"x-cs-domain-fronted-sni\":\"-\",\"x-cs-dst-ip\":\"142.250.99.95\",\"x-cs-dst-port\":\"443\",\"x-cs-http-version\":\"HTTP1.1\",\"x-cs-ip-connect-xff\":\"-\",\"x-cs-ip-xff\":\"-\",\"x-cs-page-id\":\"0\",\"x-cs-session-id\":\"0\",\"x-cs-site\":\"-\",\"x-cs-sni\":\"us-west1-b-osconfig.googleapis.com\",\"x-cs-src-ip\":\"10.70.0.19\",\"x-cs-src-ip-egress\":\"34.82.190.203\",\"x-cs-src-port\":\"32951\",\"x-cs-ssl-cipher\":\"TLS_AES_256_GCM_SHA384\",\"x-cs-ssl-engine-action\":\"Allow\",\"x-cs-ssl-engine-action-reason\":\"Established\",\"x-cs-ssl-fronting-error\":\"No\",\"x-cs-ssl-handshake-error\":\"No\",\"x-cs-ssl-ja3\":\"7a15285d4efc355608b304698cd7f9ab\",\"x-cs-ssl-version\":\"TLSv1.3\",\"x-cs-timestamp\":\"1722875059\",\"x-cs-traffic-type\":\"-\",\"x-cs-tunnel-id\":\"-\",\"x-cs-uri-path\":\"-\",\"x-cs-url\":\"-\",\"x-cs-userip\":\"10.70.0.19\",\"x-error\":\"http-malformed\",\"x-other-category\":\"Cloud Storage\",\"x-other-category-id\":\"7\",\"x-policy-action\":\"NotChecked\",\"x-policy-dst-host\":\"-\",\"x-policy-dst-host-source\":\"-\",\"x-policy-dst-ip\":\"-\",\"x-policy-justification-reason\":\"-\",\"x-policy-justification-type\":\"-\",\"x-policy-name\":\"-\",\"x-policy-src-ip\":\"-\",\"x-r-cert-enddate\":\"NotChecked\",\"x-r-cert-expired\":\"NotChecked\",\"x-r-cert-incomplete-chain\":\"NotChecked\",\"x-r-cert-issuer-cn\":\"NotChecked\",\"x-r-cert-mismatch\":\"NotChecked\",\"x-r-cert-revocation-check\":\"NotChecked\",\"x-r-cert-revoked\":\"NotChecked\",\"x-r-cert-self-signed\":\"NotChecked\",\"x-r-cert-startdate\":\"NotChecked\",\"x-r-cert-subject-cn\":\"NotChecked\",\"x-r-cert-untrusted-root\":\"NotChecked\",\"x-r-cert-valid\":\"NotChecked\",\"x-request-id\":\"0\",\"x-rs-file-category\":\"-\",\"x-rs-file-language\":\"-\",\"x-rs-file-md5\":\"-\",\"x-rs-file-sha256\":\"-\",\"x-rs-file-size\":\"-\",\"x-rs-file-type\":\"-\",\"x-s-country\":\"-\",\"x-s-custom-signing-ca-error\":\"No\",\"x-s-dp-name\":\"US-SEA2\",\"x-s-latitude\":\"-\",\"x-s-location\":\"-\",\"x-s-longitude\":\"-\",\"x-s-region\":\"-\",\"x-s-zipcode\":\"-\",\"x-sc-notification-name\":\"-\",\"x-server-ssl-err\":\"-\",\"x-sr-dst-ip\":\"-\",\"x-sr-dst-port\":\"-\",\"x-sr-headers-name\":\"-\",\"x-sr-headers-value\":\"-\",\"x-sr-src-ip\":\"-\",\"x-sr-src-port\":\"-\",\"x-sr-ssl-cipher\":\"NotChecked\",\"x-sr-ssl-client-certificate-error\":\"NotChecked\",\"x-sr-ssl-engine-action\":\"None\",\"x-sr-ssl-engine-action-reason\":\"NotEstablished\",\"x-sr-ssl-handshake-error\":\"NotChecked\",\"x-sr-ssl-ja3s\":\"NotAvailable\",\"x-sr-ssl-malformed-ssl\":\"NotChecked\",\"x-sr-ssl-version\":\"NotChecked\",\"x-ssl-bypass\":\"No\",\"x-ssl-bypass-reason\":\"-\",\"x-ssl-policy-action\":\"Decrypt\",\"x-ssl-policy-categories\":\"Technology, Cloud Storage\",\"x-ssl-policy-dst-host\":\"us-west1-b-osconfig.googleapis.com\",\"x-ssl-policy-dst-host-source\":\"Sni\",\"x-ssl-policy-dst-ip\":\"142.250.99.95\",\"x-ssl-policy-name\":\"-\",\"x-ssl-policy-src-ip\":\"10.70.0.19\",\"x-transaction-id\":\"2035489204758272484\",\"x-type\":\"http_transaction\"}",
        "type": [
            "info"
        ]
    },
    "http": {
        "request": {
            "method": "PRI"
        },
        "version": "1.1"
    },
    "input": {
        "type": "aws-s3"
    },
    "log": {
        "file": {
            "path": "https://elastic-package-netskope-bucket-82016.s3.us-east-1.amazonaws.com/trxn.csv.gz"
        },
        "offset": 3909
    },
    "netskope": {
        "transaction": {
            "bytes": 18,
            "cs_host": "us-west1-b-osconfig.googleapis.com",
            "cs_uri": "*",
            "date": "2024-08-05T00:00:00.000Z",
            "time": "16:24:19",
            "x_c_latitude": 45.6056,
            "x_c_longitude": -121.1807,
            "x_category": "Technology",
            "x_category_id": "564",
            "x_cs_access_method": "Client",
            "x_cs_page_id": "0",
            "x_cs_session_id": "0",
            "x_cs_src_ip_egress": "34.82.190.203",
            "x_cs_ssl_engine_action": "Allow",
            "x_cs_ssl_engine_action_reason": "Established",
            "x_cs_ssl_fronting_error": "No",
            "x_cs_ssl_handshake_error": "No",
            "x_cs_userip": "10.70.0.19",
            "x_error": "http-malformed",
            "x_other_category": "Cloud Storage",
            "x_other_category_id": "7",
            "x_request_id": "0",
            "x_s_custom_signing_ca_error": "No",
            "x_s_dp_name": "US-SEA2",
            "x_sr_ssl_engine_action": "None",
            "x_sr_ssl_engine_action_reason": "NotEstablished",
            "x_ssl_bypass": "No",
            "x_ssl_policy_action": "Decrypt",
            "x_ssl_policy_categories": [
                "Technology",
                " Cloud Storage"
            ],
            "x_ssl_policy_dst_host": "us-west1-b-osconfig.googleapis.com",
            "x_ssl_policy_dst_host_source": "Sni",
            "x_ssl_policy_dst_ip": "142.250.99.95",
            "x_ssl_policy_src_ip": "10.70.0.19",
            "x_type": "http_transaction"
        }
    },
    "related": {
        "hosts": [
            "us-west1-b-osconfig.googleapis.com"
        ],
        "ip": [
            "10.70.0.19",
            "142.250.99.95",
            "34.82.190.203"
        ],
        "user": [
            "nadav@skyformation.onmicrosoft.com"
        ]
    },
    "source": {
        "bytes": 18,
        "ip": "10.70.0.19",
        "port": 32951
    },
    "tags": [
        "collect_sqs_logs",
        "preserve_original_event",
        "forwarded",
        "netskope-transaction"
    ],
    "tls": {
        "cipher": "TLS_AES_256_GCM_SHA384",
        "client": {
            "ja3": "7a15285d4efc355608b304698cd7f9ab",
            "server_name": "us-west1-b-osconfig.googleapis.com"
        },
        "version": "1.3",
        "version_protocol": "tls"
    },
    "url": {
        "port": 443
    },
    "user": {
        "email": "nadav@skyformation.onmicrosoft.com"
    }
}
```