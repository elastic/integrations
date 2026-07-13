# Cloudflare Logpush Integration for Elastic

## Overview

The [Cloudflare Logpush](https://developers.cloudflare.com/logs/logpush/) integration allows you to monitor Access Request, Audit, CASB, Device Posture, DLP Forensic Copies, DNS, DNS Firewall, Email Security Alerts, Firewall Event, Gateway DNS, Gateway HTTP, Gateway Network, HTTP Request, Magic IDS, NEL Report, Network Analytics, Page Shield, Sinkhole HTTP, Spectrum Event, Zero Trust Network Session, and Workers Trace Events logs.

Cloudflare is a content delivery network and DDoS mitigation company. Cloudflare provides a network designed to make everything you connect to the Internet secure, private, fast, and reliable; secure your websites, APIs, and Internet applications; protect corporate networks, employees, and devices; and write and deploy code that runs on the network edge.

### Compatibility

This integration follows the log schemas and field definitions published in the [Cloudflare Log fields reference](https://developers.cloudflare.com/logs/reference/log-fields/).

Cloudflare Logpush supports delivering logs to the following destinations, which can all be consumed by this integration:

- [HTTP destinations](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/http/)
- [Amazon S3](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/aws-s3/)
- [S3-compatible endpoints](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/s3-compatible-endpoints/) (including [Cloudflare R2](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/r2/))
- [Google Cloud Storage](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/google-cloud-storage/)
- [Microsoft Azure Blob Storage](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/azure/)

### How it works

Cloudflare Logpush pushes logs to the destination of your choice. Elastic Agent then reads those logs and ships them to Elasticsearch, where they are processed through each data stream's ingest pipeline.

The integration supports the following collection modes:

- **HTTP Endpoint mode** — Cloudflare pushes logs directly to an HTTP endpoint hosted by your Elastic Agent.
- **AWS S3 polling mode** — Cloudflare writes logs to an S3 bucket and Elastic Agent polls the bucket by listing its contents and reading new files.
- **AWS S3 SQS mode** — Cloudflare writes logs to S3; S3 publishes object-created notifications to an SQS queue; Elastic Agent receives those notifications from SQS and reads the corresponding S3 objects. This mode supports horizontal scaling across multiple agents.
- **S3-compatible (Cloudflare R2) polling mode** — Cloudflare writes logs to an R2 or other S3-compatible bucket and Elastic Agent polls the bucket using the S3 API.
- **Azure Blob Storage polling mode** — Cloudflare writes logs to an Azure Blob Storage container and Elastic Agent polls the container by listing its contents and reading new files.
- **Google Cloud Storage polling mode** — Cloudflare writes logs to a GCS bucket and Elastic Agent polls the bucket by listing its contents and reading new files.

## What data does this integration collect?

The Cloudflare Logpush integration collects logs for the following Cloudflare [datasets](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/). Data streams are grouped by whether the underlying dataset is classified as a Cloudflare [Zero Trust dataset](https://developers.cloudflare.com/cloudflare-one/insights/logs/logpush/#zero-trust-datasets) or a non Zero Trust dataset.

### Zero Trust events

- `access_request`: HTTP requests to sites protected by Cloudflare Access. See [Access Requests schema](https://developers.cloudflare.com/logs/reference/log-fields/account/access_requests/).
- `audit`: Authentication events through Cloudflare Access, plus account-level configuration and administrative actions. See [Audit Logs schema](https://developers.cloudflare.com/logs/reference/log-fields/account/audit_logs/).
- `casb`: Security issues detected by Cloudflare CASB in connected SaaS applications. See [CASB Findings schema](https://developers.cloudflare.com/logs/reference/log-fields/account/casb_findings/).
- `device_posture`: Device posture status from the Cloudflare One Client (WARP). See [Device Posture Results schema](https://developers.cloudflare.com/logs/reference/log-fields/account/device_posture_results/).
- `gateway_dns`: DNS queries inspected by Cloudflare Gateway. See [Gateway DNS schema](https://developers.cloudflare.com/logs/reference/log-fields/account/gateway_dns/).
- `gateway_http`: HTTP requests inspected by Cloudflare Gateway. See [Gateway HTTP schema](https://developers.cloudflare.com/logs/reference/log-fields/account/gateway_http/).
- `gateway_network`: Network packets inspected by Cloudflare Gateway. See [Gateway Network schema](https://developers.cloudflare.com/logs/reference/log-fields/account/gateway_network/).
- `network_session`: Network session logs for traffic proxied by Cloudflare Gateway. See [Zero Trust Network Session schema](https://developers.cloudflare.com/logs/reference/log-fields/account/zero_trust_network_sessions/).

### Non Zero Trust events

- `dns`: Zone-scoped authoritative DNS query logs. See [DNS logs schema](https://developers.cloudflare.com/logs/reference/log-fields/zone/dns_logs/).
- `dns_firewall`: Cloudflare DNS Firewall query and response logs. See [DNS Firewall logs schema](https://developers.cloudflare.com/logs/reference/log-fields/account/dns_firewall_logs/).
- `dlp_forensic_copies`: Data Loss Prevention forensic copies of content that matched a DLP profile. See [DLP Forensic Copies schema](https://developers.cloudflare.com/logs/reference/log-fields/account/dlp_forensic_copies/).
- `email_security_alerts`: Cloudflare Email Security alerts for phishing, malware, and other email-based threats. See [Email Security Alerts schema](https://developers.cloudflare.com/logs/reference/log-fields/account/email_security_alerts/).
- `firewall_event`: Zone-level Firewall events for requests mitigated by Cloudflare security products (WAF, Rate Limiting, Firewall Rules, etc.). See [Firewall Events schema](https://developers.cloudflare.com/logs/reference/log-fields/zone/firewall_events/).
- `http_request`: HTTP/HTTPS request logs served at the Cloudflare edge. See [HTTP Requests schema](https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/).
- `magic_ids`: Magic Network Monitoring IDS detection logs. See [Magic IDS Detections schema](https://developers.cloudflare.com/logs/reference/log-fields/account/magic_ids_detections/).
- `nel_report`: Network Error Logging (NEL) reports collected from end-user browsers. See [NEL Reports schema](https://developers.cloudflare.com/logs/reference/log-fields/zone/nel_reports/).
- `network_analytics`: Network Analytics (Magic Transit / Magic WAN packet-sampled flow) logs. See [Network Analytics Logs schema](https://developers.cloudflare.com/logs/reference/log-fields/account/network_analytics_logs/).
- `page_shield_events`: Page Shield events reporting changes to scripts and connections observed on protected zones. See [Page Shield Events schema](https://developers.cloudflare.com/logs/reference/log-fields/zone/page_shield_events/).
- `sinkhole_http`: HTTP traffic captured by Cloudflare sinkholes. See [Sinkhole HTTP logs schema](https://developers.cloudflare.com/logs/reference/log-fields/account/sinkhole_http_logs/).
- `spectrum_event`: Cloudflare Spectrum events for TCP/UDP applications proxied through Cloudflare. See [Spectrum Events schema](https://developers.cloudflare.com/logs/reference/log-fields/zone/spectrum_events/).
- `workers_trace`: Cloudflare Workers Trace Events with execution logs and exceptions for Workers scripts. See [Workers Trace Events schema](https://developers.cloudflare.com/logs/reference/log-fields/account/workers_trace_events/).

### Supported use cases

Integrating Cloudflare Logpush with Elastic provides centralized visibility across Cloudflare's edge, Zero Trust, and network-layer products. Common use cases include:

- Investigating traffic, WAF, and DDoS-mitigation events from the Cloudflare edge (`http_request`, `firewall_event`, `network_analytics`).
- Monitoring Zero Trust user activity, policy decisions, and device posture (`gateway_http`, `gateway_dns`, `gateway_network`, `access_request`, `device_posture`, `network_session`).
- Detecting data exfiltration and SaaS misconfigurations (`dlp_forensic_copies`, `casb`, `email_security_alerts`).
- Auditing administrative activity on the Cloudflare account (`audit`).
- Troubleshooting DNS and client-side performance issues (`dns`, `dns_firewall`, `nel_report`, `workers_trace`).

## What do I need to use this integration?

### From Elastic

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

### From Cloudflare

To use this integration, you must be able to create and manage [Cloudflare Logpush jobs](https://developers.cloudflare.com/logs/logpush/logpush-job/) for the datasets you want to collect.

**Permissions**

Creating and managing Logpush jobs requires an API token or user role with the `Logs Write` permission (or a role that includes it, such as **Super Administrator**, **Administrator**, or **Log Share** with edit permissions). Refer to [Cloudflare Logpush permissions](https://developers.cloudflare.com/logs/logpush/permissions/) for details.

- **Zone-scoped datasets** (for example, `http_requests`, `firewall_events`, `dns_logs`, `spectrum_events`, `nel_reports`, `page_shield_events`) require a **zone-scoped token**.
- **Account-scoped datasets** (for example, `audit_logs`, `access_requests`, `casb_findings`, `device_posture_results`, `dlp_forensic_copies`, `email_security_alerts`, `gateway_*`, `dns_firewall_logs`, `magic_ids_detections`, `network_analytics_logs`, `sinkhole_http_logs`, `workers_trace_events`, `zero_trust_network_sessions`) require an **account-scoped token**.
- Zero Trust datasets (Access, Gateway, DEX) additionally require `Zero Trust: PII Read`.

**Destination-specific credentials**

Depending on the delivery destination, you also need:

- **AWS S3 / S3-compatible** — an S3 bucket (or Cloudflare R2 bucket) and credentials (Access Key ID / Secret Access Key, or an IAM role) that Elastic Agent can use to list and read objects. For SQS-based delivery, an SQS queue subscribed to S3 object-created events.
- **Google Cloud Storage** — a GCS bucket and a service account key (JSON) with read access to the bucket.
- **Azure Blob Storage** — a storage account, a blob container, and either a shared access key, a connection string, or OAuth2 client credentials with read access to the container.
- **HTTP Endpoint** — a reachable HTTPS endpoint exposed by Elastic Agent. Cloudflare requires a valid TLS certificate on the destination.

## How do I deploy this integration?

This integration supports Elastic Agent-based installations.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Onboard and configure

Configure one of the following delivery pipelines before enabling the integration in Elastic.

#### Collect data from AWS S3 Bucket

- Configure [Cloudflare Logpush to Amazon S3](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/aws-s3/) to send Cloudflare's data to an AWS S3 bucket.
- The default values of the **Bucket Prefix** are listed below. However, users can set the parameter **Bucket Prefix** according to their requirements.

  | Data Stream Name           | Bucket Prefix          |
  | -------------------------- | ---------------------- |
  | Access Request             | access_request         |
  | Audit Logs                 | audit_logs             |
  | CASB findings              | casb                   |
  | Device Posture Results     | device_posture         |
  | DLP Forensic Copies        | dlp_forensic_copies    |
  | DNS                        | dns                    |
  | DNS Firewall               | dns_firewall           |
  | Email Security Alerts      | email_security_alerts  |
  | Firewall Event             | firewall_event         |
  | Gateway DNS                | gateway_dns            |
  | Gateway HTTP               | gateway_http           |
  | Gateway Network            | gateway_network        |
  | HTTP Request               | http_request           |
  | Magic IDS                  | magic_ids              |
  | NEL Report                 | nel_report             |
  | Network Analytics          | network_analytics_logs |
  | Page Shield Events         | page_shield_events     |
  | Zero Trust Network Session | network_session        |
  | Sinkhole HTTP              | sinkhole_http          |
  | Spectrum Event             | spectrum_event         |
  | Workers Trace Events       | workers_trace          |

#### Collect data from AWS SQS

1. If Logpush forwarding to an AWS S3 Bucket hasn't been configured, then first setup an AWS S3 Bucket as mentioned in the above documentation.
2. Follow the steps below for each Logpush data stream that has been enabled:
    1. Create an SQS queue
        - To setup an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Amazon documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
        - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
    2. Setup event notification from the S3 bucket using the instructions [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html). Use the following settings:
        - Event type: `All object create events` (`s3:ObjectCreated:*`)
        - Destination: SQS Queue
        - Prefix (filter): enter the prefix for this Logpush data stream, e.g. `audit_logs/`
        - Select the SQS queue that has been created for this data stream

**Note:**
- A separate SQS queue and S3 bucket notification is required for each enabled data stream.
- Permissions for the above AWS S3 bucket and SQS queues should be configured according to the [Filebeat S3 input documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#_aws_permissions_2).
- Credentials for the above AWS S3 and SQS input types should be configured using the [link](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
- Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.
- It is recommended to use AWS SQS for Cloudflare Logpush.

#### Collect data from S3-Compatible Cloudflare R2 Buckets

- Configure [Cloudflare Logpush to Cloudflare R2](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/r2/) (or another [S3-compatible endpoint](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/s3-compatible-endpoints/)) to push logs into an R2 bucket.

**Note:**
- To obtain the **Access Key ID** and **Secret Access Key**, create an R2 API token by following the [R2 authentication documentation](https://developers.cloudflare.com/r2/api/tokens/). Once the token is created successfully, Cloudflare will display the **Access Key ID** and **Secret Access Key** values. Use these credentials to authenticate the integration.
- When creating the R2 API token, make sure it has [Admin permissions](https://developers.cloudflare.com/r2/api/s3/tokens/#permissions). This is needed to list buckets and view bucket configuration.

When configuring the integration to read from S3-Compatible Buckets such as Cloudflare R2, the following steps are required:
- Enable the **Collect logs via S3 Bucket** toggle.
- Set the **S3-Compatible Bucket Name** (shown as `[Global][S3] S3-Compatible Bucket Name` in the UI) to the R2 bucket name.
- Set the **Endpoint** field to the API endpoint shown in the bucket details. It must be a full URI used as the API endpoint of the service. For Cloudflare R2 buckets, the URI is typically of the form `https://<accountid>.r2.cloudflarestorage.com`.
- Set the **Region** field to `auto`. This is required for all non-AWS S3-compatible buckets on Elastic Agent 8.19.12 and later. For Cloudflare R2, the region is always `auto` per the [R2 S3 API documentation](https://developers.cloudflare.com/r2/api/s3/api/#bucket-region).
- **Bucket Prefix** is optional for each data stream.

#### Collect data from GCS Buckets

- Configure [Cloudflare Logpush to Google Cloud Storage](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/google-cloud-storage/) to ingest data into a GCS bucket.
- Configure the GCS bucket names and credentials along with the required configurations under the "Collect Cloudflare Logpush logs via Google Cloud Storage" section.
- Make sure the service account and authentication being used has proper levels of access to the GCS bucket. Refer to [Manage Service Account Keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys/) for more details.

**Note:**
- The GCS input currently does not support fetching of buckets using bucket prefixes, so the bucket names have to be configured manually for each data stream.
- The GCS input accepts a service account JSON key or a service account JSON file for authentication.
- The GCS input supports JSON/NDJSON data.

#### Collect data from Azure Blob Storage

- Configure [Cloudflare Logpush to Microsoft Azure](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/azure/) to ingest data into Azure Blob Storage containers.
- Configure Azure Blob Storage container names and credentials along with the required configurations under the "Collect Cloudflare Logpush logs via Azure Blob Storage" section.
- Make sure the storage account and authentication being used has proper levels of access to the Azure Blob Storage Container. Follow the documentation [here](https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-data-operations-portal) for more details.
- If you want to use RBAC for your account, follow the documentation [here](https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-access-azure-active-directory).

**Note:**
- The Azure Blob Storage input does not support fetching from containers using container prefixes, so the containers' names must be configured manually for each data stream.
- The Azure Blob Storage input accepts a service account key (shared credentials key), service account URI (connection string) and OAuth2 credentials for authentication.
- The Azure Blob Storage input only supports JSON/NDJSON data.

#### Collect data from the Cloudflare HTTP Endpoint

- Refer to [Enable HTTP destination](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/http/) for Cloudflare Logpush.
- Add the same custom header along with its value on both sides (Cloudflare job and Elastic Agent HTTP input) for additional security.
- For example, while creating a job along with a header and value for a particular dataset:

```
curl --location --request POST 'https://api.cloudflare.com/client/v4/zones/<ZONE ID>/logpush/jobs' \
--header 'X-Auth-Key: <X-AUTH-KEY>' \
--header 'X-Auth-Email: <X-AUTH-EMAIL>' \
--header 'Authorization: <BASIC AUTHORIZATION>' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name":"<public domain>",
    "destination_conf": "https://<public domain>:<public port>/<dataset path>?header_Content-Type=application/json&header_<secret_header>=<secret_value>",
    "dataset": "audit",
    "logpull_options": "fields=RayID,EdgeStartTimestamp&timestamps=rfc3339"
}'
```

**Note:**
- The `destination_conf` parameter inside the request data should set the `Content-Type` header to `application/json`. This is the content type that the HTTP endpoint expects for incoming events.
- Default port for the HTTP Endpoint is `9560`.
- When using the same port for more than one dataset, be sure to specify different dataset paths.
- To enable request ACKing, add a `wait_for_completion_timeout` request query with the timeout for an ACK. See the [HTTP Endpoint documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-http_endpoint.html) for details.

### Enable the integration in Elastic

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Cloudflare Logpush**.
3. Select the **Cloudflare Logpush** integration from the search results.
4. Select **Add Cloudflare Logpush** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect Cloudflare Logpush logs via HTTP Endpoint**, you'll need to:
        - Configure the **Listen Address** and, per data stream, the **Listen Port** and **URL**.
        - Optionally configure **Secret Header** / **Secret Value** and **SSL Configuration** to secure the endpoint.
    * To **Collect Cloudflare Logpush logs via AWS S3, AWS SQS, or S3-Compatible Buckets**, you'll need to:
        - Enable the **Collect logs via S3 Bucket** toggle when polling an S3 or S3-compatible bucket directly. Leave it disabled to consume S3 object-created events from an SQS queue.
        - For direct polling, configure the **[S3] Bucket ARN**, the **[S3] Access Point ARN**, or the **[Global][S3] S3-Compatible Bucket Name** (for Cloudflare R2 and other S3-compatible providers). For S3-compatible buckets also set **Endpoint** and **Region**.
        - Configure credentials using any of: **Access Key ID** / **Secret Access Key** (plus an optional **Session Token**), a **Role ARN**, or a **Shared Credential File** / **Credential Profile Name**.
        - For each enabled data stream, set the **[SQS] Queue URL** (when using SQS) or the **[S3] Bucket Prefix** (when polling an S3 / S3-compatible bucket). For R2 / S3-compatible buckets you may also override the bucket name per data stream using the **[<Dataset>][S3] S3-Compatible Bucket Name** field.
        - Tune throughput with **[S3/SQS] Number of Workers** and **[S3] Interval** (polling mode) or **[SQS] Visibility Timeout** / **[SQS] API Timeout** (SQS mode).
    * To **Collect Cloudflare Logpush logs via Google Cloud Storage**, you'll need to:
        - Configure **Project Id** and either **JSON Credentials key** or **JSON Credentials file path**.
        - For each data stream, configure the **Buckets** list and optionally tune **Maximum number of workers**, **Polling**, **Polling interval**, and **Bucket Timeout**.
    * To **Collect Cloudflare Logpush logs via Azure Blob Storage**, you'll need to:
        - Configure **Account Name** and (optionally) **Storage URL**, and authenticate using either a **Service Account Key**, a **Service Account URI**, or by enabling **Collect logs using OAuth2 authentication** and supplying **Client ID (OAuth2)**, **Client Secret (OAuth2)**, and **Tenant ID (OAuth2)**.
        - For each data stream, configure the **Containers** list and optionally tune **Maximum number of workers**, **Polling**, and **Polling interval**.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Cloudflare Logpush**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Troubleshooting

- For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).
- For Cloudflare-side troubleshooting and delivery status, refer to the [Logpush health dashboard](https://developers.cloudflare.com/logs/logpush/logpush-health/) and the relevant [destination-specific troubleshooting guide](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/).
- When collecting from Cloudflare R2 via the AWS S3 input, the error `failed to get AWS region for bucket: operation error S3: GetBucketLocation` usually indicates a credentials or permissions problem. Inspect the full API error response to identify the underlying issue.
- When using Azure Blob Storage, SAS tokens must have the **Write-only** permission, the service set to **Blob-only** (`ss=b`), and the resource type set to **Object-only** (`srt=o`). Set an expiration of at least five years to avoid unexpected token expiry. Refer to [Troubleshooting Azure destinations](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/azure/#troubleshooting-azure-destinations) for details.
- When using the HTTP Endpoint input, ensure the Elastic Agent endpoint is reachable over HTTPS with a trusted certificate and that any `secret.header` / `secret.value` pair configured on the agent matches the `header_*` parameter defined in the Logpush job's `destination_conf`.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

Additional considerations:

- For high-volume zones, AWS SQS mode is recommended because it distributes work across multiple Elastic Agents without requiring bucket polling.
- Tune [`max_upload_bytes`, `max_upload_records`, and `max_upload_interval_seconds`](https://developers.cloudflare.com/logs/logpush/logpush-job/api-configuration/#max-upload-parameters) on the Logpush job to match the throughput your agents and destination can handle.
- For each input, adjust the worker count and polling interval to balance latency against API calls / egress costs. The relevant fields are **[S3/SQS] Number of Workers** and **[S3] Interval** for the AWS S3 input, and **Maximum number of workers** with **Polling interval** for the Google Cloud Storage and Azure Blob Storage inputs.
- Use Cloudflare Logpush [sampling](https://developers.cloudflare.com/logs/logpush/logpush-job/api-configuration/#sampling-rate) and [filters](https://developers.cloudflare.com/logs/logpush/logpush-job/filters/) to reduce the volume of low-value events at the source.

## Reference

### Logs reference

#### access_request

This is the `access_request` dataset.

##### Example

{{event "access_request"}}

{{fields "access_request"}}

#### audit

This is the `audit` dataset.

##### Example

{{event "audit"}}

{{fields "audit"}}

#### casb

This is the `casb` dataset.

##### Example

{{event "casb"}}

{{fields "casb"}}

#### device_posture

This is the `device_posture` dataset.

##### Example

{{event "device_posture"}}

{{fields "device_posture"}}

#### dlp_forensic_copies

This is the `dlp_forensic_copies` dataset.

##### Example

{{event "dlp_forensic_copies"}}

{{fields "dlp_forensic_copies"}}

#### dns

This is the `dns` dataset.

##### Example

{{event "dns"}}

{{fields "dns"}}

#### dns_firewall

This is the `dns_firewall` dataset.

##### Example

{{event "dns_firewall"}}

{{fields "dns_firewall"}}

#### email_security_alerts

This is the `email_security_alerts` dataset.

##### Example

{{event "email_security_alerts"}}

{{fields "email_security_alerts"}}

#### firewall_event

This is the `firewall_event` dataset.

##### Example

{{event "firewall_event"}}

{{fields "firewall_event"}}

#### gateway_dns

This is the `gateway_dns` dataset.

##### Example

{{event "gateway_dns"}}

{{fields "gateway_dns"}}

#### gateway_http

This is the `gateway_http` dataset.

##### Example

{{event "gateway_http"}}

{{fields "gateway_http"}}

#### gateway_network

This is the `gateway_network` dataset.

##### Example

{{event "gateway_network"}}

{{fields "gateway_network"}}

#### http_request

This is the `http_request` dataset.

##### Example

{{event "http_request"}}

{{fields "http_request"}}

#### magic_ids

This is the `magic_ids` dataset.

##### Example

{{event "magic_ids"}}

{{fields "magic_ids"}}

#### nel_report

This is the `nel_report` dataset.

##### Example

{{event "nel_report"}}

{{fields "nel_report"}}

#### network_analytics

This is the `network_analytics` dataset.

##### Example

{{event "network_analytics"}}

{{fields "network_analytics"}}

#### network_session

This is the `network_session` dataset.

##### Example

{{event "network_session"}}

{{fields "network_session"}}

#### page_shield_events

This is the `page_shield_events` dataset.

##### Example

{{event "page_shield_events"}}

{{fields "page_shield_events"}}

#### sinkhole_http

This is the `sinkhole_http` dataset.

##### Example

{{event "sinkhole_http"}}

{{fields "sinkhole_http"}}

#### spectrum_event

This is the `spectrum_event` dataset.

##### Example

{{event "spectrum_event"}}

{{fields "spectrum_event"}}

#### workers_trace

This is the `workers_trace` dataset.

##### Example

{{event "workers_trace"}}

{{fields "workers_trace"}}

### Inputs used

These inputs are used in this integration:

- [http_endpoint](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-http_endpoint)
- [aws-s3](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-aws-s3)
- [gcs](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-gcs)
- [azure-blob-storage](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-azure-blob-storage)
