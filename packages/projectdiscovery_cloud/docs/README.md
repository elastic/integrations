# ProjectDiscovery Cloud Integration for Elastic

## Overview

The ProjectDiscovery Cloud integration helps you centralize your external attack surface management (EASM) data by ingesting security findings directly into the Elastic Stack. This gives your security teams better visibility and analysis capabilities. You can monitor vulnerabilities, track remediation progress, and automate alerting within Kibana.

This integration facilitates:
- **Vulnerability management**: Ingests security vulnerabilities identified by ProjectDiscovery scans, enabling faster remediation and historical trend analysis. The `vulnerability_scan` data stream collects detailed findings and scan results.
- **Vulnerability changelog monitoring**: Tracks the status changes of vulnerabilities over time, such as new, resolved, or reintroduced issues. The `vulnerability_changelog` data stream collects logs about these changes to help you maintain an accurate view of your security posture.

### Compatibility

This integration is compatible with the ProjectDiscovery Cloud SaaS platform and requires a `Basic` subscription or higher.

You'll also need:
- Elastic Stack version `8.19.4` or `9.0.0` and higher.
- An Elastic Agent enrolled in Fleet with outbound internet connectivity to reach the vendor's API.

### How it works

This integration uses an Elastic Agent to collect data from the ProjectDiscovery Cloud API. It polls the API for security findings and vulnerability status changes, collecting the data in JSON format over HTTPS. The data is then parsed and mapped to the Elastic Common Schema (ECS) for analysis in your Elastic deployment.

## What data does this integration collect?

The ProjectDiscovery Cloud integration collects log data via API polling. It populates the following data streams:

*   **Vulnerability Scans (`vulnerability_scan`)**: Collects detailed security findings and scan results from the ProjectDiscovery Cloud platform. This includes data on identified vulnerabilities, severity levels (Critical, High, Medium, Low, Info), and scan lifecycle events.
*   **Vulnerability Changelogs (`vulnerability_changelog`)**: Collects logs about changes in vulnerability status, which helps you track remediation progress over time.

All data is collected in JSON format and mapped to the Elastic Common Schema (ECS) for consistency.

### Supported use cases

Integrating ProjectDiscovery Cloud logs with Elastic provides a powerful solution for enhancing your security posture. Key use cases include:

*   **Centralized vulnerability management**: Monitor and analyze vulnerability data from ProjectDiscovery Cloud directly within Elastic.
*   **Remediation tracking**: Use the vulnerability changelog data to monitor the progress and effectiveness of your remediation efforts.
*   **Incident enrichment**: Correlate vulnerability findings with other security and observability data sources in Elastic to accelerate incident investigation and response.

## What do I need to use this integration?

Before you can use this integration, you need:
- An active ProjectDiscovery Cloud account.
- An API key generated from your ProjectDiscovery Cloud account for authentication.
- An Elastic deployment running version 8.19.4 or higher. For more information, see our support matrix.
- An Elastic Agent installed on a host with outbound internet connectivity, able to reach `api.projectdiscovery.io` on port `443`.
- An agent policy to which you can add the ProjectDiscovery Cloud integration.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that can connect to the ProjectDiscovery Cloud API. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to poll the ProjectDiscovery Cloud API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in ProjectDiscovery Cloud

Before you can configure the integration in Kibana, you need to retrieve an API key and your Team ID from the ProjectDiscovery Cloud dashboard.

1.  Log in to your ProjectDiscovery Cloud Dashboard.
2.  In the left-hand navigation sidebar, click the **Settings** gear icon and select **API Key**.
3.  If you don't have an API key, click the button to generate a new one. Copy the key immediately and store it in a safe place, as it will not be shown again.
4.  Navigate back to the **Settings** menu and select the **Team** tab.
5.  Locate the field labeled **Team ID** or **Workspace ID** and copy this value.
6.  Ensure that your discovery scans and monitors are active in ProjectDiscovery Cloud so that data is available for the integration to collect.
7.  Confirm that your network's firewall allows outbound traffic to the API endpoint: `https://api.projectdiscovery.io`.

### Set up steps in Kibana

Follow these steps to configure the integration in your Elastic deployment:

1.  In Kibana, navigate to **Management > Integrations**.
2.  In the search bar, enter "ProjectDiscovery Cloud" and select the integration.
3.  Click **Add ProjectDiscovery Cloud**.
4.  Configure the integration with the credentials you retrieved from ProjectDiscovery Cloud:
    *   **URL**: The base URL for the ProjectDiscovery Cloud API. This defaults to `https://api.projectdiscovery.io`.
    *   **API Key**: The secret API Key you generated.
    *   **Team ID**: The alphanumeric Team ID from your account settings.
5.  Under **Advanced Options**, you can configure the following optional settings:
    *   **Proxy URL**: If your environment requires a proxy for outbound connections, enter its URL in the format `http[s]://<user>:<password>@<server>:<port>`. Ensure special characters are URL-encoded.
    *   **SSL Configuration**: If you need custom SSL settings, provide the YAML configuration for `certificate_authorities`, `supported_protocols`, or `verification_mode`.
6.  Choose the agent policy where you want to add this configuration.
7.  Click **Save and continue**, then deploy the configuration to your Elastic Agents.

### Validation

To validate that the integration is working correctly, follow these steps:

1.  In Kibana, navigate to **Discover**.
2.  In the search bar, enter `data_stream.dataset: "projectdiscovery_cloud.vulnerability*"` and check for incoming documents.
3.  Verify that events are appearing with recent timestamps.
4.  Navigate to **Management > Fleet > Agents** to confirm that the agent running the integration is healthy.

## Troubleshooting

For help with generic Elastic Agent and ingest issues, see [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

-   **No data is being collected**:
    *   Verify network connectivity from the Elastic Agent host to `https://api.projectdiscovery.io` on port 443. Use a command like `curl -v https://api.projectdiscovery.io` to test the connection.
    *   Ensure that no firewalls or network ACLs are blocking outbound traffic from the Elastic Agent to the ProjectDiscovery Cloud API.
    *   Check the Elastic Agent logs for connection errors or messages indicating an invalid API key.
-   **API authentication errors (401 Unauthorized)**:
    *   This error means your API key is invalid.
    *   Verify the API Key configured in the integration settings matches the one from your ProjectDiscovery Cloud dashboard.
    *   Ensure there are no leading or trailing spaces or hidden characters copied with the key.
    *   Generate a new key in the ProjectDiscovery Cloud dashboard if the issue persists.
-   **API authorization errors (403 Forbidden or 404 Not Found)**:
    *   This error often indicates that the `Team ID` is incorrect or that the API key does not have permission to access the specified team's data.
    *   Double-check the `Team ID` in the **Settings > Team** section of the ProjectDiscovery Cloud dashboard and update it in the integration settings.
-   **API rate limiting errors (429 Too Many Requests)**:
    *   If you see HTTP 429 errors in the Elastic Agent logs, the integration is polling the API too frequently.
    *   Increase the polling interval in the integration's data stream settings to stay within the vendor's API quotas.
-   **Proxy URL encoding issues**:
    *   If you use a proxy and your credentials contain special characters (like `@`, `:`, or `/`), they must be URL-encoded. An unencoded URL can cause parsing failures and connection errors.
-   **Delayed configuration updates**:
    *   After you save changes to the integration policy in Kibana, it may take a few minutes for the Elastic Agent to poll for and apply the new configuration. You can check the agent's status and last check-in time in **Fleet > Agents**.

### Vendor resources

-   [ProjectDiscovery Cloud Dashboard](https://cloud.projectdiscovery.io)
-   [ProjectDiscovery Cloud API Reference](https://docs.projectdiscovery.io/api-reference/introduction)
-   [ProjectDiscovery Cloud Integrations](https://docs.projectdiscovery.io/cloud/integrations)

## Performance and scaling

To ensure optimal performance in high-volume environments, consider the following recommendations:

*   **Monitor API rate limits**: The integration collects data by polling an HTTPS API endpoint. In environments with a large number of findings, you might encounter HTTP `429` (Too Many Requests) errors. If you see these errors, increase the polling interval to stay within the vendor's API quota. Also, ensure the Elastic Agent host has sufficient bandwidth.
*   **Filter data at the source**: Use the `Team ID` field in your configuration to retrieve only the data relevant to specific environments. Filtering at the source reduces processing overhead on the Elastic Agent and decreases the storage footprint in Elasticsearch.
*   **Scale your Elastic Agent**: For high-throughput environments with frequent, large-scale scans, deploy the integration on a dedicated Elastic Agent or increase the CPU and memory allocation for the agent. This ensures efficient processing without impacting other integrations on the same host.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### vulnerability_changelog

The `vulnerability_changelog` data stream collects events related to changes in discovered vulnerabilities from ProjectDiscovery Cloud.

#### vulnerability_changelog fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| input.type | Input type | keyword |
| projectdiscovery.change_event.from |  | keyword |
| projectdiscovery.change_event.name |  | keyword |
| projectdiscovery.change_event.to |  | keyword |
| projectdiscovery.created_at |  | date |
| projectdiscovery.event.curl_command |  | keyword |
| projectdiscovery.event.error |  | keyword |
| projectdiscovery.event.extracted_results |  | keyword |
| projectdiscovery.event.extractor_name |  | keyword |
| projectdiscovery.event.host |  | keyword |
| projectdiscovery.event.info.author |  | keyword |
| projectdiscovery.event.info.classification.cpe |  | keyword |
| projectdiscovery.event.info.classification.cve_id |  | keyword |
| projectdiscovery.event.info.classification.cvss_score |  | keyword |
| projectdiscovery.event.info.classification.cwe_id |  | keyword |
| projectdiscovery.event.info.classification.epss_percentile |  | float |
| projectdiscovery.event.info.classification.epss_score |  | float |
| projectdiscovery.event.info.description |  | keyword |
| projectdiscovery.event.info.impact |  | keyword |
| projectdiscovery.event.info.metadata |  | flattened |
| projectdiscovery.event.info.name |  | keyword |
| projectdiscovery.event.info.reference |  | keyword |
| projectdiscovery.event.info.remediation |  | keyword |
| projectdiscovery.event.info.severity |  | keyword |
| projectdiscovery.event.info.tags |  | keyword |
| projectdiscovery.event.ip |  | ip |
| projectdiscovery.event.issue_trackers.custom.id |  | keyword |
| projectdiscovery.event.issue_trackers.custom.url |  | keyword |
| projectdiscovery.event.issue_trackers.github.id |  | keyword |
| projectdiscovery.event.issue_trackers.github.url |  | keyword |
| projectdiscovery.event.issue_trackers.gitlab.id |  | keyword |
| projectdiscovery.event.issue_trackers.gitlab.url |  | keyword |
| projectdiscovery.event.issue_trackers.jira.id |  | keyword |
| projectdiscovery.event.issue_trackers.jira.url |  | keyword |
| projectdiscovery.event.issue_trackers.linear.id |  | keyword |
| projectdiscovery.event.issue_trackers.linear.url |  | keyword |
| projectdiscovery.event.matched_at |  | keyword |
| projectdiscovery.event.matcher_name |  | keyword |
| projectdiscovery.event.matcher_status |  | boolean |
| projectdiscovery.event.path |  | keyword |
| projectdiscovery.event.port |  | long |
| projectdiscovery.event.request |  | keyword |
| projectdiscovery.event.response |  | keyword |
| projectdiscovery.event.template_id |  | keyword |
| projectdiscovery.event.template_path |  | keyword |
| projectdiscovery.event.timestamp |  | date |
| projectdiscovery.event.type |  | keyword |
| projectdiscovery.labels |  | keyword |
| projectdiscovery.matcher_status |  | boolean |
| projectdiscovery.result_type |  | keyword |
| projectdiscovery.scan_id |  | keyword |
| projectdiscovery.target |  | keyword |
| projectdiscovery.template_encoded |  | keyword |
| projectdiscovery.template_id |  | keyword |
| projectdiscovery.template_path |  | keyword |
| projectdiscovery.template_url |  | keyword |
| projectdiscovery.updated_at |  | date |
| projectdiscovery.vuln_hash |  | keyword |
| projectdiscovery.vuln_id |  | keyword |
| projectdiscovery.vuln_status |  | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| vulnerability.description | The description of the vulnerability that provides additional context of the vulnerability. For example (https://cve.mitre.org/about/faqs.html#cve_entry_descriptions_created) | keyword |
| vulnerability.description.text | Multi-field of `vulnerability.description`. | match_only_text |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id) | keyword |
| vulnerability.reference | A resource that provides additional information, context, and mitigations for the identified vulnerability. | keyword |
| vulnerability.report_id | The report or scan identification number. | keyword |
| vulnerability.scanner.vendor |  | constant_keyword |
| vulnerability.score.base | Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Base scores cover an assessment for exploitability metrics (attack vector, complexity, privileges, and user interaction), impact metrics (confidentiality, integrity, and availability), and scope. For example (https://www.first.org/cvss/specification-document) | float |
| vulnerability.severity | The severity of the vulnerability can help with metrics and internal prioritization regarding remediation. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |


#### vulnerability_changelog sample event

An example event for `vulnerability_changelog` looks as following:

```json
{
    "@timestamp": "2026-01-29T16:02:03.618Z",
    "agent": {
        "ephemeral_id": "658f5995-7325-4670-991e-f6bdec220100",
        "id": "f7d71c31-9197-4800-875a-fc80210dc7d2",
        "name": "elastic-agent-61557",
        "type": "filebeat",
        "version": "9.2.4"
    },
    "data_stream": {
        "dataset": "projectdiscovery_cloud.vulnerability_changelog",
        "namespace": "74713",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "f7d71c31-9197-4800-875a-fc80210dc7d2",
        "snapshot": false,
        "version": "9.2.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "projectdiscovery_cloud.vulnerability_changelog",
        "ingested": "2026-01-29T16:02:06Z",
        "kind": "event",
        "start": "2025-08-26T03:41:56.354Z",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "us-east-1.example.com"
    },
    "input": {
        "type": "cel"
    },
    "projectdiscovery": {
        "change_event": {
            "from": [
                "open",
                "true"
            ],
            "name": [
                "matcher_status",
                "vuln_status"
            ],
            "to": [
                "false",
                "fixed"
            ]
        },
        "created_at": "2025-08-26T03:41:56.388Z",
        "event": {
            "host": "us-east-1.example.com",
            "info": {
                "author": "author_1",
                "description": "A root certificate is a digital certificate issued by a trusted certificate authority that acts as a basis for other digital certificates. An untrusted root certificate is a certificate that is issued by an authority that is not trusted by the computer, and therefore cannot be used to authenticate websites or other digital certificates.\n",
                "metadata": {
                    "max-request": "1",
                    "verified": "true"
                },
                "name": "Untrusted Root Certificate - Detect",
                "reference": [
                    "https://www.sslmarket.com/ssl/trusted-and-untrusted-certificate",
                    "https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/ssl-untrusted-root-certificate/"
                ],
                "severity": "low",
                "tags": [
                    "ssl",
                    "tls",
                    "untrusted"
                ]
            },
            "ip": "175.16.199.1",
            "matcher_status": false,
            "port": 80,
            "response": "{\"timestamp\":\"2025-08-26T03:41:56.337646722Z\",\"host\":\"us-east-1.example.com\",\"ip\":\"175.16.199.2\",\"port\":\"443\",\"probe_status\":true,\"tls_version\":\"tls13\",\"cipher\":\"TLS_AES_128_GCM_SHA256\",\"not_before\":\"2025-07-13T23:50:37Z\",\"not_after\":\"2025-10-11T23:50:36Z\",\"subject_dn\":\"CN=*.test.com\",\"subject_cn\":\"*.test.com\",\"subject_an\":[\"*.test.com\"],\"serial\":\"XX:XX:XX\",\"issuer_dn\":\"CN=R11, O=Let's Encrypt, C=US\",\"issuer_cn\":\"R11\",\"issuer_org\":[\"Let's Encrypt\"],\"fingerprint_hash\":{\"md5\":\"XXX\",\"sha1\":\"XXX\",\"sha256\":\"XXX\"},\"wildcard_certificate\":true,\"tls_connection\":\"ctls\",\"sni\":\"us-east-1.example.com\"}",
            "template_id": "untrusted-root-certificate",
            "timestamp": "2025-08-26T03:41:56.354Z",
            "type": "ssl"
        },
        "matcher_status": false,
        "scan_id": "scan_id_1",
        "target": "us-east-1.example.com",
        "template_url": "https://cloud.projectdiscovery.io/public/untrusted-root-certificate",
        "updated_at": "2025-08-26T03:41:56.388Z",
        "vuln_hash": "vuln_hash_1",
        "vuln_id": "vuln_id_1",
        "vuln_status": "fixed"
    },
    "source": {
        "ip": "175.16.199.1",
        "port": 80
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "projectdiscovery_cloud",
        "forwarded"
    ],
    "vulnerability": {
        "description": "A root certificate is a digital certificate issued by a trusted certificate authority that acts as a basis for other digital certificates. An untrusted root certificate is a certificate that is issued by an authority that is not trusted by the computer, and therefore cannot be used to authenticate websites or other digital certificates.\n",
        "reference": [
            "https://www.sslmarket.com/ssl/trusted-and-untrusted-certificate",
            "https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/ssl-untrusted-root-certificate/"
        ],
        "report_id": "scan_id_1",
        "scanner": {
            "vendor": "Nuclei"
        },
        "severity": "low"
    }
}
```

### vulnerability_scan

The `vulnerability_scan` data stream collects the results from vulnerability scans performed by ProjectDiscovery Cloud.

#### vulnerability_scan fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| input.type | Input type | keyword |
| projectdiscovery.category |  | keyword |
| projectdiscovery.created_at |  | date |
| projectdiscovery.description |  | keyword |
| projectdiscovery.host |  | keyword |
| projectdiscovery.id |  | keyword |
| projectdiscovery.matched_at |  | keyword |
| projectdiscovery.matcher_name |  | keyword |
| projectdiscovery.matcher_status |  | boolean |
| projectdiscovery.reference |  | keyword |
| projectdiscovery.remediation |  | keyword |
| projectdiscovery.request |  | keyword |
| projectdiscovery.response |  | keyword |
| projectdiscovery.scan_id |  | keyword |
| projectdiscovery.severity |  | keyword |
| projectdiscovery.tags |  | keyword |
| projectdiscovery.template_id |  | keyword |
| projectdiscovery.template_name |  | keyword |
| projectdiscovery.template_url |  | keyword |
| projectdiscovery.updated_at |  | date |
| projectdiscovery.vuln_hash |  | keyword |
| projectdiscovery.vuln_status |  | keyword |
| vulnerability.description | The description of the vulnerability that provides additional context of the vulnerability. For example (https://cve.mitre.org/about/faqs.html#cve_entry_descriptions_created) | keyword |
| vulnerability.description.text | Multi-field of `vulnerability.description`. | match_only_text |
| vulnerability.reference | A resource that provides additional information, context, and mitigations for the identified vulnerability. | keyword |
| vulnerability.report_id | The report or scan identification number. | keyword |
| vulnerability.scanner.vendor |  | constant_keyword |
| vulnerability.severity | The severity of the vulnerability can help with metrics and internal prioritization regarding remediation. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |


#### vulnerability_scan sample event

An example event for `vulnerability_scan` looks as following:

```json
{
    "@timestamp": "2026-01-29T16:02:53.999Z",
    "agent": {
        "ephemeral_id": "2c1efba4-8ab7-4533-a8e7-250f8d4e95e3",
        "id": "4a7c07f7-22c1-4432-86c9-a4eb048cb43a",
        "name": "elastic-agent-39956",
        "type": "filebeat",
        "version": "9.2.4"
    },
    "data_stream": {
        "dataset": "projectdiscovery_cloud.vulnerability_scan",
        "namespace": "11442",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "4a7c07f7-22c1-4432-86c9-a4eb048cb43a",
        "snapshot": false,
        "version": "9.2.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "projectdiscovery_cloud.vulnerability_scan",
        "id": "id_1",
        "ingested": "2026-01-29T16:02:56Z",
        "kind": "event",
        "reason": "misconfiguration",
        "start": "2026-01-07T19:13:37.340Z",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "host_1.example.com"
    },
    "input": {
        "type": "cel"
    },
    "projectdiscovery": {
        "category": "misconfiguration",
        "created_at": "2026-01-07T19:13:37.340Z",
        "description": "Self-signed SSL certificates are not issued by a trusted certificate authority, providing no trust value and enabling man-in-the-middle attacks.",
        "host": "host_1.example.com",
        "id": "id_1",
        "matched_at": "host_1.example.com:443",
        "matcher_status": true,
        "reference": "https://www.rapid7.com/db/vulnerabilities/ssl-self-signed-certificate/",
        "remediation": "Purchase or generate a proper SSL certificate for this service.\n",
        "scan_id": "scan_id_1",
        "severity": "low",
        "tags": [
            "ssl",
            "tls",
            "self-signed",
            "vuln"
        ],
        "template_id": "self-signed-ssl",
        "template_name": "Self Signed SSL Certificate",
        "template_url": "https://cloud.projectdiscovery.io/public/self-signed-ssl",
        "updated_at": "2026-01-07T19:13:37.340Z",
        "vuln_hash": "vuln_hash_1",
        "vuln_status": "open"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "projectdiscovery_cloud",
        "forwarded",
        "ssl",
        "tls",
        "self-signed",
        "vuln"
    ],
    "vulnerability": {
        "description": "Self-signed SSL certificates are not issued by a trusted certificate authority, providing no trust value and enabling man-in-the-middle attacks.",
        "reference": "https://www.rapid7.com/db/vulnerabilities/ssl-self-signed-certificate/",
        "report_id": "scan_id_1",
        "scanner": {
            "vendor": "Nuclei"
        },
        "severity": "low"
    }
}
```

### Inputs used

These inputs can be used with this integration:
<details>
<summary>cel</summary>

## Setup

For more details about the CEL input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html).

Before configuring the CEL input, make sure you have:
- Network connectivity to the target API endpoint
- Valid authentication credentials (API keys, tokens, or certificates as required)
- Appropriate permissions to read from the target data source

### Collecting logs from CEL

To configure the CEL input, you must specify the `request.url` value pointing to the API endpoint. The interval parameter controls how frequently requests are made and is the primary way to balance data freshness with API rate limits and costs. Authentication is often configured through the `request.headers` section using the appropriate method for the service.

NOTE: To access the API service, make sure you have the necessary API credentials and that the Filebeat instance can reach the endpoint URL. Some services may require IP whitelisting or VPN access.

To collect logs via API endpoint, configure the following parameters:

- API Endpoint URL
- API credentials (tokens, keys, or username/password)
- Request interval (how often to fetch data)
</details>


### API usage

This integration uses the ProjectDiscovery Cloud API to collect data. The following resources provide more information about the API:

*   [ProjectDiscovery Cloud API Reference](https://docs.projectdiscovery.io/api-reference/introduction)
