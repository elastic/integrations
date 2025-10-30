# Hashicorp Vault Integration for Elastic

## Overview

The Hashicorp Vault integration for Elastic enables the collection of logs and metrics from Hashicorp Vault. This allows you to monitor Vault server health, track access to secrets, and maintain a detailed audit trail for security and compliance.

This integration facilitates the following use cases:
- **Security Monitoring and Auditing**: Track all access to secrets, who accessed them, and when, providing a detailed audit trail for compliance and security investigations.
- **Operational Monitoring**: Monitor Vault server health, performance, and operational status to identify issues before they impact production.
- **Access Pattern Analysis**: Analyze patterns in secret access to identify potential security threats or unusual behavior.
- **Compliance Reporting**: Generate reports from audit logs to demonstrate compliance with security policies and regulatory requirements.
- **Performance Optimization**: Track metrics to understand Vault usage patterns and optimize resource allocation.
- **Secret Lifecycle Management**: Monitor secret creation, access, renewal, and revocation activities across your organization.

### Compatibility

This integration has been tested with HashiCorp Vault 1.11.
It requires Elastic Stack version 8.12.0 or higher, or version 9.0.0 and above.

## What data does this integration collect?

This integration collects the following types of data from HashiCorp Vault:

- **Audit Logs** (`hashicorp_vault.audit`): Detailed records of all requests and responses to Vault APIs, including authentication attempts, secret access, policy changes, and administrative operations. Audit logs contain HMAC-SHA256 hashed values of secrets and can be collected via file or TCP socket.
- **Operational Logs** (`hashicorp_vault.log`): JSON-formatted operational logs from the Vault server, including startup messages, configuration changes, errors, warnings, and general operational events.
- **Metrics** (`hashicorp_vault.metrics`): Prometheus-formatted telemetry data from the `/v1/sys/metrics` API endpoint, including performance counters, gauges, and system health indicators.

## What do I need to use this integration?

### Vendor Prerequisites

- **For Audit Log Collection (File)**: A file audit device must be enabled with write permissions to a directory accessible by Vault.
- **For Audit Log Collection (Socket)**: A socket audit device can be configured to stream logs to a TCP endpoint where Elastic Agent is listening.
- **For Operational Log Collection**: Vault must be configured to output logs in JSON format (`log_format = "json"`) and the log file must be accessible by Elastic Agent.
- **For Metrics Collection**:
    - A Vault token with read access to the `/sys/metrics` API endpoint.
    - Vault telemetry must be configured with `disable_hostname = true`. It is also recommended to set `enable_hostname_label = true`.
    - The Elastic Agent must have network access to the Vault API endpoint.

### Elastic Prerequisites

- Elastic Stack version 8.12.0 or higher (or 9.0.0+).
- Elastic Agent installed and enrolled in Fleet.

## How do I deploy this integration?

### Vendor Setup

#### Setting up Audit Logs (File Audit Device)

1.  Create a directory for audit logs on each Vault server:
    ```bash
    mkdir /var/log/vault
    ```

2.  Enable the file audit device in Vault:
    ```bash
    vault audit enable file file_path=/var/log/vault/audit.json
    ```

3.  Configure log rotation to prevent disk space issues. The following is an example using `logrotate`:
    ```bash
    tee /etc/logrotate.d/vault <<'EOF'
    /var/log/vault/audit.json {
        rotate 7
        daily
        compress
        delaycompress
        missingok
        notifempty
        extension json
        dateext
        dateformat %Y-%m-%d.
        postrotate
            /bin/systemctl reload vault || true
        endscript
    }
    EOF
    ```

#### Setting up Audit Logs (Socket Audit Device)

1.  Note the IP address and port where Elastic Agent will be listening (e.g., port `9007`).
2.  **Important**: Configure and deploy the integration in Kibana *before* enabling the socket device in Vault, as Vault will immediately test the connection.
3.  Enable the socket audit device in Vault, substituting the IP of your Elastic Agent:
    ```bash
    vault audit enable socket address=${ELASTIC_AGENT_IP}:9007 socket_type=tcp
    ```

#### Setting up Operational Logs

Add the following line to your Vault configuration file to enable JSON-formatted logs. Ensure the log output is directed to a file that Elastic Agent can read.
```hcl
log_format = "json"
```

#### Setting up Metrics

1.  Configure Vault telemetry in your Vault configuration file:
    ```hcl
    telemetry {
      disable_hostname = true
      enable_hostname_label = true
    }
    ```

2.  Create a Vault policy that grants read access to the metrics endpoint.
    ```hcl
    path "sys/metrics" {
      capabilities = ["read"]
    }
    ```

3.  Create a Vault token with this policy:
    ```bash
    vault token create -policy=metrics-read
    ```

### Onboard / configure in Kibana

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for "HashiCorp Vault" and select the integration.
3.  Click **Add HashiCorp Vault**.
4.  Configure the integration based on your data collection needs:

    **For Audit Logs (File)**:
    - Enable the "Audit logs (file audit device)" input.
    - Specify the file path (default: `/var/log/vault/audit*.json*`).

    **For Audit Logs (TCP Socket)**:
    - Enable the "Audit logs (socket audit device)" input.
    - Configure the `Listen Address` (default: `localhost`) and `Listen Port` (default: `9007`).
    - If Vault connects from a different host, set the Listen Address to `0.0.0.0`.

    **For Operational Logs**:
    - Enable the "Operation logs" input.
    - Specify the log file path (default: `/var/log/vault/log*.json*`).

    **For Metrics**:
    - Enable the "Vault metrics (prometheus)" input.
    - Enter the Vault host URL under `Hosts` (default: `http://localhost:8200`).
    - Provide the `Vault Token` created earlier.
    - Adjust the collection `Period` if needed (default: `30s`).

5.  Click **Save and continue** to deploy the integration policy to your Elastic Agents.

### Validation

1.  **Check Agent Status**: In Fleet, verify that the Elastic Agent shows a "Healthy" status.
2.  **Verify Data Ingestion**:
    - Navigate to **Analytics > Discover** in Kibana.
    - Select the appropriate data view (`logs-hashicorp_vault.audit-*`, `logs-hashicorp_vault.log-*`, or `metrics-hashicorp_vault.metrics-*`).
    - Confirm that events are appearing with recent timestamps.
3.  **View Dashboards**:
    - Navigate to **Analytics > Dashboards**.
    - Search for "Hashicorp Vault" to find the pre-built dashboards.
    - Verify that data is populating the dashboard panels.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common Configuration Issues

- **No Data Collected**:
    - Verify Elastic Agent is healthy in Fleet.
    - Ensure the user running Elastic Agent has read permissions on log files.
    - Double-check that the configured file paths in the integration policy match the actual log file locations.
    - For operational logs, confirm Vault is configured with `log_format = "json"`.
- **TCP Socket Connection Fails**:
    - Verify network connectivity between Vault and the Elastic Agent host.
    - Check that firewall rules allow TCP connections on the configured port.
    - If Vault is remote, ensure the listen address is set to `0.0.0.0` in the integration policy.
- **Metrics Not Collected**:
    - Verify the Vault token is valid, has not expired, and has read permissions for the `/sys/metrics` endpoint.
    - Confirm Vault's telemetry configuration includes `disable_hostname = true`.

### Vendor Resources

- [HashiCorp Vault Audit Devices](https://developer.hashicorp.com/vault/docs/audit)
- [HashiCorp Vault Telemetry Configuration](https://developer.hashicorp.com/vault/docs/configuration/telemetry)
- [HashiCorp Vault Troubleshooting](https://developer.hashicorp.com/vault/docs/troubleshoot)

## Scaling

- **Audit Log Performance**: Vault's file audit device provides the strongest delivery guarantees. Ensure adequate disk I/O capacity, as Vault will block operations if it cannot write audit logs.
- **Metrics Collection**: The default collection interval is 30 seconds. Adjust this period based on your monitoring needs and Vault server load.
- **TCP Socket Considerations**: When using the socket audit device, ensure network reliability between Vault and the Elastic Agent. If the TCP connection is unavailable, Vault operations will be blocked until it is restored.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### audit

The `audit` data stream collects audit logs from the file or socket audit devices.

#### audit fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| hashicorp_vault.audit.auth.accessor | This is an HMAC of the client token accessor | keyword |
| hashicorp_vault.audit.auth.client_token | This is an HMAC of the client's token ID. | keyword |
| hashicorp_vault.audit.auth.display_name | Display name is a non-security sensitive identifier that is applicable to this auth. It is used for logging and prefixing of dynamic secrets. For example, it may be "armon" for the github credential backend. If the client token is used to generate a SQL credential, the user may be "github-armon-uuid". This is to help identify the source without using audit tables. | keyword |
| hashicorp_vault.audit.auth.entity_id | Entity ID is the identifier of the entity in identity store to which the identity of the authenticating client belongs to. | keyword |
| hashicorp_vault.audit.auth.external_namespace_policies | External namespace policies represent the policies authorized from different namespaces indexed by respective namespace identifiers. | flattened |
| hashicorp_vault.audit.auth.identity_policies | These are the policies sourced from the identity. | keyword |
| hashicorp_vault.audit.auth.metadata | This will contain a list of metadata key/value pairs associated with the authenticated user. | flattened |
| hashicorp_vault.audit.auth.no_default_policy | Indicates that the default policy should not be added by core when creating a token. The default policy will still be added if it's explicitly defined. | boolean |
| hashicorp_vault.audit.auth.policies | Policies is the list of policies that the authenticated user is associated with. | keyword |
| hashicorp_vault.audit.auth.policy_results.allowed |  | boolean |
| hashicorp_vault.audit.auth.policy_results.granting_policies.name |  | keyword |
| hashicorp_vault.audit.auth.policy_results.granting_policies.namespace_id |  | keyword |
| hashicorp_vault.audit.auth.policy_results.granting_policies.type |  | keyword |
| hashicorp_vault.audit.auth.remaining_uses |  | long |
| hashicorp_vault.audit.auth.token_issue_time |  | date |
| hashicorp_vault.audit.auth.token_policies | These are the policies sourced from the token. | keyword |
| hashicorp_vault.audit.auth.token_ttl |  | long |
| hashicorp_vault.audit.auth.token_type |  | keyword |
| hashicorp_vault.audit.entity_created | entity_created is set to true if an entity is created as part of a login request. | boolean |
| hashicorp_vault.audit.error | If an error occurred with the request, the error message is included in this field's value. | keyword |
| hashicorp_vault.audit.request.client_certificate_serial_number | Serial number from the client's certificate. | keyword |
| hashicorp_vault.audit.request.client_id |  | keyword |
| hashicorp_vault.audit.request.client_token | This is an HMAC of the client's token ID. | keyword |
| hashicorp_vault.audit.request.client_token_accessor | This is an HMAC of the client token accessor. | keyword |
| hashicorp_vault.audit.request.data | The data object will contain secret data in key/value pairs. | flattened |
| hashicorp_vault.audit.request.headers | Additional HTTP headers specified by the client as part of the request. | flattened |
| hashicorp_vault.audit.request.id | This is the unique request identifier. | keyword |
| hashicorp_vault.audit.request.mount_accessor |  | keyword |
| hashicorp_vault.audit.request.mount_type |  | keyword |
| hashicorp_vault.audit.request.namespace.id |  | keyword |
| hashicorp_vault.audit.request.namespace.path |  | keyword |
| hashicorp_vault.audit.request.operation | This is the type of operation which corresponds to path capabilities and is expected to be one of: create, read, update, delete, or list. | keyword |
| hashicorp_vault.audit.request.path | The requested Vault path for operation. | keyword |
| hashicorp_vault.audit.request.path.text | Multi-field of `hashicorp_vault.audit.request.path`. | text |
| hashicorp_vault.audit.request.policy_override | Policy override indicates that the requestor wishes to override soft-mandatory Sentinel policies. | boolean |
| hashicorp_vault.audit.request.remote_address | The IP address of the client making the request. | ip |
| hashicorp_vault.audit.request.remote_port | The remote port of the client making the request. | long |
| hashicorp_vault.audit.request.replication_cluster | Name given to the replication secondary where this request originated. | keyword |
| hashicorp_vault.audit.request.wrap_ttl | If the token is wrapped, this displays configured wrapped TTL in seconds. | long |
| hashicorp_vault.audit.response.auth.accessor |  | keyword |
| hashicorp_vault.audit.response.auth.client_token |  | keyword |
| hashicorp_vault.audit.response.auth.display_name |  | keyword |
| hashicorp_vault.audit.response.auth.entity_id |  | keyword |
| hashicorp_vault.audit.response.auth.external_namespace_policies |  | flattened |
| hashicorp_vault.audit.response.auth.identity_policies |  | keyword |
| hashicorp_vault.audit.response.auth.metadata |  | flattened |
| hashicorp_vault.audit.response.auth.no_default_policy |  | boolean |
| hashicorp_vault.audit.response.auth.num_uses |  | long |
| hashicorp_vault.audit.response.auth.policies |  | keyword |
| hashicorp_vault.audit.response.auth.token_issue_time |  | date |
| hashicorp_vault.audit.response.auth.token_policies |  | keyword |
| hashicorp_vault.audit.response.auth.token_ttl | Time to live for the token in seconds. | long |
| hashicorp_vault.audit.response.auth.token_type |  | keyword |
| hashicorp_vault.audit.response.data | Response payload. | flattened |
| hashicorp_vault.audit.response.headers | Headers will contain the http headers from the plugin that it wishes to have as part of the output. | flattened |
| hashicorp_vault.audit.response.mount_accessor |  | keyword |
| hashicorp_vault.audit.response.mount_type |  | keyword |
| hashicorp_vault.audit.response.redirect | Redirect is an HTTP URL to redirect to for further authentication. This is only valid for credential backends. This will be blanked for any logical backend and ignored. | keyword |
| hashicorp_vault.audit.response.warnings |  | keyword |
| hashicorp_vault.audit.response.wrap_info.accessor | The token accessor for the wrapped response token. | keyword |
| hashicorp_vault.audit.response.wrap_info.creation_path | Creation path is the original request path that was used to create the wrapped response. | keyword |
| hashicorp_vault.audit.response.wrap_info.creation_time | The creation time. This can be used with the TTL to figure out an expected expiration. | date |
| hashicorp_vault.audit.response.wrap_info.token | The token containing the wrapped response. | keyword |
| hashicorp_vault.audit.response.wrap_info.ttl | Specifies the desired TTL of the wrapping token. | long |
| hashicorp_vault.audit.response.wrap_info.wrapped_accessor | The token accessor for the wrapped response token. | keyword |
| hashicorp_vault.audit.type | Audit record type (request or response). | keyword |
| input.type |  | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset |  | long |
| log.source.address | Source address (IP and port) of the log message. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| nomad.allocation.id | Nomad allocation ID | keyword |
| nomad.namespace | Nomad namespace. | keyword |
| nomad.node.id | Nomad node ID. | keyword |
| nomad.task.name | Nomad task name. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |


### log

The `log` data stream collects operational logs from Vault's standard log file.

#### log fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| hashicorp_vault.log |  | flattened |
| input.type |  | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset |  | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |


### metrics

The `metrics` data stream collects Prometheus-formatted metrics from the Vault telemetry endpoint.

#### metrics fields

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |  |
| event.module | Event module | constant_keyword |  |
| hashicorp_vault.metrics.\*.counter | Hashicorp Vault telemetry data from the Prometheus endpoint. | double | counter |
| hashicorp_vault.metrics.\*.histogram | Hashicorp Vault telemetry data from the Prometheus endpoint. | histogram |  |
| hashicorp_vault.metrics.\*.rate | Hashicorp Vault telemetry data from the Prometheus endpoint. | double | gauge |
| hashicorp_vault.metrics.\*.value | Hashicorp Vault telemetry data from the Prometheus endpoint. | double | gauge |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |  |
| labels.auth_method | Authorization engine type. | keyword |  |
| labels.cluster | The cluster name from which the metric originated; set in the configuration file, or automatically generated when a cluster is created. | keyword |  |
| labels.creation_ttl | Time-to-live value assigned to a token or lease at creation. This value is rounded up to the next-highest bucket; the available buckets are 1m, 10m, 20m, 1h, 2h, 1d, 2d, 7d, and 30d. Any longer TTL is assigned the value +Inf. | keyword |  |
| labels.expiring |  | keyword |  |
| labels.gauge |  | keyword |  |
| labels.host |  | keyword |  |
| labels.instance |  | keyword |  |
| labels.job |  | keyword |  |
| labels.local |  | keyword |  |
| labels.mount_point | Path at which an auth method or secret engine is mounted. | keyword |  |
| labels.namespace | A namespace path, or root for the root namespace | keyword |  |
| labels.policy |  | keyword |  |
| labels.quantile |  | keyword |  |
| labels.queue_id |  | keyword |  |
| labels.term |  | keyword |  |
| labels.token_type | Identifies whether the token is a batch token or a service token. | keyword |  |
| labels.type |  | keyword |  |
| labels.version |  | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


### Inputs used
These inputs can be used with this integration:
<details>
<summary>logfile</summary>

## Setup
For more details about the logfile input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-log).

### Collecting logs from logfile

To collect logs via logfile, select **Collect logs via the logfile input** and configure the following parameter:

- Paths: List of glob-based paths to crawl and fetch log files from. Supports glob patterns like
  `/var/log/*.log` or `/var/log/*/*.log` for subfolder matching. Each file found starts a
  separate harvester.
</details>
<details>
<summary>tcp</summary>

## Setup

For more details about the TCP input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-tcp).

### Collecting logs from TCP

To collect logs via TCP, select **Collect logs via TCP** and configure the following parameters:

**Required Settings:**
- Host
- Port

**Common Optional Settings:**
- Max Message Size - Maximum size of incoming messages
- Max Connections - Maximum number of concurrent connections
- Timeout - How long to wait for data before closing idle connections
- Line Delimiter - Character(s) that separate log messages

## SSL/TLS Configuration

To enable encrypted connections, configure the following SSL settings:

**SSL Settings:**
- Enable SSL*- Toggle to enable SSL/TLS encryption
- Certificate - Path to the SSL certificate file (`.crt` or `.pem`)
- Certificate Key - Path to the private key file (`.key`)
- Certificate Authorities - Path to CA certificate file for client certificate validation (optional)
- Client Authentication - Require client certificates (`none`, `optional`, or `required`)
- Supported Protocols - TLS versions to support (e.g., `TLSv1.2`, `TLSv1.3`)

**Example SSL Configuration:**
```yaml
ssl.enabled: true
ssl.certificate: "/path/to/server.crt"
ssl.key: "/path/to/server.key"
ssl.certificate_authorities: ["/path/to/ca.crt"]
ssl.client_authentication: "optional"
```
</details>


### API usage
These APIs are used with this integration:
* **`/v1/sys/metrics`**: Used to collect Prometheus-formatted telemetry data. See the [HashiCorp Vault Metrics API documentation](https://developer.hashicorp.com/vault/api-docs/system/metrics) for more information.
* **`/sys/audit-hash`**: Can be used to manually verify the hash of a secret found in an audit log. See the [HashiCorp Vault Audit Hash API documentation](https://developer.hashicorp.com/vault/api-docs/system/audit-hash) for more information.
