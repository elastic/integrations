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

This integration has been tested with HashiCorp Vault 1.11 and 1.21.
It requires Elastic Stack version 8.12.0 or higher.

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
    - The Vault telemetry endpoint must be enabled.
    - A Vault token with read access to the `/sys/metrics` API endpoint.
    - The Elastic Agent must have network access to the Vault API endpoint.

### Elastic Prerequisites

- Elastic Stack version 8.12.0 or higher.
- Elastic Agent installed and enrolled in Fleet.

## How do I deploy this integration?

### Vendor Setup

#### Setting up Audit Logs (File Audit Device)

1.  Create a directory for audit logs on each Vault server:

    `mkdir /var/log/vault`

2.  Enable the file audit device in Vault:

    `vault audit enable file file_path=/var/log/vault/audit.json`

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

    `vault audit enable socket address=${ELASTIC_AGENT_IP}:9007 socket_type=tcp`

#### Setting up Operational Logs

Add the following line to your Vault configuration file to enable JSON-formatted logs. Ensure the log output is directed to a file that Elastic Agent can read.

`log_format = "json"`

#### Setting up Metrics

1.  Configure Vault telemetry in your Vault configuration file:
    ```hcl
    telemetry {
      disable_hostname = true
      enable_hostname_label = true
    }
    ```
    Restart the Vault server after saving this file.

2.  Create a Vault policy file that grants read access to the metrics endpoint.
    ```hcl
    path "sys/metrics" {
      capabilities = ["read"]
    }
    ```

3.  Apply the policy.

    `vault policy write read-metrics metrics-policy.hcl`

4.  Create a Vault token with this policy:

    `vault token create -policy="read-metrics" -display-name="elastic-agent-token"`

    Save the token value, it will be needed to complete configuring the integration in Kibana.

### Onboard / configure in Kibana

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for "HashiCorp Vault" and select the integration.
3.  Click **Add HashiCorp Vault**.
4.  Configure the integration based on your data collection needs:

    **For Audit Logs (File)**:
    - Enable the "Logs from file" --> "Audit logs (file audit device)" input.
    - Specify the file path (default: `/var/log/vault/audit*.json*`).


    **For Audit Logs (TCP Socket)**:
    - Enable the "Logs from TCP socket" input.
    - Configure the `Listen Address` (default: `localhost`) and `Listen Port` (default: `9007`).
    - If Vault connects from a different host, set the Listen Address to `0.0.0.0`.


    **For Operational Logs**:
    - Enable the "Logs from file" --> "Operation logs" input.
    - Specify the log file path (default: `/var/log/vault/log*.json*`).


    **For Metrics**:
    - Enable the "Metrics" input.
    - Enter the Vault host URL under `Hosts` (default: `http://localhost:8200`).
    - Provide the `Vault Token` created earlier.
    - Adjust the collection `Period` if needed (default: `30s`).

5.  Click **Save and continue** to deploy the integration policy to your Elastic Agents.

### Validation

1.  **Check Agent Status**: In Fleet, verify that the Elastic Agent shows a "Healthy" status.
2.  **Verify Data Ingestion**:
    - Navigate to **Discover** in Kibana.
    - Select the appropriate data view (`logs-hashicorp_vault.audit-*`, `logs-hashicorp_vault.log-*`, or `metrics-hashicorp_vault.metrics-*`).
    - Confirm that events are appearing with recent timestamps.
3.  **View Dashboards**:
    - Navigate to **Dashboards**.
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
- [HashiCorp Vault File Audit Device](https://developer.hashicorp.com/vault/docs/audit/file)
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

{{ fields "audit" }}

#### audit sample event

{{event "audit"}}

### log

The `log` data stream collects operational logs from Vault's standard log file.

#### log fields

{{ fields "log" }}

#### log sample event

{{event "log"}}

### metrics

The `metrics` data stream collects Prometheus-formatted metrics from the Vault telemetry endpoint.

#### metrics fields

{{ fields "metrics" }}

### Inputs used
{{ inputDocs }}

### API usage
These APIs are used with this integration:
* **`/v1/sys/metrics`**: Used to collect Prometheus-formatted telemetry data. See the [HashiCorp Vault Metrics API documentation](https://developer.hashicorp.com/vault/api-docs/system/metrics) for more information.
