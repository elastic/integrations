# Service Info

## Common use cases

This integration facilitates the following use cases:

- **Security Monitoring and Auditing**: Track all access to secrets, who accessed them, and when, providing a detailed audit trail for compliance and security investigations
- **Operational Monitoring**: Monitor Vault server health, performance, and operational status to identify issues before they impact production
- **Access Pattern Analysis**: Analyze patterns in secret access to identify potential security threats or unusual behavior
- **Compliance Reporting**: Generate reports from audit logs to demonstrate compliance with security policies and regulatory requirements
- **Performance Optimization**: Track metrics to understand Vault usage patterns and optimize resource allocation
- **Secret Lifecycle Management**: Monitor secret creation, access, renewal, and revocation activities across your organization

## Data types collected

This integration collects the following types of data from HashiCorp Vault:

- **Audit Logs** (`hashicorp_vault.audit`): Detailed records of all requests and responses to Vault APIs, including authentication attempts, secret access, policy changes, and administrative operations. Audit logs contain HMAC-SHA256 hashed values of secrets (not plaintext) and can be collected via file or TCP socket.
- **Operational Logs** (`hashicorp_vault.log`): JSON-formatted operational logs from the Vault server, including startup messages, configuration changes, errors, warnings, and general operational events.
- **Metrics** (`hashicorp_vault.metrics`): Prometheus-formatted telemetry data from the `/v1/sys/metrics` API endpoint, including performance counters, gauges, histograms, and system health indicators.

## Compatibility

This integration has been tested with HashiCorp Vault 1.11 and 1.21.

The integration requires Elastic Stack version 8.12.0 or higher.

## Scaling and Performance

### Audit Log Performance

Vault's file audit device provides the strongest delivery guarantees for audit logs. When using the file audit device, ensure adequate disk I/O capacity as Vault will block operations if it cannot write audit logs.

### Metrics Collection

The metrics endpoint (`/v1/sys/metrics?format=prometheus`) exposes Vault's telemetry data. The default collection interval for this integration is 30 seconds. Adjust this based on your monitoring needs and Vault server load.

### TCP Socket Considerations

When using the socket audit device for real-time log streaming, ensure network reliability between Vault and the Elastic Agent. If the TCP connection is unavailable, Vault operations will be blocked until the connection is restored.

### Log Rotation

For file-based log collection, implement log rotation to prevent disk space exhaustion. The integration supports rotated log files with compression and date extensions.

# Set Up Instructions

## Vendor prerequisites

The following prerequisites are required on the HashiCorp Vault side:

### For Audit Log Collection

- **File Audit Device**: A file audit device must be enabled with write permissions to a directory accessible by Vault
- **Socket Audit Device** (alternative): A socket audit device can be configured to stream logs to a TCP endpoint where Elastic Agent is listening

### For Operational Log Collection

- **JSON Log Format**: Vault must be configured to output logs in JSON format (set `log_format = "json"` in Vault configuration)
- **File Access**: The Vault operational log file must be accessible by Elastic Agent for collection

### For Metrics Collection

- **Vault Token**: A Vault token with read access to the `/sys/metrics` API endpoint
- **Telemetry Configuration**: Vault telemetry must be configured with `disable_hostname = true` and `enable_hostname_label = true` is recommended
- **Network Access**: The Elastic Agent must be able to reach the Vault API endpoint (default: `http://localhost:8200`)

## Elastic prerequisites

- Elastic Stack version 8.12.0 or higher
- Elastic Agent installed and enrolled in Fleet

## Vendor set up steps

### Setting up Audit Logs (File Audit Device)

1. Create a directory for audit logs on each Vault server:
```bash
mkdir /var/log/vault
```

2. Enable the file audit device in Vault:
```bash
vault audit enable file file_path=/var/log/vault/audit.json
```

3. Configure log rotation to prevent disk space issues. Example using `logrotate`:
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

### Setting up Audit Logs (Socket Audit Device)

1. Note the IP address and port where Elastic Agent will be listening (default: port 9007)

2. Enable the socket audit device in Vault (substitute your Elastic Agent IP):
```bash
vault audit enable socket address=${ELASTIC_AGENT_IP}:9007 socket_type=tcp
```

**Note**: Configure the integration in Kibana first before enabling the socket audit device, as Vault will test the connection.

**Warning: Risk of Unresponsive Vault with TCP Socket Audit Devices**: If a TCP socket audit log destination (like the Elastic Agent)
becomes unavailable, Vault may block and stop processing all requests until the connection is restored. This can lead to a service outage.
To mitigate this risk, HashiCorp strongly recommends that a socket audit device is configured as a secondary device, alongside a primary,
non-socket audit device (like the `file` audit device). For more details, see the official documentation on [Blocked Audit Devices](https://developer.hashicorp.com/vault/docs/audit/socket#configuration).

### Setting up Operational Logs

Configure Vault to output logs in JSON format by adding to your Vault configuration file:
```hcl
log_format = "json"
```

Direct Vault's log output to a file that Elastic Agent can read.

### Setting up Metrics

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
    ```bash
    vault policy write read-metrics metrics-policy.hcl
    ```

4.  Create a Vault token with this policy:
    ```bash
    vault token create -policy="read-metrics" -display-name="elastic-agent-token"
    ```
    Save the token value, it will be needed to complete configuring the integration in Kibana.

## Kibana set up steps

1. In Kibana, navigate to **Management > Integrations**

2. Search for "HashiCorp Vault" and select the integration

3. Click **Add HashiCorp Vault**

4. Configure the integration based on your data collection needs:

   **For Audit Logs (File)**:
   - Enable the "Logs from file" --> "Audit logs (file audit device)" input
   - Specify the file path (default: `/var/log/vault/audit*.json*`)
   - Optionally enable "Preserve original event" to keep raw logs

   **For Audit Logs (TCP Socket)**:
   - Enable the "Logs from TCP socket" input
   - Configure the listen address (default: `localhost`) and port (default: `9007`)
   - If Vault will connect remotely, set listen address to `0.0.0.0`

   **For Operational Logs**:
   - Enable the "Logs from file" --> "Operation logs" input
   - Specify the log file path (default: `/var/log/vault/log*.json*`)

   **For Metrics**:
   - Enable the "Metrics" input
   - Enter the Vault host URL (default: `http://localhost:8200`)
   - Provide the Vault token with read access to `/sys/metrics`
   - Optionally configure SSL settings if using HTTPS
   - Adjust the collection period if needed (default: `30s`)

5. Configure the agent policy and select the agent to run this integration

6. Click **Save and continue** to deploy the integration

# Validation Steps

After configuring the integration, validate that data is flowing correctly:

1. **Check Agent Status**: In Fleet, verify that the Elastic Agent shows a "Healthy" status

2. **Verify Data Ingestion**:
   - Navigate to **Discover** in Kibana
   - Select the appropriate data view for each data stream:
     - `logs-hashicorp_vault.audit-*` for audit logs
     - `logs-hashicorp_vault.log-*` for operational logs
     - `metrics-hashicorp_vault.metrics-*` for metrics
   - Confirm that events are appearing with recent timestamps

3. **Test Audit Logging**: Perform an action in Vault (e.g., read a secret) and verify it appears in the audit logs

4. **View Dashboards**:
   - Navigate to **Analytics > Dashboards**
   - Open the "[Hashicorp Vault] Audit Logs" to view audit log visualizations
   - Open the "[Hashicorp Vault] Operational Logs" to view operational log visualizations
   - Verify that data is populating the dashboard panels

5. **Check Metrics**: For metrics collection, verify that metrics are being collected by searching for documents with `hashicorp_vault.metrics.*` fields

# Troubleshooting

## Common Configuration Issues

### No data collected

- **Agent Status**: Check the Elastic Agent status in Fleet to ensure it's running and healthy
- **File Permissions**: Verify that the user running Elastic Agent has read permissions on log files
- **File Paths**: Ensure the configured file paths match the actual location of Vault logs
- **Log Format**: For operational logs, confirm Vault is configured with `log_format = "json"`

### TCP socket connection fails

- **Network Connectivity**: Verify network connectivity between Vault and Elastic Agent
- **Firewall Rules**: Check that firewall rules allow TCP connections on the configured port
- **Listen Address**: If Vault is on a different host, ensure the listen address is set to `0.0.0.0` rather than `localhost`
- **Port Conflicts**: Verify the configured port is not in use by another service

### Metrics not collected

- **Vault Token**: Verify the Vault token is valid and has not expired
- **Token Permissions**: Ensure the token has read access to the `/sys/metrics` endpoint
- **Telemetry Configuration**: Confirm Vault telemetry is properly configured with `disable_hostname = true`
- **Network Access**: Verify Elastic Agent can reach the Vault API endpoint

### Vault is Unresponsive or Stops Accepting Request
If Vault stops responding to requests, you may have a blocked audit device. This can happen if a TCP socket destination is unavailable or a file
audit device cannot write to disk. Review Vault's operational logs for errors related to audit logging. For more information on identifying and
resolving this, see the [Blocked Audit Device Behavior](https://developer.hashicorp.com/vault/tutorials/monitoring/blocked-audit-devices#blocked-audit-device-behavior) tutorial.

## Ingestion Errors

If `error.message` appears in ingested data:

- **Check Pipeline Errors**: Review the error message details to identify parsing or processing issues
- **Log Format Issues**: Ensure logs are in valid JSON format and match expected schema
- **Missing Required Fields**: Some audit log events require certain fields; check for incomplete log entries

## API Authentication Errors

### Token expired or invalid

- Generate a new Vault token with appropriate permissions
- Update the integration configuration in Kibana with the new token
- For long-running deployments, use a token with an appropriate TTL or create a periodic token

### Permission denied errors

- Verify the token has a policy granting read access to `/sys/metrics`
- Check Vault audit logs for permission denial details
- Example policy for metrics access:
```hcl
path "sys/metrics" {
  capabilities = ["read"]
}
```

## Vendor Resources

- [HashiCorp Vault Audit Devices](https://developer.hashicorp.com/vault/docs/audit)
- [HashiCorp Vault File Audit Device](https://developer.hashicorp.com/vault/docs/audit/file)
- [HashiCorp Vault Socket Audit Device](https://developer.hashicorp.com/vault/docs/audit/socket)
- [HashiCorp Vault Telemetry Configuration](https://developer.hashicorp.com/vault/docs/configuration/telemetry)
- [HashiCorp Vault Troubleshooting](https://developer.hashicorp.com/vault/docs/troubleshoot)

# Documentation sites

- [HashiCorp Vault Official Documentation](https://developer.hashicorp.com/vault/docs)
- [HashiCorp Vault API Documentation](https://developer.hashicorp.com/vault/api-docs)
- [HashiCorp Vault Audit Hash API](https://developer.hashicorp.com/vault/api-docs/system/audit-hash)
- [HashiCorp Vault Metrics API](https://developer.hashicorp.com/vault/api-docs/system/metrics)
- [HashiCorp Vault Configuration Reference](https://developer.hashicorp.com/vault/docs/configuration)
- [HashiCorp Vault Deployment Guide](https://developer.hashicorp.com/vault/tutorials/day-one-raft/raft-deployment-guide)
- [Elastic HashiCorp Vault Integration Documentation](https://docs.elastic.co/integrations/hashicorp_vault)


