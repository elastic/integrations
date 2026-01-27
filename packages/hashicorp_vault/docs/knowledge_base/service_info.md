# Service Info

## Common use cases

The Hashicorp Vault integration provides comprehensive visibility into the security posture and operational health of your secrets management infrastructure. By ingesting audit logs, operational logs, and performance metrics, organizations can ensure compliance and maintain high availability.

- **Security Auditing and Compliance:** Monitor every request made to Vault to ensure compliance with internal security policies and external regulations. The integration tracks who accessed what secret and when, providing a detailed audit trail.
- **Operational Health Monitoring:** Track the health and performance of the Vault cluster by monitoring operational logs for system errors, performance, and storage backend issues. This allows administrators to proactively address issues before they impact availability.
- **Performance Optimization and Capacity Planning:** Utilize metrics to identify latency in secret retrieval, track active client counts, and monitor resource utilization. This data is essential for scaling the cluster effectively to meet demand.
- **Threat Detection and Incident Response:** Identify suspicious patterns, such as repeated unauthorized access attempts, unusual API call volumes, or token reuse, using real-time audit log analysis in Kibana.

## Data types collected
This integration can collect the following types of data:
- **Vault metrics (prometheus):** Collect prometheus metrics from Vault. This includes performance telemetry from the `/sys/metrics` API endpoint, covering request counts, seal status, and memory usage.
- **Audit logs (file audit device):** Collect Vault audit logs from file. This provides detailed records of every authenticated request and response in JSON format ingested directly from a local JSON file.
- **Audit logs (socket audit device):** Collect Vault audit logs from TCP socket. This allows streaming audit logs over a network connection via TCP to a listening Elastic Agent.
- **Operation logs:** Collect Vault operational logs from file. This ingests the standard output logs of the Vault service, containing internal system events and error messages.

## Compatibility

This integration has been tested against and supports **Hashicorp Vault** version 1.11. 

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:

- **Transport/Collection Considerations:** The `logfile` input for audit logs is the recommended collection method for production environments because it provides the strongest delivery guarantees; logs are persisted to disk before being read by the Elastic Agent. The `tcp` socket input offers real-time streaming but requires a stable network connection. Note that Vault's audit devices are blocking by default; if the Elastic Agent is unreachable and the socket buffer fills up, Vault may become unresponsive to prevent un-audited actions.
- **Data Volume Management:** Audit logs can generate large volumes of data in high-traffic environments. To manage load, use Vault's built-in audit filtering to exclude high-volume, low-value paths. For metrics, adjust the **Period** variable in the integration settings (defaulting to `30s`) to balance visibility with the performance overhead of polling the `/v1/sys/metrics` endpoint.
- **Elastic Agent Scaling:** For high-throughput environments, it is recommended to deploy a dedicated Elastic Agent on each Vault node rather than using a centralized collector. This distributes the JSON parsing load across the cluster. For environments with extreme event volumes, ensure the Agent has sufficient CPU resources for the concurrent TCP connections if using the socket-based collection.

# Set Up Instructions

## Vendor prerequisites

- **Administrative Access:** You must have `sudo` access on the Vault server host and a Vault token with `root` or sufficient administrative policies to enable audit devices.
- **Network Connectivity:** Ensure the Vault server can communicate with the Elastic Agent. If using metrics, the Agent must reach the Vault API port (default `8200`). If using the socket audit device, Vault must reach the Agent on the configured TCP port (default `9007`).
- **Telemetry Access:** A Vault token with read permissions for the `/sys/metrics` path is required for metric collection.
- **Storage for Logs:** Sufficient disk space must be available in `/var/log/vault/` to store audit and operational logs before they are ingested and rotated.
- **Binary Requirements:** The `vault` CLI must be installed and authenticated to the cluster you wish to monitor.

## Elastic prerequisites

- **Agent Enrollment:** An Elastic Agent must be installed and enrolled in a policy via Fleet.
- **Connectivity:** The Elastic Agent requires network access to the Vault server's API for metrics collection and must be reachable by the Vault server if using the socket audit device.
- **Version Requirements:** This integration requires Elastic Stack version **8.12.0** or higher. It is recommended to use the latest version for full feature support.

## Vendor set up steps

### Configure Audit Log (File Device):
1. SSH into your Vault server and create a dedicated directory for logs:
   `sudo mkdir -p /var/log/vault`
2. Ensure the vault user has ownership of the directory:
   `sudo chown vault:vault /var/log/vault`
3. Enable the audit device via the Vault CLI, specifying the JSON file path:
   `vault audit enable file file_path=/var/log/vault/audit.json`
4. Configure `logrotate` to manage file growth. Create `/etc/logrotate.d/vault` and include a `postrotate` script to send a `SIGHUP` to the Vault process to ensure it reopens the log file after rotation.

### Configure Audit Log (Socket Device):
  **Warning: Risk of Unresponsive Vault with TCP Socket Audit Devices**

  If a TCP socket audit log destination (like the Elastic Agent) becomes unavailable, Vault may block and stop processing all requests until the connection is restored. This can lead to a service outage.

  To mitigate this risk, HashiCorp strongly recommends that a socket audit device is configured as a secondary device, alongside a primary, non-socket audit device (like the `file` audit device). For more details, see the official documentation on [Blocked Audit Devices](https://developer.hashicorp.com/vault/docs/audit/socket#configuration).

1. Ensure the Elastic Agent is already configured and listening on the target TCP port (default **9007**).
2. Enable the socket device via the Vault CLI using the Agent's IP:
   `vault audit enable socket address="${ELASTIC_AGENT_IP}:9007" socket_type=tcp`
3. Verify connectivity. If the Agent is not reachable, Vault may block API requests depending on your `backoff` settings.

### Configure Operational Logs:
1. Open your Vault configuration file (commonly `/etc/vault.d/vault.hcl`).
2. Set the `log_format` to `json` within the main configuration body:
   ```hcl
   log_format = "json"
   ```
3. Reload the daemon and restart Vault:
   `sudo systemctl daemon-reload && sudo systemctl restart vault`

### Configure Metrics:
1. Open the Vault configuration file and add or update the `telemetry` stanza:
   ```hcl
   telemetry {
     disable_hostname = true
     enable_hostname_label = true
   }
   ```
2. Restart the Vault service to enable the `/v1/sys/metrics` endpoint.
3. Generate a token with a policy that allows `read` permissions for the `sys/metrics` path.

## Kibana set up steps

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Hashicorp Vault** and select it.
3. Click **Add Hashicorp Vault**.
4. Configure the integration inputs as required by your environment:

### Collect Vault audit logs from file.
Collect Vault audit logs from file.
- **Paths** (`paths`): The file paths to the audit logs. Default is `['/var/log/vault/audit*.json*']`.
- **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default is `False`.

### Collect Vault operational logs from file.
Collect Vault operational logs from file.
- **Paths** (`paths`): The file paths to the operational logs. Default is `['/var/log/vault/log*.json*']`.
- **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default is `False`.

### Collect Vault audit logs sent via TCP.
Collect Vault audit logs sent via TCP.
- **Listen Address** (`listen_address`): The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default is `localhost`.
- **Listen Port** (`listen_port`): The TCP port number to listen on. Default is `9007`.
- **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default is `False`.

### Collect Vault metrics via prometheus.
Collect prometheus metrics from Vault.
- **Hosts** (`hosts`): Vault addresses to monitor. `/v1/sys/metrics?format=prometheus` is automatically appended. Default is `['http://localhost:8200']`.
- **Vault Token** (`vault_token`): A Vault token with read access to the /sys/metrics API.
- **Period** (`period`): _Optional_ Specify how often the Agent should poll the metrics API. Default is `30s`.

5. Save the integration and deploy it to an Elastic Agent policy.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on Hashicorp Vault:
- **Generate Audit Events:** Log into the Vault UI or CLI and perform a secret read operation: `vault kv get secret/test`.
- **Generate Configuration Events:** Enable a temporary secrets engine to trigger administrative audit logs: `vault secrets enable cubbyhole`.
- **Generate Operational Logs:** Restart the Vault service using `sudo systemctl restart vault` to generate initialization and seal status logs.
- **Generate Metrics:** Perform several rapid CLI requests to increment request counters and latency metrics.

### 2. Check Data in Kibana:
1. Navigate to **Discover**.
2. Select the `logs-*` or `metrics-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "hashicorp_vault.log"` or `data_stream.dataset : "hashicorp_vault.audit"`.
4. Verify logs appear. Expand a log entry and confirm these fields:
   - `event.dataset` (should match the integration datastream, e.g., `hashicorp_vault.audit`)
   - `source.ip` (if using socket logs)
   - `event.action` (e.g., `read` or `update`)
   - `message` (the raw JSON log payload)
5. Navigate to **Analytics > Dashboards** and search for "Hashicorp Vault" to verify visual data representation.

# Troubleshooting

## Common Configuration Issues

- **File Permission Denied**: If the Elastic Agent cannot read the logs, ensure the Agent user (usually `root` or `elastic-agent`) has read permissions for `/var/log/vault` and the JSON files within.
- **Socket Connection Refused**: Vault will fail to start the audit device if the Elastic Agent TCP listener is not already active. Ensure the Agent is successfully deployed with port `9007` open before running the `vault audit enable` command.
- **Operational Logs Not JSON**: If operational logs are not being parsed correctly, verify that `log_format = "json"` is present in the `vault.hcl` file and that the service was restarted.
- **Telemetry Prefixing**: If metrics look unusual, ensure `disable_hostname = true` is set in the telemetry configuration; otherwise, metric names will be prefixed with the host name, breaking the integration's standard mappings.

## Ingestion Errors

- **JSON Parsing Failures**: If the `error.message` field in Kibana indicates parsing issues, verify that `log_format = "json"` is correctly set in the Vault configuration for operational logs.
- **Hashed Secrets in Logs**: By default, Vault hashes secret values in audit logs using HMAC-SHA256. If you cannot see raw secrets, this is expected behavior.
- **Permissions Errors**: If the Elastic Agent logs show "Permission Denied" when trying to read `/var/log/vault/audit.json`, check the Linux file permissions and ensure the Agent user is part of the group that owns the log files.

## API Authentication Errors
- **403 Forbidden on Metrics**: Ensure the token provided in the Kibana configuration has a policy that allows `read` access to the `sys/metrics` path.
- **Expired Token**: Vault tokens used for metrics collection should be "periodic" or have a long TTL to prevent the integration from failing when the token expires.

## Vendor Resources

- [Vault Audit Devices: File](https://developer.hashicorp.com/vault/docs/audit/file)
- [Vault Audit Devices: Socket](https://developer.hashicorp.com/vault/docs/audit/socket)
- [Vault Telemetry Configuration](https://developer.hashicorp.com/vault/docs/configuration/telemetry)

# Documentation sites

- [Vault Audit-Hash API](https://developer.hashicorp.com/vault/api-docs/system/audit-hash)
- [Configure Systemd for Vault](https://developer.hashicorp.com/vault/tutorials/day-one-raft/raft-deployment-guide#step-3-configure-systemd)

# API usage
These APIs are used with this integration:
* **`/v1/sys/metrics`**: Used to collect Prometheus-formatted telemetry data. See the [HashiCorp Vault Metrics API documentation](https://developer.hashicorp.com/vault/api-docs/system/metrics) for more information.