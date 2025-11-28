# Service Info

## Common use cases

- **Network Security Monitoring**: Zeek provides detailed network traffic analysis for comprehensive security monitoring and threat detection within networks.
- **Threat Hunting**: Search and analyze detailed connection logs, file hashes, and protocol-specific data to proactively hunt for threats.
- **Incident Response**: Accelerate incident investigation with rich, contextual network data to understand the scope and impact of security events.
- **Network Visibility**: Gain deep insights into all network activity, including encrypted traffic metadata (via SSL/TLS metadata), DNS requests, and file transfers across the network.

## Data types collected

The Zeek integration collects logs from Zeek in JSON format, providing granular visibility into different network protocols and activities:

- **Connection data**: TCP, UDP, and ICMP connection details
- **Protocol-specific logs**: HTTP, DNS, SSL/TLS, SMTP, FTP, SSH, SMB, Kerberos, NTLM, and many more application-layer protocols
- **File analysis**: Metadata and analysis results for files transferred over the network
- **Certificate data**: SSL/TLS certificates and X.509 certificate information
- **Intelligence data**: Intelligence data matches from Zeek's intel framework
- **Security events**: Zeek notices, signature matches, and anomalous activity detection
- **Network discovery**: Information about hosts, services, and software observed on the network
- **Industrial protocols**: DNP3, Modbus for industrial control systems monitoring
- **Operational data**: Zeek statistics including packet capture loss rates, memory usage, and performance metrics

## Compatibility

- **Zeek versions**: Developed against Zeek 2.6.1 but expected to work with other versions including 4.0.9 and above
- **Platform support**: Zeek requires a Unix-like platform and currently supports Linux, FreeBSD, and macOS
- **Log format**: Requires Zeek logs to be configured in JSON format
- **Elastic Stack**: Requires Kibana version ^8.12.0 or ^9.0.0

## Scaling and Performance

For high-volume environments, Zeek deployments may need to be scaled into a cluster configuration. In this scenario:

- Logs can be aggregated on a dedicated log collector host where the Elastic Agent is installed
- This centralizes log collection and reduces the load on individual Zeek workers
- Distributed deployment allows handling of large volumes of network traffic

For more information on architectures that can be used for scaling this integration, refer to the Elastic Ingest Architectures documentation.

# Set Up Instructions

## Vendor prerequisites

- A working Zeek installation that is actively monitoring network traffic
- Zeek must be configured to output logs in JSON format (see Vendor set up steps below)
- Network access via a network tap or SPAN port for Zeek to monitor and analyze traffic

## Elastic prerequisites

- Elastic Agent must be installed on the host where Zeek logs are generated
- Only one Elastic Agent can be installed per host

## Vendor set up steps

### Configure Zeek for JSON Output

For the integration to correctly parse the logs, Zeek must be configured to output logs in JSON format. This can be done by enabling the `json-logs` policy.

Add the following line to your `local.zeek` configuration file (typically located at `/opt/zeek/share/zeek/site/local.zeek` or a similar path):

```
@load policy/tuning/json-logs.zeek
```

After adding this line, restart Zeek for the changes to take effect:

```bash
sudo zeekctl deploy
```

## Kibana set up steps

1. In Kibana, navigate to **Management > Integrations**.
2. In the search bar, type **Zeek** and select the integration.
3. Click **Add Zeek**.
4. Configure the integration name and optionally add a description.
5. Under **Settings**, specify the **Base Path** to your Zeek log files. The default paths are:
   - `/var/log/bro/current`
   - `/opt/zeek/logs/current`
   - `/usr/local/var/spool/zeek`
   
   Add the correct path for your environment if it differs.
6. Click **Save and continue**.

This will enroll the Elastic Agent in a policy to collect Zeek logs from the specified paths.

# Validation Steps

To validate that the integration is working after adding it in Kibana:

1. **Check Zeek is running**: Verify that Zeek is actively monitoring network traffic and generating logs in JSON format.

2. **Generate test traffic**: Initiate some network activities (e.g., web browsing, DNS queries) to ensure Zeek captures traffic.

3. **Verify in Kibana Discover**:
   - In Kibana, navigate to the **Discover** tab.
   - Filter the data by `data_stream.dataset : "zeek.*"`.
   - You should see incoming log data from your Zeek instance.

4. **Check dashboards**:
   - Navigate to **Analytics > Dashboard**.
   - In the search bar, type **Zeek** and select a dashboard.
   - Verify the dashboard is populated with data.

# Troubleshooting

## Common Configuration Issues

**Issue**: No data collected or appearing in Kibana

**Solutions**:
- Verify that Zeek is configured to output logs in JSON format by checking that `@load policy/tuning/json-logs.zeek` is present in your `local.zeek` configuration file
- Ensure Zeek has been restarted after configuration changes using `sudo zeekctl deploy`
- Check that the Base Path configured in the integration matches the actual location of your Zeek logs
- Verify that Zeek is actively monitoring network traffic and generating logs
- Confirm that Elastic Agent is running on the host where Zeek logs are located

**Issue**: Service failed to start

**Solutions**:
- Check for configuration errors in Zeek scripts
- Ensure the network interface is correctly specified in Zeek configuration
- Verify that Zeek has the necessary permissions to access the network interface

## Ingestion Errors

**Issue**: Parsing errors in ingested data

**Solutions**:
- Ensure Zeek logs are in JSON format (not tab-separated values)
- Verify that the `json-logs` policy is properly loaded in Zeek configuration
- Check that log files are not corrupted or have incomplete JSON objects

## API Authentication Errors

This integration does not use external APIs for data collection. It reads logs directly from files.

## Vendor Resources

- **Zeek Official Website**: https://zeek.org/
- **Zeek Documentation**: https://docs.zeek.org/en/stable/
- **Zeek Installation Guide**: https://docs.zeek.org/en/stable/install.html
- **Zeek Community Forum**: https://community.zeek.org/
- **Elastic Common Fleet Problems**: https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems

# Documentation sites

- https://zeek.org/ - Official Zeek website
- https://docs.zeek.org/en/stable/ - Zeek official documentation
- https://docs.zeek.org/en/stable/install.html - Zeek installation guide
- https://community.zeek.org/ - Zeek community forum
- https://www.elastic.co/guide/en/integrations/current/zeek.html - Elastic Zeek Integration guide
- https://www.elastic.co/blog/collecting-and-analyzing-zeek-data-with-elastic-security - Elastic blog post on Zeek integration
- https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems - Elastic Fleet troubleshooting

