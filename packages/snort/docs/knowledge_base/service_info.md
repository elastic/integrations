# Service Info

## Common use cases

- **Intrusion Detection System (IDS):** Monitor network traffic in real-time to detect unauthorized access attempts, policy violations, and other security threats.
- **Intrusion Prevention System (IPS):** Actively block detected threats to prevent potential damage to the network.
- **Packet Sniffing and Logging:** Capture and analyze network packets for troubleshooting, performance monitoring, and forensic analysis.
- **Network Traffic Analysis:** Analyze network traffic to identify malicious patterns and anomalies.
- **Compliance Monitoring:** Ensure adherence to security policies and regulatory requirements by detecting unauthorized access attempts and other security violations.

## Data types collected

This integration collects logs from Snort. The following log formats are supported:
- PFsense CSV output
- Alert Fast output (from logfile or syslog)
- Snort 3 JSON log file

The logs contain information about network traffic, including:
- Network packets
- Alerts on suspicious activity
- Network session information
- Protocol analysis data

## Compatibility

This integration has been developed against Snort v2.9 and v3, but is expected to work with other versions of Snort.

Snort is cross-platform and supports various operating systems, including multiple Linux distributions (e.g., Red Hat, Debian, Slackware, Mandrake), OpenBSD, FreeBSD, NetBSD, Solaris, SunOS, HP-UX, AIX, IRIX, Tru64, and MacOS X. It is compatible with both RISC and CISC architectures.

## Scaling and Performance

Snort's performance can be optimized by fine-tuning rules, configuring preprocessors appropriately, and ensuring hardware resources meet the demands of network traffic.

For high-traffic environments, deploying Snort in a distributed architecture with multiple sensors can help balance the load and improve detection capabilities.

# Set Up Instructions

## Vendor prerequisites

- **Dependencies**: Ensure that required libraries and dependencies, such as `libpcap`, are installed on the system.
- **User Privileges**: Administrative or root privileges are necessary for installation and configuration of Snort.

## Elastic prerequisites

/* If there are any Elastic specific prerequisites, add them here

    The stack version and agentless support is not needed, as this can be taken from the manifest */

## Vendor set up steps

1.  **Install Snort**: Download the latest version of Snort from the official website and follow the installation instructions for your operating system.
2.  **Configure Snort**: Edit the `snort.conf` file to set network variables, define rule paths, and configure output plugins. To send logs to the Elastic Stack, you can configure Snort to write to a log file or send logs via syslog.
3.  **Test Configuration**: Run Snort in test mode to validate the configuration:
    ```
    snort -T -c /path/to/snort.conf
    ```
4.  **Start Snort**: Start Snort in the desired mode (e.g., IDS or IPS) to begin monitoring network traffic.

## Kibana set up steps

1. In Kibana, go to **Management > Integrations**.
2. Search for "Snort" and click on it.
3. Click **Add Snort**.
4. Configure the integration with the appropriate settings, such as the path to the Snort log file or the UDP port for syslog.
5. Click **Save and continue**. This will install the necessary assets, such as dashboards and ingest pipelines, and deploy the configuration to the Elastic Agent.

# Validation Steps

1. **Generate Test Traffic**: Use a tool like `nmap` to simulate network scans or other activities that should trigger Snort alerts.
2. **Check Snort Logs**: Review Snort's alert logs to confirm that the test activities were detected and logged.
3. **Verify in Kibana**: In Kibana, navigate to the **Discover** tab and search for `data_stream.dataset: "snort.log"`. The alerts should appear in Kibana, confirming end-to-end data flow. You can also check the Snort dashboards for visualizations of the data.

# Troubleshooting

/* Add lists of "*Issue* / *Solutions*" for troubleshooting knowledge base into the most appropriate section below */

## Common Configuration Issues

- **Issue**: Snort fails to start due to configuration errors.
  - **Solution**: Run Snort in test mode (`snort -T -c /path/to/snort.conf`) to identify and resolve configuration issues.

- **Issue**: No alerts are being generated.
  - **Solution**: Ensure that Snort is monitoring the correct network interface and that relevant rules are enabled.

## Ingestion Errors

/* For problems that involve "error.message" being set on ingested data */

## API Authentication Errors

/* For API authentication failures, credential errors, and similar */

## Vendor Resources

/* If the vendor has a troubleshooting specific help page, add it here */

# Documentation sites

- **Official Snort Website**: https://www.snort.org/
- **Snort Documentation**: https://www.snort.org/documents
- **Snort Rule Documentation**: https://www.snort.org/rule-docs
- **Snort Blog**: https://blog.snort.org/
