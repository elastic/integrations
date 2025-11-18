# Service Info

## Common use cases

Apache ZooKeeper is a distributed coordination service commonly used for:

- **Distributed coordination**: Managing configuration information, naming, and providing distributed synchronization across distributed systems
- **Leader election**: Facilitating leader election among distributed processes to ensure only one process acts as the leader at any given time
- **Configuration management**: Providing a centralized repository for configuration data, allowing dynamic configuration changes without restarting applications
- **Service discovery**: Enabling services to discover and communicate with each other in distributed environments
- **Distributed locking**: Coordinating access to shared resources across distributed systems
- **Message queue coordination**: Often used as a coordination service for distributed messaging systems like Apache Kafka

## Data types collected

This integration collects the following types of metrics data:

- **Connection metrics** (via `cons` command): Client connection information including IP addresses, ports, packets received/sent, queued requests, and connection state
- **Monitor metrics** (via `mntr` command): Server health and performance metrics including latency statistics, znode counts, watch counts, ephemeral node counts, file descriptor usage, packet statistics, follower counts, and server state
- **Server metrics** (via `srvr` command): Server status information including mode (standalone/leader/follower), connection counts, node counts, outstanding requests, transaction IDs (zxid), epoch values, and latency statistics

## Compatibility

The ZooKeeper integration is tested with ZooKeeper 3.4.8 and is expected to work with all versions >= 3.4.0.

**Important**: Versions prior to 3.4 do not support the `mntr` command.

## Scaling and Performance

- **Read-dominant workloads**: ZooKeeper is designed for high-performance coordination, especially in read-dominant workloads where reads significantly outnumber writes
- **Quorum-based consensus**: A majority of nodes (quorum) must be available to process write requests, which impacts availability and performance
- **Horizontal scaling**: Performance can be improved by adding nodes to the ensemble, particularly for read capacity
- **Resource monitoring**: Monitor key performance metrics such as memory usage, file descriptor usage, thread count, and JVM usage to assess operational efficiency
- **Network considerations**: Low-latency and reliable network connections between ZooKeeper nodes are essential for optimal performance

# Set Up Instructions

## Vendor prerequisites

- **Java Runtime Environment**: ZooKeeper requires a compatible Java runtime environment (JRE) installed on all nodes
- **Four-Letter Words commands enabled**: From ZooKeeper 3.6.0 onwards, the four-letter word commands (`mntr`, `cons`, `srvr`) must be explicitly enabled using the `4lw.commands.whitelist` configuration parameter in the `zoo.cfg` file
- **Network access**: The ZooKeeper client port (default: 2181) must be accessible from the host running the Elastic Agent
- **Configuration file**: A properly configured `zoo.cfg` file with settings such as `tickTime`, `dataDir`, and `clientPort`

## Elastic prerequisites

The stack version and agentless support is determined by the manifest.

## Vendor set up steps

For ZooKeeper versions 3.6.0 and above, you must enable the four-letter word commands required by this integration:

1. **Enable four-letter word commands**:
   - Open your ZooKeeper configuration file (`zoo.cfg`)
   - Add or modify the following line to whitelist the required commands:
     ```
     4lw.commands.whitelist=mntr,cons,srvr
     ```
   - Note: You can also use `4lw.commands.whitelist=*` to enable all four-letter word commands, but this is less secure

2. **Restart ZooKeeper service**:
   - After modifying the configuration, restart the ZooKeeper service to apply the changes
   - Use the appropriate command for your environment (e.g., `bin/zkServer.sh restart`)

3. **Verify commands are enabled**:
   - Test that the commands are accessible by running:
     ```
     echo mntr | nc localhost 2181
     ```
   - You should receive ZooKeeper metrics in response

## Kibana set up steps

1. **Navigate to Integrations**:
   - In Kibana, go to Management > Integrations

2. **Add ZooKeeper integration**:
   - Search for "ZooKeeper" in the integrations catalog
   - Click on the ZooKeeper integration

3. **Configure the integration**:
   - Click "Add ZooKeeper Metrics"
   - Provide the ZooKeeper server address (default: `localhost:2181`)
   - Configure the collection period (default: `10s`)
   - Select which data streams to enable (connection, mntr, and/or server)

4. **Assign to an agent policy**:
   - Select an existing agent policy or create a new one
   - Save and deploy the configuration

5. **Confirm agent enrollment**:
   - Ensure the Elastic Agent is enrolled and assigned to the policy containing the ZooKeeper integration

# Validation Steps

1. **Verify ZooKeeper is accessible**:
   - From the host running the Elastic Agent, test connectivity to ZooKeeper:
     ```
     echo mntr | nc <zookeeper-host> 2181
     ```
   - You should receive metrics output

2. **Check data ingestion in Kibana**:
   - Navigate to Discover in Kibana
   - Select the ZooKeeper data streams (e.g., `metrics-zookeeper.mntr-*`)
   - Verify that documents are being ingested with recent timestamps
   - Confirm that expected fields are populated (e.g., `zookeeper.mntr.znode_count`, `zookeeper.server.mode`)

3. **View dashboards**:
   - Go to Dashboards in Kibana
   - Open the "Metricbeat ZooKeeper" dashboard
   - Verify that visualizations display data correctly
   - Check that metrics reflect the current state of your ZooKeeper service

4. **Monitor integration health**:
   - In Fleet, navigate to the agent running the ZooKeeper integration
   - Check that the integration status shows as healthy with no errors

# Troubleshooting

## Common Configuration Issues

**Service failed to start**
- Solution: Check the `zoo.cfg` file for correct configurations and ensure that the specified `dataDir` exists with appropriate permissions

**No data collected**
- Solution: Verify that the ZooKeeper service is running and accessible from the Elastic Agent host
- Solution: Check that the ZooKeeper address and port in the integration configuration are correct
- Solution: Ensure network connectivity between the Elastic Agent and ZooKeeper (test with `telnet` or `nc`)

**Four-letter word commands not working**
- Solution: For ZooKeeper 3.6.0+, verify that `4lw.commands.whitelist` is configured in `zoo.cfg`
- Solution: Restart the ZooKeeper service after modifying the configuration
- Solution: Check ZooKeeper logs for any errors related to command whitelisting

## Ingestion Errors

**Error message: "connection refused"**
- Solution: Verify that ZooKeeper is listening on the configured address and port
- Solution: Check firewall rules to ensure the port is accessible
- Solution: Confirm that the Elastic Agent has network access to the ZooKeeper host

**Error message: "mntr is not executed because it is not in the whitelist"**
- Solution: Add `4lw.commands.whitelist=mntr,cons,srvr` to your `zoo.cfg` file and restart ZooKeeper

**Missing or incomplete metrics**
- Solution: Ensure the ZooKeeper version is 3.4.0 or higher (the `mntr` command is not available in earlier versions)
- Solution: Verify that all required four-letter word commands are whitelisted

## API Authentication Errors

ZooKeeper's four-letter word commands do not typically require authentication. If you encounter authentication-related issues:

- Solution: Verify that no network proxy or security layer is blocking the connection
- Solution: Check if SASL authentication is configured on ZooKeeper and ensure the integration supports this configuration

## Vendor Resources

- **Apache ZooKeeper Administrator's Guide**: https://zookeeper.apache.org/doc/current/zookeeperAdmin.html
- **ZooKeeper Troubleshooting**: https://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_troubleshooting

# Documentation sites

- **Apache ZooKeeper Official Documentation**: https://zookeeper.apache.org/doc/current/
- **Apache ZooKeeper Administrator's Guide**: https://zookeeper.apache.org/doc/current/zookeeperAdmin.html
- **Apache ZooKeeper Releases**: https://zookeeper.apache.org/releases.html
- **Elastic ZooKeeper Integration Documentation**: https://www.elastic.co/guide/en/integrations/current/zookeeper.html
- **ZooKeeper Four Letter Words**: https://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_4lw

