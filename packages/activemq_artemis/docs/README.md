# ActiveMQ Artemis Integration

This Elastic integration collects metrics from Apache ActiveMQ Artemis instances using JMX. It provides comprehensive monitoring of broker, queue, address, acceptor, and cluster metrics.

## Use Cases

The ActiveMQ Artemis integration is designed for:

- **Message Broker Monitoring**: Track broker health, connections, and resource usage
- **Queue Management**: Monitor message queues, consumer activity, and processing rates  
- **Cluster Operations**: Observe cluster health, replication, and node status
- **Performance Analysis**: Analyze message throughput, latency, and system bottlenecks
- **Capacity Planning**: Track resource utilization trends for scaling decisions

## Compatibility

This integration has been tested with ActiveMQ Artemis versions 2.17+ and is compatible with:

- **Elastic Stack**: 8.13.0 or higher
- **ActiveMQ Artemis**: 2.17.0 or higher
- **Java**: 11 or higher (for Artemis broker)

## Configuration

### ActiveMQ Artemis JMX Setup

ActiveMQ Artemis requires JMX to be enabled for metrics collection. There are two approaches:

#### Option 1: Direct JMX Connection

Configure your Artemis broker to enable JMX by adding the following to your `broker.xml`:

```xml
<configuration>
  <core>
    <!-- Enable JMX management -->
    <jmx-management-enabled>true</jmx-management-enabled>
    <jmx-domain>org.apache.activemq.artemis</jmx-domain>
  </core>
</configuration>
```

Add JMX system properties when starting Artemis:

```bash
-Dcom.sun.management.jmxremote=true \
-Dcom.sun.management.jmxremote.port=3000 \
-Dcom.sun.management.jmxremote.ssl=false \
-Dcom.sun.management.jmxremote.authenticate=false
```

#### Option 2: Jolokia HTTP Proxy (Recommended)

For easier configuration and HTTP-based access, use Jolokia:

1. Download the Jolokia JVM agent JAR
2. Add Jolokia agent to Artemis startup:

```bash
-javaagent:jolokia-jvm-agent.jar=port=8778,host=0.0.0.0
```

3. Configure the integration to use HTTP endpoint:

```yaml
hosts: ["http://localhost:8778/jolokia"]
```

### Security Configuration

#### JMX Authentication

To enable JMX authentication:

```bash
-Dcom.sun.management.jmxremote.authenticate=true \
-Dcom.sun.management.jmxremote.password.file=/path/to/jmxremote.password \
-Dcom.sun.management.jmxremote.access.file=/path/to/jmxremote.access
```

#### SSL/TLS Configuration

For secure JMX connections:

```yaml
ssl:
  verification_mode: "certificate"
  certificate_authorities: |
    -----BEGIN CERTIFICATE-----
    [Your CA certificate]
    -----END CERTIFICATE-----
  certificate: |
    -----BEGIN CERTIFICATE-----
    [Your client certificate]
    -----END CERTIFICATE-----
  key: |
    -----BEGIN PRIVATE KEY-----
    [Your private key]
    -----END PRIVATE KEY-----
```

## Data Streams

This integration collects the following data streams:

### Broker Metrics (`activemq_artemis.broker`)

High-level broker statistics including:

- **Connection metrics**: Active and total connections
- **Message statistics**: Total messages, added, acknowledged
- **Memory usage**: Address memory usage and percentages
- **Disk usage**: Store usage and limits
- **Broker info**: Address count, queue count, HA policy, version

### Queue Metrics (`activemq_artemis.queue`)

Detailed queue performance metrics:

- **Message statistics**: Count, added, acknowledged, expired, killed
- **Consumer information**: Active consumers, delivery counts
- **Processing rates**: Messages per second for adds and acknowledgments
- **Queue properties**: Paused, temporary, auto-created, durable

### Address Metrics (`activemq_artemis.address`)

Address-level management information:

- **Routing configuration**: Supported routing types (ANYCAST/MULTICAST)
- **Queue management**: Associated queues and counts
- **Message statistics**: Total messages and unroutable count
- **Memory usage**: Address size and limit percentages
- **Paging info**: Page usage and configuration

### Acceptor Metrics (`activemq_artemis.acceptor`)

Network acceptor statistics:

- **Connection lifecycle**: Connections created and destroyed
- **Acceptor status**: Started state and configuration
- **Protocol information**: Factory class and parameters

### Cluster Metrics (`activemq_artemis.cluster`)

Cluster connectivity and replication metrics:

- **Node information**: Node ID and topology
- **Message replication**: Pending acknowledgments and received messages
- **Configuration**: Connectors, discovery groups, retry settings
- **Status**: Connection state and bridge configuration

## Example Events

### Broker Event
```json
{
  "@timestamp": "2023-09-20T14:30:45.123Z",
  "activemq_artemis": {
    "broker": {
      "connections": {
        "active": 5,
        "total": 127
      },
      "messages": {
        "count": 1256,
        "added": 45678,
        "acknowledged": 44422
      },
      "memory": {
        "address": {
          "used": 52428800,
          "used_pct": 25.3
        }
      },
      "version": "2.28.0"
    }
  }
}
```

### Queue Event
```json
{
  "@timestamp": "2023-09-20T14:30:45.123Z",
  "activemq_artemis": {
    "queue": {
      "name": "orders.processing",
      "address": "orders",
      "routing_type": "ANYCAST",
      "messages": {
        "count": 543,
        "added_rate": 12.5,
        "acknowledged_rate": 11.8
      },
      "consumers": {
        "count": 3
      }
    }
  }
}
```

## Field Reference

### `activemq_artemis.broker`

| Field | Type | Description |
|-------|------|-------------|
| `connections.active` | long | Number of active connections |
| `connections.total` | long | Total connections since start |
| `messages.count` | long | Total messages in all queues |
| `messages.added` | long | Total messages added |
| `messages.acknowledged` | long | Total messages acknowledged |
| `memory.address.used` | long | Memory used by addresses (bytes) |
| `memory.address.used_pct` | float | Address memory usage percentage |
| `disk.store.used` | long | Disk space used by store (bytes) |
| `addresses.count` | long | Number of addresses |
| `queues.count` | long | Number of queues |
| `ha.policy` | keyword | High availability policy |
| `version` | keyword | Artemis version |

### `activemq_artemis.queue`

| Field | Type | Description |
|-------|------|-------------|
| `name` | keyword | Queue name |
| `address` | keyword | Parent address |
| `routing_type` | keyword | ANYCAST or MULTICAST |
| `messages.count` | long | Current message count |
| `messages.added` | long | Total messages added |
| `messages.acknowledged` | long | Total messages acknowledged |
| `messages.added_rate` | float | Message add rate per second |
| `consumers.count` | long | Active consumer count |
| `delivering.count` | long | Messages being delivered |
| `durable` | boolean | Whether queue is durable |

### `activemq_artemis.address`

| Field | Type | Description |
|-------|------|-------------|
| `name` | keyword | Address name |
| `routing_types` | keyword | Supported routing types |
| `queues.count` | long | Number of associated queues |
| `messages.count` | long | Total messages for address |
| `size` | long | Total message size (bytes) |
| `limit.used_pct` | float | Address limit usage percentage |

### `activemq_artemis.acceptor`

| Field | Type | Description |
|-------|------|-------------|
| `name` | keyword | Acceptor name |
| `connections.created` | long | Total connections created |
| `connections.destroyed` | long | Total connections destroyed |
| `started` | boolean | Whether acceptor is started |
| `factory.class_name` | keyword | Factory class name |

### `activemq_artemis.cluster`

| Field | Type | Description |
|-------|------|-------------|
| `name` | keyword | Cluster connection name |
| `node.id` | keyword | Node identifier |
| `topology` | keyword | Cluster topology |
| `started` | boolean | Connection started state |
| `messages.pending_acknowledgment` | long | Pending replication messages |
| `messages.received` | long | Messages received from cluster |

## Troubleshooting

### JMX Connection Issues

**Problem**: Cannot connect to JMX endpoint
```
error connecting to JMX: connection refused
```

**Solutions**:
1. Verify JMX is enabled in Artemis configuration
2. Check firewall rules for JMX port (default 3000)
3. Ensure JMX authentication settings match integration config
4. Test JMX connectivity using `jconsole` or similar tools

### Jolokia HTTP Issues

**Problem**: HTTP 404 errors when using Jolokia
```
HTTP 404: Not Found
```

**Solutions**:
1. Verify Jolokia agent is loaded with Artemis
2. Check Jolokia port configuration (default 8778)
3. Ensure Jolokia endpoint path is correct: `/jolokia`

### Missing Metrics

**Problem**: Some metrics are not being collected

**Solutions**:
1. Verify Artemis version compatibility (2.17+)
2. Check that specific MBeans exist using JMX browser
3. Ensure Artemis broker has started completely
4. Review integration logs for parsing errors

### Performance Impact

**Problem**: High CPU usage from metrics collection

**Solutions**:
1. Increase collection period (default 30s)
2. Reduce number of monitored queues/addresses
3. Use Jolokia HTTP proxy instead of direct JMX
4. Monitor collection duration and adjust accordingly

## Integration Development

For developers extending this integration:

### Testing

Run integration tests:
```bash
elastic-package test system --data-streams=broker,queue,address
```

### Custom Fields

To add custom metrics, modify the JMX mappings in:
```
data_stream/<stream>/agent/stream/stream.yml.hbs
```

### Dashboard Customization

Dashboards are located in:
```
kibana/dashboard/
```

Use Kibana's dashboard editor to customize visualizations and add new panels.

## References

- [ActiveMQ Artemis Documentation](https://activemq.apache.org/components/artemis/documentation/)
- [Artemis JMX Management](https://activemq.apache.org/components/artemis/documentation/latest/management.html)
- [Jolokia JMX-HTTP Bridge](https://jolokia.org/)
- [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)