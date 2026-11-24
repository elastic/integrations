{{- generatedHeader }}
# OPC UA Integration for Elastic

## Overview

[OPC UA](https://opcfoundation.org/about/opc-technologies/opc-ua/) (OPC Unified Architecture) is the standard protocol for reading data from industrial controllers, machines and SCADA systems. The OPC UA integration for Elastic reads the values of the nodes you configure from one or more OPC UA servers at a fixed interval and stores each value, its status and its timestamps in Elasticsearch. You can then chart machine values over time, compare them across machines, and alert on values or on nodes whose status turns bad.

### Compatibility

This integration is tested against the [Microsoft OPC PLC simulator](https://github.com/Azure-Samples/iot-edge-opc-plc) 2.15.14. It works with any server that implements the OPC UA binary protocol (`opc.tcp`) and the Read service.

The integration needs an Elastic Agent version that includes the `opcua/metrics` input.

### How it works

Elastic Agent opens one OPC UA session per configured endpoint and reads all configured nodes with one Read request per collection period. Each node becomes one document. When a read fails, Elastic Agent closes the session and opens a new one in the next period.

The integration only reads values. It does not write to nodes, browse the address space, or subscribe to changes.

## What data does this integration collect?

The OPC UA integration collects one document per node and collection period, with:

* the node id, the configured label and the display name reported by the server,
* the value, stored in a typed field (`opcua.node.value.double`, `long`, `boolean`, `keyword` or `date`) according to the OPC UA data type,
* the status code, its name and its severity (`good`, `uncertain` or `bad`),
* the source and server timestamps.

Values with a bad status are not stored, but the document with the status is. Arrays, byte strings and structures are not stored; their data type is still reported.

### Supported use cases

Watch process values such as temperatures, pressures, counters and machine states over time, alert when a value leaves its range or a node's status turns bad, and correlate machine data with logs and metrics from the rest of your infrastructure.

## What do I need to use this integration?

- An OPC UA server that Elastic Agent can reach over the network, usually on TCP port 4840.
- The node ids of the values you want to read. You can find them with an OPC UA client such as UaExpert.
- If the server doesn't allow anonymous access: a user name and password, or a client certificate that the server trusts.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/docs/reference/fleet/install-elastic-agents). You can install only one Elastic Agent per host.

Elastic Agent connects to the OPC UA servers with the `opcua/metrics` input and ships the node values to Elastic.

### Set up steps in the OPC UA server

1. Note the endpoint URL of the server, for example `opc.tcp://plc.example.com:4840`.
2. Decide on the security policy and mode. With the security policy `None`, the connection is not signed or encrypted. For any other policy, create a client certificate and key for Elastic Agent, and add the certificate to the trusted certificates of the server.
3. If the server requires user authentication, create a user with read access to the nodes.
4. Note the node ids of the values to collect, for example `ns=3;s=Temperature` or `ns=2;i=1001`.

### Set up steps in Kibana

1. In Kibana, go to **Management** → **Integrations**, search for **OPC UA** and select **Add OPC UA**.
2. Set **Endpoints** to the endpoint URL of each server.
3. Set **Security policy** and **Security mode**. For a policy other than `None`, set **Client certificate** and **Client key** to the paths of the files on the Elastic Agent host, and **Application URI** to the URI in the client certificate.
4. Set **Username** and **Password** if the server requires user authentication.
5. Set **Nodes** to the list of nodes to read, for example:

   ```yaml
   - id: "ns=3;s=Temperature"
     label: oven_temperature
   - id: "ns=3;s=Running"
   ```

6. Optionally change **Period**, which sets how often the nodes are read and defaults to `10s`.
7. Select the agent policy to add the integration to, and save.

### Validation

1. In Kibana, open **Discover** and select the `metrics-*` data view.
2. Filter on `event.dataset : "opcua.node"`. One document per node arrives every collection period.
3. Check that `opcua.node.status.severity` is `good` and that a `opcua.node.value.*` field holds the value.

## Troubleshooting

- No documents arrive and the agent logs a connection error: Check that the endpoint URL is reachable from the Elastic Agent host and that the security policy and mode match one of the endpoints the server offers.
- The server rejects the connection with a certificate error: Add the client certificate to the trusted certificates of the server, and check that **Application URI** matches the URI in the certificate.
- A node has the severity `bad` and the status `StatusBadNodeIDUnknown`: The node id doesn't exist on the server. Check the namespace index and the identifier type (`s=` for strings, `i=` for numbers).
- A node has no value field: Its data type is an array, a byte string or a structure, which the integration doesn't store. Read a scalar node instead.

## Performance and scaling

Each Elastic Agent opens one session per endpoint and reads all nodes of a policy in one request per period, so the load on the server grows with the number of nodes and shrinks with a longer period. Each node creates one document per period.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### Data streams

#### node

The `node` data stream provides one document per configured node and collection period, with the node's value, status and timestamps under `opcua.node.*`.

##### node fields

{{ fields "node" }}
