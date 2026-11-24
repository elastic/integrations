{{- generatedHeader }}
# PLC4X Integration for Elastic

## Overview

[Apache PLC4X](https://plc4x.apache.org/) is a set of libraries that speak the protocols of programmable logic controllers (PLCs). The PLC4X integration for Elastic uses PLC4X to read the values of the PLC tags you configure at a fixed interval and stores each value with its data type in Elasticsearch. You can then chart process values over time, compare them across machines, and alert on them.

### Compatibility

The integration uses PLC4X 0.13.1 and supports the Modbus TCP driver. It is tested against a Modbus TCP server built with pymodbus 3.16.1.

Modbus holding registers and input registers are supported with all numeric and string data types. Modbus coils and discrete inputs are not supported yet, because PLC4X 0.13 decodes them incorrectly. A policy with such a tag fails to start.

The integration needs an Elastic Agent version that includes the `plc4x/metrics` input.

### How it works

Elastic Agent opens one PLC4X connection per configured connection string and reads each configured tag in its own request once per collection period, so a tag that can't be read doesn't hide the values of the other tags. Each tag becomes one document. When no tag can be read, Elastic Agent closes the connection and opens a new one in the next period.

The integration only reads values. It never writes to the PLC.

## What data does this integration collect?

The PLC4X integration collects one document per tag and collection period, with:

* the tag address and the configured name,
* the value, stored in a typed field (`plc4x.tag.value.double`, `long`, `boolean`, `keyword` or `date`) according to its IEC 61131-3 data type,
* the data type and the PLC4X response code of the read.

A tag that can't be read produces a document with its response code and an `error.message`, but without a value. Lists and structures are not stored; their data type is still reported.

### Supported use cases

Watch process values such as temperatures, pressures, counters and setpoints over time, alert when a value leaves its range or a tag can't be read, and correlate PLC data with logs and metrics from the rest of your infrastructure.

## What do I need to use this integration?

- A PLC or gateway that speaks Modbus TCP and that Elastic Agent can reach over the network, usually on TCP port 502.
- The register map of the PLC: which holding or input register holds which value, and in which data type.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/docs/reference/fleet/install-elastic-agents). You can install only one Elastic Agent per host.

Elastic Agent connects to the PLCs with the `plc4x/metrics` input and ships the tag values to Elastic.

### Set up steps in the PLC

1. Note the address and Modbus TCP port of the PLC, and its unit identifier if it isn't 1.
2. Look up the registers that hold the values to collect in the register map of the PLC, and their data types. A 32-bit `REAL` or `DINT` value takes two consecutive registers.

### Set up steps in Kibana

1. In Kibana, go to **Management** → **Integrations**, search for **PLC4X** and select **Add PLC4X**.
2. Set **Connection strings** to the PLC4X connection string of each PLC, for example `modbus-tcp://plc.example.com:502?unit-identifier=1`.
3. Set **PLC tags** to the list of tags to read. Each `address` uses the PLC4X Modbus syntax `<area>:<address>:<data type>`. Addresses are 1-based, so `holding-register:1` is the first holding register. For example:

   ```yaml
   - address: "holding-register:1:REAL"
     name: oven_temperature
   - address: "input-register:5:UINT"
     name: part_counter
   ```

4. Optionally change **Period**, which sets how often the tags are read and defaults to `10s`.
5. Select the agent policy to add the integration to, and save.

### Validation

1. In Kibana, open **Discover** and select the `metrics-*` data view.
2. Filter on `event.dataset : "plc4x.tag"`. One document per tag arrives every collection period.
3. Check that `plc4x.tag.response_code` is `OK` and that a `plc4x.tag.value.*` field holds the value.

## Troubleshooting

- No documents arrive and the agent logs a connection error: Check that the PLC is reachable from the Elastic Agent host on the Modbus TCP port, and that the connection string starts with `modbus-tcp://`.
- A tag has the response code `INTERNAL_ERROR` and `error.message` contains `ILLEGAL_DATA_ADDRESS` (shown hex-encoded as `494c4c4547414c5f444154415f41444452455353`): The register doesn't exist on the PLC. Check the address against the register map, and remember that addresses are 1-based.
- A tag has the response code `INVALID_ADDRESS`: The address isn't valid PLC4X syntax. Check the area, the address and the data type.
- A value looks wrong: Check the data type and the byte order. `REAL`, `DINT` and other 32-bit types are read from two registers in big-endian order.
- The policy fails to start with `coil addresses are not supported yet`: Coils and discrete inputs can't be read yet. Read a register that mirrors the value instead.

## Performance and scaling

Each tag is read in its own request, so the load on the PLC grows with the number of tags and shrinks with a longer period. Each tag creates one document per period.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### Data streams

#### tag

The `tag` data stream provides one document per configured tag and collection period, with the tag's value, data type and response code under `plc4x.tag.*`.

##### tag fields

{{ fields "tag" }}
