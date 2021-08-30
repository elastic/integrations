# VMware Carbon Black EDR Integration

The VMware Carbon Black EDR integration collects EDR Server and raw Endpoint events exported by [Carbon Black EDR Event Forwarder.](https://github.com/carbonblack/cb-event-forwarder) The following output methods are supported: `http`, `tcp`, `udp` and `file`.

## Compatibility

This integration has been tested with the 3.7.4 version of EDR Event Forwarder.

## Configuration

The following configuration is necessary in `cb-event-forwarder.conf`:

- `output_format=json` (default)

For `http` output:
  - `output_type=http`
  - `http_post_template=[{{"{{"}}range .Events}}{{"{{"}}.EventText}}{{"{{"}}end}}]`
  - `content_type=application/json` (default)

For `tcp` output:
  - `output_type=tcp`
  - `tcpout=<Address of Elastic Agent>:<port>`

For `udp` output:
- `output_type=tcp`
- `tcpout=<Address of Elastic Agent>:<port>`

For `file` output:
- `output_type=file`
- `outfile=<path to a file readable by Elastic Agent>`

{{event "log"}}

{{fields "log"}}

