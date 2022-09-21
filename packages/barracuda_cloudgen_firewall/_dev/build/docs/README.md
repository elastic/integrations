# Barracuda CloudGen Firewall integration

This integration ingests and parses logs from
[Barracuda CloudGen Firewalls][cloudgen-product-link].

Barracuda CloudGen Firewall allows you to stream event logs from Firewall
Insights to Elastic Agent. This provides information on firewall activity,
threat logs, and information related to network, version, and location of
managed firewall units. Data is sent to Elastic Agent over a TCP connection
using CloudGen Firewall's built-in generic Logstash output.

### Setup

For a detailed walk-through of the setup steps the see [How to Enable Filebeat
Stream to a Logstash Pipeline][cloudgen-logstash-docs]. These steps were written
with a Logstash server as the intended destination, and where it references the
"Hostname" use the address and port of the Elastic Agent that is running this
integration. Logstash is not used as part of this integration.

[cloudgen-product-link]: https://www.barracuda.com/products/cloudgenfirewall
[cloudgen-logstash-docs]: https://campus.barracuda.com/product/cloudgenfirewall/doc/96025953/how-to-enable-filebeat-stream-to-a-logstash-pipeline/

## Logs

This is the Barracuda CloudGen Firewall `log` dataset.

{{fields "log"}}