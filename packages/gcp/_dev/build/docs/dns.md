# DNS

## Logs

The `dns` dataset collects queries that name servers resolve for your Virtual Private Cloud (VPC) networks, as well as queries from an external entity directly to a public zone.

{{fields "dns"}}

{{event "dns"}}


This is the `dns_public_logs` dataset. This dataset ingest logs for all queries sent to the Google Cloud DNS servers for the Public Hosted Zones within the GCP project. Depending on how many DNS queries are submitted for a domain name (example.com) or subdomain name (www.example.com), which resolvers are used, and the TTL for the record, query logs might contain information about only one query out of every several thousand queries that are submitted to DNS resolvers.

{{event "dns_public_logs"}}

{{fields "dns_public_logs"}}