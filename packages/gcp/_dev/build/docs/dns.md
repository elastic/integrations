# Cloud DNS

Cloud DNS logging tracks queries to the authoritative name servers for the public DNS zones and for all DNS queries originating from the project's VPCs.
More information on the type of data included in the DNS logs can be found in the [documentation](https://cloud.google.com/dns/docs/monitoring)

## Logs

### DNS

This is the `DNS` dataset.

{{event "dns"}}

{{fields "dns"}}

### DNS Public Zone Query Logs

This is the `dns_public_logs` dataset. This dataset ingest logs for all queries sent to the Google Cloud DNS servers for the Public Hosted Zones within the GCP project. Depending on how many DNS queries are submitted for a domain name (example.com) or subdomain name (www.example.com), which resolvers are used, and the TTL for the record, query logs might contain information about only one query out of every several thousand queries that are submitted to DNS resolvers.

{{event "dns_public_logs"}}

{{fields "dns_public_logs"}}