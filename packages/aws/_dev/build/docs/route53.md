# Route 53

This integration is used to fetch logs from [Route 53](https://aws.amazon.com/route53/).
## Logs

### Public Hosted Zone Logs

The `route53_public_logs` dataset collects information about public DNS queries that Route 53 receives.

Query logs contain only the queries that DNS resolvers forward to Route 53. If a DNS resolver has already cached the response to a query (such as the IP address for a load balancer for example.com), the resolver will continue to return the cached response without forwarding the query to Route 53 until the TTL for the corresponding record expires.

Depending on how many DNS queries are submitted for a domain name (example.com) or subdomain name (www.example.com), which resolvers your users are using, and the TTL for the record, query logs might contain information about only one query out of every several thousand queries that are submitted to DNS resolvers.

See [Route 53 Documentation](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html) for more information

{{event "route53_public_logs"}}

{{fields "route53_public_logs"}}

### Resolver Logs

The `route53_resolver_logs` dataset collects all DNS queries & responses for:
* Queries that originate in Amazon Virtual Private Cloud VPCs that you specify, as well as the responses to those DNS queries.
* Queries from on-premises resources that use an inbound Resolver endpoint.
* Queries that use an outbound Resolver endpoint for recursive DNS resolution.
* Queries that use Route 53 Resolver DNS Firewall rules to block, allow, or monitor domain lists.

As is standard for DNS resolvers, resolvers cache DNS queries for a length of time determined by the time-to-live (TTL) for the resolver. The Route 53 Resolver caches queries that originate in your VPCs, and responds from the cache whenever possible to speed up responses. Resolver query logging logs only unique queries, not queries that Resolver is able to respond to from the cache.

For example, suppose that an EC2 instance in one of the VPCs that a query logging configuration is logging queries for, submits a request for accounting.example.com. Resolver caches the response to that query, and logs the query. If the same instance’s elastic network interface makes a query for accounting.example.com within the TTL of the Resolver’s cache, Resolver responds to the query from the cache. The second query is not logged.

See [Route 53 Documentation](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html) for more information

{{event "route53_resolver_logs"}}

{{fields "route53_resolver_logs"}}
