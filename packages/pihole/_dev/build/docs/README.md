{{- generatedHeader }}

# Pi-hole Integration

The Pi-hole Integration allows you to monitor DNS query activity from your Pi-hole instances. Pi-hole is a network-level DNS filtering application that blocks ads and trackers.

Use the Pi-hole Integration to collect DNS query logs from your Pi-hole instances. Then visualize that data in Kibana, create alerts to notify you of DNS issues or suspicious activity, and analyze network traffic patterns.

## Data streams

The Pi-hole Integration collects both logs and metrics that provide insights into DNS activity on your network:

### Logs
- **DNS Queries**: Individual DNS query records with query type, resolution status, client information, upstream server details, and DNSSEC status

### Metrics
- **Query History**: Time-series metrics showing DNS query volume over time, broken down by total queries, cached responses, blocked queries, and forwarded queries
- **Pi-hole Summary**: Comprehensive statistics including total queries, blocking effectiveness, query type breakdowns (A, AAAA, PTR, etc.), query status breakdowns (cache hits, forwarded, blocked, etc.), and query reply types
- **Top Clients**: Metrics identifying the most active DNS clients on your network, with separate tracking for allowed and blocked queries
- **Top Domains**: Metrics showing the most frequently queried domains, with separate tracking for allowed and blocked domains

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

### Pi-hole Requirements

- Pi-hole instance (v6.0 or later recommended) with API access enabled
- Admin panel password for authentication
- Network connectivity from the Elastic Agent to the Pi-hole instance
- Pi-hole API endpoint accessible at `http(s)://<pihole-url>/api/`

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

### Pi-hole API Authentication

This integration uses Pi-hole's session-based authentication mechanism:

1. The integration POSTs the admin password to `/api/auth` to obtain a session ID (SID)
2. The SID is included in the `X-FTL-SID` header for all subsequent API requests
3. After data collection completes, the session is terminated with a DELETE request to `/api/auth`

Each collection cycle obtains a fresh session ID and terminates it after use, preventing authentication errors from session expiration.

### Configuration

**Required Fields:**
- **Pi-hole URL**: The URL of your Pi-hole instance (e.g., `http://192.168.1.1` or `https://pihole.example.com`)
- **API Password**: Your Pi-hole admin panel password

**Optional Fields:**
- **Collection Interval**: How often to collect DNS queries (default: 60s). For high-volume networks (>400 queries/minute), consider reducing to 10-15 seconds to avoid missing queries.
- **Proxy URL**: Optional HTTP proxy for connecting to Pi-hole
- **SSL Configuration**: Custom SSL/TLS settings for HTTPS connections
- **HTTP Client Timeout**: Request timeout duration (default: 30s)

### Data Collection Strategy

**DNS Queries (Logs):**
The integration uses timestamp-based pagination to avoid duplicate records:
- On the first run, it collects up to 1000 most recent queries
- On subsequent runs, it fetches only queries newer than the last collection using the `from` parameter
- The timestamp cursor persists across agent restarts and integration upgrades
- Maximum of 1000 queries per collection interval (adjust interval if you exceed this limit)

**Metrics Data Streams:**
Query History, Pi-hole Summary, Top Clients, and Top Domains collect point-in-time snapshots at each collection interval:
- Default collection interval: 5 minutes (configurable per data stream)
- No pagination required - each collection captures the current state
- Query History provides 10-minute interval buckets for time-series analysis
- Top Clients and Top Domains each collect top 10 allowed and top 10 blocked items per collection

## Logs reference

### DNS Queries

The `dns_queries` data stream collects individual DNS query records from Pi-hole with detailed information about each query.

**Collected Information:**
- DNS query details (domain, query type, response code)
- Client information (IP address, hostname)
- Upstream DNS server
- Query status (cached, forwarded, blocked, etc.)
- DNSSEC validation status
- Reply time in seconds
- Extended DNS Error (EDE) codes and text
- CNAME records (if applicable)
- Gravity list ID (for blocked queries)

#### Example Event

{{ event "dns_queries" }}

#### ECS Field Mappings

The integration maps Pi-hole data to the Elastic Common Schema (ECS):

| Pi-hole Field | ECS Field | Description |
|--------------|-----------|-------------|
| `domain` | `dns.question.name` | The queried domain name |
| `type` | `dns.question.type` | DNS record type (A, AAAA, CNAME, etc.) |
| `reply_type` | `dns.response_code` | DNS response code |
| `client_ip` | `source.ip` | Client IP address |
| `client_name` | `source.domain` | Client hostname |
| `upstream_name` | `destination.ip` | Upstream DNS server |
| `time` | `@timestamp` | Query timestamp |

#### Exported fields

{{ fields "dns_queries" }}

## Metrics reference

### Query History

The `query_history` data stream collects time-series metrics showing DNS query patterns over time with 10-minute intervals.

**Collected Information:**
- Total DNS queries in the interval
- Queries answered from cache
- Blocked queries
- Queries forwarded to upstream DNS servers

This data stream is ideal for tracking DNS traffic patterns, identifying peak usage times, and monitoring the effectiveness of Pi-hole's caching and blocking mechanisms.

#### Example Event

{{ event "query_history" }}

#### Exported fields

{{ fields "query_history" }}

### Pi-hole Summary

The `pihole_summary` data stream collects comprehensive statistics about Pi-hole's overall performance and activity.

**Collected Information:**
- Total queries and blocking statistics
- Query frequency (queries per minute)
- Unique domains and clients
- Gravity list information and last update timestamp
- Query type breakdown (A, AAAA, PTR, TXT, MX, HTTPS, SVCB, and 10+ other record types)
- Query status breakdown (cache hits, forwarded, blocked by gravity/regex, special domains, stale cache, and 10+ other statuses)
- Query reply type breakdown (NODATA, NXDOMAIN, CNAME, IP, SERVFAIL, and 10+ other reply types)

This data stream provides a complete picture of Pi-hole's DNS filtering and caching behavior, making it invaluable for capacity planning, troubleshooting, and security monitoring.

#### Example Event

{{ event "pihole_summary" }}

#### Exported fields

{{ fields "pihole_summary" }}

### Top Clients

The `top_clients` data stream identifies the most active DNS clients on your network.

**Collected Information:**
- Client IP address and hostname
- Number of queries from each client
- Query action (allowed or blocked)
- Total queries and blocked queries across all clients

Each collection gathers the top 10 clients for allowed queries and top 10 clients for blocked queries, providing visibility into both normal DNS usage patterns and potential security issues or misconfigured devices.

#### Example Event

{{ event "top_clients" }}

#### Exported fields

{{ fields "top_clients" }}

### Top Domains

The `top_domains` data stream shows the most frequently queried domains.

**Collected Information:**
- Domain name
- Number of queries for the domain
- Query action (allowed or blocked)
- Total queries and blocked queries across all domains

Each collection gathers the top 10 allowed domains and top 10 blocked domains, helping identify popular services, potential data exfiltration attempts, and the effectiveness of blocklists.

#### Example Event

{{ event "top_domains" }}

#### Exported fields

{{ fields "top_domains" }}

## Troubleshooting

### Common Issues

**No data appearing in Elasticsearch:**
- Verify Pi-hole URL is correct and accessible from the Elastic Agent
- Check that the API password is correct
- Enable request tracing (`enable_request_tracer: true`) and check logs at `logs/cel/http-request-trace-*.ndjson`

**Missing queries (less than expected):**
- If you have high query volume (>400 queries/minute), reduce the collection interval to 10-15 seconds
- Check Elastic Agent logs for errors or timeouts

**Authentication errors:**
- Verify the admin password is correct
- Check Pi-hole API is accessible at `/api/auth`
- Ensure Pi-hole version supports session-based authentication (v6.0+)

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For high-volume networks with multiple Pi-hole instances:
- Deploy separate Elastic Agent instances for each Pi-hole
- Use namespace separation to distinguish between different Pi-hole instances
- Consider reducing collection interval for high-traffic instances

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### API usage

This integration uses the following Pi-hole API endpoints:

**Authentication:**
- `POST /api/auth` - Authenticates and obtains a session ID
- `DELETE /api/auth` - Terminates the session

**Data Collection:**
- `GET /api/queries?length=1000&from=<timestamp>` - Retrieves DNS query logs with timestamp-based filtering (dns_queries data stream)
- `GET /api/history` - Retrieves time-series query metrics (query_history data stream)
- `GET /api/stats/summary` - Retrieves comprehensive Pi-hole statistics (pihole_summary data stream)
- `GET /api/stats/top_clients?blocked=false` - Retrieves top allowed DNS clients (top_clients data stream)
- `GET /api/stats/top_clients?blocked=true` - Retrieves top blocked DNS clients (top_clients data stream)
- `GET /api/stats/top_domains?blocked=false` - Retrieves top allowed domains (top_domains data stream)
- `GET /api/stats/top_domains?blocked=true` - Retrieves top blocked domains (top_domains data stream)

All data collection endpoints require authentication via the `X-FTL-SID` header. Each data stream manages its own session lifecycle independently.

For more information about the Pi-hole API, see the [Pi-hole API documentation](https://docs.pi-hole.net/ftldns/api/).
