# P1 integration ingest report

- **Run ID:** `fix-timestamp-v2`
- **Generated:** 20260625T100457Z

Counts use `logs-*` and `metrics-*` with **no time range** (fixtures may have historical `@timestamp` values).
Failed docs are counted from `::failures` backing indices when present.

| Package | Installed | Fixtures | Submitted | Bulk errors | Saved | Failed | @timestamp range |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| aws_securityhub | — | 1 | 10 | 0 | 10 | 0 | 2025-09-19T09:17:19.594Z → 2025-09-26T16:27:28.631Z |
| azure_ai_foundry | — | 4 | 10 | 0 | 10 | 0 | 2024-07-02T06:14:56.237Z → 2025-06-24T12:23:02.435Z |
| azure_app_service | — | 6 | 11 | 0 | 9 | 0 | 2022-12-14T12:17:57.273Z → 2024-09-18T09:18:29.915Z |
| azure_openai | — | 4 | 7 | 0 | 7 | 0 | 2024-04-08T12:23:02.435Z → 2025-03-05T10:39:40.226Z |
| cisco_meraki | — | 7 | 273 | 0 | 269 | 0 | 2026-06-25T09:56:02.435Z → 2026-06-25T09:56:26.381Z |
| cisco_secure_email_gateway | — | 11 | 164 | 0 | 164 | 0 | 2026-06-25T09:56:31.388Z → 2026-06-25T09:57:20.248Z |
| cisco_umbrella | — | 7 | 43 | 0 | 43 | 0 | 2026-06-25T09:57:25.402Z → 2026-06-25T09:57:55.348Z |
| citrix_waf | — | 2 | 20 | 0 | 20 | 0 | 2026-06-25T09:58:00.188Z → 2026-06-25T09:58:05.128Z |
| fortinet_fortigate | — | 7 | 207 | 0 | 207 | 0 | 2026-06-25T09:58:10.381Z → 2026-06-25T09:58:40.180Z |
| jamf_pro | — | 24 | 31 | 5 | 24 | 0 | 2024-09-04T09:57:52.001Z → 2026-06-25T10:01:30.165Z |
| microsoft_dhcp | — | 2 | 32 | 0 | 32 | 0 | 2026-06-25T10:01:35.166Z → 2026-06-25T10:01:40.155Z |
| osquery | — | 1 | 2213 | 0 | 2213 | 0 | 2017-12-07T12:21:20.000Z → 2018-01-08T17:19:48.000Z |
| servicenow | — | 4 | 54 | 0 | 54 | 0 | 2026-06-25T10:02:45.340Z → 2026-06-25T10:03:02.110Z |
| snort | — | 6 | 64 | 0 | 59 | 0 | 2026-06-25T10:03:07.274Z → 2026-06-25T10:03:47.002Z |
| suricata | — | 5 | 64 | 0 | 64 | 0 | 2018-07-05T19:01:09.820Z → 2024-07-30T16:53:24.501Z |

## Per-integration query (no time filter)

### `aws_securityhub`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-aws_securityhub"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `azure_ai_foundry`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-azure_ai_foundry"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `azure_app_service`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-azure_app_service"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `azure_openai`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-azure_openai"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `cisco_meraki`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-cisco_meraki"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `cisco_secure_email_gateway`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-cisco_secure_email_gateway"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `cisco_umbrella`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-cisco_umbrella"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `citrix_waf`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-citrix_waf"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `fortinet_fortigate`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-fortinet_fortigate"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `jamf_pro`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-jamf_pro"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `microsoft_dhcp`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-microsoft_dhcp"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `osquery`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-osquery"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `servicenow`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-servicenow"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `snort`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-snort"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `suricata`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-suricata"
  AND tags == "p1-run-fix-timestamp-v2"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```
