# P1 integration ingest report

- **Run ID:** `full-p1-run-resume`
- **Generated:** 20260625T031805Z

Counts use `logs-*` with **no time range** (fixtures may have historical `@timestamp` values).

| Package | Installed | Fixtures | Submitted | Bulk errors | Saved | @timestamp range |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| microsoft_dhcp | yes | 2 | 32 | 0 | 0 |  |
| microsoft_intune | yes | 2 | 6 | 0 | 6 | 2023-10-27T00:10:43.554Z → 2026-02-19T00:20:52.479Z |
| openai | yes | 0 | 0 | 0 | 0 |  |
| osquery | yes | 1 | 2213 | 0 | 0 |  |
| ping_federate | yes | 2 | 5 | 0 | 4 | 2012-05-18T11:41:48.452Z → 2024-11-28T05:58:55.832Z |
| ping_one | yes | 1 | 99 | 1 | 98 | 2022-07-06T06:12:00.400Z → 2025-09-19T15:00:04.408Z |
| prisma_cloud | yes | 7 | 19 | 4 | 3 | 2023-09-04T09:28:22.240Z → 2023-09-19T07:15:31.899Z |
| qualys_vmdr | yes | 5 | 26 | 3 | 15 | 2021-08-30T22:57:42.484Z → 2024-05-16T10:00:05.000Z |
| salesforce | yes | 6 | 13 | 0 | 8 | 2021-10-06T07:13:07.000Z → 2023-01-04T06:44:36.203Z |
| servicenow | yes | 4 | 54 | 0 | 0 |  |
| snort | yes | 6 | 64 | 0 | 0 |  |
| snyk | yes | 2 | 27 | 1 | 26 | 2024-04-15T19:47:21.565Z → 2025-04-17T08:49:38.673Z |
| suricata | yes | 5 | 64 | 0 | 0 |  |
| sysdig | yes | 4 | 36 | 0 | 11 | 2025-04-05T03:00:01.115Z → 2025-08-11T11:25:45.394Z |
| tanium | yes | 9 | 54 | 0 | 1 | 2022-11-18T10:10:57.000Z → 2022-11-18T10:10:57.000Z |
| ti_misp | yes | 4 | 43 | 0 | 30 | 2014-10-03T07:14:05.000Z → 2023-11-20T13:53:24.000Z |
| wiz | yes | 6 | 23 | 0 | 22 | 2023-07-31T06:26:08.708Z → 2026-06-24T23:00:36.638Z |
| zscaler_zia | yes | 15 | 47 | 0 | 61 | 2021-12-31T08:08:08.000Z → 2026-12-31T14:03:06.000Z |

## Per-integration query (no time filter)

### `microsoft_intune`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-microsoft_intune"
  AND tags == "p1-run-full-p1-run-resume"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `ping_federate`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-ping_federate"
  AND tags == "p1-run-full-p1-run-resume"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `ping_one`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-ping_one"
  AND tags == "p1-run-full-p1-run-resume"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `prisma_cloud`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-prisma_cloud"
  AND tags == "p1-run-full-p1-run-resume"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `qualys_vmdr`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-qualys_vmdr"
  AND tags == "p1-run-full-p1-run-resume"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `salesforce`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-salesforce"
  AND tags == "p1-run-full-p1-run-resume"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `snyk`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-snyk"
  AND tags == "p1-run-full-p1-run-resume"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `sysdig`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-sysdig"
  AND tags == "p1-run-full-p1-run-resume"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `tanium`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-tanium"
  AND tags == "p1-run-full-p1-run-resume"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `ti_misp`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-ti_misp"
  AND tags == "p1-run-full-p1-run-resume"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `wiz`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-wiz"
  AND tags == "p1-run-full-p1-run-resume"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `zscaler_zia`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-zscaler_zia"
  AND tags == "p1-run-full-p1-run-resume"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```
