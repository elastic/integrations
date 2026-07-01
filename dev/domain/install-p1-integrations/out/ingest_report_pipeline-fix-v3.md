# P1 integration ingest report

- **Run ID:** `pipeline-fix-v3`
- **Generated:** 20260629T223506Z

Counts use `logs-*` and `metrics-*` with **no time range** (fixtures may have historical `@timestamp` values).
Failed docs are counted from `::failures` backing indices when present.

| Package | Installed | Fixtures | Submitted | Bulk errors | Saved | Failed | Pipeline errors | Unparsed `message` | @timestamp range |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| azure_openai | — | 4 | 7 | 0 | 7 | 0 | 0 | 0 | 2024-04-08T12:23:02.435Z → 2025-03-05T10:39:40.226Z |
| salesforce | — | 6 | 13 | 2 | 11 | 0 | 0 | 0 | 2021-10-19T05:07:07.128Z → 2024-07-08T07:26:18.239Z |
| azure_ai_foundry | — | 4 | 10 | 0 | 10 | 0 | 0 | 0 | 2024-07-02T06:14:56.237Z → 2025-06-24T12:23:02.435Z |
| azure_app_service | — | 6 | 11 | 0 | 9 | 0 | 0 | 0 | 2022-12-14T12:17:57.273Z → 2024-09-18T09:18:29.915Z |

## Per-integration query (no time filter)

### `azure_openai`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-azure_openai"
  AND tags == "p1-run-pipeline-fix-v3"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `salesforce`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-salesforce"
  AND tags == "p1-run-pipeline-fix-v3"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `azure_ai_foundry`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-azure_ai_foundry"
  AND tags == "p1-run-pipeline-fix-v3"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```

### `azure_app_service`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-azure_app_service"
  AND tags == "p1-run-pipeline-fix-v3"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```
