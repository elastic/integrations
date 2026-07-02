# P1 integration ingest report

- **Run ID:** `apikey-smoke-test`
- **Generated:** 20260624T173530Z

Counts use `logs-*` with **no time range** (fixtures may have historical `@timestamp` values).

| Package | Installed | Fixtures | Submitted | Bulk errors | Saved | @timestamp range |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| slack | — | 1 | 6 | 0 | 6 | 2018-03-16T15:32:23.000Z → 2024-03-05T08:39:07.000Z |

## Per-integration query (no time filter)

### `slack`

```esql
FROM logs-*
| WHERE tags == "p1-ingest-slack"
  AND tags == "p1-run-apikey-smoke-test"
| STATS count = COUNT(*), min_ts = MIN(@timestamp), max_ts = MAX(@timestamp)
```
