# Zoom CEL regression tests

These tests run the CEL programs from the three report input templates against a
local mock HTTP server. They require Python 3 and Elastic's Mito CEL runner:

```sh
go install github.com/elastic/mito/cmd/mito@v1.28.2
python3 packages/zoom/_dev/scripts/test_pagination.py -v
```

Run from the repository root with `mito` on `PATH`. No Elastic stack, Zoom account,
or credentials are needed. The tests replace the CEL clock with fixed timestamps
to verify that both dates stay fixed across UTC midnight, including when the
retention boundary moves. They also check token recovery after HTTP errors,
JSON API errors with HTTP 200, and XML/HTML responses with HTTP 200, plus window
completion and checkpoint replay after a collector restart.
