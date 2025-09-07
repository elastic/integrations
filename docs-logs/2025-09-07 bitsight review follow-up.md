Title: Bitsight CEL review fix and re-test
Date: 2025-09-07

Summary
- Applied upstream review feedback from efd6 on PR https://github.com/elastic/integrations/pull/14161.
- Updated CEL program to decode JSON directly from `resp.Body` without `bytes()` conversion.

Changes
- File: packages/bitsight/data_stream/vulnerability/agent/stream/cel.yml.hbs
  - Replace `bytes(resp.Body).decode_json()` with `resp.Body.decode_json()` in three places.

Validation
- Ran in package root `packages/bitsight`:
  - `elastic-package format` → OK
  - `elastic-package lint` → OK
  - `elastic-package test pipeline -d vulnerability` → PASS (all pipeline tests)
  - `elastic-package test static` → PASS (Verify sample_event.json)
  - `elastic-package test asset` → PASS (index template and ingest pipeline loaded)
  - `elastic-package build` → OK (artifact under build/packages/bitsight-0.1.0.zip)

Notes
- `elastic-package test system` attempted, but failed during post-run log dump with the current CLI (v0.111.0) due to missing internal log path in the elastic-agent container. Stack services are healthy. Consider retrying with a newer elastic-package (v0.114.0 suggested by the tool) if system test logs are required.

