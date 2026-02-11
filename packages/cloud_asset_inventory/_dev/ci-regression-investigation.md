# CI regression: cloud_security_posture (9.4 stack) passed Feb 3, broke after

## What we know

- **PR 17185** (Cloud Security Posture – GCP Cloud Connectors) **CI passed on Feb 3rd** with elastic-package 0.118 and 9.4.0 stack.
- Same check (**Check integrations cloud_security_posture**) **fails now** (week of Feb 10).
- Nothing in the **integrations repo** that could explain it was merged in the past week.

## What did NOT change (integrations repo)

- **go.mod / go.sum**: Last elastic-package bump was **Dec 30, 2025** (0.117.1 → 0.118.0, commit 3d541c7f27). No dependency changes since.
- **.buildkite/**: No commits touching `.buildkite/` in the last 40 commits (Feb 2–9). Last `common.sh` change was Jan 16 (backports) and Dec 4 (cleanup).
- So: **no CI script or dependency change in the past week.**

## Where the stack version comes from

- For **cloud_security_posture** (manifest `kibana: "^9.4.0"`), `prepare_stack` uses `oldest_supported_version` → **find_oldest_supported_version.py**.
- That script calls **Artifacts API**: `https://artifacts-api.elastic.co/v1/versions`.
- It resolves to **9.4.0-SNAPSHOT** when that alias/version is present (no 9.4.1 yet).
- So the **exact Docker images** (elasticsearch, kibana, fleet-server) are whatever **9.4.0-SNAPSHOT** points to **at the time of the run**. That pointer updates whenever a new snapshot is published.

## Conclusion: regression is in the 9.4.0-SNAPSHOT stack images

- **Feb 3**: CI used the 9.4.0-SNAPSHOT images available that day → stack came up, tests passed.
- **After that**: A **new 9.4.0-SNAPSHOT** build was published (fleet-server and/or Kibana/Elasticsearch). One of those images has a regression (e.g. fleet-server → Elasticsearch at localhost:9200, or Kibana pushing wrong output to fleet-server).
- So the break is **not** in:
  - integrations repo
  - elastic-package 0.118 (unchanged since Dec 30)
- The break **is** almost certainly in:
  - **Elastic stack 9.4.0-SNAPSHOT** images (fleet-server, Kibana, or how they’re built/configured), or
  - The **artifact** that the SNAPSHOT alias points to (new build published in the last week).

## What to do next

1. **Find which 9.4.0-SNAPSHOT build was used on Feb 3** (e.g. from Buildkite logs: image digests or build IDs for fleet-server/kibana/elasticsearch).
2. **Compare to the current 9.4.0-SNAPSHOT** (digests / build IDs). Identify the first snapshot publish after Feb 3 that’s in the failure window.
3. **In the elastic-stack / fleet-server / Kibana repos**: Review commits (or image build pipelines) between that “last good” and “first bad” snapshot.
4. **Optional short-term workaround**: If there’s a way to pin the stack to a **specific snapshot build** (e.g. by digest or build ID) in CI, pin to the last known good 9.4.0-SNAPSHOT until the stack regression is fixed.
