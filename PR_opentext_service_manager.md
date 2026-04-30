<!-- Type of change
Please label this PR with one of the following labels, depending on the scope of your change:
- Bug
- Enhancement
- Breaking change
- Deprecation
-->

**Suggested label:** Enhancement

## Proposed commit message

```
Add OpenText Service Manager integration for incident REST collection
```

### WHAT

- New integration package **`opentext_service_manager`** (`format_version` 3.3.5), owner `elastic/security-service-integrations`.
- **`incident` logs data stream** using **`cel`** input and **`cel.yml.hbs`**:
  - `GET` against user-supplied incidents REST URL with `query`, `sort`, `view=expand`, `start`, and `count` ([RESTful Queries](https://docs.microfocus.com/SM/9.52/Hybrid/Content/webservicesguide/rest_queries.htm), [RESTful Commands](https://docs.microfocus.com/SM/9.51/Hybrid/Content/webservicesguide/rest_commands.htm)).
  - HTTP Basic authentication for operator credentials ([RESTful Authentication](https://docs.microfocus.com/SM/9.51/Hybrid/Content/webservicesguide/rest_authentication.htm)).
  - Initial collection bounded by **`initial_interval`** on the configured cursor time field; subsequent polls advance a watermark using strict inequality plus tie-breaker on **`number`** (or configurable fields).
  - **`want_more`** continuation with **`start += batch size`** while retaining **`poll_end`** and pending row keys in the persisted **`cursor`** so large result sets page without loading entire collections at once.
  - Emits one event per incident with **`message`** set to the JSON-encoded **`properties`** map when present (otherwise the entity object).
- **Ingest pipeline** maps JSON into **`opentext_service_manager.incident`** (`flattened`), sets ECS **`event.kind`** / **`event.category`** / **`event.type`**, handles collection errors.
- **Assets:** SVG logo based on [OpenText wordmark](https://docs.microfocus.com/assets/global/opentext-logo.svg) on a dark background for Fleet visibility (aligned with [docs.microfocus.com](https://docs.microfocus.com/) styling).
- **Tests:** Pipeline test (`test-incident.log` + expected JSON). No system test yet (no SM REST mock in-repo).
- **`changelog.yml`** entry for **`0.1.0`**.

### WHY

OpenText Service Manager (formerly Micro Focus / HP Service Manager) is still widely deployed; teams need a first-party Elastic integration that follows documented REST patterns for incident retrieval, pagination, and incremental polling without duplicate incidents where the API semantics allow. A dedicated package documents configuration clearly and keeps the CEL program maintainable compared to ad hoc Custom API (CEL) input-only setups.

---

## Checklist

- [ ] I have reviewed [tips for building integrations](https://www.elastic.co/docs/extend/integrations/tips-for-building) and this pull request is aligned with them.
- [x] I have verified that all data streams collect metrics or logs.
- [x] I have added an entry to my package's `changelog.yml` file.
- [ ] I have verified that Kibana version constraints are current according to [guidelines](https://github.com/elastic/elastic-package/blob/master/docs/howto/stack_version_support.md#when-to-update-the-condition).
- [x] I have verified that any added dashboard complies with Kibana's [Dashboard good practices](https://docs.elastic.dev/ux-guidelines/data-viz/dashboard-good-practices) *(N/A — no dashboards in this revision)*

---

## Author's Checklist

<!-- Recommended
Add a checklist of things that are required to be reviewed in order to have the PR approved
-->

- [ ] Confirm **`changelog.yml`** `link` is updated to this PR once opened (currently points at the integrations repo root).
- [ ] Validate CEL program against a live or lab Service Manager REST endpoint (`entities` JSON shape, field names for cursor/tie-breaker).
- [ ] Consider adding a **system test** with an HTTP mock when a stable SM-like JSON fixture is agreed on.
- [ ] Confirm **Kibana version** condition `^8.17.4 || ^9.0.0` matches stack support policy for new packages.

---

## How to test this PR locally

From the integrations repository root (adjust path to your **`elastic-package`** binary):

```bash
elastic-package lint --fail-on-warnings packages/opentext_service_manager
elastic-package test pipeline --package opentext_service_manager -v
```

Optional: build and install the package into a local stack per Elastic integration contributor workflows.

**Manual smoke test:** Configure the integration with a real incidents URL (for example `https://<host>/<SM REST base>/incidents`), operator Basic auth, default **`native_query`** `Category="incident"`, and verify documents appear under **`logs-opentext_service_manager.incident-*`** with **`opentext_service_manager.incident`** populated.

---

## Related issues

<!-- Recommended
Link related issues below. Insert the issue link or reference after the word "Closes" if merging this should automatically close it.

- Closes #123
- Relates #123
- Requires #123
- Supersedes #123
-->

- 

---

## Screenshots

<!-- Optional
Add here screenshots presenting:
- Kibana UI forms presenting configuration options exposed by the integration
- dashboards with collected metrics or logs
-->

Optional for this PR: Fleet integration policy form showing URL, credentials, **`native_query`**, **`batch_size`**, and **`initial_interval`**. No dashboards shipped in v0.1.0.

---

*This file is temporary copy-paste content for the GitHub PR description; delete after opening the PR if desired.*
