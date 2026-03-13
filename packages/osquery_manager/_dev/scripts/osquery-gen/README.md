# osquery-gen (config driven)

Config-driven generator for osquery_manager field/schema generation.

This tool reads `osquery`, `beats`, and `ecs` versions from YAML, resolves the
latest matching patch release, and generates:

- `packages/osquery_manager/data_stream/result/fields/osquery.yml`
- `packages/osquery_manager/data_stream/result/fields/ecs.yml`
- `packages/osquery_manager/schemas/osquery.json`
- `packages/osquery_manager/schemas/ecs.json`

Extension metadata in osquery schema is enforced:

- osquerybeat extension tables/views include `owner: "elastic"`
- osquerybeat extension views include `view: true`

## Config

Example:

```yaml
osquery:
  version: "5.21.0"
beats:
  version: "9.3"
ecs:
  version: "9.2"
```

Version values can be:

- exact patch (for example `5.18.1`)
- major/minor prefix (for example `5.18`) to auto-select latest patch

Notes:

- Output is always written to `packages/osquery_manager` under the detected `integrations` repo root.
- osquerybeat extension specs are always fetched and merged.

## Run

From the tool directory:

```bash
cd packages/osquery_manager/_dev/scripts/osquery-gen
go run . -config ./config.yml
```

Development mode (skip mandatory package check):

```bash
go run . -config ./config.yml -skip-package-check
```
