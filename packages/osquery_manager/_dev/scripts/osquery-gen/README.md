# osquery-gen (config driven)

Config-driven generator for osquery_manager field/schema generation.

This tool reads `osquery` version, `beats` git selection, and ECS keep fields from `config.yml`,
reads the ECS git ref from `packages/osquery_manager/_dev/build/build.yml`
(`dependencies.ecs.reference`, e.g. `git@v9.3.0`), resolves the latest matching
patch for osquery/beats when using semver config, and generates:

- `packages/osquery_manager/data_stream/result/fields/osquery.yml`
- `packages/osquery_manager/data_stream/result/fields/ecs.yml`
- `packages/osquery_manager/schemas/osquery.json`
- `packages/osquery_manager/schemas/ecs.json`
- `packages/osquery_manager/schemas/metadata.json` (`ecs_version`, `osquery_version`)

Extension metadata in osquery schema is enforced:

- osquerybeat extension tables/views include `owner: "elastic"`
- osquerybeat extension views include `view: true`

## Config

`config.yml`:

```yaml
osquery:
  version: "5.21.0"
beats:
  version: "9.3"
ecs:
  keep_fields:
    - file.pe.sections
```

**Beats** (extension specs under `elastic/beats`): set **either** an explicit git ref **or** a semver-style `version`. Precedence is **tag > branch > version**:

- `tag`: exact ref (for example `v9.4.2`); must contain the osquery extension specs path.
- `branch`: branch name (for example `main`); same validation as `tag`.
- `version`: exact patch or major/minor prefix (for example `9.3`) to auto-select a release tag, then the same ref probing as before.

If both `tag` and `branch` are set, `tag` wins.

For coordinated changes that are not available in an `elastic/beats` ref yet,
pass `-beats-path /path/to/beats`. The path may point to a Beats checkout or
directly to its osquery extension `specs` directory.

Package CI consumes the committed generated artifacts and does not fetch the
configured Beats ref. The ref or local path is needed only when regenerating,
so an integrations PR can be validated before the related Beats release.

**Osquery** `version` values can be:

- exact patch (for example `5.18.1`)
- major/minor prefix (for example `5.18`) to auto-select latest patch

ECS version for downloads and generated `ecs.yml` / `ecs.json` comes from
`_dev/build/build.yml` (same ref `elastic-package` uses for `external: ecs`):

```yaml
dependencies:
  ecs:
    reference: git@v9.3.0
```

**ECS** `keep_fields` entries force specific ECS field names into the generated
`data_stream/result/fields/ecs.yml` even when the field is an object/nested node
or has a type outside the generator's default allow-list.

Notes:

- Output is always written to `packages/osquery_manager` under the detected `integrations` repo root.
- osquerybeat extension specs are always loaded and merged.

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

## Upgrade Osquery

From the integrations repository root, run:

```bash
CHANGELOG_LINK=https://github.com/elastic/integrations/issues/12345 \
KIBANA_VERSION='~9.4.6 || ^9.5.2' mage updateOsqueryManager
```

This resolves the latest stable release, regenerates and validates the package,
bumps the package minor version, adds its changelog entry, and writes the
resolved exact version back to `config.yml`. A numbered GitHub issue or pull
request is required because integrations package validation requires it in the
changelog. `KIBANA_VERSION` must list only stack releases that contain the
upgraded Osquery runtime. Use separate ranges when an older minor receives the
fix after a newer minor has already shipped, so unpatched releases are not
included. To select a release or consume unreleased extension specs from a
local Beats checkout:

```bash
CHANGELOG_LINK=https://github.com/elastic/integrations/issues/12345 \
KIBANA_VERSION='~9.4.6 || ^9.5.2' OSQUERY_VERSION=5.23.1 \
BEATS_PATH=../beats mage updateOsqueryManager
```

1. Review all generated fields, schemas, and `schemas/metadata.json`.
2. Review the generated package version and changelog description. The target
   uses a minor bump because an Osquery schema upgrade can expose new query
   capabilities.

The osquerybeat bundled runtime should be upgraded first so the integration
does not advertise schema capabilities newer than deployed endpoints.
