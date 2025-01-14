# Package for PPBGDI integrations

This package contains PPBGDI specific integrations:

- Custom PPBGDI integrations
- Customized official integrations

Customized official integrations are developed in this package for simplicity and convenience.
Once they are working fine, they may be backported to the official integration in separate PRs.

## Dashboards

### Naming conventions

All names of managed PPBGDI dashboards must have the following naming:

```txt
[<data_stream.Type> PPBGDI] <system or service> <Meaningful name>

Examples:

[Logs PPBGDI] AWS - Cloudfront Overview
[Logs PPBGDI] service-stac Overview 
```

All dashboards must be tagged accordingly:

- PPBGDI
- system
- service
- AWS in case of AWS-services like cloudfront
- ...

### Create/Export

Dashboards which are created or edited can be exported to this package with the elastic-package tool.

**_Note:_** _The dashboard-id can be found in the dashboard-url. Example: https://kibana-dev.geobax.tech/app/dashboards#/view/**ppbgdi-d5dae57d-6529-4bb4-9ef5-10d755817398**_

```bash
# Observability dev cluster
summon -p ssm -e bgdi-observability-dev elastic-package export dashboards --id <dashboard-id>

# Observability dev cluster
summon -p ssm -e bgdi-observability-prod elastic-package export dashboards --id <dashboard-id>

```

Usage:

- Use up/down keys to navigate thru dashboard list
- Use space key to toggle select
- Use enter to export
- Use control-c to abort

Exported assets are saved to the following directories:

| Asset       | Directory           |
|-------------|---------------------|
| Dashboards  | ./kibana/dashboard  |
| Searches    | ./kibana/search     |
| Tags        | ./kibana/tag        |

**_Note:_** _Searches and tags can only be saved indirectly, when referenced in a exported dashboard.
To export/persist solitary searches, add them to the PPBGDI_SEARCHES helper dashboard, which was created
for that reason._

### Edit

**_Note:_** _The dashboard-id can be found in the dashboard-url. Example: https://kibana-dev.geobax.tech/app/dashboards#/view/**ppbgdi-d5dae57d-6529-4bb4-9ef5-10d755817398**_

Managed dashboards can not be edited. To make them editable, use the following command:

```bash
# Observability dev cluster
summon -p ssm -e bgdi-observability-dev elastic-package edit dashboards --id <dashboard-id>

# Observability dev cluster
summon -p ssm -e bgdi-observability-prod elastic-package edit dashboards --id <dashboard-id>

```

Once editing is done, [export](#createexport) the dashboard.

## Deploy package

Once the work is done, build and deploy/publish the package:

1. Update ./CHANGELOG.md with your change and new package version.
2. Update 'version' in ./manifest.yml to the new version.
3. Upload the package to the artifacts bucket. `deploy-package.sh <package-name> <package-version>`
4. Update the package version in the fleet configuration of the dev and prod cluster terraform module and apply the terraform code (`integration_ppbgdi_version`).
5. Clean-up Kibana assets if needed (In some cases, the initial assets need to be deleted once the managed ones are deployed).
