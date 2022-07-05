# import-beats

## Deprecated

The `import-beats` script was intended to help with initial migration from Beats modules to Elastic Integrations. A developer
working on migrating Beats modules used it once to flush the initial skeleton of an integration. Unfortunately,
the script is not actively maintained and we (@ecosystem team) would rather deprecate it to prevent its accidental future
adoption in developer workflows (_You shouldn't adopt it for continuous module-integration transformation._).

## About

The script is responsible for importing existing beats modules and transforming
them into integration packages compatible with Elastic Package Registry (EPR).

The `import-beats` script depends on active Kibana instance, which is used to
migrate existing dashboards to a newer version.

## Usage

```bash
$ mage ImportBeats
```

... or using `go run` (no need to install `mage`):

```bash
$ go run dev/import-beats/*.go -help
Usage of /var/folders/gz/dht4sjdx5w9f72knybys10zw0000gn/T/go-build777100057/b001/exe/agent:
  -beatsDir string
    	Path to the beats repository (default "../beats")
  -ecsDir string
    	Path to the Elastic Common Schema repository (default "../ecs")
  -euiDir string
    	Path to the Elastic UI framework repository (default "../eui")
  -kibanaDir string
    	Path to the kibana repository (default "../kibana")
  -kibanaHostPort string
    	Kibana host and port (default "http://localhost:5601")
  -kibanaPassword string
    	Kibana password (default "changeme")
  -kibanaUsername string
    	Kibana username (default "elastic")
  -outputDir string
    	Path to the output directory (default "dev/packages/beats")
  -skipKibana
    	Skip storing Kibana objects
```

## Import all packages

1. Make sure that the following repositories have been fetched locally:
https://github.com/elastic/beats
https://github.com/elastic/ecs
https://github.com/elastic/eui
https://github.com/elastic/kibana

These projects are expected to be found at the same level with `integrations` repository like:
`beats        ecs          eui       integrations     kibana`

2. Make sure you've the `mage` tool installed.
3. Start Kibana server (make sure the endpoint is accessible: http://localhost:5601/)
4. Run the importing procedure with the following command:

```bash
$ mage ImportBeats
```

## Package import procedure

This section describes next steps of the `import-beats` script that are performed to build integration packages in
the output directory.

Keep in mind that the script doesn't clean previously created artifacts, so you may encounter leftovers (detached
dashboards, renamed ingest pipeline, etc.). If you need to preserve a clean state in the output directory (which is
versioned), remove its content before executing the script.

The script requires few repositories (Kibana, EUI, etc.) to be present, but doesn't require to execute any of build
targets. It depends only on the existing, version content, so simple `git clone` should be enough.

### Package repository

The package repository is responsible for building packages - loading package data from sources (Beats modules, Kibana
resources, etc.) and writing them to disk. It supports two types of beats - **logs** and **metrics**.

#### Load input data from sources

The script needs to visit and process input data from [beats](https://github.com/elastic/beats), generally logs and
metrics modules.

Starting with modules, it collects and processes information about module fields, release type, icons, screenshots,
Kibana dashboards and docs. While browsing data streams content, it focuses on fields specific for the data stream, release
type, ingestion pipeline, stream and agent configuration.

##### Fields

Fields are extracted from `fields.yml` files and divided into 3 buckets - ECS fields, module fields
and package fields.

##### Integration title

The correct spelling makes better impression on users, so the scripts uses `title` property in the module fields
as the proper form. Remember to adjust this value if working on the migration from Beats.

##### Release type

Values: _beta, experimental, ga_

~~The value depends on definitions in module and data stream fields. The scripts determines the correct release type
for data stream, depending on overall release status for module (e.g. data stream can't be annotated as GA if the entire module
is in beta).~~

Currently, all imported packages are created with default value - experimental.

##### Images

The script supports two kinds of images - **icons** and **screenshots**. Even though they're stored in different media
formats, they're analyzed to prepare a metadata information (title, size and media type).

###### Icons

The icons are loaded from the following sources: Kibana home tutorials and Elastic UI. Icons must be in SVG format and
have defined dimensions (information stored in manifest, used by Kibana). Keep in mind that only icon files referenced
in tutorials are processed.

###### Screenshots

The script parses module docs to find and collect all references to screenshots showing Kibana dashboards.

##### Kibana dashboards

The script performs a convertion of all existing Kibana dashboards into new format. Packages stores Kibana objects
divided into buckets based on the object type (e.g. dashboards, visualizations, maps).

Many existing dashboards are compliant with earlier Kibana versions hence they're loaded to the Kibana instance to let
it migrate to the newer format (Kibana instance must be accessible during the importing process).

Every Kibana object needs to be stored in a decoded form (unpacked JSON format) as it's easier to find changes between
particular revisions.

There is also a change related to the `event.module` field - the field is no longer available in the integration.
The script adjusts dashboards automatically by replacing all references with a special clause including all data streams,
e.g.:

_The module "duck" contains 3 data streams: foo, bar, baz._

The `event.module = duck` will be transformed into
`(event.data stream = duck.foo OR event.data stream = duck.bar OR event.data stream = duck.baz)`.

##### Dependency requirements

The scripts parses available Kibana objects for information about supported versions and determines what is
the minimal required Kibana version.

The required version of the Elasticsearch is hardcoded (`>7.0.1`).

##### Documentation

Documentation in the Beats repository refers to modules, metricsets and filesets. Unfortunately it doesn't fit
well in the concept of integrations, so all documentation pages need to be adjusted.

Every integration may have a doc template defined, so that the script can pick it up while building packages.
The template can refer to functions, e.g. to render a table with fields used by a data stream.

##### Ingest pipelines

If the fileset used an ingest pipeline, the script includes it in the target package, but renamed to `default.json` or
`default.yml`.

##### Streams

Stream configuration defines available Metricbeat and Filebeat settings used to reconfigure the integration.

Depending on the data stream type, the configuration can be imported from the following files: `_meta/config.*.yml`
for Metricbeat or `manifest.yml` for Filebeat. The new format provides additional properties (required, show_user,
title, multi), which can be used to provide better user experience in Kibana UI. Unfortunately the script can't
detect these properties automatically, so manual adjustments will be required.

Metricbeat configuration might be hard to extract because of missing variable definitions (`_meta/config.*.yml` are
like samples). The script analyzes the `_meta/config.*.yml` files and tries to deduce, which variables belong to
particular metricsets.

##### Agent configuration

The agent configuration is a template used by Kibana to prepare the final configuration deployed on agents. The script
needs to convert the Beats configuration as the templating engine has changed from the standard Golang one to
the [handlebarsjs](https://handlebarsjs.com/). The script doesn't run any advanced syntax analysis and bases only on
simple find-and-replace functions (which actually covers vast majority of cases).

At the moment, a developer is obliged to verify the convertion result.

#### Write package content to disk

The script writes down all packages to the specified output directory. As it doesn't remove existing resources, it's
safer to clean the output directory first. This is the moment when copying resources, rendering doc templates and
creating required directories happens.

At the moment all packages are annotated with version `0.0.1`.

## Troubleshooting

### Importing process takes too long

While developeing, you can try to perform the migration with skipping migration of all Kibana objects,
as this is the most time consuming part of whole process:

```bash
$ SKIP_KIBANA=true mage ImportBeats
```
