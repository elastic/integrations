**STATUS: Proposal**

# Overview

This describes how integrations are built and then packaged for the [integrations registry](https://github.com/elastic/integrations-registry). The format described in this document is focused allowing build and test integrations which then are packaged with tools. 

The format of a package for the registry can be found [here](https://github.com/elastic/integrations-registry#package-structure). But for the development of a package, this is not enough as we also need testing of datasets which needs additional meta data. The proposed structure allows to tests metricsets / filsets in a similar way as we do today. With `mage package` all assets are packaged together to conform to the package structure.

# Definitions

**Integration package**: An integration package is a packaged version of an integration. This is what is served by the integrations registry. An example on what such a package looks like can be found [here](https://github.com/elastic/integrations-registry#package-structure). It’s important to state that the shipped package does not look identical to the format here which is optimised for development and testing.

**Integration**: Integration definition with manifest and several datasets with the assets for the Elastic Stack.

**Dataset**: Group of assets which are grouped together for testing and development purposes.


# Integration files structure

As today with modules, the base structure for the implementation is split up into integrations which contains multiple datasets. All the assets are inside each dataset and the dataset file structure is very similar to the final structure of a package. The structure looks as following:

```
{integration-name}/dataset/{dataset-name}/{package-structure}
```

An example of the above for an apache.access log ingest pipeline is:

```
apache/dataset/access/elasticsearch/ingest-pipeline/default.json
```

On the top level of each integration, it contains the `manifest.yml`, `LICENSE.txt` file and the `changelog.yml`.

## Assets

Below are all the existing assets described. The assets which are already defined in [ASSET.md](https://github.com/elastic/integrations-registry/blob/master/ASSETS.md) from the package definition are not repeated here.

### manifest.yml

The manifest contains all the information about the integration and follows the logic of the [package manifest](https://github.com/elastic/integrations-registry/blob/master/ASSETS.md#general-assets). The manifest might be enriched with further information from its dataset during packaging. Also verifications on compatiblity version etc. will be done.

It contains a few additional fields which are not part of the package:

**datasets**

This is a list of dataset this integration depends on. As packages today do not allow to depend on other packages, it is important to have a dependency feature during building integration to not have to duplicate all the assets. Some examples here are fields for ECS or fields specific to Filebeat. An example is below:

```
datasets:
    - name: "ecs:ecs"
    - name: "filebeat:filebeat"
```

No versions are mentioned above of the datasets. It's up to the implementer to make sure to increase the version number of the integration if a dependency changes. Alternative we could use versions which are then validate and if not correct anymore, an error is thrown. This would probably be more dev friendly but more complex to implement.

**Package config**

Not all integrations which are in this repo need packaging. For example the Filebeat or ECS integration directory are only placeholders for the assets but will not come any integration. To prevent these from packaging. `package: false` can be set.

### changelog.yml

Every integration should keep a changelog so if a user upgrades, we can show the user what changed. If a dependency of an integration changes, its up to the integration to add these items to the changelog list if needed.

The changelog is in a structure format, so it can be read out and visualised in the package manager.

More details about the changelog can be found here: https://github.com/elastic/integrations-registry/blob/master/ASSETS.md#changelogyml

```
# The changelog.yml contains all the changes made to the integration and it's datasets.
# If a dataset is adjusted, it should also be added to this changelog.
# The changelog is in a structure format so the order does not matter and it can be used
# for visualisation in the UI.

- version: 1.0.4
  changes:
    - description: >
        Unexpected breaking change had to be introduced. This should not happen in a minor.
      type: breaking-change
      link: https://github.com/elastic/beats/issues/13504
- version: 1.0.3
  changes:
    - description: Fix broken template
      type: bugfix
      link: https://github.com/elastic/beats/issues/13507
    - description: It is a known issue that the dashboard does not load properly
      type: known-issue
      link: https://github.com/elastic/beats/issues/13506
```

### testing.yml

The testing.yml can contain information about how the integration should be tested. So far the focus is on testing datasets so this file might not be necessary. It could be used to include in datasets to share common testing info.

### docs/README.md

README document which contains all the documentation about the integration. It is possible that each dataset has its own additional documentation. It is expected that this will be just appended to the main README on packaging.

### img/

Directory for all the icons, screenshots and potentially videos. 

Question: Should we name this media?

### dataset/{dataset}/testing.yml

This yaml file should contain all the configuration on how a dataset can be tested. It might contain which services have to be booted up for testing and how the tests should be run.

### dataset/{dataset}/testdata

All the data used for testing. For example example logs and the generated output of it.

### dataset/fields/fields.yml

The fields.yml contains the content to generate the Elasticsearch index template and the Kibana index pattern. This happens in the integrations manager.

On thing that is important is that all fields.yml used, start with the global full path. At the moment we have some fields.yml in the datasets which are relative to the module they are in. We need to change those.
The idea is that the order of the fields.yml does not matter when combining them all into 1 file.

## Reusable content

Any dataset can be reused by just referencing it in the manifest. But some of these reused assets don't need packaging on it's own. These go into integrations directory list `filebeat` or `ecs` as datasets where `package: false` is set. This allows to reuse all these assets without also getting a package for it. It would be possible to store these assets outside the "integration" directory for better separation. But implementation of the collection script has shown, that the script stays much simpler like this.


## Versioning

The version of a package is taken from the manifest file. If the CoreDNS package contains `version: 1.2.3` it will build the package `coredns-1.2.3`. For now, no exact version of a dataset is specified. If a dataset is updated, next time packaging is called for an integration, it will pull in the newest assets. So if there is a breaking change in a dataset, it's up the integration package dev to decide if this is needed. To reduce errors we could introduce exact specification of a dataset version. This would mean in case a dataset version is updated, all datasets which reference it must be updated too. As everything is in one repository, this shouldn't be too much hassle but would make it more explicit.

It is expected that [semantic versioning](https://semver.org) is used.

### Backports

I expect most integrations to only be moving forward and have rarely breaking changes. Because of this no backports to branches etc. are needed. In case this is needed, there are several options:

* Have a branch for this integration. Packaging will just work as is.
* Have this integration in a separate repo.


## Conversion of modules to integrations

As the data of a module and an integration stay mostly the same, transformation from a module to an integration can mostly be automated. I started to play around with some tooling to convert existing modules to integrations but I would prefer to delay the discussion around this until we agreed on the format for building integrations.

# Questions

* Why don't we store the main assets of an integration in for example `coredns/dataset/coredns` instead of just the top level? 
  * One of the main reasons is that it heavily simplifies the code of collecting assets, as there is just one and no checks have to be made if there are also assets on the top level. It also prevents potential directory name conflicts.
  
