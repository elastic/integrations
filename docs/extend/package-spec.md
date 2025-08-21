---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/package-spec.html
---

# Package specification [package-spec]

Integrations are a type of package and therefore must adhere to the Elastic package specification. The package specification describes:

* The folder structure of a package and the expected files within these folders
* The structure of expected files' contents


### Asset organization [asset-organization]

In general, assets within a package are organized by `<elastic-stack-component>/<asset-type>`. For example, ingest pipelines are stored in the `elasticsearch/ingest-pipeline` folder. This logic applies to all {{es}}, {{kib}}, and Agent assets.

Top-level assets are picked up as JSON documents and pushed to the corresponding {{es}} and {{kib}} APIs.


#### Data streams [data-streams]

There is a specific folder called `data_stream`. Each data stream should have its folder of assets within this folder, and the names of these data streams must follow the data stream naming scheme.

The contents of these folders follow the `<elastic-stack-component>/<asset-type>` structure. During installation, {{fleet}} enforces data stream naming rules. All assets in this folder belong directly or indirectly to data streams.

In most scenarios, only data stream assets are needed. However, there are exceptions where global assets are required to get more flexibility. For example, an {{ilm-init}} policy that applies to all data streams.


### Supported assets [supported-assets]

The following assets are typically found in an Elastic package:

* {{es}}

    * Ingest Pipeline
    * Index Template
    * Transform
    * Index template settings

* {{kib}}

    * Dashboards
    * Visualization
    * {{data-sources-cap}}
    * {{ml-init}} Modules
    * Map
    * Search
    * Security rules

* Other

    * fields.yml



### Directory structure [directory-structure]

```text
apache
│   changelog.yml
│   manifest.yml
└───_dev
└───data_stream
└───docs
└───img
└───kibana
```


### Spec [directory-spec]

Included from the package-spec repository. This will update when the spec is updated.

```yaml
##
## Entrypoint of "integration packages" specification.
##
## Describes the folders and files that make up a package.
##
spec:
  additionalContents: true
  totalContentsLimit: 65535
  totalSizeLimit: 250MB
  sizeLimit: 150MB
  configurationSizeLimit: 5MB
  relativePathSizeLimit: 3MB
  fieldsPerDataStreamLimit: 2048
  contents:
  - description: The main package manifest file
    type: file
    contentMediaType: "application/x-yaml"
    sizeLimit: 5MB
    name: "manifest.yml"
    required: true
    $ref: "./manifest.spec.yml"
  - description: The package's CHANGELOG file
    type: file
    contentMediaType: "application/x-yaml"
    name: "changelog.yml"
    required: true
    $ref: "./changelog.spec.yml"
  - description: The package's NOTICE file
    type: file
    contentMediaType: "text/plain"
    name: "NOTICE.txt"
    required: false
  - description: The package's license file
    type: file
    contentMediaType: "text/plain"
    name: "LICENSE.txt"
    required: false
  - description: Folder containing data stream definitions
    type: folder
    name: data_stream
    required: false
    $ref: "./data_stream/spec.yml"
  - description: Folder containing documentation for the package
    type: folder
    name: docs
    required: true
    $ref: "./docs/spec.yml"
  - description: Folder containing agent-related definitions
    type: folder
    name: agent
    required: false
    $ref: "./agent/spec.yml"
  - description: Folder containing Kibana assets used by the package
    type: folder
    name: kibana
    required: false
    $ref: "./kibana/spec.yml"
  - description: Folder containing development resources
    type: folder
    name: _dev
    required: false
    visibility: private
    $ref: "./_dev/spec.yml"
  - description: Folder containing Elasticsearch assets used by the package
    type: folder
    name: elasticsearch
    required: false
    $ref: "./elasticsearch/spec.yml"
  - description: Configuration file to process the results returned from the package validation. This file is just for package validation and it should be ignored when installing or using the package.
    type: file
    contentMediaType: "application/x-yaml"
    name: "validation.yml"
    required: false
    $ref: "./validation.spec.yml"
  - description: Folder containing images for the package
    type: folder
    name: img
    required: false
    $ref: "./img/spec.yml"

versions:
  - before: 3.2.2
    patch:
      - op: remove
        path: "/contents/11" # Definition for img folder.
```
