---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/asset-testing.html
---

# Asset testing [asset-testing]

Elastic Packages define assets to be loaded into {{es}} and {{kib}}. Asset loading tests exercise install a package to ensure that its assets are loaded into {{es}} and {{kib}} as expected.


## Conceptual process [asset-testing-concepts]

Conceptually, running an asset load test involves the following steps:

1. Build the package.
2. Deploy {{es}}, {{kib}}, and the {{package-registry}} (all of which are part of the {{stack}}). This step takes time, so you should typically do it once as a prerequisite to running asset loading tests on multiple packages.
3. Install the package.
4. Use various {{kib}} and {{es}} APIs to confirm that the package assets were loaded into {{kib}} and {{es}} as expected.
5. Remove the package.


## Define an asset loading test [define-asset-test]

As a package developer, there is no work required to define an asset loading test for your package. All the necessary information is contained in the package files.


## Run an asset loading test [running-asset-test]

First, you must build your package. This step corresponds to step 1 in the [Conceptual process](#asset-testing-concepts) section.

Navigate to the root folder of the package, or any sub-folder under it, and run the following command.

```bash
elastic-package build
```

Next, deploy {{es}}, {{kib}}, and the {{package-registry}}. This step corresponds to step 2 in the [Conceptual process](#asset-testing-concepts) section.

```bash
elastic-package stack up -d
```

To view a list of the available options for this command, run `elastic-package stack up -h` or `elastic-package help stack up`.

Next, set the environment variables that are required for additional `elastic-package` commands.

```bash
$(elastic-package stack shellinit)
```

Next, invoke the asset loading test runner. This step corresponds to steps 3 to 5 in the [Conceptual process](#asset-testing-concepts) section.

Navigate to the root folder of the package, or any sub-folder under it, and run the following command.

```bash
elastic-package test asset
```

Finally, when all the asset loading tests have completed, bring down the {{stack}}. This step corresponds to step 4 in the [Conceptual process](#asset-testing-concepts) section.

```bash
elastic-package stack down
```

