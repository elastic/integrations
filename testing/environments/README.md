## Cheat sheet: elastic-package

Update already downloaded Docker images:

`elastic-package stack update -v`

Quickly boot up the stack use:

_Run from within the Integrations repository to consider local package sources (expected for package development)._

`elastic-package stack up -d -v`

Take down the stack:

`elastic-package stack down -v`

Advanced: if you need to modify the internal Docker compose definition, edit files in `~/.elastic-package/stack`, but
keep in mind that these files shouldn't be modified and your changes will be reverted once you update the `elastic-package`:

```bash
$tree ~/.elastic-package/stack
/Users/JohnDoe/.elastic-package/stack
├── Dockerfile.package-registry
├── development
├── kibana.config.yml
├── package-registry.config.yml
└── snapshot.yml
```

## Cheat sheet: reload local changes in Kibana

Rebuild the modified package:

`mage build` (for all packages)

or

```bash
$ cd packages/apache
$ elastic-package build
```

(for single package, in this sample - _Apache_).

Rebuild and restart the package-registry image:

`elastic-package stack up -v -d --services package-registry`

You should see your latest changes in the Kibana UI.