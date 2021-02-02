# Tips for building integrations

The section offers a set of tips for developers to improve integrations that they're working on. It combines hints, guidelines,
recommendations and tricks. Please consider this section as a live document that may evolve in the future, depending
on the business or technical requirements for the entire platform (Elastic Package Registry, Elastic Agent and Kibana).

## elastic-package

[elastic-package](https://github.com/elastic/elastic-package) is a command line tool, written in Go, used for developing Elastic packages. It can help you lint,
format, test, build, and promote your packages. This is the official builder tool to develop Integrations. See the
[Getting started](https://github.com/elastic/elastic-package#getting-started) section to ramp up quickly and review its features.

If you need the revision of elastic-package in the correct version (the same one as the CI uses), which is defined in `go.mod`, use the following command
(in the Integrations repository):

```bash
$ go build github.com/elastic/elastic-package
$ ./elastic-package help
```

## New integrations

### Manifest files

1. Set the initial version to `0.1.0`.

   Tagging the integration with a lower version, like `0.0.1`, means that it's at very early stage and most likely
   it doesn't work at all. It might be partially developed.

2. Set the initial release to `beta`.

   If you working on the new integration that will be release in the next release cycle, you can tag it with `beta`.
   Otherwise, feel free to stick with the `experimental` tag.

3. Select one or two categories for the integration.

   The list of available categories is present in the Package Registry source: https://github.com/elastic/package-registry/blob/e93e801a6dfbfa6f83c8b69f6e9405603151f937/util/package.go#L27-L51

4. Make sure that the version condition for Kibana is set to `^7.10.0` and not `>=7.10.0`. Otherwise the package is also in 8.0.0 but we do not know today if it will actually be compatible with >= 8.0.0.

   ```yaml
   conditions:
     kibana.version: '^7.10.0'
   ```

5. Set the proper package owner (either Github team or personal account)

   Good candidates for a team: `elastic/integrations-platforms`, `elastic/integrations-services`

## All integrations

### Development

1. When you're developing integrations and you'd like to propagate your changes to the package registry, first rebuild the package:

   ```bash
   $ cd packages/apache
   $ elastic-package build
   ```

   Then, rebuild and redeploy the Package Registry:

   _It's important to execute the following command in the Integrations repository._

   ```bash
   $ elastic-package stack up -v -d --services package-registry
   ```

   Explanation: it's much faster to rebuild and restart the container with the Package Registry, than work with
   mounted volumes.

### Code reviewers

1. Ping "Team:Integrations".

   Use the team label to notify relevant team members about the incoming pull request.

#### Manifest files

1. Descriptions of configuration options should be as short as possible.

   Remember to keep only the meaningful information about the configuration option.

   Good candidates: references to the product configuration, accepted string values, explanation.

   Bad candidates: *Collect metrics from A, B, C, D,... X, Y, Z datasets.*

2. Descriptions should be human readable.

   Try to rephrase sentences like: *Collect foo_Bar3 metrics*, into *Collect Foo Bar metrics*.

3. Description should be easy to understand.

   Simplify sentences, don't provide information about the input if not required.

   Bad candidate: *Collect application logs (log input)*

   Good candidates: *Collect application logs*, *Collect standard logs for the application*

4. Letter casing is important for screenshot descriptions.

   These descriptions are visualized in the Kibana UI. It would be better experience to have them clean and consistent.

   Bad candidate: *filebeat running on ec2 machine*

   Good candidates: *Filebeat running on AWS EC2 machine*

#### CI

1. Run `elastic-package check` and `elastic-package test` locally.

   If you want to verify if your integration works as intended, you can execute the same steps as CI:

   ```bash
   $ cd packages/apache
   $ elastic-package check -v
   $ elastic-package test -v
   ```

   Keep in mind that the `elastic-package test` command requires a live cluster running and exported environment variables.
   The environment variables can be set with `eval "$(elastic-package stack shellinit)"`.


#### Fields

1. Remove empty fields files.

   If you notice that fields file (e.g. `package-fields.yml`) doesn't contain any field definitions or it defines root only,
   feel free to remove it.

   Bad candidate:
   ```yaml
   - name: mypackage.mydataset
     type: group
     release: experimental
   ```
