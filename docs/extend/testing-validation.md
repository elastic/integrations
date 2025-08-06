---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/testing-and-validation.html
---

# Testing and validation [testing-and-validation]

1. Build the package you’d like to verify (e.g. `apache`):

    ```bash
    cd apache
    elastic-package build
    ```

2. Start the testing environment:

    Run from inside the Integrations repository:

    ```bash
    elastic-package stack up -d -v
    ```

    The command above will boot up the {{stack}} ({{es}}, {{kib}}, and {{package-registry}}) using Docker containers. It rebuilds the {{package-registry}} Docker image using packages built in step 1. and boots up the {{package-registry}}.

    To reload the already deployed {{package-registry}}, use the following command:

    ```bash
    elastic-package stack up -v -d --services package-registry
    ```

3. Verify that your integration is available in the correct version. For example, MySQL: [http://localhost:8080/search?package=mysql](http://localhost:8080/search?package=mysql) (use `experimental=true` parameter if the package is in experimental version. Alternatively set `release` to `beta` or higher in your package’s `manifest.yml`, if appropriate.)

    ```json
    [
      {
        "description": "MySQL Integration",
        "download": "/epr/mysql/mysql-0.0.1.tar.gz",
        "icons": [
          {
            "src": "/package/mysql/0.0.1/img/logo_mysql.svg",
            "title": "logo mysql",
            "size": "32x32",
            "type": "image/svg+xml"
          }
        ],
        "name": "mysql",
        "path": "/package/mysql/0.0.1",
        "title": "MySQL",
        "type": "integration",
        "version": "0.0.1"
      }
    ]
    ```

    The `elastic-package stack` provides an enrolled instance of the {{agent}}. Use that one instead of a local application if you can run the service (you’re integrating with) in the Docker network and you don’t need to rebuild the Elastic-Agent or it’s subprocesses (e.g. {{filebeat}} or {{metricbeat}}). The service Docker image can be used for <<system-testing,system testing]. If you prefer to use a local instance of the {{agent}}, proceed with steps 4 and 5:

4. (Optional) Download the [{{agent}}](https://www.elastic.co/downloads/elastic-agent).
5. (Optional) Enroll the {{agent}} and start it:

    Use the "Enroll new agent" option in the {{kib}} UI (Ingest Manager → Fleet → Create user and enable Fleet) and run a similar command:

    ```bash
    ./elastic-agent enroll http://localhost:5601/rel cFhNVlZIRUIxYjhmbFhqNTBoS2o6OUhMWkF4SFJRZmFNZTh3QmtvR1cxZw==
    ./elastic-agent run
    ```

    The `elastic-agent` starts two other processes: `metricbeat` and `filebeat`.

6. Run the product you’re integrating with (e.g. a docker image with MySQL).
7. Install package.

    Click out the configuration in the {{kib}} UI, deploy it and wait for the agent to pick out the updated configuration.

8. Navigate with {{kib}} UI to freshly installed dashboards, verify the metrics/logs flow.

## Use test runners [_use_test_runners]

`elastic-package` provides different types of test runners. See [*Test an integration*](/extend/testing.md) to learn about the various methods for testing packages.

The `test` subcommand requires a reference to the live {{stack}}. You can define service endpoints using environment variables. If you’re using the {{stack}} created with `elastic-package`, you can use export endpoints with `elastic-package stack shellinit`:

```bash
$ eval "$(elastic-package stack shellinit)"
```

To preview environment variables:

```bash
$ elastic-package stack shellinit
export ELASTIC_PACKAGE_ELASTICSEARCH_HOST=http://127.0.0.1:9200
export ELASTIC_PACKAGE_ELASTICSEARCH_USERNAME=elastic
export ELASTIC_PACKAGE_ELASTICSEARCH_PASSWORD=changeme
export ELASTIC_PACKAGE_KIBANA_HOST=http://127.0.0.1:5601
```


## Review test coverage [_review_test_coverage]

The `elastic-package` tool can calculate test coverage for packages and export coverage reports in the [Cobertura](https://cobertura.github.io/cobertura/) format. Coverage reports contain information about present or missing pipelines, and system and static tests, so they help in identifying untested integrations. For pipeline tests, it features detailed source-code coverage reports highlighting the ingest processors that are covered during testing.

The CI job runner collects coverage data and stores them together with build artifacts. The Cobertura plugin (**Coverage Report** tab) uses this data to visualize test coverage grouped by package, data stream, and test type.


## Cobertura format vs. package domain language [_cobertura_format_vs_package_domain_language]

As the Cobertura report format refers to packages, classes, methods, and such, unfortunately it doesn’t map easily onto the packages domain. We have decided to make a few assumptions for the Cobertura classification:

* **Package**: `integration`
* **File**: `data stream`
* **Class**: test type (`pipeline tests`, `system tests`, etc.)
* **Method**: "OK" if there are any tests present.

For pipeline tests, which include actual source-code coverage, the mapping is different:

* **Package**: `integration.data_stream`
* **File**: Path to ingest pipeline file
* **Class**: Ingest pipeline name
* **Method**: Ingest processor
