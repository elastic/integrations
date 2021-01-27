# Testing and validation

## Run the whole setup

1. Build the package you'd like to verify (e.g. `apache`):
   ```bash
   $ cd apache
   $ elastic-package build
   ```

2. Start testing environment:

   _Run from inside the Integrations repository._

   ```bash
   $ elastic-package stack up -d -v
   ```

   The command above will boot up the Elastic stack (Elasticsearch, Kibana, Package Registry) using Docker containers.
   It rebuilds the Package Registry Docker image using packages built in step 1. and boots up the Package Registry.

   To reload the already deployed Package Registry use the following command:

   ```bash
   $ elastic-package stack up -v -d --services package-registry
   ```

3. Verify that your integration is available (in the right version), e.g. MySQL: http://localhost:8080/search?package=mysql (use
   `experimental=true` parameter if the package is in experimental version. Alternatively set `release` to `beta` or higher in your
   package's `manifest.yml`, if appropriate.)

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

The `elastic-package stack` provides an enrolled instance of the Elastic Agent. Use that one instead of a local application
if you can run the service (you're integrating with) in the Docker network. The service Docker image can be used for [system
testing](https://github.com/elastic/elastic-package/blob/master/docs/howto/system_testing.md). If you prefer to use a local
instance of the Elastic Agent

4. Download the Elastic-Agent from https://www.elastic.co/downloads/elastic-agent

5. Enroll the agent and start it:

   Use the "Enroll new agent" option in the Kibana UI (Ingest Manager -> Fleet -> Create user and enable Fleet) and run a similar command:

   ```bash
   $ ./elastic-agent enroll http://localhost:5601/rel cFhNVlZIRUIxYjhmbFhqNTBoS2o6OUhMWkF4SFJRZmFNZTh3QmtvR1cxZw==
   $ ./elastic-agent run
   ```

   The `elastic-agent` will start two other processes - `metricbeat` and `filebeat`.

6. Run the product you're integrating with (e.g. a docker image with MySQL).

7. Install package.

    Click out the configuration in the Kibana UI, deploy it and wait for the agent to pick out the updated configuration.

8. Navigate with Kibana UI to freshly installed dashboards, verify the metrics/logs flow.

## Use test runners

`elastic-package` provides different types of test runners. Review [howto](https://github.com/elastic/elastic-package/tree/master/docs/howto) guides
to learn about the various methods for testing packages.

The `test` subcommand requires a reference to the live Elastic stack. Service endpoints can be defined via environment variables.
If you're using the Elastic stack created with `elastic-package`, you can use export endpoints with `elastic-package stack shellinit`:

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