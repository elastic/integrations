---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/system-testing.html
---

# System testing [system-testing]

Elastic Packages comprise of data streams. A system test exercises the end-to-end flow of data for a package’s data stream — from ingesting data from the package’s integration service all the way to indexing it into an {{es}} data stream.


## Conceptual process [system-concepts]

Conceptually, running a system test involves the following steps:

1. Deploy the {{stack}}, including {{es}}, {{kib}}, and the {{agent}}. This step takes time. so you should typically do it once as a prerequisite to running system tests on multiple data streams.
2. Enroll the {{agent}} with {{fleet}} (running in the {{kib}} instance). This step also can be done once, as a prerequisite.
3. Depending on the Elastic Package whose data stream is being tested, deploy an instance of the package’s integration service.
4. Create a test policy that configures a single data stream for a single package.
5. Assign the test policy to the enrolled Agent.
6. Wait a reasonable amount of time for the Agent to collect data from the integration service and index it into the correct {{es}} data stream.
7. Query the first 500 documents based on `@timestamp` for validation.
8. Validate mappings are defined for the fields contained in the indexed documents.
9. Validate that the JSON data types contained `_source` are compatible with mappings declared for the field.
10. Delete test artifacts and tear down the instance of the package’s integration service.
11. Once all desired data streams have been system tested, tear down the {{stack}}.


## Limitations [system-test-limitations]

At the moment, system tests have limitations. The salient ones are: * There isn’t a way to assert that the indexed data matches data from a file (e.g. golden file testing).


## Defining a system test [system-test-definition]

Packages have a specific folder structure (only relevant parts shown).

```bash
<package root>/
  data_stream/
    <data stream>/
      manifest.yml
  manifest.yml
```

To define a system test we must define configuration on at least one level: a package or a data stream’s one.

First, we must define the configuration for deploying a package’s integration service. We can define it on either the package level:

```bash
<package root>/
  _dev/
    deploy/
      <service deployer>/
        <service deployer files>
```

or the data stream’s level:

```bash
<package root>/
  data_stream/
    <data stream>/
      _dev/
        deploy/
          <service deployer>/
            <service deployer files>
```

`<service deployer>` - a name of the supported service deployer:

* `docker` - Docker Compose
* `k8s` - Kubernetes
* `tf` - Terraform


### Docker Compose service deployer [system-docker-compose]

The `<service deployer files>` must include a `docker-compose.yml` file when using the Docker Compose service deployer. The `docker-compose.yml` file defines the integration service for the package. For example, if your package has a logs data stream, the log files from your package’s integration service must be written to a volume. For example, the `apache` package has the following definition in it’s integration service’s `docker-compose.yml` file.

```bash
version: '2.3'
services:
  apache:
    # Other properties such as build, ports, etc.
    volumes:
      - ${SERVICE_LOGS_DIR}:/usr/local/apache2/logs
```

Here, `SERVICE_LOGS_DIR` is a special keyword. It is something that we will need later.


### Terraform service deployer [system-terraform]

When using the Terraform service deployer, the `<service deployer files>` must include at least one `*.tf` file. The `*.tf` files define the infrastructure using the Terraform syntax. The Terraform-based service can be handy to boot up resources using a selected cloud provider and use them for testing (e.g. observe and collect metrics).

Sample `main.tf` definition:

```bash
variable "TEST_RUN_ID" {
  default = "detached"
}

provider "aws" {}

resource "aws_instance" "i" {
  ami           = data.aws_ami.latest-amzn.id
  monitoring = true
  instance_type = "t1.micro"
  tags = {
    Name = "elastic-package-test-${var.TEST_RUN_ID}"
  }
}

data "aws_ami" "latest-amzn" {
  most_recent = true
  owners = [ "amazon" ] # AWS
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*"]
  }
}
```

Notice the use of the `TEST_RUN_ID` variable. It contains a unique ID, which can help differentiate resources created in potential concurrent test runs.


### Kubernetes service deployer [system-kubernetes]

The Kubernetes service deployer requires the `_dev/deploy/k8s` directory to be present. It can include additional `*.yaml` files to deploy custom applications in the Kubernetes cluster (e.g. Nginx deployment). If no resource definitions (`*.yaml` files ) are needed, the `_dev/deploy/k8s` directory must contain an `.empty` file (to preserve the `k8s` directory under version control).

The Kubernetes service deployer needs [kind](https://kind.sigs.k8s.io/) to be installed and the cluster to be up and running:

```bash
wget -qO-  https://raw.githubusercontent.com/elastic/elastic-package/main/scripts/kind-config.yaml | kind create cluster --config -
```

Before executing system tests, the service deployer applies once the deployment of the {{agent}} to the cluster and links the kind cluster with the Elastic stack network - applications running in the kind cluster can reach {{es}} and {{kib}} instances. The {{agent}}'s deployment is not deleted after tests to shorten the total test execution time, but it can be reused.

See how to execute system tests for the Kubernetes integration (`pod` data stream):

```bash
elastic-package stack up -d -v # start the Elastic stack
wget -qO-  https://raw.githubusercontent.com/elastic/elastic-package/main/scripts/kind-config.yaml | kind create cluster --config -
elastic-package test system --data-streams pod -v # start system tests for the "pod" data stream
```


### Test case definition [system-test-case]

Next, we must define at least one configuration for each data stream that we want to system test. You can define multiple test cases for the same data stream.

*Hint: if you plan to define only one test case, you can consider the filename `test-default-config.yml`.*

```bash
<package root>/
  data_stream/
    <data stream>/
      _dev/
        test/
          system/
            test-<test_name>-config.yml
```

The `test-<test_name>-config.yml` file allows you to define values for package and data stream-level variables. For example, the `apache/access` data stream’s `test-access-log-config.yml` is shown below.

```bash
vars: ~
input: logfile
data_stream:
  vars:
    paths:
      - "{{SERVICE_LOGS_DIR}}/access.log*"
```

The top-level `vars` field corresponds to package-level variables defined in the `apache` package’s `manifest.yml` file. In the above example, we don’t override any of these package-level variables, so their default values, are used in the `apache` package’s `manifest.yml` file.

The `data_stream.vars` field corresponds to data stream-level variables for the current data stream (`apache/access` in the above example). In the above example we override the `paths` variable. All other variables are populated with their default values, as specified in the `apache/access` data stream’s `manifest.yml` file.

Notice the use of the `{{SERVICE_LOGS_DIR}}` placeholder. This corresponds to the `${SERVICE_LOGS_DIR}` variable we saw in the `docker-compose.yml` file earlier. In the above example, the `/usr/local/apache2/logs/access.log*` files located inside the Apache integration service container become available at the same path from {{agent}}'s perspective.

When a data stream’s manifest declares multiple streams with different inputs you can use the `input` option to select the stream to test. The first stream whose input type matches the `input` value will be tested. By default, the first stream declared in the manifest will be tested.


#### Placeholders [system-placeholders]

The `SERVICE_LOGS_DIR` placeholder is not the only one available for use in a data stream’s `test-<test_name>-config.yml` file. The complete list of available placeholders is shown below.

| Placeholder name | Data type | Description |
| --- | --- | --- |
| `Hostname` | string | Addressable host name of the integration service. |
| `Ports` | []int | Array of addressable ports the integration service is listening on. |
| `Port` | int | Alias for `Ports[0]`. Provided as a convenience. |
| `Logs.Folder.Agent` | string | Path to integration service’s logs folder, as addressable by the Agent. |
| `SERVICE_LOGS_DIR` | string | Alias for `Logs.Folder.Agent`. Provided as a convenience. |

Placeholders used in the `test-<test_name>-config.yml` must be enclosed in `{{` and `}}` delimiters, per Handlebars syntax.


## Running a system test [system-running-test]

Once the two levels of configurations are defined as described in the previous section, you are ready to run system tests for a package’s data streams.

First you must deploy the {{stack}}. This corresponds to steps 1 and 2 as described in the [Conceptual-process](/extend/pipeline-testing.md#pipeline-concepts) section.

```bash
elastic-package stack up -d
```

For a complete listing of options available for this command, run `elastic-package stack up -h` or `elastic-package help stack up`.

Next, you must set environment variables needed for further `elastic-package` commands.

```bash
$(elastic-package stack shellinit)
```

Next, you must invoke the system tests runner. This corresponds to steps 3 to 7 as described in the [Conceptual-process](/extend/pipeline-testing.md#pipeline-concepts) section.

If you want to run system tests for **all data streams** in a package, navigate to the package’s root folder (or any sub-folder under it) and run the following command.

```bash
elastic-package test system
```

If you want to run system tests for **specific data streams** in a package, navigate to the package’s root folder (or any sub-folder under it) and run the following command.

```bash
elastic-package test system --data-streams <data stream 1>[,<data stream 2>,...]
```

Finally, when you are done running all system tests, bring down the {{stack}}. This corresponds to step 8 in the [Conceptual-process](/extend/pipeline-testing.md#pipeline-concepts) section.

```bash
elastic-package stack down
```


### Generating sample events [system-sample-events]

As the system tests exercise an integration end-to-end from running the integration’s service all the way to indexing generated data from the integration’s data streams into {{es}}, it is possible to generate `sample_event.json` files for each of the integration’s data streams while running these tests.

```bash
elastic-package test system --generate
```
