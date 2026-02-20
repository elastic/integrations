---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/system-testing.html
---

# System Testing Guide [system-testing]

System tests validate the complete data flow from your integration service to Elasticsearch, ensuring that data is properly ingested, processed, and indexed. This guide covers setting up and running system tests using `elastic-package`.

For more information on system tests, please refer to [HOWTO: Writing system tests for a package](https://github.com/elastic/elastic-package/blob/main/docs/howto/system_testing.md)

## Quick Start [system-quickstart]

```bash
# Start the Elastic stack
elastic-package stack up -d

# Run system tests
cd packages/your-package
elastic-package test system

# Clean up
elastic-package stack down
```

## What System Tests Validate [system-validation]

System tests verify:
- Data ingestion from your service to the Elastic Agent
- Pipeline processing and field mappings
- Document indexing into Elasticsearch data streams
- Field type compatibility and mapping validation
- Integration configuration and policy deployment

The test framework automatically:
1. Deploys your integration service (Docker/Kubernetes/Terraform)
2. Configures the Elastic Agent with test policies
3. Collects and indexes sample data
4. Validates documents
5. Checks field mappings and data type compatibility
6. Cleans up test artifacts

## Setting Up System Tests [system-setup]

System tests require two main components:

### 1. Service Deployment Configuration

Define how to deploy your integration service for testing. Choose one of three deployment methods:

**Package-level deployment** (applies to all data streams):
```
<package-root>/
  _dev/
    deploy/
      docker/          # Docker Compose
      k8s/            # Kubernetes  
      tf/             # Terraform
```

**Data stream-level deployment** (specific to one data stream):
```
<package-root>/
  data_stream/
    <data-stream>/
      _dev/
        deploy/
          docker/
```

With the service deployer, you configure the service which will send data to your integration during the test. A live service can be configured to run and send data to the integration, to provide a realistic complete system test.

As running a live service is often not possible, mock data, using a real transport, is often used for system tests. For example, if a service provides data with syslog over UDP, instead of running a live service, the data can be sent by setting up a deployment which writes mock syslog data to a socket listening to UDP.
[elastic/stream](https://github.com/elastic/stream) is a utility which can be used with system tests to stream mock data to many types of protocols.

### 2. Test Case Configuration

Define test scenarios for each data stream:

```
<package-root>/
  data_stream/
    <data-stream>/
      _dev/
        test/
          system/
            test-<scenario>-config.yml
```

The test case configuration defines the agent and integration configuration used in the tests, as well as the service deployer configuration used.
## Deployment Methods [deployment-methods]

### Docker Compose [docker-deployment]

Most common for testing services that can run in containers.

**File structure:**
```
_dev/deploy/docker/
  docker-compose.yml
  Dockerfile (optional)
  config/ (optional)
```

**Example `docker-compose.yml`:**
```yaml
version: '2.3'
services:
  apache:
    image: httpd:2.4
    ports:
      - "80"
    volumes:
      - ${SERVICE_LOGS_DIR}:/usr/local/apache2/logs
    environment:
      - APACHE_LOG_LEVEL=info
```

**Key placeholders:**
- `${SERVICE_LOGS_DIR}` - Maps to log directory accessible by Agent
- `${HOSTNAME}` - Service hostname for Agent configuration

### Kubernetes [k8s-deployment]

Useful for testing Kubernetes-native integrations or when you need orchestration.

**Prerequisites:**
```bash
# Install kind and create cluster
wget -qO- https://raw.githubusercontent.com/elastic/elastic-package/main/scripts/kind-config.yaml | kind create cluster --config -
```

**File structure:**
```
_dev/deploy/k8s/
  deployment.yaml
  service.yaml
  .empty (if no YAML files needed)
```

**Example deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-test
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        ports:
        - containerPort: 80
```

### Terraform [terraform-deployment]

Best for cloud resources or complex infrastructure testing.

**File structure:**
```
_dev/deploy/tf/
  main.tf
  variables.tf (optional)
  outputs.tf (optional)
```

**Example `main.tf`:**
```
variable "TEST_RUN_ID" {
  default = "detached"
}

provider "aws" {
  region = "us-west-2"
}

resource "aws_instance" "test_instance" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  monitoring    = true
  
  tags = {
    Name = "elastic-package-test-${var.TEST_RUN_ID}"
  }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*"]
  }
}
```

**Built-in variables:**
- `TEST_RUN_ID` - Unique identifier for concurrent test isolation

## Test Configuration [test-config]

### Basic Configuration [basic-config]

**Example `test-default-config.yml`:**
```yaml
vars: ~  # Use package-level defaults
input: logfile  # Select input type if multiple exist
data_stream:
  vars:
    paths:
      - "{{SERVICE_LOGS_DIR}}/access.log*"
    exclude_files: [".gz$"]
```

### Advanced Configuration [advanced-config]

**Multiple test scenarios:**
```yaml
# test-custom-config.yml
vars:
  username: testuser
  password: testpass
data_stream:
  vars:
    hosts: ["{{Hostname}}:{{Port}}"]
    ssl.enabled: true
    period: 30s
```

**Testing specific input types:**
```yaml
# test-tcp-config.yml  
input: tcp
data_stream:
  vars:
    listen_address: "0.0.0.0"
    listen_port: 8080
```

### Configuration Placeholders [placeholders]

Use these placeholders in your test configuration:

| Placeholder | Type | Description |
|-------------|------|-------------|
| `{{Hostname}}` | string | Service hostname/IP |
| `{{Port}}` | int | First exposed port |
| `{{Ports}}` | []int | All exposed ports |
| `{{SERVICE_LOGS_DIR}}` | string | Log directory path for Agent |
| `{{Logs.Folder.Agent}}` | string | Same as SERVICE_LOGS_DIR |

**Example usage:**
```yaml
data_stream:
  vars:
    hosts: ["{{Hostname}}:{{Port}}"]
    paths: ["{{SERVICE_LOGS_DIR}}/*.log"]
    url: "http://{{Hostname}}:{{Ports.0}}/metrics"
```

### Configuration Options

For the complete list of options that can be used to define test case behaviour, refer to [Test case definition](https://github.com/elastic/elastic-package/blob/main/docs/howto/system_testing.md#test-case-definition).

## Running System Tests [running-tests]

### Environment Setup [env-setup]

```bash
# Start Elastic stack (one-time setup)
elastic-package stack up -d

# Verify stack is running
elastic-package stack status
```

### Test Execution [test-execution]

**Run all data streams:**
```bash
cd packages/your-package
elastic-package test system
```

**Run specific data streams:**
```bash
elastic-package test system --data-streams access,error
```

**Run with verbose output:**
```bash
elastic-package test system -v
```

**Generate sample events during testing:**
```bash
elastic-package test system --generate
```

**Run tests for specific test scenarios:**
```bash
elastic-package test system --data-streams access --test-config test-custom-config.yml
```

### Troubleshooting [troubleshooting]

It's generally easiest to develop system tests after other types of tests are written and passing, so you can isolate failure that might be caused by the system test infrastructure or configuration from problems that are caused by other parts of the integration.

**View detailed logs:**
```bash
elastic-package test system -v --report-format human
```

**Debug service deployment:**
```bash
# Check service logs
docker logs <service-container>

# For Kubernetes
kubectl logs deployment/nginx-test

# Check Agent status
elastic-package stack dump
```

**Keep the service running**
Using the `--defer-cleanup` flag, test case execution can be paused before cleanup, so you can inspect the state of the stack, for example what data exists in indices, after the tests have run and before the data is removed from elasticsearch.
```bash
elastic-package test system --defer-cleanup 10m
```

**Common issues:**
- **Service not reachable:** Check port mappings and network configuration
- **No data indexed:** Verify log paths and file permissions
- **Field mapping errors:** Check field types in pipeline configuration
- **Test timeout:** Increase wait time or check service startup

### Cleanup [cleanup]

```bash
# Clean up test artifacts
elastic-package clean

# Stop Elastic stack
elastic-package stack down
```

## Best Practices [best-practices]

### Test Design [test-design]

1. **Keep tests focused:** One service per data stream test
2. **Use realistic data:** Generate representative log/metric samples
3. **Test edge cases:** Include error conditions and malformed data
4. **Minimize resource usage:** Use lightweight service images
5. **Document dependencies:** Clearly specify external requirements

### Configuration Management [config-management]

1. **Use descriptive test names:** `test-error-logs-config.yml` vs `test-config.yml`
2. **Parameterize environments:** Use placeholders for hostnames/ports
3. **Version control everything:** Include all deployment and test files
4. **Test multiple scenarios:** Different input types, authentication methods
5. **Keep configurations minimal:** Override only necessary variables

### Performance [performance]

1. **Reuse stack deployment:** Don't restart for each test
2. **Parallel test execution:** Use `--data-streams` to test subsets

## Sample Event Generation [sample-events]

System tests can automatically generate `sample_event.json` files for documentation and validation:

```bash
# Generate samples during testing
elastic-package test system --generate

# Output location
packages/your-package/data_stream/your-stream/_dev/test/system/sample_event.json
```

These files are useful for:
- Documentation and examples
- Field reference validation
- Debugging data transformation issues
- Pipeline testing input data
