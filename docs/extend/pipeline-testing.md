---
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/pipeline-testing.html
---

# Pipeline Testing Guide [pipeline-testing]

Pipeline tests validate your Elasticsearch ingest pipelines by feeding them test data and comparing the output against expected results. This is essential for ensuring your data transformation logic works correctly before deploying to production.
Input to the tests are log or json files at the point that they would be ingested into elasticsearch, after any agent processors would run on a real integration. Output for the tests are documents after they have been processed by the ingest pipeline, and would be written to Elasticsearch indices in a real integration.

For more information on pipeline tests, refer to [https://github.com/elastic/elastic-package/blob/main/docs/howto/pipeline_testing.md](https://github.com/elastic/elastic-package/blob/main/docs/howto/pipeline_testing.md).

## Quick Start [pipeline-quickstart]

```bash
# Start Elasticsearch
elastic-package stack up -d --services=elasticsearch
$(elastic-package stack shellinit)

# Run pipeline tests
cd packages/your-package
elastic-package test pipeline

# Generate expected results (first time setup)
elastic-package test pipeline --generate

# Clean up
elastic-package stack down
```

## What Pipeline Tests Validate [pipeline-validation]

Pipeline tests verify:
- Field extraction and parsing logic
- Data type conversions and formatting
- ECS field mapping compliance
- Error handling and edge cases
- Performance of complex processors

## Test Structure [test-structure]

Pipeline tests live in the data stream's test directory:

```
packages/your-package/
  data_stream/
    your-stream/
      _dev/
        test/
          pipeline/
            test-sample.log                # Raw log input
            test-sample.log-config.yml     # Test configuration (optional)
            test-sample.log-expected.json  # Expected output
            test-events.json               # JSON event input
            test-events.json-expected.json # Expected output
```

## Test Input Types [input-types]

### Raw Log Files [raw-logs]

Best for testing log-based integrations. Use actual log samples from your application.

**Example: `test-access.log`**
```
127.0.0.1 - - [07/Dec/2016:11:04:37 +0100] "GET /test1 HTTP/1.1" 404 571 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36"
127.0.0.1 - - [07/Dec/2016:11:04:58 +0100] "GET / HTTP/1.1" 304 0 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:49.0) Gecko/20100101 Firefox/49.0"
```

**Advantages:**
- Use real application logs
- Natural multiline handling
- Easy to collect samples from production
- Good for regression testing

### JSON Events [json-events]

Best for testing structured data inputs or when you need precise control over input fields.

**Example: `test-metrics.json`**
```json
{
  "events": [
    {
      "@timestamp": "2024-01-15T10:30:00.000Z",
      "message": "{\"cpu_usage\": 85.2, \"memory_usage\": 1024}",
      "agent": {
        "hostname": "web-server-01"
      }
    },
    {
      "@timestamp": "2024-01-15T10:31:00.000Z", 
      "message": "{\"cpu_usage\": 72.8, \"memory_usage\": 896}",
      "agent": {
        "hostname": "web-server-01"
      }
    }
  ]
}
```

**Advantages:**
- Precise control over input data
- Perfect for metrics and structured data
- Easy to test edge cases
- Good for mocking complex scenarios

## Test Configuration [test-config]

Configure test behavior with optional `-config.yml` files:

### Basic Configuration [basic-config]

**Example: `test-access.log-config.yml`**
```yaml
# Add static fields to all events
fields:
  "@timestamp": "2020-04-28T11:07:58.223Z"
  ecs.version: "8.0.0"
  event.dataset: "nginx.access"
  event.category: ["web"]

# Handle dynamic/variable fields
dynamic_fields:
  url.original: "^/.*$"        # Regex pattern matching
  user_agent.original: ".*"    # Any user agent
  source.ip: "^\\d+\\.\\d+\\.\\d+\\.\\d+$"  # IP addresses

# Fields that should be keywords despite numeric values
numeric_keyword_fields:
  - http.response.status_code
  - network.iana_number
```

### Multiline Configuration [multiline-config]

For logs that span multiple lines:

**Example: `test-java-stacktrace.log-config.yml`**
```yaml
multiline:
  first_line_pattern: "^\\d{4}-\\d{2}-\\d{2}"  # Date at start of new entry

fields:
  "@timestamp": "2024-01-15T10:30:00.000Z"
  log.level: "ERROR"
```

### Advanced Configuration [advanced-config]

**Example: `test-complex.log-config.yml`**
```yaml
# Static fields
fields:
  "@timestamp": "2024-01-15T10:30:00.000Z"
  event.dataset: "myapp.logs"
  tags: ["test", "development"]

# Dynamic patterns
dynamic_fields:
  # Match any UUID format
  user.id: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
  # Match any session ID
  session.id: "^[A-Za-z0-9]{32}$"
  # Match timestamps in different formats
  "@timestamp": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}"

# Convert these numeric values to keywords
numeric_keyword_fields:
  - process.pid
  - http.response.status_code

# Multiline Java stack traces
multiline:
  first_line_pattern: "^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}"
  max_lines: 50
```

## Expected Results [expected-results]

Define expected output in `-expected.json` files:

**Example: `test-access.log-expected.json`**
```json
{
  "expected": [
    {
      "@timestamp": "2016-12-07T10:04:37.000Z",
      "event": {
        "category": ["web"],
        "dataset": "nginx.access",
        "outcome": "failure"
      },
      "http": {
        "request": {
          "method": "GET"
        },
        "response": {
          "status_code": 404,
          "body": {
            "bytes": 571
          }
        },
        "version": "1.1"
      },
      "source": {
        "ip": "127.0.0.1"
      },
      "url": {
        "original": "/test1"
      },
      "user_agent": {
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36"
      }
    }
  ]
}
```

## Running Pipeline Tests [running-tests]

### Environment Setup [env-setup]

```bash
# Start only Elasticsearch (faster than full stack)
elastic-package stack up -d --services=elasticsearch

# Set environment variables
$(elastic-package stack shellinit)

# Verify Elasticsearch is running
curl -X GET "localhost:9200/_cluster/health"
```

### Basic Test Execution [basic-execution]

```bash
# Run all pipeline tests in current package
elastic-package test pipeline

# Run tests for specific data streams
elastic-package test pipeline --data-streams access,error

# Run with verbose output
elastic-package test pipeline -v

# Run tests and show detailed diff on failure
elastic-package test pipeline --report-format human
```

### Generating Expected Results [generating-results]

Use this for initial test setup or when updating pipelines:

```bash
# Generate expected results for all tests
elastic-package test pipeline --generate

# Generate for specific data streams
elastic-package test pipeline --data-streams access --generate

# Review generated files before committing
git diff _dev/test/pipeline/
```

Verify the correctness of the generated expected files. `elastic-package` will create the expected files from the output of the current ingest pipeline. It cannot know if this is actually correct; you will need to verify this.

**Workflow tip:**
1. Create test input files first
2. Run with `--generate` to create expected results
3. Review generated output for correctness
4. Commit both input and expected files
5. Future runs will validate against these expectations

### Test Development Workflow [test-workflow]

```bash
# 1. Create test input
echo 'error log entry here' > _dev/test/pipeline/test-error.log

# 2. Generate expected results
elastic-package test pipeline --data-streams your-stream --generate

# 3. Review generated output
cat _dev/test/pipeline/test-error.log-expected.json

# 4. Run tests to validate
elastic-package test pipeline --data-streams your-stream

# 5. Iterate on pipeline, then regenerate when needed
elastic-package test pipeline --data-streams your-stream --generate
```

### Troubleshooting [troubleshooting]

**Common issues and solutions:**

**Test failures with field mismatches:**
```bash
# Run with verbose output to see detailed diffs
elastic-package test pipeline -v --report-format human

# Check for dynamic fields that need configuration
# Add patterns to dynamic_fields in config file
```

**Pipeline not found errors:**
```bash
# Verify pipeline files exist
ls -la data_stream/*/elasticsearch/ingest_pipeline/

# Check pipeline syntax
elastic-package lint

# Manually test pipeline upload
curl -X PUT "localhost:9200/_ingest/pipeline/your-pipeline" \
  -H "Content-Type: application/json" \
  -d @data_stream/your-stream/elasticsearch/ingest_pipeline/default.yml
```

**Multiline parsing issues:**
```bash
# Test multiline patterns separately
echo -e "line1\nline2\nline3" | grep -P "^your-pattern"

# Validate regex patterns
python3 -c "import re; print(re.match(r'^your-pattern', 'test-line'))"
```

**Field type mismatches:**
```bash
# Check mapping definitions
cat data_stream/*/fields/fields.yml

# Add numeric fields to config if needed
# numeric_keyword_fields: [field.name]
```

## Best Practices [best-practices]

### Test Design [test-design]

1. **Test real data**: Use actual log samples from production. Be sure to sanitize any sensitive data before committing to source control.
2. **Cover edge cases**: Include malformed, empty, and unusual inputs
3. **Test error conditions**: Verify graceful handling of bad data
4. **Keep tests focused**: One test file per scenario
5. **Use descriptive names**: `test-successful-login.log` vs `test1.log`

### Test Coverage [test-coverage]

Ensure comprehensive coverage:
```bash
# Test different log levels
test-debug.log
test-info.log  
test-warn.log
test-error.log

# Test different formats
test-json-format.log
test-plain-format.log
test-multiline-stacktrace.log

# Test edge cases
test-empty-lines.log
test-malformed.log
test-unicode.log
```

### Configuration Management [config-management]

1. **Minimize static fields**: Only add what's necessary
2. **Use dynamic patterns carefully**: Too broad patterns may hide real issues
3. **Document regex patterns**: Add comments explaining complex patterns

## Debugging Tips [debugging-tips]

### Interactive Testing [interactive-testing]

```bash
# Test individual pipeline components
curl -X POST "localhost:9200/_ingest/pipeline/_simulate" \
  -H "Content-Type: application/json" \
  -d '{
    "pipeline": {"processors": [{"grok": {"field": "message", "patterns": ["your-pattern"]}}]},
    "docs": [{"_source": {"message": "test log line"}}]
  }'
```

### Field Inspection [field-inspection]

```bash
# Check what fields are actually generated
elastic-package test pipeline --generate
jq '.expected[0] | keys' test-sample.log-expected.json
```