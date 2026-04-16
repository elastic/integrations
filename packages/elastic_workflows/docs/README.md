# Elastic Workflows

Monitor your Elastic Workflows with out-of-the-box dashboards.

## Dashboards

### Workflows Execution Overview

Provides a high-level view of workflow execution activity:

- **Executions over time** — total workflow runs bucketed by time interval
- **Status breakdown** — proportion of completed, failed, timed out, and cancelled executions
- **Failure rate** — percentage of executions ending in error or timeout
- **Average duration** — mean execution time across all workflows
- **Top workflows by execution count** — most frequently triggered workflows
- **Top failing workflows** — workflows with the highest failure rates

## Data sources

This package includes dashboards that read from the following Elasticsearch indices created by the Workflows Execution Engine:

| Index | Description |
|-------|-------------|
| `.workflows-executions` | Workflow-level execution records |
| `.workflows-step-executions` | Per-step execution records |
| `.workflows-execution-data-stream-logs` | Execution log entries |

## Requirements

- Kibana 9.3.0 or later (Elastic Workflows)
- Workflows must be available in your deployment
