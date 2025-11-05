# Neon Cyber Integration for Elastic

## Overview

The [Neon Cyber](https://www.neoncyber.com) integration for Elastic enables collection of workforce events and cybersecurity detections from the Neon [API](https://api.neoncyber.io/v1/docs])

## What data does this integration collect?

The Neon Cyber integration collects log messages of the following types:
* Events including geo, navigation, auth, app, extensions, and platform
* Detections including compromised credentials, phishing, malware, and more

### What do I need to use this integration?

This integration requires you to generate a developer API key from the account settings of your Neon Cyber instance.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.


## Inputs used

### Event Logs

{{event "events"}}

{{fields "events"}}

### Detection Logs

{{event "detections"}}

{{fields "detections"}}
