# Entro

## Overview

[Entro Security](https://entro.security/) allows you to discover, monitor, and protect non-human identities (NHIs) and secrets. Entro Security also provides management of the lifecycle of these identities and secrets, from creation to rotation.

Use the Entro integration with Elastic to monitor your exposed secrets and types. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference audit logs when troubleshooting an issue.

For example, if you wanted to see what types of secrets are being exposed more than usual you could look at the Entro audit logs to isolate this information.

## Data streams
The Entro Security integration collects logs that help you keep a record of security events related to Non-Human Identities (NHIs) and secrets.

**Audit:** Audit allows collecting Audit Log Events
The Audit data stream collects detailed events about exposed secrets discovered by the Entro platform. This includes the type of secret, where it was found, and the value of the secret itself. See more details in the Logs reference.

## Requirements
Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Collect data from the Entro Security API

Log in to your Entro Security platform and generate an API Token. Note keep this token private and secure.

Identify the base URL for your Entro API endpoint. When prompted during setup, you will need to provide this information.

## Reference

## Logs reference

### Audit

The audit data stream provides events from the Entro Security /v1/scan/auditLogs endpoint. This data stream enriches the raw logs with ECS fields and categorizes the event for security analysis.

#### Example

**Exported fields**

{{event "audit"}}
