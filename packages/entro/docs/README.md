# Entro

## Overview

[Entro Security](https://entro.security/) allows you to discover, monitor, and protect non-human identities (NHIs) and secrets. Entro Security also provides management of the lifecycle of these identities and secrets, from creation to rotation.

Use the Entro integration with Elastic to monitor your exposed secrets and types. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference audit logs when troubleshooting an issue.

For example, if you wanted to see what types of secrets are being exposed more than usual you could look at the Entro audit logs to isolate this information.

## Data streams
The Entro Security integration collects logs that help you keep a record of security events related to Non-Human Identities (NHIs) and secrets. Right

**Audit:** Audit allows collecting Audit Log Events
The Audit data stream collects detailed events about exposed secrets discovered by the Entro platform. This includes the type of secret, where it was found, and the value of the secret itself. See more details in the Logs reference.

## Requirements
You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This integration has the following third-party requirements:

An active Entro Security platform subscription.
An API Token generated from the Entro Security platform with permissions to access the audit log endpoints.

## Setup

### Before setting up the integration, you will need credentials to connect to the Entro Security API.

Log in to your Entro Security platform and generate an API Token. Note keep this token private and secure.

Identify the base URL for your Entro API endpoint. When prompted during setup, you will need to provide this information.

## Reference

## Logs reference

### Audit

The audit data stream provides events from the Entro Security /v1/scan/auditLogs endpoint. This data stream enriches the raw logs with ECS fields and categorizes the event for security analysis.

#### Example

**Exported fields**

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2025-05-27T20:12:44.000Z",
    "agent": {
        "ephemeral_id": "02e0b0b3-0669-46e0-9595-9cebc4e47721",
        "id": "e5b2169f-6a42-482f-b8dc-5f55da82499d",
        "name": "elastic-agent-82489",
        "type": "filebeat",
        "version": "8.17.4"
    },
    "data_stream": {
        "dataset": "entro.audit",
        "namespace": "29645",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e5b2169f-6a42-482f-b8dc-5f55da82499d",
        "snapshot": false,
        "version": "8.17.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "entro.audit",
        "id": "105d6a3d-6468-4fcc-994e-f525011c53cf",
        "ingested": "2025-07-08T17:25:00Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "elastic-agent-82489"
    },
    "input": {
        "type": "cel"
    },
    "log": {
        "origin": {
            "file": {
                "line": 878
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "entro-event"
    ],
    "vulnerability": {
        "category": [
            "Secret"
        ],
        "description": "GENERIC_CREDS_WINDOWS_PASSWORD",
        "value": "asd123123"
    }
}
```
