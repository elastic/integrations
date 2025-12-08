# Entity ID Enricher

The Entity ID Enricher integration provides automatic, stable entity identification for users and hosts across all Elastic logs. This integration computes `user.entity.id` and `host.entity.id` fields using deterministic ranking rules, enabling reliable entity analytics without requiring transforms or additional processing.

## Overview

This integration deploys a global ingest pipeline that automatically enriches all `logs-*` data streams with stable entity identifiers. The enrichment happens at ingestion time using a Painless script that follows well-defined ranking systems for both user and host entities.

### Key Features

- ✅ **Automatic enrichment** of all `logs-*` data streams (from any integration or custom source)
- ✅ **Non-destructive**: Never overwrites existing `user.entity.id` or `host.entity.id` values
- ✅ **Error-safe**: Handles missing fields gracefully without throwing exceptions
- ✅ **Priority-safe**: Runs as a `final_pipeline` after existing integration pipelines
- ✅ **Deterministic**: Produces stable, consistent entity IDs based on ranking rules
- ✅ **Flexible**: Can be manually attached to any data stream via `index.final_pipeline`

## How It Works

### Pipeline Architecture

The integration installs a global composable index template that:

1. Matches all `logs-*` index patterns
2. Sets `index.final_pipeline` to `logs-entity_id_enricher@default`
3. Ensures the enrichment pipeline runs **after** any existing integration pipelines

This design means:

- **Existing integrations keep working**: Their default pipelines run first
- **Custom logs-\* data streams are enriched automatically**: No configuration needed
- **Non-logs data streams can opt in**: By manually setting `index.final_pipeline`

### Entity ID Computation

The Painless script computes entity IDs only when they don't already exist, following these ranking systems:

## Host Entity Ranking System

The pipeline computes `host.entity.id` using the following precedence (first available wins):

1. `host.entity.id` (if already populated; do not overwrite)
2. `host.id`
3. `host.name.host.domain`
4. `host.hostname.host.domain`
5. `host.name|host.mac`
6. `host.hostname|host.mac`
7. `host.hostname`
8. `host.name`

**Note**: Empty strings and invalid values are ignored throughout the ranking process.

## User Entity Ranking System

The pipeline computes `user.entity.id` using the following precedence (first available wins):

1. `user.entity.id` (if already populated; do not overwrite)
2. `user.id`
3. `user.email`
4. `user.name@user.domain` (when user.domain is available)
5. `user.name@host.entity.id` (when host identifier is available)
6. `user.name`

**Note**: The host entity ID is computed first, so it can be used in the user entity ID computation when needed.

### User Entity ID Examples

```json
// Example 1: User with ID (highest priority)
{
  "user": {
    "id": "user-12345",
    "email": "alice@example.com",
    "name": "alice"
  },
  "host": {
    "name": "laptop-01"
  }
}
// Result: user.entity.id = "user-12345"

// Example 2: User with email (second priority)
{
  "user": {
    "email": "alice@example.com",
    "name": "alice"
  },
  "host": {
    "name": "laptop-01"
  }
}
// Result: user.entity.id = "alice@example.com"

// Example 3: User name with user.domain
{
  "user": {
    "name": "bob",
    "domain": "company.local"
  },
  "host": {
    "name": "server-02"
  }
}
// Result: user.entity.id = "bob@company.local"

// Example 4: User name with host context
{
  "user": {
    "name": "bob"
  },
  "host": {
    "name": "server-02"
  }
}
// Result:
//   host.entity.id = "server-02"
//   user.entity.id = "bob@server-02"

// Example 5: User name only (no host or domain)
{
  "user": {
    "name": "charlie"
  }
}
// Result: user.entity.id = "charlie"
```

### Host Entity ID Examples

```json
// Example 1: Host with id only (highest priority after entity.id)
{
  "host": {
    "id": "host-uuid-123",
    "name": "web-server-01",
    "domain": "company.com"
  }
}
// Result: host.entity.id = "host-uuid-123"

// Example 2: Host with name and domain
{
  "host": {
    "name": "web-server-01",
    "domain": "company.com"
  }
}
// Result: host.entity.id = "web-server-01.company.com"

// Example 3: Host with hostname and domain
{
  "host": {
    "hostname": "db-server-03",
    "domain": "prod.local"
  }
}
// Result: host.entity.id = "db-server-03.prod.local"

// Example 4: Host with name and mac
{
  "host": {
    "name": "laptop-05",
    "mac": "00:1B:63:84:45:E6"
  }
}
// Result: host.entity.id = "laptop-05|00:1B:63:84:45:E6"

// Example 5: Host with hostname and mac
{
  "host": {
    "hostname": "workstation-99",
    "mac": "00:1B:63:84:45:E7"
  }
}
// Result: host.entity.id = "workstation-99|00:1B:63:84:45:E7"

// Example 6: Host with hostname only
{
  "host": {
    "hostname": "standalone-server"
  }
}
// Result: host.entity.id = "standalone-server"

// Example 7: Host with name only
{
  "host": {
    "name": "simple-host"
  }
}
// Result: host.entity.id = "simple-host"
```

## Installation and Usage

### Prerequisites

- Elasticsearch 8.13.0 or later
- Elastic subscription: Basic or higher

### Installation

1. Install the integration through Kibana Fleet or the Integrations UI
2. The integration will automatically create:
   - Global ingest pipeline: `logs-entity_id_enricher@default`
   - Global index template for `logs-*` with priority 50
3. No additional configuration is required

### Automatic Enrichment for logs-\* Data Streams

Once installed, **all** data indexed to any `logs-*` data stream will automatically have entity IDs computed:

- ✅ Elastic Agent integrations (e.g., `logs-system.auth-*`)
- ✅ Beats (e.g., `logs-filebeat-*`)
- ✅ Custom `logs-*` data streams

**No action required** – enrichment happens automatically.

### Manual Attachment to Other Data Streams

To enrich data streams that don't match `logs-*`:

1. Create or update the index template for your data stream
2. Add the following setting:

```json
{
  "template": {
    "settings": {
      "index.final_pipeline": "logs-entity_id_enricher@default"
    }
  }
}
```

Example using Dev Tools:

```json
PUT _index_template/my-custom-template
{
  "index_patterns": ["metrics-myapp-*"],
  "priority": 100,
  "template": {
    "settings": {
      "index.final_pipeline": "logs-entity_id_enricher@default"
    }
  }
}
```

### Testing the Pipeline

#### Using Simulate API

You can test the pipeline without indexing data:

```json
POST _ingest/pipeline/logs-entity_id_enricher@default/_simulate
{
  "docs": [
    {
      "_source": {
        "@timestamp": "2025-11-18T12:00:00.000Z",
        "user": {
          "name": "alice",
          "email": "alice@example.com"
        },
        "host": {
          "name": "laptop-01",
          "id": "host-uuid-123"
        }
      }
    }
  ]
}
```

Expected result:

```json
{
  "docs": [
    {
      "doc": {
        "_source": {
          "@timestamp": "2025-11-18T12:00:00.000Z",
          "user": {
            "name": "alice",
            "email": "alice@example.com",
            "entity": {
              "id": "alice@example.com"
            }
          },
          "host": {
            "name": "laptop-01",
            "id": "host-uuid-123",
            "entity": {
              "id": "host-uuid-123"
            }
          }
        }
      }
    }
  ]
}
```

#### Index Test Documents

Index a test document to any `logs-*` data stream:

```json
POST logs-entity_id_enricher.logs-default/_doc
{
  "@timestamp": "2025-11-18T12:00:00.000Z",
  "message": "Test login event",
  "user": {
    "name": "bob"
  },
  "host": {
    "name": "server-02",
    "domain": "prod.local"
  }
}
```

Expected enrichment:

- `host.entity.id` = `"server-02.prod.local"` (host.name.host.domain)
- `user.entity.id` = `"bob@server-02.prod.local"` (user.name@host.entity.id)

Verify the enrichment:

```json
GET logs-entity_id_enricher.logs-default/_search
{
  "query": {
    "match_all": {}
  },
  "fields": ["user.entity.id", "host.entity.id"]
}
```

## Protection Against Overwrites

The pipeline **never** modifies existing entity IDs. If `user.entity.id` or `host.entity.id` already exist in the document, the script skips computation entirely for that field.

Example:

```json
// Input document with pre-existing entity ID
{
  "user": {
    "email": "alice@example.com",
    "entity": {
      "id": "custom-user-id-from-source"
    }
  }
}

// After enrichment: user.entity.id remains unchanged
{
  "user": {
    "email": "alice@example.com",
    "entity": {
      "id": "custom-user-id-from-source"  // ← NOT overwritten
    }
  }
}
```

## Error Handling

The pipeline is designed to be fault-tolerant:

- **Missing fields**: Gracefully skipped, no errors thrown
- **Null values**: Treated as missing, next ranking option attempted
- **Invalid types**: Handled safely by Painless type checking
- **Pipeline failures**: Captured in `error.message` field via `on_failure` handler

## Performance Considerations

- **Lightweight**: Single Painless script processor with minimal overhead
- **Efficient**: Only executes when entity IDs are missing
- **No external calls**: All computation happens in-memory during ingestion
- **No re-indexing required**: Works on new documents as they arrive

## Compatibility with Existing Integrations

This integration is designed to coexist with all other Elastic integrations:

- **Priority 50**: Lower than most integration templates (typically 200-300)
- **Final pipeline**: Runs after all integration-specific pipelines
- **Non-destructive**: Never modifies fields set by other integrations
- **Opt-out friendly**: Remove or modify the global template if needed

### Example: Integration Priority Stack

```
1. Integration-specific template (priority 250)
   ├─ Sets index.default_pipeline to logs-apache.access-1.2.3
   └─ Runs integration's custom processors

2. Entity ID Enricher template (priority 50)
   └─ Sets index.final_pipeline to logs-entity_id_enricher@default
       └─ Runs AFTER integration pipeline completes
```

## Use Cases

### Entity Analytics

Stable entity IDs enable:

- User behavior analytics across multiple hosts
- Host activity tracking across time
- Entity-centric threat detection
- Cross-integration entity correlation

### SIEM and Security

- Consistent user identification for investigations
- Host tracking across network segments
- Entity-based alerting rules
- Threat hunting by entity

### Observability

- User session tracking
- Host performance correlation
- Multi-source entity attribution
- Entity-level dashboards

## Troubleshooting

### Entity IDs Not Being Set

1. **Check pipeline installation**:

   ```json
   GET _ingest/pipeline/logs-entity_id_enricher@default
   ```

2. **Check index template**:

   ```json
   GET _index_template/logs@entity_id_enricher
   ```

3. **Verify data stream settings**:

   ```json
   GET logs-*/_settings
   ```

   Look for `index.final_pipeline` setting.

4. **Check for source field availability**:
   Ensure at least one field from the ranking system exists in your documents.

### Entity IDs Not Matching Expected Values

1. **Review ranking rules**: Entity ID selection follows strict precedence
2. **Check for pre-existing values**: Pipeline never overwrites existing IDs
3. **Verify field types**: Arrays (like `host.ip`) use the first element
4. **Test with simulate API**: Validate expected behavior before indexing

### Pipeline Conflicts

If the pipeline conflicts with existing infrastructure:

1. **Adjust template priority**: Modify the template priority if needed
2. **Remove global template**: Delete the template to disable automatic enrichment
3. **Use selective attachment**: Manually attach only to specific data streams

## Maintenance

### Updating the Pipeline

To modify the enrichment logic:

1. Update the pipeline definition in the package
2. Reinstall the integration
3. The updated pipeline applies to new documents immediately
4. Existing documents retain their original entity IDs

### Removing the Integration

To uninstall:

1. Delete the integration from Kibana
2. Remove the index template:
   ```json
   DELETE _index_template/logs@entity_id_enricher
   ```
3. Remove the pipeline:
   ```json
   DELETE _ingest/pipeline/logs-entity_id_enricher@default
   ```

**Note**: Existing entity IDs in documents will remain unchanged.

## Contributing

This integration is maintained by the Elastic Security Service Integrations team. For issues, questions, or contributions, please contact the team or open an issue in the integrations repository.

## License

This integration is distributed under the Elastic License 2.0.

## Version History

- **0.0.1** (Initial release)
  - Global enrichment for `logs-*` data streams
  - User and host entity ID computation
  - Safe, non-destructive processing
  - Final pipeline architecture
