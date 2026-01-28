# Entity ID Enricher Integration

> **Automatic, stable entity identification for users and hosts across all Elastic logs**

[![Version](https://img.shields.io/badge/version-0.0.1-blue.svg)]()
[![License](https://img.shields.io/badge/license-Elastic%202.0-green.svg)]()
[![Type](https://img.shields.io/badge/type-Integration-orange.svg)]()

## 🎯 Overview

The **Entity ID Enricher** integration provides automatic enrichment of `user.entity.id` and `host.entity.id` fields for all logs in your Elastic deployment. It uses a deterministic ranking system implemented in Painless to compute stable, consistent entity identifiers at ingestion time—no transforms or additional infrastructure required.

### Key Benefits

- ✅ **Zero Configuration**: Works automatically with all `logs-*` data streams
- ✅ **Non-Destructive**: Never overwrites existing entity IDs
- ✅ **Error-Safe**: Handles missing fields gracefully
- ✅ **Integration-Friendly**: Runs after existing pipelines via `final_pipeline`
- ✅ **Performant**: < 5ms overhead per document
- ✅ **Flexible**: Can be attached to any data stream

## 🚀 Quick Start

### Install

1. Open **Kibana → Management → Integrations**
2. Search for **"Entity ID Enricher"**
3. Click **Add Entity ID Enricher**
4. Save and deploy

### Verify

```bash
# Check the pipeline was installed
GET _ingest/pipeline/logs-entity_id_enricher@default

# Test with a sample document
POST _ingest/pipeline/logs-entity_id_enricher@default/_simulate
{
  "docs": [{
    "_source": {
      "user": {"name": "alice"},
      "host": {"name": "server-01"}
    }
  }]
}
```

### Use

All `logs-*` data streams are automatically enriched. Just query your logs:

```bash
GET logs-*/_search
{
  "size": 10,
  "fields": ["user.entity.id", "host.entity.id"]
}
```

## 📖 Documentation

- **[Complete Documentation](docs/README.md)** - Detailed guide with examples

## 🎓 How It Works

### Entity ID Ranking Systems

#### Host Entity ID

The pipeline computes `host.entity.id` using the following precedence (first available wins):

```
1. host.entity.id (if already populated; do not overwrite)
2. host.id
3. host.name.host.domain
4. host.hostname.host.domain
5. host.name|host.mac
6. host.hostname|host.mac
7. host.hostname
8. host.name
```

#### User Entity ID

The pipeline computes `user.entity.id` using the following precedence (first available wins):

```
1. user.entity.id (if already populated; do not overwrite)
2. user.id
3. user.email
4. user.name@user.domain (when user.domain is available)
5. user.name@host.entity.id (when host identifier is available)
6. user.name
```

**Note**: Empty strings and invalid values are ignored throughout the ranking process.

### Examples

**Example 1: User with name + Host with ID**

```json
// Input
{
  "user": {"name": "alice"},
  "host": {"id": "host-123"}
}

// Output (enriched)
{
  "user": {
    "name": "alice",
    "entity": {"id": "alice@host-123"}
  },
  "host": {
    "id": "host-123",
    "entity": {"id": "host-123"}
  }
}
```

**Example 2: Host with domain**

```json
// Input
{
  "user": {"name": "alice"},
  "host": {"name": "server-01", "domain": "example.com"}
}

// Output (enriched)
{
  "user": {
    "name": "alice",
    "entity": {"id": "alice@server-01.example.com"}
  },
  "host": {
    "name": "server-01",
    "domain": "example.com",
    "entity": {"id": "server-01.example.com"}
  }
}
```

**Example 3: User with email**

```json
// Input
{
  "user": {"email": "alice@company.com"},
  "host": {"name": "server-01"}
}

// Output (enriched)
{
  "user": {
    "email": "alice@company.com",
    "entity": {"id": "alice@company.com"}
  },
  "host": {
    "name": "server-01",
    "entity": {"id": "server-01"}
  }
}
```

## 🏗️ Architecture

### Pipeline Attachment Strategy

The integration uses a **global composable index template** with `index.final_pipeline`:

```
logs-* Data Stream
  ↓
Integration Pipeline (if any)  ← runs first
  ↓
Entity ID Enricher Pipeline    ← runs last (final_pipeline)
  ↓
Document indexed with entity IDs
```

This ensures:

- Existing integrations continue working
- Entity enrichment happens after all other processing
- No conflicts with existing pipelines

### Components

1. **Ingest Pipeline**: `logs-entity_id_enricher@default`

   - Single Painless script processor
   - Computes entity IDs based on ranking rules
   - Includes error handling

2. **Index Template**: Priority 50, applies to `logs-*`

   - Sets `index.final_pipeline`
   - Defines field mappings for entity IDs

3. **Data Stream**: Optional validation stream
   - `logs-entity_id_enricher.logs-default`
   - Includes sample events

## 🧪 Testing

### Quick Test

```bash
# Test the pipeline
POST _ingest/pipeline/logs-entity_id_enricher@default/_simulate
{
  "docs": [{
    "_source": {
      "user": {"email": "test@example.com"},
      "host": {"name": "server"}
    }
  }]
}
```

### Validation Script

```bash
cd packages/entity_id_enricher/_dev/test/pipeline
./validate-pipeline.sh http://localhost:9200
```

### Test Cases

The package includes 8 comprehensive test cases covering:

- User with email (highest priority)
- User with name + host context
- Host-only scenarios
- Pre-existing entity IDs (no overwrite)
- Missing fields (graceful handling)
- Array handling (host.ip)

See [test cases](_dev/test/pipeline/test-expected-results.md) for details.

## 🔧 Advanced Usage

### Attach to Custom Data Streams

To enrich non-`logs-*` data streams:

```json
PUT _index_template/my-custom-template
{
  "index_patterns": ["custom-*"],
  "priority": 100,
  "template": {
    "settings": {
      "index.final_pipeline": "logs-entity_id_enricher@default"
    }
  }
}
```

### Check Current Settings

```bash
# View all data streams using the pipeline
GET logs-*/_settings/index.final_pipeline

# View the pipeline definition
GET _ingest/pipeline/logs-entity_id_enricher@default

# View the index template
GET _index_template/logs@*entity*
```

## ⚠️ Important Notes

### Non-Destructive Processing

The pipeline **never** overwrites existing entity IDs:

```json
// Input (with pre-existing entity ID)
{"user": {"email": "test@test.com", "entity": {"id": "CUSTOM"}}}

// Output (unchanged)
{"user": {"email": "test@test.com", "entity": {"id": "CUSTOM"}}}
```

### Compatibility

- **Elasticsearch**: 8.13.0+
- **License**: Basic or higher
- **Integrations**: Compatible with all Elastic integrations
- **Priority**: 50 (lower than most integration templates)

## 🐛 Troubleshooting

### Entity IDs Not Appearing

1. Check pipeline exists: `GET _ingest/pipeline/logs-entity_id_enricher@default`
2. Check template applied: `GET logs-*/_settings/index.final_pipeline`
3. Verify source fields exist in your documents
4. Test with simulate API

### Wrong Entity ID Computed

1. Review ranking rules in [documentation](docs/README.md)
2. Check if entity ID existed before enrichment
3. Verify field types (arrays vs strings)

### Pipeline Conflicts

- Adjust template priority if needed
- Remove global template to disable auto-enrichment
- Use manual attachment for selective enrichment

## 📊 Performance

- **Latency**: < 5ms per document
- **Memory**: Minimal (in-memory operations only)
- **CPU**: Low overhead
- **Scalability**: Linear with ingestion rate

## 🤝 Contributing

Maintained by **elastic/security-service-integrations**

- Report issues in the [elastic/integrations](https://github.com/elastic/integrations) repository
- Follow Elastic's contribution guidelines
- Test thoroughly before submitting PRs

## 📄 License

Elastic License 2.0

## 📚 Additional Resources

- [Elastic Entity Analytics](https://www.elastic.co/guide/en/security/current/entity-analytics.html)
- [ECS User Fields](https://www.elastic.co/guide/en/ecs/current/ecs-user.html)
- [ECS Host Fields](https://www.elastic.co/guide/en/ecs/current/ecs-host.html)
- [Painless Scripting](https://www.elastic.co/guide/en/elasticsearch/painless/current/index.html)

---

**Version**: 0.0.1 | **Last Updated**: 2025-11-18 | **Status**: ✅ Ready for Testing
