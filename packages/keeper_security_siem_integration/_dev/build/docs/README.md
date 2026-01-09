# Keeper Security Integration

The Keeper Security integration provides **truly agentless** data collection by allowing Keeper to push audit events directly to Elasticsearch via the Bulk API. This integration enables seamless monitoring and analysis of Keeper Security platform activities without requiring any Elastic Agent installation.

## Overview

### Compatibility

This integration is compatible with:
- Keeper Security Enterprise Platform (all versions that support audit event streaming)
- Elasticsearch 8.0+ with Bulk API access
- Kibana 9.0+ for dashboard visualization
- Self-managed and Elastic Cloud deployments

### How it works

The Keeper Security integration uses a direct push architecture where:

1. **Keeper Security Platform** generates audit events for user activities and administrative actions
2. **Direct API Push**: Keeper pushes events directly to Elasticsearch using the Bulk API
3. **Ingest Pipeline**: Events are processed through the `logs-keeper.audit-1.0.0` ingest pipeline
4. **ECS Mapping**: Data is automatically mapped to Elastic Common Schema (ECS) fields
5. **Index Storage**: Processed events are stored in `logs-keeper.audit-*` indices
6. **Visualization**: Pre-built dashboards provide immediate insights into Keeper activities

This architecture provides real-time event processing with minimal latency and eliminates the need for intermediate collection agents.

## What data does this integration collect?

The Keeper Security integration collects comprehensive audit events including:

### Event Types
- **Authentication Events**: Two-factor authentication changes, login activities
- **Security Actions**: Master password changes, security policy modifications  
- **Administrative Operations**: User management, role assignments, policy updates
- **Record Access**: Password retrievals, file access, sharing activities
- **Enterprise Management**: Organization settings, compliance actions

### Use Cases
- **Security Monitoring**: Track unauthorized access attempts and security policy violations
- **Compliance Reporting**: Generate audit trails for regulatory requirements (SOX, HIPAA, PCI-DSS)
- **User Activity Analysis**: Monitor user behavior patterns and identify anomalies
- **Incident Response**: Investigate security incidents with detailed audit trails
- **Risk Assessment**: Analyze access patterns and identify potential security risks

## What do I need to use this integration?

### Elastic Prerequisites
- **Elasticsearch Cluster**: Self-managed (8.0+) or Elastic Cloud deployment
- **Kibana Access**: Version 9.0+ for dashboard and configuration management
- **API Permissions**: Ability to create API keys with index write privileges
- **GeoIP Database**: Recommended for IP geolocation enrichment

### Keeper Security Prerequisites
- **Keeper Enterprise Account**: Active enterprise subscription
- **Administrative Access**: Enterprise admin privileges to configure audit streaming
- **Network Connectivity**: Outbound HTTPS access from Keeper to your Elasticsearch cluster
- **API Integration**: Keeper platform configured for external audit streaming

## How do I deploy this integration?

For complete deployment instructions, refer to the {{url "getting-started-observability" "Observability Getting Started guide"}} for foundational setup steps.

### Onboard and configure

**1. Install Integration Assets**

In Kibana:
1. Navigate to **Management > Integrations**
2. Search for "Keeper Security" 
3. Click **Add Keeper Security**
4. Click **Install assets only** (no agent policy needed)
5. Confirm installation

This installs:
- Index templates for `logs-keeper.audit-*`
- Ingest pipeline `logs-keeper.audit-1.0.0`
- Pre-built dashboards and visualizations  
- Field mappings and ECS compliance

**2. Create API Key**

In Kibana Dev Tools, execute:

```json
POST /_security/api_key
{
  "name": "keeper-integration",
  "expiration": "365d", 
  "role_descriptors": {
    "keeper-writer": {
      "cluster": ["monitor"],
      "indices": [
        {
          "names": ["logs-keeper.audit-*"],
          "privileges": ["auto_configure", "create_doc"]
        }
      ]
    }
  }
}
```

Copy the Base64 encoded API key for Keeper configuration.

**3. Enable GeoIP Enrichment (Recommended)**

Enable GeoIP database for IP geolocation:

```json
PUT /_cluster/settings
{
  "persistent": {
    "ingest.geoip.downloader.enabled": true,
    "ingest.geoip.downloader.poll.interval": "3d"
  }
}
```

**4. Configure Keeper Security Platform**

Contact your Keeper Security administrator to:
- Configure audit event streaming to your Elasticsearch endpoint
- Provide the API key and endpoint URL (`https://YOUR_HOST/logs-keeper.audit-1.0.0/_bulk`)
- Verify network connectivity between Keeper and Elasticsearch

### Validation

**Test API Endpoint**:
```bash
curl --location 'https://YOUR_HOST/logs-keeper.audit-1.0.0/_bulk' \
--header 'Authorization: ApiKey YOUR_API_KEY' \
--header 'Content-Type: application/x-ndjson' \
--data-raw '{"create":{}}
{"test_event":"validation_test"}
'
```

**Verify Data Ingestion**:
1. Go to **Discover** in Kibana
2. Select index pattern: `logs-keeper.audit-*`
3. Verify events appear with proper ECS field mapping

**Check Dashboard**:
1. Navigate to **Analytics > Dashboard**
2. Open "Keeper SIEM Integration - Dashboard"
3. Confirm visualizations populate with incoming data

## Troubleshooting

### Common Issues

**No Data Appearing**
- Verify API key permissions using the test curl command
- Check Keeper Security platform audit streaming configuration
- Confirm network connectivity between Keeper and Elasticsearch
- Review Elasticsearch logs for ingestion errors

**Missing GeoIP Data**
- Verify GeoIP downloader is enabled: `GET /_ingest/geoip/stats`
- Check that public IP addresses are being processed (private IPs won't have geo data)
- Allow time for GeoIP database download (initial setup can take several minutes)

**Field Mapping Issues**
- Ensure integration assets were installed properly
- Verify ingest pipeline `logs-keeper.audit-1.0.0` exists: `GET /_ingest/pipeline/logs-keeper.audit-1.0.0`
- Check index template mapping: `GET /_index_template/logs-keeper.audit`

**Dashboard Not Loading**
- Confirm Kibana version compatibility (9.0+)
- Verify integration installation completed successfully
- Check that data is present in the `logs-keeper.audit-*` indices

For additional troubleshooting, consult the {{url "security" "Elastic Security documentation"}} and Keeper Security platform documentation.

## Performance and scaling

### Architecture Recommendations

**Single Instance Deployment**:
- Suitable for small to medium enterprises (<1000 events/hour)
- Single Elasticsearch node with adequate storage
- Basic monitoring and alerting

**High-Volume Deployment**:
- Recommended for large enterprises (>1000 events/hour)
- Multi-node Elasticsearch cluster with dedicated data nodes
- Index lifecycle management (ILM) for automated data retention
- Monitoring with dedicated monitoring cluster

### Scaling Considerations

**Event Volume**: Keeper audit events are typically low-volume but burst during peak activity periods. Plan for 10x normal volume during security incidents or mass administrative actions.

**Storage Planning**: Each audit event averages 1-2KB after processing. Estimate storage needs based on retention requirements and event frequency.

**Index Management**: Implement ILM policies to automatically manage index size and retention:

```json
PUT /_ilm/policy/keeper-audit-policy
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "10GB",
            "max_age": "30d"
          }
        }
      },
      "warm": {
        "min_age": "30d",
        "actions": {
          "allocate": {
            "number_of_replicas": 0
          }
        }
      },
      "delete": {
        "min_age": "365d"
      }
    }
  }
}
```

## Reference

### Audit Events Reference

The Keeper Security integration processes audit events from the Keeper Security platform and maps them to ECS-compliant fields for analysis and visualization.

#### Sample Event

{{event "audit"}}

#### Exported Fields

{{fields "audit"}}

### APIs Used

This integration uses the following APIs:
- **Elasticsearch Bulk API**: For direct event ingestion
- **Elasticsearch Index Templates API**: For field mapping configuration  
- **Elasticsearch Ingest Pipeline API**: For event processing and enrichment
- **Keeper Security Audit Streaming API**: For event delivery (configured on Keeper side)

### Ingest Pipeline

The integration uses the `logs-keeper.audit-1.0.0` ingest pipeline which:
- Maps Keeper-specific fields to ECS schema
- Enriches IP addresses with geographic information (when GeoIP is enabled)
- Processes timestamps and ensures proper field types
- Adds correlation fields for security analysis

### ML Modules

Currently, no machine learning modules are included with this integration. Custom ML jobs can be created to detect:
- Anomalous authentication patterns
- Unusual access times or locations
- Bulk administrative actions
- Suspicious user behavior patterns

### Change Log

Refer to the [CHANGELOG.md](../../../changelog.yml) for version history and updates.
