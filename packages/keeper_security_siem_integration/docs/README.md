# Keeper Security - Agentless Integration

The Keeper Security integration provides **truly agentless** data collection by allowing Keeper to push audit events directly to Elasticsearch via the Bulk API. **No Elastic Agent installation required.**

## Architecture

Keeper Security Platform → Elasticsearch Bulk API → Ingest Pipeline → Index

**Key Benefits:**
- ✅ **No agents to install or manage**
- ✅ **Direct push to Elasticsearch**  
- ✅ **Automatic ECS field mapping**
- ✅ **Built-in dashboards and visualizations**
- ✅ **Real-time event processing**

## Setup Instructions

### 1. Install Integration Assets

**In Kibana:**
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

### 2. Create API Key

**In Kibana:**
1. Go to **Management > Dev Tools**
2. Paste the command below and run:

```
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
**Note: you can increase the expiration date.**

3.	Copy the Base64 encoded API key - you’ll need this for Keeper configuration

### 3. Enable GeoIP Enrichment

To enrich Keeper events with geographic location based on remote_address:

In Kibana Dev Tools, enable the built-in GeoIP downloader:

```
PUT /_cluster/settings
{
  "persistent": {
    "ingest.geoip.downloader.enabled": true,
    "ingest.geoip.downloader.poll.interval": "3d"
  }
}
```

Verify GeoIP database status:

```
GET /_ingest/geoip/stats
```

Once enabled, the ingest pipeline will automatically add source.geo.* fields for public IP addresses.

⸻

## Data Processing

Input Event (from Keeper)
```
{
  "audit_event": "set_two_factor_on",
  "remote_address": "64.6.65.6",
  "category": "security",
  "client_version": "CLI.5.3.1",
  "username": "user8241@company.com",
  "enterprise_id": 1469,
  "timestamp": "2025-08-26T10:32:18.621Z"
}
```

Processed Event (in Elasticsearch)

```
{
  "@timestamp": [
    "2025-08-26T20:53:50.844Z"
  ],
  "data_stream.dataset": [
    "keeper.audit"
  ],
  "data_stream.namespace": [
    "default"
  ],
  "data_stream.type": [
    "logs"
  ],
  "event.agent_id_status": [
    "missing"
  ],
  "event.category": [
    "authentication",
    "web"
  ],
  "event.dataset": [
    "keeper.audit"
  ],
  "event.ingested": [
    "2025-08-26T20:53:50.000Z"
  ],
  "event.kind": [
    "event"
  ],
  "event.module": [
    "keeper"
  ],
  "event.type": [
    "access",
    "info"
  ],
  "audit_event": [
    "change_master_password"
  ],
  "category": [
    "security"
  ],
  "client_version": [
    "EMConsole.18.0.0"
  ],
  "enterprise_id": [
    1189
  ],
  "remote_address": [
    "4.2.2.3"
  ],
  "username": [
    "user4@company.com"
  ],
  "organization.id": [
    "1189"
  ],
  "organization.name": [
    "keeper-security"
  ],
  "related.ip": [
    "4.2.2.3"
  ],
  "related.user": [
    "user4@company.com"
  ],
  "source.geo.city_name": [
    "Easley"
  ],
  "source.geo.continent_name": [
    "North America"
  ],
  "source.geo.country_iso_code": [
    "US"
  ],
  "source.geo.country_name": [
    "United States"
  ],
  "source.geo.location": [
    {
      "coordinates": [
        -82.5812,
        34.8295
      ],
      "type": "Point"
    }
  ],
  "source.geo.region_iso_code": [
    "US-SC"
  ],
  "source.geo.region_name": [
    "South Carolina"
  ],
  "source.ip": [
    "4.2.2.3"
  ],
  "user.email": [
    "user4@company.com"
  ],
  "user.name": [
    "user4@company.com"
  ],
  "user_agent.original": [
    "Keeper/EMConsole.18.0.0"
  ],
  "_id": "uGMo6JgBEdIT5KvSloV9",
  "_index": ".ds-logs-keeper.audit-1.0.0-2025.08.26-000001",
  "_score": null
}
```

⸻

## Verification

1. Test the Endpoint

```
curl --location 'https://YOUR_HOST/logs-keeper.audit-1.0.0/_bulk' \ 
--header 'Authorization: ApiKey YOUR_API_KEY' \
--header 'Content-Type: application/x-ndjson' \
--data-raw '{"create":{}}
{"test_event":"test_event"}
'
```

2. Check Data in Kibana
	1.	Go to Discover
	2.	Select index pattern: logs-keeper.audit-*
	3.	Verify events appear with proper ECS fields

3. View Dashboards
	1.	Go to Analytics > Dashboard
	2.	Open “Keeper SIEM Integration - Dashboard”
	3.	Verify visualizations populate with data