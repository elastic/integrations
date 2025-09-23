# Create the config lookup index for chargeback configuration.
# This index will store a single document with the configuration settings.

PUT chargeback_conf_lookup
{
  "settings": { 
    "index.mode": "lookup", 
    "index.hidden": true 
  },
  "mappings": {
    "_meta": {
      "managed": true,
      "package": { "name": "chargeback", "version": "0.2.0" }
    },
    "properties": {
      "config_join_key": { "type": "keyword" },
      "conf_ecu_rate": { "type": "float" },
      "conf_ecu_rate_unit": { "type": "keyword"},
      "conf_indexing_weight": { "type": "integer" },
      "conf_query_weight": { "type": "integer" },
      "conf_storage_weight": { "type": "integer" }
    }
  }
}

# Add the default configuration to the chargeback_conf_lookup index.
POST chargeback_conf_lookup/_doc/config
{
  "config_join_key": "chargeback_config",
  "conf_ecu_rate": 0.85,
  "conf_ecu_rate_unit": "EUR",
  "conf_indexing_weight": 20,
  "conf_query_weight": 20,
  "conf_storage_weight": 40
}

# Create the lookup indices for billing and cluster contributions.
PUT billing_cluster_cost_lookup
{
  "settings": {
    "index.mode": "lookup",
    "index.hidden": true
  },
  "mappings": {
    "_meta": {
      "managed": true,
      "package": { "name": "chargeback", "version": "0.2.0" }
    },
    "properties": {
      "@timestamp": { "type": "date" },
      "billing_name": {
        "type": "text",
        "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } }
      },
      "billing_type": {
        "type": "text",
        "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } }
      },
      "composite_key": { "type": "keyword" },
      "config_join_key": { "type": "keyword" },
      "deployment_id": { "type": "keyword" },
      "deployment_name": {
        "type": "text",
        "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } }
      },
      "total_ecu": { "type": "float" }
    }
  }
}

# Create data view used for control.
POST kbn:/api/data_views/data_view
{
  "data_view": {
    "name": "[Chargeback] Billing Cluster Cost",
    "title": "billing_cluster_cost_lookup",
    "id": "2bf6c0d816ef0a2d56d03ede549c16c08c35db2cf02d78c12756a98a33f50e4f"
  }
}