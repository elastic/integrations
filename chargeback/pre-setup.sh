# The usage transforms can work on both Cloud Stack monitoring data, or Elasticsearch Integration data
# If you have Stack monitoring in place and do not have the Elasticsearch Integration running, create this alias.
POST _aliases
{
  "actions": [
    { "add": { "index": ".monitoring-es-8-mb", "alias": "chargeback-monitoring-read", "is_write_index": false }}
  ]
}

# If you do have the Elasticsearch Integration running, create this alias.
POST _aliases
{
  "actions": [
    { "add": { "index": "monitoring-indices", "alias": "chargeback-monitoring-read", "is_write_index": false }}
  ]
}

# Create the lookup indices for chargeback configuration and billing metrics
# These indices are used to store configuration and billing data for chargeback calculations.

PUT chargeback_conf_lookup
{
  "settings": { 
    "index.mode": "lookup", 
    "index.hidden": true 
  },
  "mappings": {
    "_meta": {
      "managed": true,
      "package": { "name": "chargeback", "version": "0.0.3" }
    },
    "properties": {
      "config_join_key": { "type": "keyword" },
      "conf_ecu_rate": { "type": "float" },
      "conf_indexing_weight": { "type": "integer" },
      "conf_query_weight": { "type": "integer" },
      "conf_storage_weight": { "type": "integer" }
    }
  }
}

POST chargeback_conf_lookup/_doc/config
{
  "config_join_key": "chargeback_config",
  "conf_ecu_rate": 0.85,
  "conf_indexing_weight": 20,
  "conf_query_weight": 20,
  "conf_storage_weight": 40
}

PUT billing_cluster_cost_lookup
{
  "settings": {
    "index.mode": "lookup",
    "index.hidden": true
  },
  "mappings": {
    "_meta": {
      "managed": true,
      "package": { "name": "chargeback", "version": "0.0.3" }
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


PUT cluster_datastream_contribution_lookup
{
  "settings": {
    "index.mode": "lookup",
    "index.hidden": true
  },
  "mappings": {
    "_meta": {
      "managed": true,
      "package": { "name": "chargeback", "version": "0.0.3" }
    },
    "properties": {
      "@timestamp": { "type": "date" },
      "composite_key": { "type": "keyword" },
      "composite_datastream_key": { "type": "keyword" },
      "config_join_key": { "type": "keyword" },
      "cluster_name": { "type": "keyword" },
      "deployment_id": { "type": "keyword" },
      "datastream_name": { "type": "keyword" },
      "datastream_sum_indexing_time": { "type": "double" },
      "datastream_sum_query_time": { "type": "double" },
      "datastream_sum_store_size": { "type": "double" },
      "datastream_sum_data_set_store_size": { "type": "double" }
    }
  }
}

PUT cluster_deployment_contribution_lookup
{
  "settings": {
    "index.mode": "lookup",
    "index.hidden": true
  },
  "mappings": {
    "_meta": {
      "managed": true,
      "package": { "name": "chargeback", "version": "0.0.3" }
    },
    "properties": {
      "@timestamp": { "type": "date" },
      "composite_key": { "type": "keyword" },
      "config_join_key": { "type": "keyword" },
      "cluster_name": { "type": "keyword" },
      "deployment_id": { "type": "keyword" },
      "deployment_sum_indexing_time": { "type": "double" },
      "deployment_sum_query_time": { "type": "double" },
      "deployment_sum_store_size": { "type": "double" },
      "deployment_sum_data_set_store_size": { "type": "double" }
    }
  }
}

PUT cluster_tier_and_datastream_contribution_lookup
{
  "settings": {
    "index.mode": "lookup",
    "index.hidden": true
  },
  "mappings": {
    "_meta": {
      "managed": true,
      "package": { "name": "chargeback", "version": "0.0.3" }
    },
    "properties": {
      "@timestamp": { "type": "date" },
      "composite_key": { "type": "keyword" },
      "composite_tier_key": { "type": "keyword" },
      "config_join_key": { "type": "keyword" },
      "cluster_name": { "type": "keyword" },
      "deployment_id": { "type": "keyword" },
      "tier": { "type": "keyword" },
      "datastream": { "type": "keyword" },
      "tier_and_datastream_sum_indexing_time": { "type": "double" },
      "tier_and_datastream_sum_query_time": { "type": "double" },
      "tier_and_datastream_sum_store_size": { "type": "double" },
      "tier_and_datastream_sum_data_set_store_size": { "type": "double" }
    }
  }
}


PUT cluster_tier_contribution_lookup
{
  "settings": {
    "index.mode": "lookup",
    "index.hidden": true
  },
  "mappings": {
    "_meta": {
      "managed": true,
      "package": { "name": "chargeback", "version": "0.0.3" }
    },
    "properties": {
      "@timestamp": { "type": "date" },
      "composite_key": { "type": "keyword" },
      "composite_tier_key": { "type": "keyword" },
      "config_join_key": { "type": "keyword" },
      "cluster_name": { "type": "keyword" },
      "deployment_id": { "type": "keyword" },
      "tier": { "type": "keyword" },
      "tier_sum_indexing_time": { "type": "double" },
      "tier_sum_query_time": { "type": "double" },
      "tier_sum_store_size": { "type": "double" },
      "tier_sum_data_set_store_size": { "type": "double" }
    }
  }
}
