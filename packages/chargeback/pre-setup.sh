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
      "package": { "name": "chargeback", "version": "0.2.0" }
    },
    "properties": {
      "config_join_key": { "type": "keyword" },
      "conf_ecu_rate": { "type": "float" },
      "conf_ecu_rate_unit": { "type": "keyword"},
      "conf_indexing_weight": { "type": "integer" },
      "conf_query_weight": { "type": "integer" },
      "conf_storage_weight": { "type": "integer" },
      "conf_recommended_memory_util": { "type": "integer" },
      "conf_recommended_cpu_util": { "type": "integer" },
      "conf_recommended_disk_util": { "type": "integer" }
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
  "conf_storage_weight": 40,
  "conf_recommended_memory_util": 70,
  "conf_recommended_cpu_util": 70,
  "conf_recommended_disk_util": 60
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
      "total_ecu": { "type": "float" },
      "sku": { "type": "keyword" }
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
      "package": { "name": "chargeback", "version": "0.2.0" }
    },
    "properties": {
      "@timestamp": { "type": "date" },
      "composite_key": { "type": "keyword" },
      "composite_datastream_key": { "type": "keyword" },
      "config_join_key": { "type": "keyword" },
      "cluster_name": { "type": "keyword" },
      "deployment_id": { "type": "keyword" },
      "datastream": { "type": "keyword" },
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
      "package": { "name": "chargeback", "version": "0.2.0" }
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
      "package": { "name": "chargeback", "version": "0.2.0" }
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
      "package": { "name": "chargeback", "version": "0.2.0" }
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

PUT cluster_tier_utilization_lookup
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
      "cluster_name": {
        "type": "text",
        "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } }
      },
      "composite_key": { "type": "keyword" },
      "composite_tier_key": { "type": "keyword" },
      "config_join_key": { "type": "keyword" },
      "deployment_id": { "type": "keyword" },
      "deployment_name": {
        "type": "text",
        "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } }
      },
      "tier": { "type": "keyword" },
      "cluster_id": {
        "type": "text",
        "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } }
      },
      "memory_usage_pct_avg": { "type": "double" },
      "disk_usage_pct_avg": { "type": "double" },
      "cpu_usage_pct_avg": { "type": "double" }
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