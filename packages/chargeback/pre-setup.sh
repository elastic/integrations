# Create the config lookup index for chargeback configuration.
# This index will store a single document with the configuration settings.

PUT chargeback_conf_lookup
{
  "settings": { 
    "index.mode": "lookup"
  },
  "mappings": {
    "_meta": {
      "managed": true,
      "package": { "name": "chargeback", "version": "0.2.4" }
    },
    "properties": {
      "config_join_key": { "type": "keyword" },
      "conf_ecu_rate": { "type": "float" },
      "conf_ecu_rate_unit": { "type": "keyword"},
      "conf_indexing_weight": { "type": "integer" },
      "conf_query_weight": { "type": "integer" },
      "conf_storage_weight": { "type": "integer" },
      "conf_start_date": {"type": "date"},
      "conf_end_date": {"type": "date"}
    }
  }
}

# Add the default configuration to the chargeback_conf_lookup index.
POST chargeback_conf_lookup/_doc
{
  "config_join_key": "chargeback_config",
  "conf_ecu_rate": 0.85,
  "conf_ecu_rate_unit": "EUR",
  "conf_indexing_weight": 20,
  "conf_query_weight": 20,
  "conf_storage_weight": 40,
  "conf_start_date": "2024-01-01T12:00:00.000Z",
  "conf_end_date": "2030-12-31T23:59:59.000Z"
}