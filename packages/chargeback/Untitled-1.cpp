// get the amount of usage by ds/tier
from cluster_tier_and_datastream_contribution_lookup
//| where datastream == "logs-system.security-default"
// get deployment stats for insight into the totals
| LOOKUP JOIN cluster_deployment_contribution_lookup on composite_key 
// determine how much the DS is attributing to the resources spend
| eval 
    ds_indexing_portion = tier_and_datastream_sum_indexing_time / deployment_sum_indexing_time * 100,
    ds_query_portion = tier_and_datastream_sum_query_time / deployment_sum_query_time * 100,
    ds_total_time = tier_and_datastream_sum_indexing_time + tier_and_datastream_sum_query_time,
    deployment_total_time = deployment_sum_indexing_time + deployment_sum_query_time,
    ds_total_portion = ds_total_time / deployment_total_time * 100
| LOOKUP JOIN billing_cluster_cost_lookup on composite_key
// Parse the sku so we get to a node role which we call the cost_type.
// So we can down the line match on node.roles
| grok sku "%{WORD}.es.%{WORD:es_node_type}"
| grok sku "Cloud-Platinum_%{DATA}.%{WORD:platinum_non_es_node_type}"
| GROK sku "%{WORD}.%{WORD:non_es_node_type}"
| eval cost_type = CASE(
    es_node_type is not null, es_node_type,
    platinum_non_es_node_type is not null, platinum_non_es_node_type,
    non_es_node_type   
)
// construct the cost_type so we can match it with the billing info
| eval cost_type = CASE(
    cost_type == "data", "data-transfer",
    cost_type == "datahot", "data_content",
    cost_type == "datawarm", "data_warm",    
    cost_type == "datacold", "data_cold",
    cost_type == "datafrozen", "data_frozen",
    cost_type
)
| DROP es_node_type, non_es_node_type
// We care about the node.roles used in the data portion of the cluster
| where cost_type IN ("data_content", "data_warm", "data_cold", "data_frozen")
// remove tiers which we don't actually have for the datastream but got added because of the lookup
| eval 
    config_join_key = "chargeback_config",
    temp_tier = CASE(
        tier == "hot/content", "data_content",
        tier == "warm", "data_warm",
        tier == "cold", "data_cold",
        tier == "frozen", "data_frozen"
    )
| where temp_tier == cost_type
| drop temp_tier
// Get the config values, e.g the recommended mem utilization and value conversion rate
| eval config_join_key = "chargeback_config"
| LOOKUP JOIN chargeback_conf_lookup ON config_join_key
// Construct the tier lookup key
| EVAL composite_tier_key = CONCAT(composite_key, "_", cost_type)
// Get the utilization information
| LOOKUP JOIN cluster_tier_utilization_lookup ON composite_tier_key
// Calculate the total cost of the tier in the local currency and the utilization scores
| EVAL 
    cluster_tier_cost = total_ecu * conf_ecu_rate,
    mem_util = memory_usage_pct_avg / conf_recommended_memory_util,
    disk_util = disk_usage_pct_avg / conf_recommended_disk_util,
    mem_cost = total_ecu * conf_ecu_rate / (addressable_memory + total_storage) * addressable_memory,
    disk_cost = total_ecu * conf_ecu_rate / (addressable_memory + total_storage) * total_storage
// reconstruct the datacontent so people know it is also the hot tier
| eval cost_type = CASE(
    cost_type == "data_content", "data_hot/data_content",
    cost_type
)
| WHERE cluster_name IS NOT NULL
// spread out the mem cost over indexing and querying
| EVAL 
    // get how much of the mem_cost is attributed to the datastream
    //realized_mem_cost = mem_cost * mem_util,
    //ds_mem_cost = realized_mem_cost / 100 * ds_total_portion,
    ds_mem_cost = mem_cost / 100 * ds_total_portion,
    // attribute that ds cost to the indexing and query portions
    indexing_cost = ds_mem_cost / ds_total_portion * ds_indexing_portion,
    query_cost = ds_mem_cost / ds_total_portion * ds_query_portion
| drop conf*
| keep mem_cost, ds_total_portion, ds_mem_cost, *util, cluster_name, datastream, @timestamp
//| stats sum(ds_total_portion) by cluster_name, @timestamp 
//| stats sum(mem_cost), sum(ds_mem_cost) by cluster_name, @timestamp
//| stats sum(ds_mem_cost) by cluster_name
//| stats sum(cluster_tier_cost) by cluster_name 
//| stats x=sum(mem_cost), y=sum(disk_cost) by cluster_name 
//| eval cost = x + y


