#!/bin/bash

# Create a temp file
TMP_FILE=$(mktemp)

# Function to write file header and content
append_file_with_header() {
  local filepath="$1"
  local abs_path
  abs_path=$(cd "$(dirname "$filepath")" && pwd)
  echo "--- FILE: $(basename "$filepath")" >> "$TMP_FILE"
  echo "--- DIR : $abs_path" >> "$TMP_FILE"
  echo >> "$TMP_FILE"
  cat "$filepath" >> "$TMP_FILE"
  echo -e "\n\n" >> "$TMP_FILE"
}

# Append each file with headers
append_file_with_header ./chargeback/manifest.yml
append_file_with_header ./data_stream/billing/agent/stream/cel.yml.hbs
append_file_with_header ./data_stream/billing/fields/base-fields.yml
append_file_with_header ./data_stream/billing/manifest.yml
append_file_with_header ./data_stream/usage/_dev/test/default/config.yml
append_file_with_header ./data_stream/usage/_dev/test/default/manifest.yml
append_file_with_header ./data_stream/usage/agent/stream/cel.yml.hbs
append_file_with_header ./data_stream/usage/fields/base-fields.yml
append_file_with_header ./data_stream/usage/manifest.yml
append_file_with_header ./elasticsearch/ingest_pipeline/es_usage.yml
append_file_with_header ./elasticsearch/ingest_pipeline/ess_billing.yml
append_file_with_header ./elasticsearch/transform/billing_cluster_cost/fields/fields.yml
append_file_with_header ./elasticsearch/transform/billing_cluster_cost/manifest.yml
append_file_with_header ./elasticsearch/transform/billing_cluster_cost/transform.yml
append_file_with_header ./elasticsearch/transform/cluster_datastream_contribution/fields/fields.yml
append_file_with_header ./elasticsearch/transform/cluster_datastream_contribution/manifest.yml
append_file_with_header ./elasticsearch/transform/cluster_datastream_contribution/transform.yml
append_file_with_header ./elasticsearch/transform/cluster_deployment_contribution/fields/fields.yml
append_file_with_header ./elasticsearch/transform/cluster_deployment_contribution/manifest.yml
append_file_with_header ./elasticsearch/transform/cluster_deployment_contribution/transform.yml
append_file_with_header ./elasticsearch/transform/cluster_tier_and_ds_contribution/fields/fields.yml
append_file_with_header ./elasticsearch/transform/cluster_tier_and_ds_contribution/manifest.yml
append_file_with_header ./elasticsearch/transform/cluster_tier_and_ds_contribution/transform.yml
append_file_with_header ./elasticsearch/transform/cluster_tier_contribution/fields/fields.yml
append_file_with_header ./elasticsearch/transform/cluster_tier_contribution/manifest.yml
append_file_with_header ./elasticsearch/transform/cluster_tier_contribution/transform.yml
append_file_with_header ./manifest.yml
append_file_with_header ./validation.yml

# Copy to clipboard
pbcopy < "$TMP_FILE"

# Clean up
rm "$TMP_FILE"

echo "✅ File contents with paths copied to clipboard."
