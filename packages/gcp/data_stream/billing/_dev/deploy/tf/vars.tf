variable "TEST_RUN_ID" {
  default = "detached"
}

variable "project_id" {
  type    = string
  default = "elastic-obs-integrations-dev"
}

variable "test_data_file" {
  type    = string
  default = "test-data.ndjson"
}

variable "billing_biquery_schema_file" {
  type    = string
  default = "billing-schema.json"
}
