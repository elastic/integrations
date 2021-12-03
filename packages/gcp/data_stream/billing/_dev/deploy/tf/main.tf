provider "google" {
  project = var.project_id
}

resource "google_bigquery_dataset" "testing" {
  dataset_id                  = "integration_testing_${var.TEST_RUN_ID}"
  friendly_name               = "GCP Integration testing"
  description                 = "Used for testing the gcp integration package"
  location                    = "EU"
  default_table_expiration_ms = 3600000

  labels = {
    owner  = "elastic_integrations"
    env    = "test"
    run_id = var.TEST_RUN_ID
  }
}

resource "google_bigquery_table" "default" {
  dataset_id = google_bigquery_dataset.testing.dataset_id
  table_id   = "billing_export_test_data_${var.TEST_RUN_ID}"

  deletion_protection = false

  time_partitioning {
    type = "DAY"
  }

  labels = {
    owner  = "elastic_integrations"
    env    = "test"
    run_id = var.TEST_RUN_ID
  }

  schema = file("${path.root}/${var.billing_biquery_schema_file}")

  # use local-exec to run a go script leveraging BigQuery SDK to upload test data to the table
  # using go as is cross-platform
  provisioner "local-exec" {
    command = <<EOT
go run import/main.go \
  --project-id=${var.project_id} \
  --dataset-id=${google_bigquery_dataset.testing.dataset_id} \
  --table-id=${google_bigquery_table.default.table_id} \
  --schema-file="${path.root}/${var.billing_biquery_schema_file}" \
  --filename="${path.root}/${var.test_data_file}"
EOT
  }

}
