provider "google" {
  project = var.project_id
}

provider "local" {}

resource "google_bigquery_dataset" "testing" {
  dataset_id                  = "integration_testing_${var.TEST_RUN_ID}"
  friendly_name               = "GCP Integration testing"
  description                 = "Used for testing the gcp integration package"
  location                    = "EU"
  default_table_expiration_ms = 3600000

  labels = {
    team   = "integrations"
    env    = "test"
    run_id = var.TEST_RUN_ID
  }
}


# Creates a local file with useful test data for gcp.billing data stream.
# The underlying metricbeat metricset queries based on current year and month,
# so this file, which is then uploaded to BigQuery table, should have current
# year and month.
# NOTE: project.id must not be NULL (used to filter results)
# NOTE: project.name must not be NULL (used to build eventID)
# NOTE: when this resource content changes, google_bigquery_table.default should be tainted
resource "local_file" "bq_test_data" {
  content = templatefile("${path.root}/${var.test_data_file}.tftpl", {
    ymd           = "2021-12-22"
    invoice_month = "202112"
  })

  filename = "${path.root}/${var.test_data_file}"

  file_permission = "0660"
}

resource "google_bigquery_table" "default" {
  dataset_id = google_bigquery_dataset.testing.dataset_id
  table_id   = "billing_export_test_data_${var.TEST_RUN_ID}"

  deletion_protection = false

  # NOTE: generation of test data file is required, as the file is used in the 
  # local-exec provisioner where there are no dependency checks.
  # NOTE: when this resource content changes the provisioner is not run 
  # automatically.
  depends_on = [local_file.bq_test_data]

  time_partitioning {
    type = "DAY"
  }

  labels = {
    team   = "integrations"
    env    = "test"
    run_id = var.TEST_RUN_ID
  }

  schema = file("${path.root}/${var.billing_biquery_schema_file}")

  # use local-exec to run a go script leveraging BigQuery SDK to upload test data to the table
  # using go as is cross-platform
  provisioner "local-exec" {
    command = <<EOT
bq --location=EU load \
  --source_format=NEWLINE_DELIMITED_JSON \
  --project_id=${var.project_id} \
  ${google_bigquery_dataset.testing.dataset_id}.${google_bigquery_table.default.table_id} \
  "${path.root}/${var.test_data_file}" \
  "${path.root}/${var.billing_biquery_schema_file}"
EOT
  }

}
