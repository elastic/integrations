provider "google" {
  default_labels = {
    environment  = var.ENVIRONMENT
    repo         = var.REPO
    branch       = var.BRANCH
    build        = var.BUILD_ID
    created_date = var.CREATED_DATE

    division     = "engineering"
    org          = "obs"
    team         = "ecosystem"
    project      = "integrations-testing"
    ephemeral    = true
  }
}

resource "google_storage_bucket" "panw_cortex_xdr_event_bucket" {
  name     = "elastic-package-gcs-bucket-${var.TEST_RUN_ID}"
  location = var.BUCKET_REGION
  uniform_bucket_level_access = true
}
# See https://github.com/elastic/oblt-infra/blob/main/conf/resources/repos/integrations/01-gcp-buildkite-oidc.tf

resource "google_storage_bucket_object" "panw_cortex_xdr_event_bucket_object" {
  name   = var.OBJECT_NAME
  bucket = google_storage_bucket.panw_cortex_xdr_event_bucket.name
  source = var.FILE_PATH
}

output "panw_cortex_xdr_event_bucket_name" {
  value = google_storage_bucket.panw_cortex_xdr_event_bucket.name
}
