variable "TEST_RUN_ID" {
  default = "detached"
}

variable "gcp_project_id" {
  type    = string
  default = "elastic-obs-integrations-dev"
}

variable "collection_name" {
  type    = string
  default = "integration-test-collection"
}

variable "zone" {
  type = string
  // NOTE: if you change this value you **must** change it also for test
  // configuration, otherwise the tests will not be able to find metrics in
  // the specified region
  default = "us-central1-a"
  # https://cloud.google.com/compute/docs/regions-zones#available
}

provider "google" {
  project = var.gcp_project_id
}

resource "google_firestore_document" "mydoc6" {
  collection  = "${var.collection_name}-${var.TEST_RUN_ID}"
  document_id = "elastic-document-${var.TEST_RUN_ID}"
  fields      = "{\"something\":{\"mapValue\":{\"fields\":{\"akey\":{\"stringValue\":\"avalue\"}}}}}"
}
