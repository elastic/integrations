variable "TEST_RUN_ID" {
  default = "detached"
}

variable "project_id" {
  type    = string
  default = "elastic-obs-integrations-dev"
}

variable "collection_name" {
  type    = string
  default = "collection1"
}

variable "document_id" {
  type    = string
  default = "document1"
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
  project = var.project_id
}

resource "google_firestore_document" "mydoc" {
  project     = var.project_id
  collection  = var.collection_name
  document_id = var.document_id
  fields      = "{\"something\":{\"mapValue\":{\"fields\":{\"akey\":{\"stringValue\":\"avalue\"}}}}}"
}
