provider "google" {
  credentials = var.GOOGLE_CREDENTIALS
}

resource "google_storage_bucket" "bucket" {
  name     = "${var.BUCKET_NAME}-${var.TEST_RUN_ID}"
  location = "US"
}

resource "google_storage_bucket_object" "object" {
  name   = var.OBJECT_NAME
  bucket = google_storage_bucket.bucket.name
  source = var.FILE_PATH
}

output "bucket_name" {
  value = google_storage_bucket.bucket.name
}