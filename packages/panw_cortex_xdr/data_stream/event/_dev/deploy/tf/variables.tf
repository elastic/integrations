variable "BUCKET_NAME" {
  description = "The name of the GCS bucket"
  type        = string
  default     = "cortex_system_test"
}

variable "FILE_PATH" {
  description = "The local path to the file to upload"
  type        = string
  default     = "./files/test-event.log.gz"
}

variable "OBJECT_NAME" {
  description = "The name of the object in the bucket"
  type        = string
  default     = "test-event.log"
}

variable "TEST_RUN_ID" {
  default = "detached"
}

variable "GOOGLE_CREDENTIALS" {
  description = "GCP service account credentials in JSON format"
  type        = string
  default     = <<EOF
{
  "type": "{account_type}",
  "project_id": "{project_id}",
  "private_key_id": "{private_key_id}",
  "private_key": "{private_key}",
  "client_email": "{client_email}",
  "client_id": "{client_id}",
  "auth_uri": "{auth_uri}",
  "token_uri": "{token_uri}",
  "auth_provider_x509_cert_url": "{auth_provider_x509_cert_url}",
  "client_x509_cert_url": "{client_x509_cert_url}",
  "universe_domain": "{universe_domain}"
}
EOF
}
