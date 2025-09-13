variable "BRANCH" {
  description = "Branch name or pull request for tagging purposes"
  default = "unknown-branch"
}

variable "BUILD_ID" {
  description = "Build ID in the CI for tagging purposes"
  default = "unknown-build"
}

variable "CREATED_DATE" {
  description = "Creation date in epoch time for tagging purposes"
  default = "unknown-date"
}

variable "ENVIRONMENT" {
  default = "unknown-environment"
}

variable "REPO" {
  default = "unknown-repo"
}

variable "FILE_PATH" {
  description = "The local path to the file to upload"
  type        = string
  default     = "./files/events.csv.gz"
}

variable "TEST_RUN_ID" {
  default = "detached"
}

variable "OBJECT_NAME" {
  description = "The name of the object in the bucket"
  type        = string
  default     = "events.csv.gz"
}

variable "BUCKET_REGION" {
  description = "The region of the bucket"
  type = string
  default = "US"
}

// If testing using the elastic-siem account then update the default value for below
// mentioned variable GOOGLE_CREDENTIALS and service_account_key in test-event-config.yml
// with your actual credentials
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
