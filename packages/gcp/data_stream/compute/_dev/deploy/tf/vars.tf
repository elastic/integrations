variable "TEST_RUN_ID" {
  default = "detached"
}

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

variable "gcp_project_id" {
  type = string
}

variable "zone" {
  type = string
  // NOTE: if you change this value you **must** change it also for test
  // configuration, otherwise the tests will not be able to find metrics in
  // the specified region
  default = "us-central1-a"
  # https://cloud.google.com/compute/docs/regions-zones#available
}
