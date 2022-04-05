variable "TEST_RUN_ID" {
  default = "detached"
}

variable "repo_name" {
  default = "unknown"
}

variable "pull_request" {
  default = "unknown"
}

variable "ci_build" {
  default = "unknown"
}

variable "gcp_project_id" {
  type    = string
  default = "elastic-obs-integrations-dev"
}

variable "zone" {
  type = string
  // NOTE: if you change this value you **must** change it also for test
  // configuration, otherwise the tests will not be able to find metrics in
  // the specified region
  default = "us-central1-a"
  # https://cloud.google.com/compute/docs/regions-zones#available
}
