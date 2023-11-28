variable "BRANCH" {
  description = "Branch name or pull request for tagging purposes"
  default     = "unknown-branch"
}

variable "BUILD_ID" {
  description = "Build ID in the CI for tagging purposes"
  default     = "unknown-build"
}

variable "CREATED_DATE" {
  description = "Creation date in epoch time for tagging purposes"
  default     = "unknown-date"
}

variable "ENVIRONMENT" {
  default = "unknown-environment"
}

variable "REPO" {
  default = "unknown-repo-name"
}

variable "TEST_RUN_ID" {
  default = "detached"
}

variable "bucket_name" {
  default = "elastic-package-crowdstrike-fdr"
}

variable "queue_name" {
  default = "elastic-package-crowdstrike-fdr"
}

// If testing using the elastic-siem account then add the following line to
// services.terraform.environment in the env.yml file to override this
// variable.
//
//   TF_VAR_eventbridge_role_arn=arn:aws:iam::144492464627:role/eb-scheduler-role-20231101165501426500000001
//
// This is needed because the elastic-siem user accounts do not allow IAM
// changes.
variable "eventbridge_role_arn" {
  description = "ARN of the role that EventBridge should assume to send SQS notifications."
  default     = null
  type        = string
}
