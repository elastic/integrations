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

variable "object_count" {
  description = <<-DESC
    Number of identical CloudTrail S3 objects to upload. Terraform creates
    this many aws_s3_object resources, each with a unique key, all sourced
    from files/cloudtrail-corpus.log.

    Total events ingested = object_count x lines in the corpus file
    (1000 as committed), so the default of 1 yields 1000 events.

    Raise this only when you need more volume than the committed corpus.
    Prefer adding lines to files/cloudtrail-corpus.log instead: real
    CloudTrail objects hold hundreds to thousands of events, so many tiny
    objects distort the S3/SQS fetch cost relative to production.
  DESC
  default     = 1
}
