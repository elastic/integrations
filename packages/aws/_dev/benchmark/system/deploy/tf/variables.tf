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
    from files/cloudtrail-corpus.log wrapped as a gzipped Records envelope.

    Total events ingested = object_count x lines in the corpus file
    (1000 as committed), so the default of 20 yields 20000 events. Multiple
    objects keep SQS deliveries arriving after the first document so the
    1s readiness poll does not swallow the whole run.

    Raise this for a longer run. Prefer adding lines to
    files/cloudtrail-corpus.log when growing volume: real CloudTrail objects
    hold hundreds to thousands of events.
  DESC
  default     = 20
}

