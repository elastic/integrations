variable "TEST_RUN_ID" {
  default = "detached"
}

variable "files_path" {
  description = "Path to the directory containing files to upload"
  type        = string
  default     = "./files"
}

provider "aws" {
  default_tags {
    tags = {
      environment  = var.ENVIRONMENT
      repo         = var.REPO
      branch       = var.BRANCH
      build        = var.BUILD_ID
      created_date = var.CREATED_DATE
    }
  }
}

# Define a list of file prefixes to be used for creating buckets
locals {
  file_prefixes = ["discovery", "findings"]
}

# Create S3 buckets based on file prefixes
resource "aws_s3_bucket" "security_lake_logs" {
  for_each = toset(local.file_prefixes)

  bucket = "security-lake-logs-${each.key}-bucket-${var.TEST_RUN_ID}"
}

# Upload files to corresponding buckets based on their file prefix
resource "aws_s3_object" "objects" {
  for_each = { for file in fileset(var.files_path, "**") : file => file if contains(local.file_prefixes, split("_", file)[0]) }

  bucket = aws_s3_bucket.security_lake_logs[split("_", each.value)[0]].id

  key    = each.value  # The S3 object key will reflect the nested directory structure
  source = "${var.files_path}/${each.value}"  # Full path to the source file

  etag = filemd5("${var.files_path}/${each.value}")
}

output "bucket_arn_discovery" {
  value = aws_s3_bucket.security_lake_logs["discovery"].arn
  description = "The ARN of the 'discovery' bucket"
}

output "bucket_arn_findings" {
  value = aws_s3_bucket.security_lake_logs["findings"].arn
  description = "The ARN of the 'findings' bucket"
}
