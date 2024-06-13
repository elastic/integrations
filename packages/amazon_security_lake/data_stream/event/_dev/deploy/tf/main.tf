variable "TEST_RUN_ID" {
  default = "detached"
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

resource "aws_s3_bucket" "security_lake_logs" {
  bucket = "elastic-package-security-lake-logs-bucket-${var.TEST_RUN_ID}"
}

resource "aws_s3_object" "object" {
  bucket = aws_s3_bucket.security_lake_logs.id
  key    = "aws_test_log"
  source = "./files/test.parquet"

  # The filemd5() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the md5() function and the file() function:
  # etag = "${md5(file("path/to/file"))}"
  etag       = filemd5("./files/test.parquet")
}

output "bucket_arn" {
  value = aws_s3_bucket.security_lake_logs.arn
  description = "The ARN of the S3 bucket"
}
