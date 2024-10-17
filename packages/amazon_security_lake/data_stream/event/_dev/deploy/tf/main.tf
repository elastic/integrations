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

resource "aws_s3_bucket" "security_lake_logs" {
  bucket = "security-lake-logs-bucket-${var.TEST_RUN_ID}"
}

# Upload files to the single bucket with directory structures based on their file prefix
resource "aws_s3_object" "objects" {
  for_each = fileset(var.files_path, "**")

  bucket = aws_s3_bucket.security_lake_logs.id
  
  # Create the directory structure based on the file prefix
  key    = "${split("_", each.value)[0]}/${each.value}" 

  source = "${var.files_path}/${each.value}"  # Full path to the source file

  etag = filemd5("${var.files_path}/${each.value}")
}

output "bucket_arn" {
  value = aws_s3_bucket.security_lake_logs.arn
  description = "The ARN of the S3 bucket"
}