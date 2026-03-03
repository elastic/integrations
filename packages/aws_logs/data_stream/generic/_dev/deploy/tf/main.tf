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

resource "aws_s3_bucket" "aws_logs" {
  bucket = "elastic-package-aws-logs-bucket-${var.TEST_RUN_ID}"
}

resource "aws_sqs_queue" "aws_logs_queue" {
  name       = "elastic-package-aws-logs-queue-${var.TEST_RUN_ID}"
  policy     = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:*:*:elastic-package-aws-logs-queue-${var.TEST_RUN_ID}",
      "Condition": {
        "ArnEquals": { "aws:SourceArn": "${aws_s3_bucket.aws_logs.arn}" }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_notification" "aws_logs_notification" {
  bucket = aws_s3_bucket.aws_logs.id

  queue {
    queue_arn = aws_sqs_queue.aws_logs_queue.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_object" "object" {
  bucket = aws_s3_bucket.aws_logs.id
  key    = "aws_test_log"
  source = "./files/test.log"

  # The filemd5() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the md5() function and the file() function:
  # etag = "${md5(file("path/to/file"))}"
  etag       = filemd5("./files/test.log")
  depends_on = [aws_sqs_queue.aws_logs_queue]
}

output "queue_url" {
  value = aws_sqs_queue.aws_logs_queue.url
}
