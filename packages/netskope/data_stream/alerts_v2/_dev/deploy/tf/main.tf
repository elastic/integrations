provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      aws_environment  = var.ENVIRONMENT
      aws_repo         = var.REPO
      aws_branch       = var.BRANCH
      aws_build        = var.BUILD_ID
      aws_created_date = var.CREATED_DATE
    }
  }
}

resource "aws_s3_bucket" "aws_bucket" {
  bucket = "elastic-package-netskope-bucket-${var.TEST_RUN_ID}"
}

resource "aws_sqs_queue" "aws_queue" {
  name       = "elastic-package-netskope-queue-${var.TEST_RUN_ID}"
  policy     = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:*:*:elastic-package-netskope-queue-${var.TEST_RUN_ID}",
      "Condition": {
        "ArnEquals": { "aws:SourceArn": "${aws_s3_bucket.aws_bucket.arn}" }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_notification" "aws_bucket_notification" {
  bucket = aws_s3_bucket.aws_bucket.id

  queue {
    queue_arn = aws_sqs_queue.aws_queue.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_object" "aws_object" {
  bucket = aws_s3_bucket.aws_bucket.id
  key    = "event.csv.gz"
  content_base64   = base64gzip(file("./files/test-alerts-v2.csv"))
  content_encoding = "gzip"
  content_type     = "text/csv"

  depends_on = [aws_sqs_queue.aws_queue]
}

output "aws_queue_url" {
  value = aws_sqs_queue.aws_queue.url
}