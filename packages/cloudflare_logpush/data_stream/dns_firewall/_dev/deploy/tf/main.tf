provider "aws" {
  region = "us-east-1"
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

resource "aws_s3_bucket" "bucket" {
  bucket = "elastic-package-dns-firewall-bucket-${var.TEST_RUN_ID}"
}

resource "aws_sqs_queue" "queue" {
  name       = "elastic-package-dns-firewall-queue-${var.TEST_RUN_ID}"
  policy     = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:*:*:elastic-package-dns-firewall-queue-${var.TEST_RUN_ID}",
      "Condition": {
        "ArnEquals": { "aws:SourceArn": "${aws_s3_bucket.bucket.arn}" }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.bucket.id

  queue {
    queue_arn = aws_sqs_queue.queue.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_object" "object" {
  bucket = aws_s3_bucket.bucket.id
  key    = "test-dns-firewall.log"
  source = "./files/test-dns-firewall.log"

  depends_on = [aws_sqs_queue.queue]
}

output "queue_url" {
  value = aws_sqs_queue.queue.url
}
