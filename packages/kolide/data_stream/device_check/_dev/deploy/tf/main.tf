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

resource "aws_s3_bucket" "kolide" {
  bucket = "elastic-package-kolide-bucket-${var.TEST_RUN_ID}"
}

resource "aws_sqs_queue" "kolide_queue" {
  name   = "elastic-package-kolide-queue-${var.TEST_RUN_ID}"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:*:*:elastic-package-kolide-queue-${var.TEST_RUN_ID}",
      "Condition": {
        "ArnEquals": { "aws:SourceArn": "${aws_s3_bucket.kolide.arn}" }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_notification" "kolide_notification" {
  bucket = aws_s3_bucket.kolide.id

  queue {
    queue_arn = aws_sqs_queue.kolide_queue.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_object" "object" {
  for_each = fileset("${path.module}/files", "*.json")

  bucket = aws_s3_bucket.kolide.id
  # Flat fixture files are named "<check-id>__<timestamp>.json"; reconstruct the
  # real Kolide Log Pipeline key layout: kolide/check_runs/<check-id>/<timestamp>.json
  key    = "kolide/check_runs/${replace(each.value, "__", "/")}"
  source = "${path.module}/files/${each.value}"

  etag       = filemd5("${path.module}/files/${each.value}")
  depends_on = [aws_s3_bucket_notification.kolide_notification]
}

output "queue_url" {
  value = aws_sqs_queue.kolide_queue.url
}
